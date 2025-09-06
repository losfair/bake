use serde_json::json;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    process::{Command, ExitStatus, Stdio},
    sync::atomic::Ordering,
};
use tokio::net::UnixListener;

use crate::DEBUG;
use tokio_vsock::{VsockAddr, VsockStream};

const ALL_NS: &[&str] = &[
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_NICE",
    "CAP_SYS_PACCT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
];

pub fn run() -> anyhow::Result<()> {
    cmd(r#"set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t cgroup2 cgroup2 /sys/fs/cgroup
ip link set lo up
"#);
    let cmdline = Box::leak(
        std::fs::read_to_string("/proc/cmdline")
            .unwrap()
            .into_boxed_str(),
    )
    .split(' ')
    .filter(|x| !x.is_empty())
    .map(|x| x.split_once('=').unwrap_or((x, "")))
    .collect::<HashMap<&'static str, &'static str>>();
    let quiet = cmdline.contains_key("quiet");
    if !quiet {
        DEBUG.store(true, Ordering::Relaxed);
        println!("Bottlefire v0.1.0");
        cmd("cat /proc/version");
    }
    let rootfs_offset = cmdline
        .get("bake.rootfs_offset")
        .and_then(|x| x.parse::<u64>().ok())
        .expect("bake.rootfs_offset not found");
    let rootfs_size = cmdline
        .get("bake.rootfs_size")
        .and_then(|x| x.parse::<u64>().ok())
        .expect("bake.rootfs_size not found");
    cmd(&format!(
        "echo '0 {} linear /dev/vda {}' | dmsetup create rootfs",
        rootfs_size, rootfs_offset
    ));
    cmd(r#"
set -e
mkdir /rootfs.base /rootfs /ephemeral
mkfs.ext4 -q /dev/vdb
mount -t ext4 /dev/vdb /ephemeral
mkdir -p /ephemeral/rootfs.overlay/upper /ephemeral/rootfs.overlay/work /ephemeral/container-tmp
chmod 1777 /ephemeral/container-tmp
mount /dev/mapper/rootfs /rootfs.base
mount -t overlay -o rw,lowerdir=/rootfs.base,upperdir=/ephemeral/rootfs.overlay/upper,workdir=/ephemeral/rootfs.overlay/work overlay /rootfs
"#);
    if !quiet {
        cmd("ls /dev; mount");
    }

    // start socks5 server
    crate::socks5::run_socks5_vsock().expect("failed to start socks5 server");

    // proxy socks5 to host
    crate::socks5::run_socks5_tcp_to_vsock_proxy().expect("failed to start socks5 host proxy");

    // start tun2socks
    cmd(r#"set -e
ip tuntap add mode tun dev hostnet
ip addr add 198.18.0.1/32 dev hostnet
ip link set dev hostnet up
ip route add default dev hostnet
"#);

    crate::socks5::run_socks5_udp_injection("hostudp").expect("failed to start udp injection task");
    cmd(r#"set -e
ip route add default dev hostudp table 100
nft add table inet mangle
nft 'add chain inet mangle output { type route hook output priority mangle; }'
nft 'add rule inet mangle output meta l4proto udp meta mark set 0x64'
ip rule add fwmark 0x64 lookup 100
"#);

    let mut tun2socks = Command::new("/usr/bin/tun2socks")
        .arg("-device")
        .arg("hostnet")
        .arg("-proxy")
        .arg("socks5://127.0.0.10:10")
        .arg("-interface")
        .arg("lo")
        .stdin(Stdio::null())
        .stdout(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .stderr(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .spawn()
        .unwrap();
    std::thread::spawn(move || {
        let ret = tun2socks.wait();
        panic!("tun2socks exited: {:?}", ret);
    });

    // Setup 9p volume mounts via vsock proxy (host port 12)
    if let Some(vols) = cmdline
        .get("bake.volumes")
        .map(|s| urlencoding::decode(s).unwrap().into_owned())
        .and_then(|x| serde_json::from_str::<Vec<String>>(&x).ok())
    {
        if !vols.is_empty() {
            setup_9p_volumes(&vols);
        }
    }

    // Parse container runtime arguments
    let entrypoint = cmdline
        .get("bake.entrypoint")
        .map(|s| urlencoding::decode(s).unwrap().into_owned());
    let args = cmdline
        .get("bake.args")
        .map(|s| urlencoding::decode(s).unwrap().into_owned())
        .and_then(|x| serde_json::from_str::<Vec<String>>(&x).ok())
        .unwrap_or_default();
    let env = cmdline
        .get("bake.env")
        .map(|s| urlencoding::decode(s).unwrap().into_owned())
        .and_then(|x| serde_json::from_str::<Vec<String>>(&x).ok())
        .unwrap_or_default();
    let cwd = cmdline
        .get("bake.cwd")
        .map(|s| urlencoding::decode(s).unwrap().into_owned())
        .unwrap_or_default();
    let res = start_container(entrypoint, args, env, cwd)?;
    if !res.success() {
        eprintln!("exit status: {:?}", res);
    }
    let _ = std::fs::write("/proc/sysrq-trigger", b"b");

    Ok(())
}

fn cmd(cmd: &str) {
    assert!(
        Command::new("/bin/busybox")
            .arg("sh")
            .arg("-c")
            .arg(cmd)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .unwrap()
            .success()
    );
}

fn setup_9p_volumes(vols: &Vec<String>) {
    // Create a lightweight runtime to host listeners; keep it alive.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()
        .unwrap();

    // Base dir for unix sockets
    let base = "/ephemeral/9p-sock";
    let _ = std::fs::create_dir_all(base);

    for (idx, guest_path) in vols.iter().enumerate() {
        let uds_path = format!("{}/vol{}.sock", base, idx);

        // Start a unix-to-vsock proxy that writes the guest path prefix
        let guest_path_clone = guest_path.clone();
        let uds_path_clone = uds_path.clone();
        rt.block_on(async { start_9p_unix_to_vsock_proxy(&uds_path_clone, &guest_path_clone) })
            .expect("failed to start unix to vsock proxy");

        // Ensure mountpoint exists under overlay root
        let mnt_point = format!("/rootfs{}", guest_path);
        if let Err(e) = std::fs::create_dir_all(&mnt_point) {
            eprintln!("failed to create mountpoint {}: {:?}", mnt_point, e);
            continue;
        }

        // Perform the mount using 9p over unix socket
        // Note: the source is the unix socket path (trans=unix)
        let mount_cmd = format!(
            "mount -t 9p -o trans=unix,version=9p2000.L {} {}",
            uds_path, mnt_point
        );
        cmd(&mount_cmd);
    }

    // Keep runtime alive for the lifetime of the init process
    std::mem::forget(rt);
}

fn start_9p_unix_to_vsock_proxy(uds_path: &str, guest_path: &str) -> anyhow::Result<()> {
    let listener = UnixListener::bind(uds_path)?;
    let guest_path = guest_path.to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                break;
            };
            let guest_path = guest_path.clone();

            // Connect to host vsock CID 2, port 12
            // Then write the length-prefixed guest path, little-endian
            tokio::spawn(async move {
                let mut outbound = VsockStream::connect(VsockAddr::new(2, 12)).await?;

                let name_bytes = guest_path.as_bytes();
                <VsockStream as tokio::io::AsyncWriteExt>::write_all(
                    &mut outbound,
                    &(name_bytes.len() as u32).to_le_bytes(),
                )
                .await?;
                <VsockStream as tokio::io::AsyncWriteExt>::write_all(&mut outbound, name_bytes)
                    .await?;

                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                Ok::<_, anyhow::Error>(())
            });
        }
    });
    Ok(())
}

fn start_container(
    entrypoint: Option<String>,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
) -> anyhow::Result<ExitStatus> {
    // Create container directories
    cmd("mkdir -p /var/lib/container");
    std::env::set_current_dir("/var/lib/container")?;

    // Create resolv.conf with Google DNS
    fs::write("/var/lib/container/resolv.conf", "nameserver 8.8.8.8\n")?;

    let env_vars: Vec<String> = if env.is_empty() {
        vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()]
    } else {
        let mut vars =
            vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()];
        vars.extend(env);
        vars
    };

    // Determine the process command and args
    let mut process_args = if let Some(entrypoint) = entrypoint {
        vec![entrypoint]
    } else {
        vec![]
    };
    process_args.extend(args);

    // Generate OCI runtime spec
    let spec = generate_oci_spec(&process_args, &env_vars, cwd);

    // Write config.json
    let mut config_file = fs::File::create("/var/lib/container/config.json")?;
    config_file.write_all(serde_json::to_string_pretty(&spec)?.as_bytes())?;
    drop(config_file);

    // Start container with runc (we're already in the bundle directory)
    let status = Command::new("runc")
        .arg("run")
        .arg("--no-pivot")
        .arg("container1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    Ok(status)
}

fn generate_oci_spec(args: &[String], env: &[String], cwd: String) -> serde_json::Value {
    json!({
        "ociVersion": "1.0.0",
        "process": {
            "terminal": true,
            "user": {
                "uid": 0,
                "gid": 0
            },
            "args": args,
            "env": env,
            "cwd": if cwd.is_empty() { "/" } else { cwd.as_str() },
            "capabilities": {
                "bounding": ALL_NS,
                "effective": ALL_NS,
                "inheritable": ALL_NS,
                "permitted": ALL_NS,
                "ambient": ALL_NS
            },
            "rlimits": [
                {
                    "type": "RLIMIT_NOFILE",
                    "hard": 1048576,
                    "soft": 1048576
                }
            ],
            "noNewPrivileges": false
        },
        "root": {
            "path": "/rootfs",
            "readonly": false
        },
        "hostname": "container",
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc"
            },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": [
                    "nosuid",
                    "strictatime",
                    "mode=755",
                    "size=65536k"
                ]
            },
            {
                "destination": "/dev/pts",
                "type": "devpts",
                "source": "devpts",
                "options": [
                    "nosuid",
                    "noexec",
                    "newinstance",
                    "ptmxmode=0666",
                    "mode=0620",
                    "gid=5"
                ]
            },
            {
                "destination": "/sys",
                "type": "sysfs",
                "source": "sysfs",
                "options": [
                    "nosuid",
                    "noexec",
                    "nodev",
                    "ro"
                ]
            },
            {
                "destination": "/sys/fs/cgroup",
                "type": "cgroup",
                "source": "cgroup",
                "options": [
                    "nosuid",
                    "noexec",
                    "nodev",
                    "relatime",
                    "ro"
                ]
            },
            {
                "destination": "/etc/resolv.conf",
                "type": "bind",
                "source": "/var/lib/container/resolv.conf",
                "options": [
                    "bind",
                    "ro"
                ]
            },
            {
                "destination": "/tmp",
                "type": "bind",
                "source": "/ephemeral/container-tmp",
                "options": [
                    "bind",
                    "rw"
                ]
            }
        ],
        "linux": {
            "resources": {
                "devices": [
                    {
                        "allow": true,
                        "access": "rwm"
                    }
                ]
            },
            "namespaces": [
                {
                    "type": "pid"
                },
                {
                    "type": "ipc"
                },
                {
                    "type": "uts"
                },
                {
                    "type": "mount"
                }
            ],
            "maskedPaths": [],
            "readonlyPaths": []
        }
    })
}
