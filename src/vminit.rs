use crate::util::{
    ArchivedVolumeManifest, best_effort_raise_fd_limit, copy_bidirectional_fastclose,
    decompose_vsock_stream, set_nonblocking,
};
use anyhow::Context;
use nix::mount::MsFlags;
use serde_json::json;
use std::{
    borrow::Cow,
    collections::HashMap,
    fs::{self, OpenOptions, Permissions},
    io::Write,
    net::{IpAddr, SocketAddr},
    os::{
        fd::{AsFd, AsRawFd},
        unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Command, ExitStatus, Stdio},
    str::FromStr,
    sync::atomic::Ordering,
};
use tokio::{io::AsyncReadExt, net::UnixListener};

use crate::{DEBUG, util::ArchivedBootManifest};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

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
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
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
    best_effort_raise_fd_limit();
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

    // Fetch boot manifest
    let mut boot_manifest = Vec::new();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            VsockStream::connect(VsockAddr::new(2, 13))
                .await?
                .read_to_end(&mut boot_manifest)
                .await
        })?;
    let boot_manifest = rkyv::access::<ArchivedBootManifest, rkyv::rancor::Error>(&boot_manifest)
        .with_context(|| "invalid boot request")?;

    // start socks5 server
    crate::socks5::run_socks5_vsock().expect("failed to start socks5 server");

    // proxy socks5 to host
    crate::socks5::run_socks5_tcp_to_vsock_proxy().expect("failed to start socks5 host proxy");

    crate::socks5::run_socks5_udp_injection("hostudp").expect("failed to start udp injection task");
    if !boot_manifest.disable_hostnet {
        // configure udp routing and start tun2socks
        cmd(r#"set -e
ip route add default dev hostudp table 100
nft add table inet mangle
nft 'add chain inet mangle output { type route hook output priority mangle; }'
nft 'add rule inet mangle output meta l4proto udp meta mark set 0x64'
ip rule add preference 100 fwmark 0x64 lookup 100

ip tuntap add mode tun dev hostnet
ip addr add 198.18.0.1/32 dev hostnet
ip link set dev hostnet up
ip route add default dev hostnet
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
    }

    // Configure WireGuard if provided by host
    if let Some(conf) = boot_manifest.wireguard_conf.as_deref() {
        std::fs::write("/ephemeral/wg.conf", conf).expect("failed to write wg.conf");
        let parsed = crate::wireguard::parse_wireguard_conf(conf);
        let sanitized = crate::wireguard::serialize_without_keys(&parsed, &["address", "dns"]);
        std::fs::write("/ephemeral/wg.setconf", sanitized).expect("failed to write wg.setconf");
        use std::collections::BTreeSet;
        let mut addr_set = BTreeSet::new();
        let mut allowed_set = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for sec in &parsed.sections {
            if sec.name.eq_ignore_ascii_case("interface") {
                for (k, v) in &sec.items {
                    if k.eq_ignore_ascii_case("address") {
                        for item in v {
                            addr_set.insert(item.clone());
                        }
                    }
                }
            } else if sec.name.eq_ignore_ascii_case("peer") {
                for (k, v) in &sec.items {
                    if k.eq_ignore_ascii_case("allowedips") {
                        for item in v {
                            allowed_set.insert(item.clone());
                        }
                    }
                    if k.eq_ignore_ascii_case("endpoint") {
                        for item in v {
                            endpoints.insert(item.clone());
                        }
                    }
                }
            }
        }
        // Create interface, apply config, assign addresses, bring up
        cmd("ip link add dev wg0 mtu 1280 type wireguard");
        cmd("wg setconf wg0 /ephemeral/wg.setconf");
        for addr in addr_set {
            cmd(&format!(
                "ip addr add {} dev wg0",
                shell_escape::escape(addr.into())
            ));
        }
        cmd("ip link set up dev wg0");
        for cidr in allowed_set {
            // Use -4/-6 depending on address family for clarity
            if cidr.contains(':') {
                cmd(&format!(
                    "ip -6 route add {} dev wg0 table 99",
                    shell_escape::escape(cidr.into())
                ));
            } else {
                cmd(&format!(
                    "ip -4 route add {} dev wg0 table 99",
                    shell_escape::escape(cidr.into())
                ));
            }
        }
        for endpoint in endpoints {
            let Ok(addr) = SocketAddr::from_str(&endpoint) else {
                continue;
            };
            let IpAddr::V4(ip) = addr.ip() else {
                continue;
            };
            let status = Command::new("/sbin/ip")
                .arg("route")
                .arg("add")
                .arg(ip.to_string())
                .arg("dev")
                .arg("hostudp")
                .arg("table")
                .arg("99")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .unwrap();
            if !status.success() {
                panic!("ip route add dev hostudp failed");
            }
        }
        cmd("ip rule add preference 99 from all lookup 99");
    }

    if !boot_manifest.volumes.is_empty() {
        setup_9p_volumes(&boot_manifest.volumes);
    }

    std::fs::write(
        "/etc/ssh/sshd_config",
        r#"HostKey /etc/ssh/ssh_host_ecdsa_key
PermitRootLogin without-password
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
ForceCommand /ssh.sh
"#,
    )
    .with_context(|| "failed to write sshd_config")?;

    std::fs::write(
        "/ssh.sh",
        r#"#!/bin/sh
set -e
cd /var/lib/container
if [ -z "$SSH_TTY" ]; then
  exec runc exec container1 sh -c "$SSH_ORIGINAL_COMMAND"
else
  if [ -z "$SSH_ORIGINAL_COMMAND" ]; then
    exec runc exec -t container1 sh
  else
    exec runc exec -t container1 sh -c "$SSH_ORIGINAL_COMMAND"
  fi
fi
"#,
    )
    .with_context(|| "failed to write ssh.sh")?;
    std::fs::set_permissions("/ssh.sh", Permissions::from_mode(0o555))?;

    std::fs::write(
        "/etc/ssh/ssh_host_ecdsa_key",
        boot_manifest.ssh_ecdsa_private_key.as_bytes(),
    )
    .with_context(|| "failed to write ssh_host_ecdsa_key")?;
    std::fs::set_permissions("/etc/ssh/ssh_host_ecdsa_key", Permissions::from_mode(0o600))?;
    std::fs::create_dir_all("/root/.ssh")?;
    std::fs::write(
        "/root/.ssh/authorized_keys",
        boot_manifest.ssh_ecdsa_public_key.as_bytes(),
    )
    .with_context(|| "failed to write authorized_keys")?;
    std::fs::set_permissions("/root/.ssh/authorized_keys", Permissions::from_mode(0o600))?;

    sshd_vsock(VsockAddr::new(u32::MAX, 22))
        .with_context(|| "failed to start sshd vsock listener")?;

    let res = start_container(
        boot_manifest
            .uid
            .as_ref()
            .map(|x| x.to_native())
            .unwrap_or(0),
        boot_manifest
            .gid
            .as_ref()
            .map(|x| x.to_native())
            .unwrap_or(0),
        boot_manifest.entrypoint.as_ref(),
        &boot_manifest.args[..],
        boot_manifest
            .env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .chain(
                std::iter::once(|| "TERM=xterm".to_string())
                    .filter(|_| !boot_manifest.env.contains_key("TERM"))
                    .map(|x| x()),
            ),
        boot_manifest.cwd.as_deref().unwrap_or_default(),
    )?;
    if !res.success() {
        eprintln!("exit status: {:?}", res);
    }
    // Respect kernel cmdline flag to avoid reboot for debugging
    if cmdline.contains_key("bake.noreboot") {
        if DEBUG.load(Ordering::Relaxed) {
            eprintln!("[vminit] bake.noreboot present; holding VM after container exit");
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    } else {
        unsafe {
            libc::sync();
        }
        if !DEBUG.load(Ordering::Relaxed) {
            let _ = std::fs::write("/proc/sys/kernel/printk", b"0");
        }
        unsafe {
            libc::reboot(libc::RB_AUTOBOOT);
        }
    }

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

fn setup_9p_volumes(vols: &[ArchivedVolumeManifest]) {
    // Create a lightweight runtime to host listeners; keep it alive.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()
        .unwrap();

    // Base dir for unix sockets
    let base = "/ephemeral/9p-sock";
    let _ = std::fs::create_dir_all(base);

    let mut vd_names = ('c'..='z').map(|x| format!("/dev/vd{}", x));

    for (idx, vol) in vols.iter().enumerate() {
        let uds_path = format!("{}/vol{}.sock", base, idx);

        // Start a unix-to-vsock proxy that writes the guest path prefix
        let uds_path_clone = uds_path.clone();
        rt.block_on(async { start_9p_unix_to_vsock_proxy(&uds_path_clone, &vol.guest_path) })
            .expect("failed to start unix to vsock proxy");

        let mount_it = |path: &Path| {
            nix::mount::mount(
                Some(uds_path.as_str()),
                path,
                Some("9p"),
                MsFlags::empty(),
                Some("trans=unix,version=9p2000.L"),
            )
            .expect("9p mount failed");
        };
        let guest_path = Path::new("/rootfs").join(vol.guest_path.as_str().trim_start_matches('/'));
        if let Some(host_filename) = vol.host_filename.as_deref() {
            if vol.ext4 {
                let _ = std::fs::create_dir_all(&guest_path);
                let vd = vd_names.next().expect("too many ext4 volumes");
                let status = Command::new("mount")
                    .arg("-t")
                    .arg("ext4")
                    .arg("-o")
                    .arg(if vol.ro { "ro,relatime" } else { "rw,relatime" })
                    .arg(vd)
                    .arg(&guest_path)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status()
                    .unwrap();
                if !status.success() {
                    panic!("ext4 mount failed: {}", vol.guest_path);
                }
            } else {
                let filebase = format!("/filebase/{}", idx);
                let _ = std::fs::create_dir_all(&filebase);
                mount_it(Path::new(&filebase));
                if let Some(parent) = guest_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o000)
                    .open(&guest_path);

                nix::mount::mount(
                    Some(format!("{}/{}", filebase, host_filename).as_str()),
                    guest_path.as_path(),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .expect("bind mount failed");
            }
        } else {
            let _ = std::fs::create_dir_all(&guest_path);
            mount_it(&guest_path);
        }
    }

    // Keep runtime alive for the lifetime of the init process
    std::mem::forget(rt);
}

fn start_9p_unix_to_vsock_proxy(uds_path: &str, guest_path: &str) -> anyhow::Result<()> {
    let listener = UnixListener::bind(uds_path)?;
    let guest_path = guest_path.to_string();
    tokio::spawn(async move {
        loop {
            let Ok((inbound, _)) = listener.accept().await else {
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

                let e = copy_bidirectional_fastclose(
                    inbound.into_std()?.into(),
                    decompose_vsock_stream(outbound)?,
                )
                .await;
                if let Err(e) = e {
                    eprintln!("9p proxy error: {:?}", e);
                }
                Ok::<_, anyhow::Error>(())
            });
        }
    });
    Ok(())
}

fn start_container(
    uid: u32,
    gid: u32,
    entrypoint: Option<impl AsRef<str>>,
    args: &[impl AsRef<str>],
    env: impl Iterator<Item = String>,
    cwd: &str,
) -> anyhow::Result<ExitStatus> {
    // Create container directories
    cmd("mkdir -p /var/lib/container");
    std::env::set_current_dir("/var/lib/container")?;

    // Create resolv.conf with Google DNS
    fs::write("/var/lib/container/resolv.conf", "nameserver 8.8.8.8\n")?;

    // Create hosts
    fs::write("/var/lib/container/hosts", "127.0.0.1 localhost\n")?;

    let mut env_vars =
        vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()];
    env_vars.extend(env);

    // Determine the process command and args
    let mut process_args = if let Some(entrypoint) = &entrypoint {
        vec![entrypoint.as_ref()]
    } else {
        vec![]
    };
    process_args.extend(args.iter().map(|x| x.as_ref()));

    // Generate OCI runtime spec
    let spec = generate_oci_spec(uid, gid, &process_args, &env_vars, cwd);

    // Write config.json
    let mut config_file = fs::File::create("/var/lib/container/config.json")?;
    config_file.write_all(serde_json::to_string_pretty(&spec)?.as_bytes())?;
    drop(config_file);

    // Console bridge (vsock CID 2, port 14)
    let tty = crate::vm_console::start_console_bridge()?;

    // Start container with runc (we're already in the bundle directory)
    let mut cmd = Command::new("runc");
    cmd.arg("run")
        .arg("--no-pivot")
        .arg("container1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        let tty_fd = tty.as_raw_fd();
        cmd.pre_exec(move || {
            libc::login_tty(tty_fd);
            Ok(())
        });
    }
    let status = cmd.status()?;

    Ok(status)
}

fn sshd_vsock(vsock_listen: VsockAddr) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()
        .unwrap();
    let sock = rt.block_on(async { VsockListener::bind(vsock_listen) })?;
    rt.spawn(async move {
        loop {
            let Ok((conn, _)) = sock.accept().await else {
                break;
            };
            let mut cmd = Command::new("/usr/sbin/sshd");
            cmd.arg("-i")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit());
            set_nonblocking(conn.as_fd(), false).expect("failed to set nonblocking");
            let fd = conn.as_fd().as_raw_fd();
            unsafe {
                let ppid = libc::getpid();
                cmd.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                        || libc::getppid() != ppid
                    {
                        libc::abort();
                    }
                    if libc::dup2(fd, 0) < 0 || libc::dup2(fd, 1) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            if let Err(e) = cmd.spawn() {
                eprintln!("failed to spawn sshd: {:?}", e);
            }
        }
    });
    std::mem::forget(rt);
    Ok(())
}

fn generate_oci_spec(
    uid: u32,
    gid: u32,
    args: &[&str],
    env: &[String],
    cwd: &str,
) -> serde_json::Value {
    json!({
        "ociVersion": "1.0.0",
        "process": {
            "terminal": true,
            "user": {
                "uid": uid,
                "gid": gid
            },
            "args": args,
            "env": env,
            "cwd": if cwd.is_empty() { "/" } else { cwd },
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
                "destination": "/etc/hosts",
                "type": "bind",
                "source": "/var/lib/container/hosts",
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
