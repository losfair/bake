mod console;
mod embed;
mod fileshare;
mod firecracker;
mod raw_udp;
mod socks5;
mod ssh_launcher;
mod util;
mod vm_console;
mod vminit;
mod wireguard;

use anyhow::Context;
use bytes::Bytes;
use clap::Parser;
use memmap2::Mmap;
use rand::Rng;
use rkyv::{Archive, Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::os::raw::{c_char, c_void};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::net::UnixListener;
use tokio::runtime::Runtime;

use crate::embed::{EmbeddedInfo, get_embedded_data, write_embedded_data};
use crate::fileshare::spawn_file_server;
use crate::firecracker::{BootSource, Drive, FirecrackerConfig, MachineConfig, VsockConfig};
use crate::util::{
    BootManifest, VolumeManifest, align_up, best_effort_raise_fd_limit,
    copy_bidirectional_fastclose,
};
use crate::util::{quote_systemd_string, vsock_uds_connect};
use crate::vm_console::host_run_console;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static DEBUG: AtomicBool = AtomicBool::new(false);
static TMP_BASE_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static RT: OnceLock<Runtime> = OnceLock::new();

#[derive(Archive, Deserialize, Serialize)]
struct Embedded {
    firecracker: Bytes,
    kernel: Bytes,
    initrd: Bytes,
    rootfs_size: u64,
    entrypoint: Option<String>,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    uid: Option<u32>,
    gid: Option<u32>,
}

fn main() -> anyhow::Result<()> {
    if std::env::var("BAKE_DEBUG").ok().as_deref() == Some("1") {
        DEBUG.store(true, Ordering::Relaxed);
    }

    if std::env::var("BAKE_NOT_INIT").ok().as_deref() != Some("1") && unsafe { libc::getpid() } == 1
    {
        return vminit::run();
    }

    // Check if we have embedded data by looking for our custom sections
    let embedded = check_for_embedded_sections();

    if let Some(embedded) = embedded {
        run_mode(embedded)
    } else {
        build_mode()
    }
}

#[derive(Debug, Parser)]
#[command(name = "bake", about = "Embed Firecracker resources into a binary")]
struct BuildArgs {
    #[arg(short, long, default_value = "/proc/self/exe")]
    input: String,

    #[arg(short, long)]
    output: String,

    #[arg(long, env = "BAKE_BUILD_FIRECRACKER")]
    firecracker: String,

    #[arg(long, env = "BAKE_BUILD_KERNEL")]
    kernel: String,

    #[arg(long, env = "BAKE_BUILD_INITRD")]
    initrd: String,

    #[arg(long, env = "BAKE_BUILD_ROOTFS")]
    rootfs: String,

    #[arg(long)]
    entrypoint: Option<String>,

    #[arg(long)]
    arg: Vec<String>,

    #[arg(long, value_name = "KEY=VALUE")]
    env: Vec<String>,

    #[arg(long)]
    cwd: Option<String>,

    #[arg(long)]
    uid: Option<u32>,

    #[arg(long)]
    gid: Option<u32>,
}

fn check_for_embedded_sections() -> Option<(EmbeddedInfo, &'static [u8], &'static ArchivedEmbedded)>
{
    let info = get_embedded_data()?;
    let embedded_len = u32::from_le_bytes(info.data[0..4].try_into().unwrap()) as usize;
    let embedded = &info.data[16..16 + embedded_len];
    let rootfs_offset = align_up(16 + embedded_len, 512);
    if DEBUG.load(Ordering::Relaxed) {
        eprintln!(
            "embedded data @ {:p}, header length {}, rootfs offset {}",
            info.data.as_ptr(),
            embedded_len,
            rootfs_offset
        );
    }
    let archived = rkyv::access::<ArchivedEmbedded, rkyv::rancor::Error>(embedded)
        .expect("invalid archived data");
    let rootfs =
        &info.data[rootfs_offset..rootfs_offset + archived.rootfs_size.to_native() as usize];
    Some((info, rootfs, archived))
}

fn build_mode() -> anyhow::Result<()> {
    let args = BuildArgs::parse();

    let output_path = &args.output;
    let firecracker_path = &args.firecracker;
    let kernel_path = &args.kernel;
    let initrd_path = &args.initrd;
    let rootfs_path = &args.rootfs;
    let input_path = &args.input;
    let entrypoint = args.entrypoint.clone();
    let args_vec: Vec<String> = args.arg.clone();
    let env_vec: Vec<String> = args.env.clone();
    let cwd = args.cwd.clone().unwrap_or_default();
    let uid = args.uid.clone();
    let gid = args.gid.clone();

    // Read resource files
    let firecracker_data = &*Box::leak(Box::new(unsafe {
        Mmap::map(&File::open(firecracker_path)?)?
    }));
    let kernel_data = &*Box::leak(Box::new(unsafe { Mmap::map(&File::open(kernel_path)?)? }));
    let initrd_data = &*Box::leak(Box::new(unsafe { Mmap::map(&File::open(initrd_path)?)? }));
    let mut rootfs_file = File::open(rootfs_path)?;
    let rootfs_size = rootfs_file.metadata()?.size();
    let input = unsafe { Mmap::map(&File::open(input_path)?)? };
    let embedded = Embedded {
        firecracker: Bytes::from_static(firecracker_data),
        kernel: Bytes::from_static(kernel_data),
        initrd: Bytes::from_static(initrd_data),
        rootfs_size,
        entrypoint,
        args: args_vec,
        env: env_vec,
        cwd,
        uid,
        gid,
    };
    let embedded = rkyv::to_bytes::<rkyv::rancor::Error>(&embedded).expect("serialization failed");
    let embedded_len = (embedded.len() as u32).to_le_bytes();
    let align_fill_bytes_1 = align_up(embedded.len() + 16, 512) - (embedded.len() + 16);
    assert!(align_fill_bytes_1 < 512);
    let align_fill_bytes_1 = vec![0u8; align_fill_bytes_1];
    let align_fill_bytes_2 = align_up(rootfs_size as usize, 512) - rootfs_size as usize;
    assert!(align_fill_bytes_2 < 512);
    let align_fill_bytes_2 = vec![0u8; align_fill_bytes_2];

    // Create ELF with embedded sections
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&input)?;
    write_embedded_data(
        &mut [
            &mut Cursor::new(&embedded_len[..]),
            &mut Cursor::new(&[0u8; 12]),
            &mut Cursor::new(&embedded),
            &mut Cursor::new(&align_fill_bytes_1),
            &mut rootfs_file,
            &mut Cursor::new(&align_fill_bytes_2),
        ],
        &mut output_file,
        input.len(),
    )?;
    drop(output_file);

    fs::set_permissions(output_path, Permissions::from_mode(0o755))?;

    println!("{}", output_path);
    Ok(())
}

#[derive(clap::Subcommand, Debug)]
enum RunSubcommand {
    /// Connect to the running microVM via SSH
    Ssh {
        /// PID of the target instance
        #[arg(short = 'p', long = "pid")]
        pid: Option<i32>,
        /// Extra ssh(1) arguments after `--`
        #[arg(trailing_var_arg = true, last = true)]
        ssh_args: Vec<String>,
    },
    /// Print a systemd service unit for current options
    Systemd {
        /// Container arguments (after `--`)
        #[arg(trailing_var_arg = true, last = true)]
        container_args: Vec<String>,
    },
}

#[derive(Debug, Parser)]
#[command(name = "bake", about = "Bottlefire microVM Image")]
struct RunArgs {
    /// Number of CPU cores
    #[arg(long)]
    cpus: Option<u32>,

    /// Amount of memory (in MB) allocated to the microVM
    #[arg(long, default_value_t = 256)]
    memory: u32,

    /// Kernel command line
    #[arg(long = "boot-args", default_value = "console=ttyS0 reboot=k panic=-1")]
    boot_args: String,

    /// Container entrypoint
    #[arg(long)]
    entrypoint: Option<String>,

    /// Container arguments (after `--`)
    #[arg(trailing_var_arg = true, last = true)]
    container_args: Vec<String>,

    /// Container environment variables
    #[arg(short = 'e', long, value_name = "KEY=VALUE")]
    env: Vec<String>,

    /// Enable verbose output
    #[arg(long)]
    verbose: bool,

    /// Container working directory
    #[arg(long, default_value = "")]
    cwd: String,

    /// Container user ID inside the microVM
    #[arg(long)]
    uid: Option<u32>,

    /// Container group ID inside the microVM
    #[arg(long)]
    gid: Option<u32>,

    /// Publish host:vm port forward (e.g. -p 8080:8080)
    #[arg(short = 'p', long = "publish", value_name = "HOST:VM")]
    publish: Vec<String>,

    /// Directory/volume mappings (e.g. -v ./data:/data)
    #[arg(short = 'v', long = "volume", value_name = "HOST:VM[:ro]")]
    volume: Vec<String>,

    /// Allow outbound network to IPv4 address or CIDR (repeatable)
    #[arg(long = "allow-net")]
    allow_net: Vec<String>,

    /// Disable outbound network bridge
    #[arg(long = "disable-hostnet")]
    disable_hostnet: bool,

    /// WireGuard config file path (wg setconf format)
    #[arg(long = "wireguard-conf-file")]
    wireguard_conf_file: Option<PathBuf>,

    /// Size of ephemeral disk (in MB) for overlay filesystem [default: 2048]
    #[arg(long, default_value_t = 2048)]
    ephemeral_disk_size: u32,

    /// Path to write SSH private key to
    #[arg(long, env = "BAKE_SSH_PRIVATE_KEY_PATH")]
    ssh_private_key_path: Option<PathBuf>,

    /// Unix socket path to listen for SSH connections
    #[arg(long, env = "BAKE_SSH_SOCK_PATH")]
    ssh_sock_path: Option<PathBuf>,

    /// Path to write SSH connect script to
    #[arg(long, env = "BAKE_SSH_SCRIPT_PATH")]
    ssh_script_path: Option<PathBuf>,

    /// Subcommands for interacting with a running instance
    #[command(subcommand)]
    cmd: Option<RunSubcommand>,
}

fn generate_systemd_unit(args: &RunArgs) -> anyhow::Result<()> {
    let executable_path = std::env::current_exe()?;
    let executable_path = executable_path.to_string_lossy();

    let mut service_args = Vec::new();

    if let Some(cpus) = args.cpus {
        service_args.push(format!("--cpus {}", cpus));
    }

    service_args.push(format!("--memory {}", args.memory));

    service_args.push(format!(
        "--boot-args {}",
        shell_escape::escape(args.boot_args.as_str().into())
    ));

    if let Some(ref entrypoint) = args.entrypoint {
        service_args.push(format!(
            "--entrypoint {}",
            shell_escape::escape(entrypoint.as_str().into())
        ));
    }

    for env in &args.env {
        service_args.push(format!(
            "--env {}",
            shell_escape::escape(env.as_str().into())
        ));
    }

    if !args.cwd.is_empty() {
        service_args.push(format!(
            "--cwd {}",
            shell_escape::escape(args.cwd.as_str().into())
        ));
    }

    if let Some(uid) = args.uid {
        service_args.push(format!("--uid {}", uid));
    }
    if let Some(gid) = args.gid {
        service_args.push(format!("--gid {}", gid));
    }

    for publish in &args.publish {
        service_args.push(format!(
            "--publish {}",
            shell_escape::escape(publish.as_str().into())
        ));
    }

    for volume in &args.volume {
        service_args.push(format!(
            "--volume {}",
            shell_escape::escape(volume.as_str().into())
        ));
    }

    for ip in &args.allow_net {
        service_args.push(format!("--allow-net {}", ip));
    }
    if args.disable_hostnet {
        service_args.push("--disable-hostnet".into());
    }
    if let Some(path) = &args.wireguard_conf_file {
        service_args.push(format!(
            "--wireguard-conf-file {}",
            shell_escape::escape(path.to_string_lossy().into())
        ));
    }

    service_args.push(format!(
        "--ephemeral-disk-size {}",
        args.ephemeral_disk_size
    ));

    if !args.container_args.is_empty() {
        service_args.push("--".into());
        for carg in &args.container_args {
            service_args.push(format!("{}", shell_escape::escape(carg.as_str().into())));
        }
    }

    let args_str = if service_args.is_empty() {
        String::new()
    } else {
        format!(" \\\n    {}", service_args.join(" \\\n    "))
    };

    let mut service_file = format!(
        r#"[Unit]
Description=Bottlefire microVM Service

[Service]
Type=simple
ExecStart={}{}
Restart=always
RestartSec=5
PrivateTmp=true
ProtectSystem=strict
CapabilityBoundingSet=
NoNewPrivileges=true
Environment=BAKE_SSH_PRIVATE_KEY_PATH=/tmp/id_ecdsa
Environment=BAKE_SSH_SOCK_PATH=/tmp/ssh.sock
Environment=BAKE_SSH_SCRIPT_PATH=/tmp/ssh.sh
"#,
        executable_path, args_str
    );

    for env in &args.env {
        service_file.push_str("Environment=\"BAKE_VM_");
        service_file.push_str(&quote_systemd_string(env));
        service_file.push_str("\"\n");
    }

    service_file.push_str(
        r#"
[Install]
WantedBy=multi-user.target
"#,
    );

    print!("{}", service_file);
    Ok(())
}

fn run_mode(
    (info, rootfs, embedded): (EmbeddedInfo, &'static [u8], &'static ArchivedEmbedded),
) -> anyhow::Result<()> {
    let mut parsed = RunArgs::parse();

    // If a subcommand is specified, handle it and exit.
    if let Some(cmd) = &parsed.cmd {
        match cmd {
            RunSubcommand::Ssh { pid, ssh_args } => {
                return ssh_launcher::launch_ssh(*pid, ssh_args.clone());
            }
            RunSubcommand::Systemd { container_args } => {
                parsed.container_args = container_args.clone();
                return generate_systemd_unit(&parsed);
            }
        }
    }

    best_effort_raise_fd_limit();

    RT.set(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .thread_name("bake-worker")
            .build()
            .unwrap(),
    )
    .ok()
    .expect("RT.set()");

    // Auto-detect CPUs if not provided
    let cpus: u32 = parsed.cpus.unwrap_or_else(|| {
        let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if n > 0 { n as u32 } else { 1 }
    });
    let memory = &parsed.memory;
    let boot_args = &parsed.boot_args;
    let verbose = &parsed.verbose;
    let cwd = &parsed.cwd;

    // CLI params take precedence over embedded params
    let entrypoint = parsed
        .entrypoint
        .as_ref()
        .map(|x| x.as_str())
        .or_else(|| embedded.entrypoint.as_ref().map(|x| x.as_str()));
    let args: Vec<String> = if !parsed.container_args.is_empty() {
        parsed.container_args.clone()
    } else {
        embedded.args.iter().map(|x| x.to_string()).collect()
    };
    let mut env: HashMap<String, String> = HashMap::new();

    // Merge embedded env with BAKE_VM_ env and CLI env
    // Precedence: CLI > BAKE_VM_ > embedded

    // Embedded env
    for x in &*embedded.env {
        let Some((key, value)) = x.split_once('=') else {
            continue;
        };
        env.insert(key.to_string(), value.to_string());
    }

    // Collect BAKE_VM_ environment variables from host and strip prefix
    for (key, value) in std::env::vars() {
        let Some(stripped_key) = key.strip_prefix("BAKE_VM_") else {
            continue;
        };
        env.insert(stripped_key.to_string(), value);
    }

    // Add CLI env vars
    for x in &parsed.env {
        let Some((key, value)) = x.split_once('=') else {
            continue;
        };
        env.insert(key.to_string(), value.to_string());
    }

    let cwd = if cwd.is_empty() {
        embedded.cwd.to_string()
    } else {
        cwd.clone()
    };

    // Determine default uid/gid: CLI > embedded > None
    let uid: Option<u32> = parsed
        .uid
        .or_else(|| embedded.uid.as_ref().map(|x| x.to_native()));
    let gid: Option<u32> = parsed
        .gid
        .or_else(|| embedded.gid.as_ref().map(|x| x.to_native()));

    // Create memfd for firecracker binary
    let firecracker_path = unsafe { memfd_from_mmap("firecracker", &embedded.firecracker)? };

    // Create memfd for kernel
    let kernel_path = unsafe { memfd_from_mmap("kernel", &embedded.kernel)? };

    // Create memfd for initrd
    let initrd_path = unsafe { memfd_from_mmap("initrd", &embedded.initrd)? };

    // No O_CLOEXEC to be inherited by firecracker
    let exe_fd = unsafe {
        libc::open(
            b"/proc/self/exe\0".as_ptr() as *const c_char,
            libc::O_RDONLY,
        )
    };
    let exe_path = format!("/proc/self/fd/{}", exe_fd);

    let rootfs_offset = unsafe { rootfs.as_ptr().offset_from(info.base.as_ptr()) };
    assert!(rootfs_offset % 512 == 0);

    let mut boot_args = format!(
        "{} bake.rootfs_offset={} bake.rootfs_size={}",
        boot_args,
        rootfs_offset / 512,
        align_up(rootfs.len(), 512) / 512
    );

    if !verbose {
        boot_args.push_str(" quiet");
    }

    // Propagate host debug no-reboot flag into VM kernel cmdline
    if std::env::var("BAKE_NO_REBOOT").ok().as_deref() == Some("1") {
        boot_args.push_str(" bake.noreboot=1");
    }

    let tmp_base_dir = std::env::temp_dir().join(format!(
        "bottlefire-bake-fc-{}",
        faster_hex::hex_string(&rand::rng().random::<[u8; 16]>())
    ));
    std::fs::create_dir(&tmp_base_dir).with_context(|| {
        format!(
            "failed to create vsock base dir at {}",
            tmp_base_dir.display()
        )
    })?;
    TMP_BASE_DIR
        .try_lock()
        .unwrap()
        .replace(tmp_base_dir.clone());
    unsafe {
        libc::signal(libc::SIGTERM, term_signal as usize);
        libc::signal(libc::SIGINT, term_signal as usize);
        libc::signal(libc::SIGHUP, term_signal as usize);
    }
    scopeguard::defer! {
      let _ = std::fs::remove_dir_all(&tmp_base_dir);
    }
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(x) = TMP_BASE_DIR.try_lock() {
            if let Some(path) = &*x {
                let _ = std::fs::remove_dir_all(path);
            }
        }
        prev_hook(info)
    }));
    let ephemeral_disk = tmp_base_dir.join("ephemeral.img");
    let vsock_outbound_uds = tmp_base_dir.join("fc.sock");
    let vsock_inbound_socks5_uds = tmp_base_dir.join("fc.sock_10");
    let vsock_inbound_socks5_udp_uds = tmp_base_dir.join("fc.sock_11");
    let vsock_inbound_9p = tmp_base_dir.join("fc.sock_12");
    let vsock_inbound_boot_manifest_request = tmp_base_dir.join("fc.sock_13");
    let vsock_inbound_console = tmp_base_dir.join("fc.sock_14");
    // Apply network allowlist (if any) for outbound network
    if !parsed.allow_net.is_empty() || parsed.disable_hostnet {
        crate::socks5::set_allow_net(parsed.allow_net.clone());
    }

    if !parsed.disable_hostnet {
        crate::socks5::run_socks5_unix(&vsock_inbound_socks5_uds)
            .with_context(|| "failed to start socks5 uds listener")?;
    }
    crate::socks5::run_socks5_udp_unix(&vsock_inbound_socks5_udp_uds)
        .with_context(|| "failed to start socks5 udp uds listener")?;
    let console_task = host_run_console(RT.get().unwrap(), &vsock_inbound_console)
        .with_context(|| "failed to start console listener")?;

    // Start requested TCP port forwards via vsock SOCKS5 (port 10)
    if !parsed.publish.is_empty() {
        let uds_path = vsock_outbound_uds
            .to_str()
            .expect("invalid vsock_outbound_uds")
            .to_string();
        spawn_port_forwards(parsed.publish, uds_path);
    }

    // Start plan9 filesystem server
    let volumes = if !parsed.volume.is_empty() {
        spawn_file_server(parsed.volume, &vsock_inbound_9p)
    } else {
        vec![]
    };

    if volumes.iter().filter(|x| x.ext4).count() > 20 {
        panic!("too many ext4 volumes, max 20");
    }

    let ssh_ecdsa_private_key = ssh_key::PrivateKey::random(
        &mut rand_core_06::OsRng,
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .with_context(|| "failed to generate ssh key")?;
    let ssh_ecdsa_public_key = ssh_ecdsa_private_key.public_key().to_openssh().unwrap();
    let ssh_ecdsa_private_key = ssh_ecdsa_private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    let ssh_ecdsa_private_key_path = mkmemfd(
        "id_ecdsa",
        ssh_ecdsa_private_key.as_bytes(),
        Permissions::from_mode(0o400),
    )?;
    mkmemfd(
        "id_ecdsa.pub",
        ssh_ecdsa_public_key.as_bytes(),
        Permissions::from_mode(0o400),
    )?;

    let ssh_ecdsa_private_key_path: &Path = if let Some(x) = &parsed.ssh_private_key_path {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(x)
            .and_then(|mut x| x.write_all(ssh_ecdsa_private_key.as_bytes()))
            .with_context(|| "failed to write ssh key to BAKE_SSH_PRIVATE_KEY_PATH")?;
        x
    } else {
        Path::new(&ssh_ecdsa_private_key_path)
    };

    let ssh_proxy_path = parsed
        .ssh_sock_path
        .unwrap_or_else(|| tmp_base_dir.join("ssh.sock"));
    serve_ssh_proxy(&ssh_proxy_path, &vsock_outbound_uds)
        .with_context(|| "failed to start ssh proxy service")?;
    mkmemfd(
        "ssh_proxy_path",
        ssh_proxy_path.as_os_str().as_encoded_bytes(),
        Permissions::from_mode(0o444),
    )?;

    if let Some(x) = &parsed.ssh_script_path {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o700)
            .open(x)
            .and_then(|mut x| x.write_all(format!(r#"#!/bin/sh
exec ssh -i {} -o "ProxyCommand nc -U {}" -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" root@localhost
"#, shell_escape::escape(ssh_ecdsa_private_key_path.to_string_lossy()), shell_escape::escape(ssh_proxy_path.to_string_lossy())).as_bytes()))
            .with_context(|| "failed to write to BAKE_SSH_SCRIPT_PATH")?;
    }

    let manifest = BootManifest {
        entrypoint: entrypoint.map(|x| x.to_string()),
        args,
        cwd: if cwd.is_empty() { None } else { Some(cwd) },
        env,
        volumes: volumes
            .iter()
            .map(|x| VolumeManifest {
                guest_path: x.guest.clone(),
                host_filename: if x.is_file {
                    Some(
                        Path::new(&x.host)
                            .file_name()
                            .and_then(|x| x.to_str())
                            .unwrap_or_else(|| panic!("cannot determine host filename: {:?}", x))
                            .to_string(),
                    )
                } else {
                    None
                },
                ext4: x.ext4,
                ro: x.ro,
            })
            .collect(),
        uid,
        gid,
        disable_hostnet: parsed.disable_hostnet,
        wireguard_conf: if let Some(ref path) = parsed.wireguard_conf_file {
            Some(
                std::fs::read_to_string(path)
                    .with_context(|| "failed to read wireguard conf file")?,
            )
        } else {
            None
        },
        ssh_ecdsa_private_key,
        ssh_ecdsa_public_key,
    };
    serve_boot_manifest_request(&vsock_inbound_boot_manifest_request, &manifest)?;

    let mut drives = vec![
        Drive {
            drive_id: "rootfs".into(),
            is_root_device: true,
            is_read_only: true,
            io_engine: "Async".into(),
            path_on_host: exe_path,
        },
        Drive {
            drive_id: "ephemeral".into(),
            is_root_device: false,
            is_read_only: false,
            io_engine: "Async".into(),
            path_on_host: ephemeral_disk
                .to_str()
                .expect("invalid ephemeral disk path")
                .to_string(),
        },
    ];

    for (i, vol) in volumes.iter().enumerate() {
        if vol.ext4 {
            drives.push(Drive {
                drive_id: format!("vol-{}", i),
                is_root_device: false,
                is_read_only: vol.ro,
                io_engine: "Async".into(),
                path_on_host: vol.host.clone(),
            })
        }
    }

    {
        // Convert MB to bytes
        let disk_size: u64 = parsed.ephemeral_disk_size as u64 * 1024 * 1024;
        let mut disk = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ephemeral_disk)
            .with_context(|| "failed to open ephemeral disk")?;
        disk.seek(SeekFrom::Start(disk_size - 1))
            .and_then(|_| disk.write(&[0u8]))
            .with_context(|| "failed to initialize ephemeral disk")?;
    }

    let firecracker_config = FirecrackerConfig {
        boot_source: BootSource {
            kernel_image_path: kernel_path,
            initrd_path,
            boot_args,
        },
        drives,
        machine_config: MachineConfig {
            vcpu_count: cpus,
            mem_size_mib: *memory,
        },
        network_interfaces: vec![],
        vsock: VsockConfig {
            guest_cid: 3,
            uds_path: vsock_outbound_uds
                .to_str()
                .expect("invalid vsock_outbound_uds")
                .to_string(),
        },
    };

    // Check for dry run mode
    if std::env::var("BAKE_DRY_RUN").ok().as_deref() == Some("1") {
        let config_json = serde_json::to_string_pretty(&firecracker_config)?;
        println!("{}", config_json);
        return Ok(());
    }

    let config_json = serde_json::to_vec(&firecracker_config)?;
    let config_path = mkmemfd("config", &config_json, Permissions::from_mode(0o444))?;

    // Start firecracker with the specified parameters
    let mut cmd = ProcessCommand::new(&firecracker_path);
    cmd.arg("--config-file")
        .arg(config_path)
        .arg("--no-api")
        .arg("--enable-pci")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !*verbose {
        cmd.arg("--level").arg("error");
    }
    unsafe {
        let ppid = libc::getpid();
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != ppid {
                libc::abort();
            }
            Ok(())
        });
    }

    let mut cmd = cmd.spawn()?;
    let stdout = cmd.stdout.take().unwrap();
    let stderr = cmd.stderr.take().unwrap();
    for mut pipe in [
        Box::new(stdout) as Box<dyn Read + Send + Sync>,
        Box::new(stderr) as Box<dyn Read + Send + Sync>,
    ] {
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok(n) = pipe.read(&mut buf) else {
                    break;
                };
                let mut stdout = std::io::stdout().lock();
                let _ = stdout.write_all(&buf[..n]);
                let _ = stdout.flush();
            }
        });
    }
    let status = cmd.wait()?;
    console_task.abort();
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "firecracker exited with status {}",
            status
                .code()
                .map(|x| x.to_string())
                .unwrap_or_else(|| "unknown".into())
        ))
    }
}

fn spawn_port_forwards(publishes: Vec<String>, uds_path: String) {
    RT.get().unwrap().spawn(async move {
        for spec in publishes {
            if let Some((ip, host, vm)) = parse_publish(&spec) {
                let uds_path = uds_path.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_listener(ip, host, vm, &uds_path).await {
                        eprintln!("port forward {}:{}:{} failed: {:?}", ip, host, vm, e);
                    }
                });
            } else {
                eprintln!("invalid -p/--publish spec: {} (expected HOST:VM)", spec);
            }
        }
    });
}

fn parse_publish(spec: &str) -> Option<(std::net::IpAddr, u16, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        2 => {
            let host: u16 = parts[0].parse().ok()?;
            let vm: u16 = parts[1].parse().ok()?;
            Some((std::net::IpAddr::from([127, 0, 0, 1]), host, vm))
        }
        3 => {
            let ip: std::net::IpAddr = parts[0].parse().ok()?;
            let host: u16 = parts[1].parse().ok()?;
            let vm: u16 = parts[2].parse().ok()?;
            Some((ip, host, vm))
        }
        _ => None,
    }
}

async fn forward_listener(
    bind_ip: std::net::IpAddr,
    host_port: u16,
    vm_port: u16,
    uds_path: &str,
) -> anyhow::Result<()> {
    let bind_addr = std::net::SocketAddr::new(bind_ip, host_port);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    loop {
        let (inbound, _) = listener.accept().await?;
        let uds_path = Path::new(uds_path).to_path_buf();
        tokio::spawn(async move {
            match vsock_uds_connect(&uds_path, 10).await {
                Ok(mut stream) => {
                    // SOCKS5 handshake: no auth
                    let mut resp = [0u8; 2];
                    if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err()
                        || stream.flush().await.is_err()
                        || stream.read_exact(&mut resp).await.is_err()
                        || resp != [0x05, 0x00]
                    {
                        return;
                    }

                    // CONNECT 127.0.0.1:vm_port
                    let port_be = vm_port.to_be_bytes();
                    let req = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port_be[0], port_be[1]];
                    if stream.write_all(&req).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }

                    // Reply: version, status, rsv, atyp, addr..., port
                    let mut hdr = [0u8; 4];
                    if stream.read_exact(&mut hdr).await.is_err()
                        || hdr[0] != 0x05
                        || hdr[1] != 0x00
                    {
                        return;
                    }
                    let addr_len = match hdr[3] {
                        0x01 => 4,
                        0x03 => {
                            let mut l = [0u8; 1];
                            if stream.read_exact(&mut l).await.is_err() {
                                return;
                            }
                            l[0] as usize
                        }
                        0x04 => 16,
                        _ => 0,
                    };
                    if addr_len == 0 {
                        return;
                    }
                    let mut skip = vec![0u8; addr_len + 2];
                    if let Err(_) = stream.read_exact(&mut skip).await {
                        return;
                    }

                    let Ok(inbound) = inbound.into_std() else {
                        return;
                    };
                    let Ok(stream) = stream.into_std() else {
                        return;
                    };
                    // Pipe data both ways
                    if let Err(e) =
                        copy_bidirectional_fastclose(inbound.into(), stream.into()).await
                    {
                        eprintln!("forward connection failed: {:?}", e);
                    }
                }
                Err(e) => {
                    eprintln!("failed to connect vsock proxy: {:?}", e);
                }
            }
        });
    }
}

fn mkmemfd(name: &str, data: &[u8], permissions: Permissions) -> anyhow::Result<String> {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;

    let name_cstring = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid name for memfd"))?;

    // Create memfd
    // No cloexec!
    let fd = unsafe { libc::memfd_create(name_cstring.as_ptr(), libc::MFD_ALLOW_SEALING) };

    if fd == -1 {
        return Err(io::Error::last_os_error().into());
    }

    // Write data to memfd
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(data)?;
    file.flush()?;

    // Seal it
    if unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } != 0
    {
        anyhow::bail!("file sealing failed: {:?}", std::io::Error::last_os_error());
    }

    if unsafe { libc::fchmod(fd, permissions.mode()) } < 0 {
        anyhow::bail!("fchmod failed: {:?}", std::io::Error::last_os_error());
    }

    // Return the file descriptor (but don't close it)
    std::mem::forget(file);
    Ok(format!("/proc/self/fd/{}", fd))
}

fn serve_boot_manifest_request(path: &Path, manifest: &BootManifest) -> anyhow::Result<()> {
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    let manifest = rkyv::to_bytes::<rkyv::rancor::Error>(manifest)?;
    std::thread::spawn(move || {
        // only serve the manifest once
        let Ok((mut conn, _)) = listener.accept() else {
            return;
        };
        let _: Result<_, _> = conn
            .write_all(&manifest)
            .and_then(|_| conn.shutdown(std::net::Shutdown::Write));
    });
    Ok(())
}

fn serve_ssh_proxy(path: &Path, vsock_outbound_uds: &Path) -> anyhow::Result<()> {
    let listener = RT
        .get()
        .unwrap()
        .block_on(async { UnixListener::bind(path) })?;
    let vsock_outbound_uds = Arc::new(vsock_outbound_uds.to_path_buf());
    RT.get().unwrap().spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                break;
            };
            let vsock_outbound_uds = vsock_outbound_uds.clone();
            tokio::spawn(async move {
                let Ok(outbound) = vsock_uds_connect(&vsock_outbound_uds, 22).await else {
                    return;
                };
                let Ok(conn) = conn.into_std() else {
                    return;
                };
                let Ok(outbound) = outbound.into_std() else {
                    return;
                };
                let _ = copy_bidirectional_fastclose(conn.into(), outbound.into()).await;
            });
        }
    });
    Ok(())
}

unsafe fn memfd_from_mmap(name: &str, data: &'static [u8]) -> anyhow::Result<String> {
    unsafe {
        let pgsize = libc::sysconf(libc::_SC_PAGESIZE);
        assert!(pgsize >= 4096);
        let pgsize = pgsize as usize;

        let path = mkmemfd(name, data, Permissions::from_mode(0o777))?;
        let ptr = data.as_ptr();
        let end = ptr.add(data.len());
        let ptr = align_up(ptr as usize, pgsize);
        let end = end as usize & !(pgsize - 1);

        if end > ptr {
            if DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "madvise({:p}, {:#x}, MADV_DONTNEED)",
                    ptr as *mut c_void,
                    end - ptr
                );
            }
            assert_eq!(
                libc::madvise(ptr as *mut c_void, end - ptr, libc::MADV_DONTNEED),
                0
            );
        }
        Ok(path)
    }
}

unsafe extern "C" fn term_signal(sig: i32) {
    if let Ok(x) = TMP_BASE_DIR.try_lock() {
        if let Some(path) = &*x {
            let _ = std::fs::remove_dir_all(path);
        }
    }
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}
