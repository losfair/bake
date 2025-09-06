mod embed;
mod fileshare;
mod firecracker;
mod raw_udp;
mod socks5;
mod util;
mod vminit;

use anyhow::Context;
use bytes::Bytes;
use clap::Parser;
use memmap2::Mmap;
use rand::Rng;
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::os::raw::{c_char, c_void};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::embed::{EmbeddedInfo, get_embedded_data, write_embedded_data};
use crate::fileshare::spawn_file_server;
use crate::firecracker::{BootSource, Drive, FirecrackerConfig, MachineConfig, VsockConfig};
use crate::util::align_up;
use crate::util::vsock_uds_connect;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static DEBUG: AtomicBool = AtomicBool::new(false);
static TMP_BASE_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

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

    /// Container arguments
    #[arg(long)]
    arg: Vec<String>,

    /// Container environment variables
    #[arg(long, value_name = "KEY=VALUE")]
    env: Vec<String>,

    /// Enable verbose output
    #[arg(long)]
    verbose: bool,

    /// Container working directory
    #[arg(long, default_value = "")]
    cwd: String,

    /// Publish host:vm port forward (e.g. -p 8080:8080)
    #[arg(short = 'p', long = "publish", value_name = "HOST:VM")]
    publish: Vec<String>,

    /// Directory/volume mappings (e.g. -v ./data:/data)
    #[arg(short = 'v', long = "volume", value_name = "HOST:VM[:ro]")]
    volume: Vec<String>,
}

fn run_mode(
    (info, rootfs, embedded): (EmbeddedInfo, &'static [u8], &'static ArchivedEmbedded),
) -> anyhow::Result<()> {
    let parsed = RunArgs::parse();
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
    let args: Vec<String> = {
        let cli_args: Vec<String> = parsed.arg.clone();
        if !cli_args.is_empty() {
            cli_args
        } else {
            embedded.args.iter().map(|x| x.to_string()).collect()
        }
    };
    let env: Vec<String> = {
        let cli_env: Vec<String> = parsed.env.clone();
        // Merge embedded env with CLI env, CLI takes precedence for duplicate keys
        let mut merged_env = embedded
            .env
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        for cli_var in cli_env {
            if let Some(key) = cli_var.split('=').next() {
                // Remove existing env var with same key
                merged_env.retain(|env_var| !env_var.starts_with(&format!("{}=", key)));
            }
            merged_env.push(cli_var);
        }
        merged_env
    };
    let cwd = if cwd.is_empty() {
        embedded.cwd.to_string()
    } else {
        cwd.clone()
    };

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

    // Add container runtime arguments to kernel command line
    if let Some(entrypoint) = entrypoint {
        let encoded = urlencoding::encode(entrypoint);
        boot_args.push_str(&format!(" bake.entrypoint={}", encoded));
    }

    if !args.is_empty() {
        let args_str = serde_json::to_string(&args).unwrap();
        let encoded = urlencoding::encode(&args_str);
        boot_args.push_str(&format!(" bake.args={}", encoded));
    }

    if !env.is_empty() {
        let env_str = serde_json::to_string(&env).unwrap();
        let encoded = urlencoding::encode(&env_str);
        boot_args.push_str(&format!(" bake.env={}", encoded));
    }

    if !cwd.is_empty() {
        let encoded = urlencoding::encode(&cwd);
        boot_args.push_str(&format!(" bake.cwd={}", encoded));
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
    crate::socks5::run_socks5_unix(&vsock_inbound_socks5_uds)
        .with_context(|| "failed to start socks5 uds listener")?;
    crate::socks5::run_socks5_udp_unix(&vsock_inbound_socks5_udp_uds)
        .with_context(|| "failed to start socks5 udp uds listener")?;

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

    if !volumes.is_empty() {
        let env_str =
            serde_json::to_string(&volumes.iter().map(|x| x.guest.as_str()).collect::<Vec<_>>())
                .unwrap();
        let encoded = urlencoding::encode(&env_str);
        boot_args.push_str(&format!(" bake.volumes={}", encoded));
    }

    {
        // 2GB
        const DISK_SIZE: u64 = 2 * 1024 * 1024 * 1024;
        let mut disk = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ephemeral_disk)
            .with_context(|| "failed to open ephemeral disk")?;
        disk.seek(SeekFrom::Start(DISK_SIZE - 1))
            .and_then(|_| disk.write(&[0u8]))
            .with_context(|| "failed to initialize ephemeral disk")?;
    }

    let firecracker_config = FirecrackerConfig {
        boot_source: BootSource {
            kernel_image_path: kernel_path,
            initrd_path,
            boot_args,
        },
        drives: vec![
            Drive {
                drive_id: "rootfs".into(),
                is_root_device: true,
                is_read_only: true,
                path_on_host: exe_path,
            },
            Drive {
                drive_id: "ephemeral".into(),
                is_root_device: false,
                is_read_only: false,
                path_on_host: ephemeral_disk
                    .to_str()
                    .expect("invalid ephemeral disk path")
                    .to_string(),
            },
        ],
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
    let config_path = mkmemfd("config", &config_json)?;

    // Start firecracker with the specified parameters
    let mut cmd = ProcessCommand::new(&firecracker_path);
    cmd.arg("--config-file")
        .arg(config_path)
        .arg("--no-api")
        .arg("--enable-pci")
        .stdin(Stdio::inherit())
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
    // Build a small runtime to host listeners and tasks; keep it alive.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()
        .unwrap();
    rt.spawn(async move {
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
    std::mem::forget(rt);
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
        let (mut inbound, _) = listener.accept().await?;
        let uds_path = uds_path.to_string();
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

                    // Pipe data both ways
                    if let Err(e) = tokio::io::copy_bidirectional(&mut inbound, &mut stream).await {
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

fn mkmemfd(name: &str, data: &[u8]) -> anyhow::Result<String> {
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
        anyhow::bail!("file sealing failed: {:?}", std::io::Error::last_os_error())
    }

    // Return the file descriptor (but don't close it)
    std::mem::forget(file);
    Ok(format!("/proc/self/fd/{}", fd))
}

unsafe fn memfd_from_mmap(name: &str, data: &'static [u8]) -> anyhow::Result<String> {
    unsafe {
        let pgsize = libc::sysconf(libc::_SC_PAGESIZE);
        assert!(pgsize >= 4096);
        let pgsize = pgsize as usize;

        let path = mkmemfd(name, data)?;
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
