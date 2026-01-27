use std::{
    collections::HashMap,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    path::Path,
    sync::atomic::Ordering,
};

use fdlimit::Outcome;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest, unix::AsyncFd},
    net::UnixStream,
};

#[cfg(target_os = "linux")]
use tokio_vsock::VsockStream;

use crate::DEBUG;

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Clone, Debug)]
pub struct BootManifest {
    pub entrypoint: Option<String>,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub volumes: Vec<VolumeManifest>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub disable_hostnet: bool,
    pub wireguard_conf: Option<String>,
    pub ssh_ecdsa_private_key: String,
    pub ssh_ecdsa_public_key: String,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Clone, Debug)]
pub struct VolumeManifest {
    pub guest_path: String,
    pub host_filename: Option<String>,
    pub ro: bool,
    pub ext4: bool,
}

pub fn align_up(value: usize, align: usize) -> usize {
    assert_eq!(align.count_ones(), 1);
    (value + (align - 1)) & !(align - 1)
}

pub async fn vsock_uds_connect(uds_path: &Path, port: u32) -> anyhow::Result<UnixStream> {
    'outer: loop {
        let mut stream = UnixStream::connect(uds_path).await?;
        stream
            .write_all(format!("CONNECT {}\n", port).as_bytes())
            .await?;
        stream.flush().await?;

        let mut recv_buf = [0u8; 64];
        let mut recv_cursor = 0usize;
        loop {
            let b = match stream.read_u8().await {
                Ok(b) => b,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue 'outer;
                    }
                    return Err(e.into());
                }
            };
            if b == b'\n' {
                break;
            }

            if recv_cursor == recv_buf.len() {
                anyhow::bail!("buffer overflow");
            }
            recv_buf[recv_cursor] = b;
            recv_cursor += 1;
        }
        let msg = std::str::from_utf8(&recv_buf[..recv_cursor])?;
        if !msg.starts_with("OK ") {
            anyhow::bail!("unexpected response: {}", msg);
        }

        return Ok(stream);
    }
}

pub fn set_nonblocking(fd: BorrowedFd, nb: bool) -> std::io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL, 0);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(
            fd.as_raw_fd(),
            libc::F_SETFL,
            if nb {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            },
        ) < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn quote_systemd_string(s: &str) -> String {
    let mut output = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '/' || ch == '=' {
            output.push(ch);
        } else {
            let mut bytes = [0u8; 4];
            let bytes = ch.encode_utf8(&mut bytes);
            for b in bytes.as_bytes() {
                output.push_str(&format!("\\x{:02x}", b));
            }
        }
    }
    output
}

pub fn best_effort_raise_fd_limit() {
    match fdlimit::raise_fd_limit() {
        Ok(Outcome::LimitRaised { from, to }) => {
            if DEBUG.load(Ordering::Relaxed) {
                eprintln!("raised fd limit from {} to {}", from, to);
            }
        }
        Ok(Outcome::Unsupported) => {
            eprintln!("raising fd limit is not supported on this platform");
        }
        Err(e) => {
            eprintln!("failed to raise fd limit: {:?}", e);
        }
    }
}

pub async fn copy_bidirectional_fastclose(a: OwnedFd, b: OwnedFd) -> std::io::Result<()> {
    async fn copy<'b>(
        a: &'b AsyncFd<OwnedFd>,
        b: &'b AsyncFd<OwnedFd>,
        drain: bool,
    ) -> std::io::Result<()> {
        const BUFFER_SIZE: usize = 8192;
        let mut buf = vec![0u8; BUFFER_SIZE];
        loop {
            let n = if drain {
                nix::unistd::read(a.get_ref(), &mut buf).map_err(std::io::Error::from)?
            } else {
                a.async_io(Interest::READABLE, |x| {
                    nix::unistd::read(x, &mut buf).map_err(std::io::Error::from)
                })
                .await?
            };
            if n == 0 {
                if drain {
                    unsafe {
                        libc::shutdown(b.as_raw_fd(), libc::SHUT_WR);
                    }
                }
                return Ok(());
            }
            let mut buf = &buf[..n];
            while !buf.is_empty() {
                let written = b
                    .async_io(Interest::WRITABLE, |x| {
                        nix::unistd::write(x, buf).map_err(std::io::Error::from)
                    })
                    .await?;
                assert!(written > 0);
                buf = &buf[written..];
            }
        }
    }
    let a = AsyncFd::with_interest(a, Interest::READABLE | Interest::WRITABLE)?;
    let b = AsyncFd::with_interest(b, Interest::READABLE | Interest::WRITABLE)?;
    let ret = tokio::select! {
      biased;
      x = copy(&a, &b, false) => x,
      x = copy(&b, &a, false) => x,
    };
    let _ = tokio::join!(copy(&a, &b, true), copy(&b, &a, true));
    ret
}

#[cfg(target_os = "linux")]
pub fn decompose_vsock_stream(s: VsockStream) -> std::io::Result<OwnedFd> {
    s.as_fd().try_clone_to_owned()
}

#[cfg(target_os = "macos")]
pub fn decompose_vsock_stream(s: UnixStream) -> std::io::Result<OwnedFd> {
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::io::FromRawFd;
    let std_stream = s.into_std()?;
    Ok(unsafe { OwnedFd::from_raw_fd(std_stream.into_raw_fd()) })
}
