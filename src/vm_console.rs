use std::path::Path;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    runtime::Runtime,
    task::JoinHandle,
};

// Guest-side imports (Linux-only)
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use tokio::io::{Interest, unix::AsyncFd};
#[cfg(target_os = "linux")]
use tokio_vsock::{VsockAddr, VsockStream};
#[cfg(target_os = "linux")]
use crate::util::set_nonblocking;

use crate::console::{ConsoleRequest, ConsoleResponse};
#[cfg(target_os = "linux")]
use crate::console::ArchivedConsoleResponse;

/// Start console bridge inside the VM guest.
/// This connects to the host via vsock and bridges to a local PTY.
#[cfg(target_os = "linux")]
pub fn start_console_bridge() -> anyhow::Result<OwnedFd> {
    // Runtime to host the vsock bridge tasks; keep it alive.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .thread_name("bake-vm-console")
        .build()
        .unwrap();

    // Create a pty pair
    let (master_fd, slave_fd) = unsafe {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        if libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) != 0
        {
            anyhow::bail!("openpty failed: {:?}", std::io::Error::last_os_error());
        }
        (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))
    };

    let slave_fd_for_ioctl = slave_fd.try_clone().unwrap();

    let conn = rt
        .block_on(async { VsockStream::connect(VsockAddr::new(2, 14)).await })
        .expect("failed to connect to vsock (2, 14)");

    rt.spawn(async move {
      set_nonblocking(master_fd.as_fd(), true).expect("failed to set nonblocking");
      let master_fd = AsyncFd::new(master_fd).unwrap();
      let (mut conn_r, mut conn_w) = conn.into_split();
      let rd_fut = async  {
        let mut buf = vec![0u8; 4096];
        loop {
        let n =  master_fd.async_io(Interest::READABLE, |x| nix::unistd::read(x, &mut buf).map_err(std::io::Error::from)).await?;
          if n == 0 {
            break;
          }
          let msg = ConsoleRequest::Data(buf[..n].to_vec());
          let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&msg)?;
          write_frame(&mut conn_w, &bytes).await.with_context(|| "writing frame")?;
        }
        Ok::<_, anyhow::Error>(())
      };

      let wr_fut = async  {
        loop {
          let Ok(frame) = read_frame(&mut conn_r).await else {
            break;
          };
          let archived = rkyv::access::<ArchivedConsoleResponse, rkyv::rancor::Error>(&frame)?;
          match archived {
              crate::console::ArchivedConsoleResponse::Data(data) => {
                let mut data = &data[..];
                while !data.is_empty() {
                  let n = master_fd.async_io(Interest::WRITABLE, |x| nix::unistd::write(x, data).map_err(std::io::Error::from)).await?;
                  data = &data[n..];
                }
              }
              crate::console::ArchivedConsoleResponse::SetWindowSize { rows, cols } => {
                  unsafe {
                      let mut ws: libc::winsize = std::mem::zeroed();
                      ws.ws_row = (*rows).into();
                      ws.ws_col = (*cols).into();
                      let _ = libc::ioctl(slave_fd_for_ioctl.as_raw_fd(), libc::TIOCSWINSZ, &ws);
                  }
              }
          }
        }
        Ok::<_, anyhow::Error>(())
      };

     let ret = tokio::select! {
        biased;
        x = rd_fut => x,
        x = wr_fut => x,
      };
      panic!("vm_console exited: {:?}", ret);
    });

    // Keep runtime alive for the lifetime of the process
    std::mem::forget(rt);

    Ok(slave_fd)
}

/// Run console on the host side.
/// This accepts Unix socket connections and bridges stdin/stdout.
pub fn host_run_console(rt: &Runtime, path: &Path) -> anyhow::Result<JoinHandle<()>> {
    let listener = rt.block_on(async { UnixListener::bind(path) })?;
    let task = rt.spawn(async move {
        // only accept once
        let Ok((conn, _)) = listener.accept().await else {
            return;
        };

        // Enable raw mode on host tty for pass-through control characters
        struct TermiosGuard(Option<(i32, libc::termios)>);
        impl Drop for TermiosGuard {
            fn drop(&mut self) {
                if let Some((fd, orig)) = self.0.take() {
                    unsafe {
                        let _ = libc::tcsetattr(fd, libc::TCSANOW, &orig);
                    }
                }
            }
        }

        let mut guard = TermiosGuard(None);
        let tty_fd = choose_tty_fd();
        unsafe {
            if tty_fd >= 0 {
                let mut tio: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(tty_fd, &mut tio) == 0 {
                    let orig = tio;
                    tio.c_iflag &=
                        !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
                    tio.c_oflag &= !(libc::OPOST);
                    tio.c_cflag |= libc::CS8;
                    tio.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
                    tio.c_cc[libc::VMIN] = 1;
                    tio.c_cc[libc::VTIME] = 0;
                    let _ = libc::tcsetattr(tty_fd, libc::TCSANOW, &tio);
                    guard.0 = Some((tty_fd, orig));
                }
            }
        }

        let (mut conn_r, conn_w) = conn.into_split();
        let conn_w = tokio::sync::Mutex::new(conn_w);

        // stdin -> tx
        let stdin_fut = async {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let msg = ConsoleResponse::Data(buf[..n].to_vec());
                let bytes = match rkyv::to_bytes::<rkyv::rancor::Error>(&msg) {
                    Ok(b) => b,
                    Err(_) => break,
                };
                if write_frame(&mut *conn_w.lock().await, &bytes)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        };

        // winsize updates via SIGWINCH
        let winsize_fut = async {
            if tty_fd < 0 {
                futures::future::pending::<()>().await;
                unreachable!();
            }

            use tokio::signal::unix::{SignalKind, signal};
            let mut sig = match signal(SignalKind::window_change()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut last_rows = 0u16;
            let mut last_cols = 0u16;
            let mut first_iteration = true;
            loop {
                if first_iteration {
                    first_iteration = false;
                } else {
                    if sig.recv().await.is_none() {
                        break;
                    }
                }
                unsafe {
                    let mut ws: libc::winsize = std::mem::zeroed();
                    if libc::ioctl(tty_fd, libc::TIOCGWINSZ, &mut ws) != 0 {
                        continue;
                    }
                    if ws.ws_row == 0 && ws.ws_col == 0 {
                        continue;
                    }
                    if ws.ws_row == last_rows && ws.ws_col == last_cols {
                        continue;
                    }
                    last_rows = ws.ws_row;
                    last_cols = ws.ws_col;
                    let msg = ConsoleResponse::SetWindowSize {
                        rows: ws.ws_row,
                        cols: ws.ws_col,
                    };
                    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&msg).unwrap();
                    let _ = write_frame(&mut *conn_w.lock().await, &bytes).await;
                }
            }
        };

        // VM -> stdout (ConsoleRequest::Data)
        let stdout_fut = async {
            let mut stdout = tokio::io::stdout();
            loop {
                let frame = match read_frame(&mut conn_r).await {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let archived = match rkyv::access::<
                    crate::console::ArchivedConsoleRequest,
                    rkyv::rancor::Error,
                >(&frame)
                {
                    Ok(a) => a,
                    Err(_) => break,
                };
                match archived {
                    crate::console::ArchivedConsoleRequest::Data(data) => {
                        if stdout.write_all(data).await.is_err() {
                            break;
                        }
                        let _ = stdout.flush().await;
                    }
                }
            }
        };

        tokio::join!(stdin_fut, stdout_fut, winsize_fut);
        drop(guard);
    });
    Ok(task)
}

async fn read_frame<R>(conn: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(conn, &mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    tokio::io::AsyncReadExt::read_exact(conn, &mut buf).await?;
    Ok(buf)
}

async fn write_frame<W>(conn: &mut W, bytes: &[u8]) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let len = bytes.len() as u32;
    tokio::io::AsyncWriteExt::write_all(conn, &len.to_le_bytes()).await?;
    tokio::io::AsyncWriteExt::write_all(conn, bytes).await?;
    tokio::io::AsyncWriteExt::flush(conn).await?;
    Ok(())
}

// Resolve controlling TTY fd to use for termios/ioctl
fn choose_tty_fd() -> i32 {
    for fd in [0, 1, 2] {
        let is_tty = unsafe { libc::isatty(fd) };
        if is_tty == 1 {
            return fd;
        }
    }
    -1
}
