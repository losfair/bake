use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::{AsFd, OwnedFd},
    path::Path,
    sync::{Arc, LazyLock, atomic::Ordering},
    time::Duration,
};

use fast_socks5::{
    ReplyError, Socks5Command, consts,
    server::{AcceptAuthentication, Config, Socks5Socket},
    util::target_addr::TargetAddr,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Interest, unix::AsyncFd},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream},
    sync::{OnceCell, broadcast},
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use crate::{
    DEBUG,
    raw_udp::{ArchivedUdpPacket, RawUdp, UdpPacket},
    util::{copy_bidirectional_fastclose, decompose_vsock_stream},
};

static UDPBUS_RX: LazyLock<broadcast::Sender<UdpPacket>> =
    LazyLock::new(|| broadcast::Sender::new(128));

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Ipv4Cidr {
    network: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix as u32)
        }
    }
    fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_u = u32::from(ip);
        let m = Self::mask(self.prefix);
        (ip_u & m) == (self.network & m)
    }
}

fn parse_ipv4_cidr_or_addr(s: &str) -> Option<Ipv4Cidr> {
    if let Some((ip_s, pref_s)) = s.split_once('/') {
        let ip = ip_s.parse::<Ipv4Addr>().ok()?;
        let prefix = pref_s.parse::<u8>().ok()?;
        if prefix > 32 {
            return None;
        }
        let m = Ipv4Cidr::mask(prefix);
        let net = u32::from(ip) & m;
        Some(Ipv4Cidr {
            network: net,
            prefix,
        })
    } else {
        let ip = s.parse::<Ipv4Addr>().ok()?;
        Some(Ipv4Cidr {
            network: u32::from(ip),
            prefix: 32,
        })
    }
}

// Outbound network allowlist (IPv4 CIDRs). Empty/None means allow all.
static ALLOW_NET: OnceCell<Arc<HashSet<Ipv4Cidr>>> = OnceCell::const_new();

pub fn set_allow_net(entries: Vec<String>) {
    let mut set: HashSet<Ipv4Cidr> = HashSet::new();
    for e in entries {
        if let Some(c) = parse_ipv4_cidr_or_addr(e.trim()) {
            set.insert(c);
        } else if DEBUG.load(Ordering::Relaxed) {
            eprintln!("invalid --allow-net entry, ignoring: {}", e);
        }
    }
    let _ = ALLOW_NET.set(Arc::new(set));
}

fn ip_allowed(ip: IpAddr) -> bool {
    match ALLOW_NET.get() {
        None => true,
        Some(set) => match ip {
            IpAddr::V4(v4) => set.iter().any(|c| c.contains(v4)),
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or(false, |v4| set.iter().any(|c| c.contains(v4))),
        },
    }
}

pub fn run_socks5_unix(uds_path: &Path) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .thread_name("bake-s5unix")
        .build()
        .unwrap();
    let listener = rt.block_on(async { UnixListener::bind(uds_path) })?;
    rt.spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(conn) = conn.into_std() else {
                    return;
                };
                if let Err(e) = serve_socks5(conn.into()).await {
                    if DEBUG.load(Ordering::Relaxed) {
                        eprintln!("run_socks5_unix: {:?}", e);
                    }
                }
            });
        }
    });
    std::mem::forget(rt);
    Ok(())
}

pub fn run_socks5_udp_unix(uds_path: &Path) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .thread_name("bake-s5udp")
        .build()
        .unwrap();
    let listener = rt.block_on(async { UnixListener::bind(uds_path) })?;
    rt.spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                break;
            };
            let Ok(sockfd) = conn.as_fd().try_clone_to_owned() else {
                continue;
            };

            tokio::spawn(async move {
                if let Err(e) = serve(conn, sockfd, serve_socks5_udp).await {
                    eprintln!("run_socks5_udp_unix: {:?}", e);
                }
            });
        }
    });
    std::mem::forget(rt);
    Ok(())
}

pub fn run_socks5_vsock() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .thread_name("bake-s5vsock")
        .build()
        .unwrap();
    let listener = rt.block_on(async { VsockListener::bind(VsockAddr::new(u32::MAX, 10)) })?;
    rt.spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(conn) = decompose_vsock_stream(conn) else {
                    return;
                };
                if let Err(e) = serve_socks5(conn).await {
                    eprintln!("run_socks5_vsock: {:?}", e);
                }
            });
        }
    });
    std::mem::forget(rt);
    Ok(())
}

pub fn run_socks5_tcp_to_vsock_proxy() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .thread_name("bake-s5t2v")
        .build()
        .unwrap();
    let listener = rt.block_on(async { TcpListener::bind("127.0.0.10:10").await })?;
    rt.spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let outbound = tokio::select! {
                  biased;
                  _ = conn.ready(Interest::PRIORITY) => return,
                  x = VsockStream::connect(VsockAddr::new(2, 10)) => x,
                };
                let Ok(outbound) = outbound else {
                    return;
                };
                let Ok(outbound) = decompose_vsock_stream(outbound) else {
                    return;
                };
                let Ok(conn) = conn.into_std() else {
                    return;
                };
                let _ = copy_bidirectional_fastclose(conn.into(), outbound).await;
            });
        }
    });
    std::mem::forget(rt);
    Ok(())
}

pub fn run_socks5_udp_injection(tun2socks_ifname: &str) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .thread_name("bake-s5udpinj")
        .build()
        .unwrap();
    let udp =
        rt.block_on(async { RawUdp::open(tun2socks_ifname, "198.18.0.2".parse().unwrap()) })?;
    let udp = Arc::new(udp);
    let host = rt.block_on(async { VsockStream::connect(VsockAddr::new(2, 11)).await })?;
    rt.spawn(async move {
        let (mut rx, mut tx) = tokio::io::split(host);
        let udp_rx = udp.clone();
        let udp_tx = udp;

        let rx_fut = async {
            loop {
                let msg = udp_rx.recv().await?;
                let msg = rkyv::to_bytes::<rkyv::rancor::Error>(&msg).unwrap();
                tx.write_all(&(msg.len() as u32).to_le_bytes()).await?;
                tx.write_all(&msg).await?;
            }
        };
        let tx_fut = async {
            let mut pkt = vec![0u8; 9600];
            loop {
                let len = rx.read_u32_le().await? as usize;
                assert!(len <= pkt.len());
                rx.read_exact(&mut pkt[..len]).await?;
                let pkt = &pkt[..len];
                let pkt = rkyv::access::<ArchivedUdpPacket, rkyv::rancor::Error>(pkt).unwrap();

                // eprintln!(
                //     "INJECT: {}:{}->{}:{}",
                //     pkt.src_ip.as_ipv4(),
                //     pkt.src_port.to_native(),
                //     pkt.dst_ip.as_ipv4(),
                //     pkt.dst_port.to_native(),
                // );
                udp_tx
                    .inject(
                        pkt.src_ip.as_ipv4(),
                        pkt.dst_ip.as_ipv4(),
                        pkt.src_port.to_native(),
                        pkt.dst_port.to_native(),
                        &pkt.payload[..],
                        64,
                    )
                    .await?;
            }
        };
        let res: anyhow::Result<()> = tokio::select! {
          biased;
          x = tx_fut => x,
          x = rx_fut => x,
        };
        res.expect("udp injection task failed");
    });
    std::mem::forget(rt);
    Ok(())
}

async fn serve<
    C: AsyncRead + AsyncWrite + Unpin + 'static,
    Fut: Future<Output = anyhow::Result<()>>,
>(
    conn: C,
    sockfd: OwnedFd,
    f: impl FnOnce(C) -> Fut,
) -> anyhow::Result<()> {
    let sockfd = AsyncFd::with_interest(sockfd.as_fd(), Interest::PRIORITY)?;
    tokio::select! {
      biased;
      _ = sockfd.ready(Interest::PRIORITY) => {
        // eprintln!("PRIORITY received, shutting down");
        Ok(())
      }
      x = f(conn) => x
    }
}

async fn serve_socks5(conn: OwnedFd) -> anyhow::Result<()> {
    static CONFIG: OnceCell<Arc<Config<AcceptAuthentication>>> = OnceCell::const_new();
    let config = CONFIG
        .get_or_init(|| async {
            let mut config = Config::default();
            config.set_dns_resolve(false);
            config.set_execute_command(false);
            Arc::new(config)
        })
        .await;
    let conn = UnixStream::from_std(std::os::unix::net::UnixStream::from(conn))?;
    let sock = Socks5Socket::new(conn, config.clone());
    let sock = sock.upgrade_to_socks5().await?;
    match sock.cmd() {
        Some(Socks5Command::TCPConnect) => {
            let target_addr = match sock.target_addr() {
                Some(x) => match x.clone().resolve_dns().await {
                    Ok(TargetAddr::Ip(x)) => x,
                    Ok(_) => panic!("unexpected target addr type"),
                    Err(e) => {
                        anyhow::bail!("dns resolution failed: {:?}: {:?}", x, e);
                    }
                },
                _ => anyhow::bail!("invalid target addr"),
            };
            // Check allowlist before proceeding
            if !ip_allowed(target_addr.ip()) {
                if DEBUG.load(Ordering::Relaxed) {
                    eprintln!("TCP blocked by allowlist: {}", target_addr);
                }
                let mut sock = sock.into_inner();
                sock.write_all(&new_reply(&ReplyError::ConnectionNotAllowed, target_addr))
                    .await?;
                return Ok(());
            }
            let mut sock = sock.into_inner();
            sock.write_all(&new_reply(&ReplyError::Succeeded, target_addr))
                .await?;
            let sock = sock.into_std()?;
            let outbound = TcpStream::connect(target_addr).await?;
            outbound.set_nodelay(true)?;

            let _ = copy_bidirectional_fastclose(sock.into(), outbound.into_std()?.into()).await;
        }
        _ => {}
    }
    Ok(())
}

async fn serve_socks5_udp(
    conn: impl AsyncRead + AsyncWrite + Unpin + 'static,
) -> anyhow::Result<()> {
    // vm local port -> host socket
    let portmap: moka::sync::Cache<u16, (Arc<UdpSocket>, Arc<tokio::sync::oneshot::Sender<()>>)> =
        moka::sync::Cache::builder()
            .time_to_idle(Duration::from_secs(60))
            .build();
    let (rx, mut tx) = tokio::io::split(conn);
    let rx_fut = async {
        let mut rx = BufReader::new(rx);
        let mut buf = vec![0u8; 9600];
        loop {
            let len = rx.read_u32_le().await? as usize;
            if len > buf.len() {
                anyhow::bail!("packet too large");
            }
            rx.read_exact(&mut buf[..len]).await?;
            let packet = rkyv::access::<ArchivedUdpPacket, rkyv::rancor::Error>(&buf[..len])?;
            let client_addr =
                SocketAddrV4::new(packet.src_ip.as_ipv4(), packet.src_port.to_native());
            let socket = portmap
                .try_get_with(client_addr.port(), || portmap_elem_init(client_addr))
                .map_err(|e: Arc<anyhow::Error>| {
                    anyhow::anyhow!("failed to create host udp socket: {:?}", e)
                })?
                .0;
            // Allowlist check for UDP destination
            if !ip_allowed(IpAddr::V4(packet.dst_ip.as_ipv4())) {
                if DEBUG.load(Ordering::Relaxed) {
                    eprintln!(
                        "UDP blocked by allowlist: {}:{}",
                        packet.dst_ip.as_ipv4(),
                        packet.dst_port.to_native()
                    );
                }
                continue;
            }
            socket
                .send_to(
                    &packet.payload,
                    SocketAddr::new(packet.dst_ip.as_ipv4().into(), packet.dst_port.to_native()),
                )
                .await?;
            if DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "UDP TX {}:{}->{}:{}",
                    packet.src_ip.as_ipv4(),
                    packet.src_port.to_native(),
                    packet.dst_ip.as_ipv4(),
                    packet.dst_port.to_native(),
                );
            }
        }
    };
    let tx_fut = async {
        let mut sub = UDPBUS_RX.subscribe();
        loop {
            let pkt = match sub.recv().await {
                Ok(x) => x,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => unreachable!(),
            };
            let pkt = rkyv::to_bytes::<rkyv::rancor::Error>(&pkt).unwrap();
            tx.write_all(&(pkt.len() as u32).to_le_bytes()).await?;
            tx.write_all(&pkt).await?;
            tx.flush().await?;
        }
    };
    tokio::select! {
      biased;
      x = rx_fut => x,
      x = tx_fut => x,
    }
}

// copied from fast_socks5
fn new_reply(error: &ReplyError, sock_addr: SocketAddr) -> Vec<u8> {
    let (addr_type, mut ip_oct, mut port) = match sock_addr {
        SocketAddr::V4(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV4,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
        SocketAddr::V6(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV6,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
    };

    let mut reply = vec![
        consts::SOCKS5_VERSION,
        error.as_u8(), // transform the error into byte code
        0x00,          // reserved
        addr_type,     // address type (ipv4, v6, domain)
    ];
    reply.append(&mut ip_oct);
    reply.append(&mut port);

    reply
}

fn portmap_elem_init(
    client_addr: SocketAddrV4,
) -> anyhow::Result<(Arc<UdpSocket>, Arc<tokio::sync::oneshot::Sender<()>>)> {
    let socket = std::net::UdpSocket::bind("[::]:0")?;
    socket.set_nonblocking(true)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
    let socket_clone = socket.clone();
    let (kill_tx, kill_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let fut = async {
            let mut pkt = vec![0u8; 9600];
            loop {
                let Ok((n, mut addr)) = socket_clone.recv_from(&mut pkt).await else {
                    break;
                };
                if let IpAddr::V6(x) = addr.ip() {
                    if let Some(x) = x.to_ipv4_mapped() {
                        addr.set_ip(IpAddr::V4(x));
                    }
                }
                let IpAddr::V4(ip) = addr.ip() else {
                    if DEBUG.load(Ordering::Relaxed) {
                        eprintln!("dropping packet with invalid source: {}", addr);
                    }
                    continue;
                };
                if DEBUG.load(Ordering::Relaxed) {
                    eprintln!(
                        "UDP RX: {}:{} -> {}:{}",
                        ip,
                        addr.port(),
                        client_addr.ip(),
                        client_addr.port()
                    );
                }
                let _ = UDPBUS_RX.send(UdpPacket {
                    src_ip: ip,
                    dst_ip: *client_addr.ip(),
                    src_port: addr.port(),
                    dst_port: client_addr.port(),
                    payload: pkt[..n].to_vec(),
                });
            }
        };
        tokio::select! {
          biased;
          _ = fut => {}
          _ = kill_rx => {}
        }
    });
    Ok((socket, Arc::new(kill_tx)))
}
