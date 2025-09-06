use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::{AsyncDevice, Configuration, Layer};

/// Parsed packet view for convenience when receiving
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct UdpPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

pub struct RawUdp {
    tun: AsyncDevice,
}

impl RawUdp {
    /// Create a TUN device for UDP packet processing.
    pub fn open(ifname: &str, address: Ipv4Addr) -> Result<Self> {
        let mut config = Configuration::default();
        config
            .tun_name(ifname)
            .layer(Layer::L3)
            .address(address)
            .mtu(1280)
            .up();

        let device = tun::create(&config).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Failed to create TUN device: {}", e),
            )
        })?;

        let tun = AsyncDevice::new(device).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Failed to create async TUN device: {}", e),
            )
        })?;

        Ok(Self { tun })
    }

    /// Receive one raw IPv4+UDP packet from the TUN device.
    /// Blocks until a packet arrives.
    pub async fn recv(&mut self) -> Result<UdpPacket> {
        loop {
            // 9600B buffer for raw IPv4 packets
            let mut buf = vec![0u8; 9600];
            let n = self.tun.read(&mut buf).await?;

            if n < 20 {
                // eprintln!("DEBUG: Packet too short: {} bytes, first 16 bytes: {:02x?}", n, &buf[..n.min(16)]);
                continue; // Skip this packet
            }

            // Check if this is IPv4
            let version = buf[0] >> 4;
            if version != 4 {
                // eprintln!("DEBUG: Not IPv4 packet, version: {}", version);
                continue; // Skip non-IPv4 packets
            }

            // Parse IPv4
            let ihl_bytes = (buf[0] & 0x0F) as usize * 4;
            let protocol = buf[9];

            // eprintln!("DEBUG: Packet length: {}, version: {}, IHL: {} bytes, protocol: {}",
            //           n, version, ihl_bytes, protocol);

            if ihl_bytes < 20 || n < ihl_bytes + 8 {
                // eprintln!("DEBUG: Invalid packet structure - IHL: {}, total len: {}, needed: {}",
                //           ihl_bytes, n, ihl_bytes + 8);
                continue; // Skip malformed packets
            }

            if protocol != 17 {
                // eprintln!("DEBUG: Not UDP packet, protocol: {}", protocol);
                continue; // Skip non-UDP packets
            }

            // This is a valid IPv4+UDP packet, process it
            let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
            let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

            // Parse UDP
            let u = ihl_bytes;
            let src_port = u16::from_be_bytes([buf[u], buf[u + 1]]);
            let dst_port = u16::from_be_bytes([buf[u + 2], buf[u + 3]]);
            let udp_len = u16::from_be_bytes([buf[u + 4], buf[u + 5]]) as usize;

            if udp_len < 8 || u + udp_len > n {
                // eprintln!("DEBUG: Invalid UDP length: {} vs available: {}", udp_len, n - u);
                continue; // Skip malformed UDP packets
            }

            let payload = buf[u + 8..u + udp_len].to_vec();

            return Ok(UdpPacket {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                payload,
            });
        }
    }

    /// Inject a UDP packet via the TUN device.
    ///
    /// Creates a complete IPv4+UDP packet and writes it to the TUN interface.
    pub async fn inject(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        ttl: u8,
    ) -> Result<()> {
        // Build UDP
        let udp_len = 8 + payload.len();
        let mut udp = vec![0u8; 8];
        put_u16(&mut udp[0..2], src_port);
        put_u16(&mut udp[2..4], dst_port);
        put_u16(&mut udp[4..6], udp_len as u16);
        put_u16(&mut udp[6..8], 0); // checksum placeholder

        // Build IPv4 header
        let total_len = 20 + udp_len;
        let mut ip = vec![0u8; 20];
        ip[0] = (4u8 << 4) | (5u8); // version=4, IHL=5
        ip[1] = 0; // DSCP/ECN
        put_u16(&mut ip[2..4], total_len as u16);
        put_u16(&mut ip[4..6], 0); // identification
        put_u16(&mut ip[6..8], 0x4000); // flags: DF set, no fragmentation
        ip[8] = ttl;
        ip[9] = 17; // UDP
        put_u32(&mut ip[12..16], src_ip);
        put_u32(&mut ip[16..20], dst_ip);
        // checksum over the IPv4 header
        put_u16(&mut ip[10..12], 0);
        let ip_sum = checksum16(&ip);
        put_u16(&mut ip[10..12], ip_sum);

        // UDP checksum with IPv4 pseudo-header
        let mut pseudo = Vec::with_capacity(12 + udp_len);
        // Pseudo header: src, dst, zero, proto, udp_len
        pseudo.extend_from_slice(&src_ip.octets());
        pseudo.extend_from_slice(&dst_ip.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
        // UDP header + payload
        pseudo.extend_from_slice(&udp);
        pseudo.extend_from_slice(payload);

        // If odd length, pad with zero for checksum calc
        let checksum = checksum16_pad(&pseudo);
        let udp_checksum = if checksum == 0 { 0xFFFF } else { checksum };
        put_u16(&mut udp[6..8], udp_checksum);

        // Final packet: IP + UDP + payload
        let mut pkt = Vec::with_capacity(total_len);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&udp);
        pkt.extend_from_slice(payload);

        // Write to TUN device
        self.tun.write_all(&pkt).await?;
        Ok(())
    }
}

/* -------------------- helpers -------------------- */

fn put_u16(dst: &mut [u8], v: u16) {
    dst.copy_from_slice(&v.to_be_bytes());
}
fn put_u32(dst: &mut [u8], ip: Ipv4Addr) {
    dst.copy_from_slice(&ip.octets());
}

/// Internet checksum (ones’ complement) over even-length slice
fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    // Fold to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Internet checksum permitting odd-length input (pads with 0)
fn checksum16_pad(data: &[u8]) -> u16 {
    if data.len() % 2 == 0 {
        return checksum16(data);
    }
    let mut tmp = Vec::with_capacity(data.len() + 1);
    tmp.extend_from_slice(data);
    tmp.push(0);
    checksum16(&tmp)
}
