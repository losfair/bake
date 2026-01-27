//! Shared packet types for cross-platform networking.
//!
//! These types are used by both host-side (cross-platform) and guest-side (Linux-only)
//! networking code.

use std::net::Ipv4Addr;

/// UDP packet data for serialization over vsock/Unix socket channels.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct UdpPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}
