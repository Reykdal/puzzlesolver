use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::net::{build_ipv4_header, build_udp_header, send_raw_packet};
use crate::secret::SecretResult;

#[derive(Debug)]
pub struct EvilResult {
    pub hidden_port: u16,
    pub phrase: String,
}

pub fn build_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    evil: bool,
) -> Vec<u8> {
    let udp_header = build_udp_header(&src_ip, &dst_ip, src_port, dst_port, payload);
    let udp_segment_len = (udp_header.len() + payload.len()) as u16;
    let ip_header = build_ipv4_header(src_ip, dst_ip, udp_segment_len, evil);

    let mut packet = Vec::with_capacity(ip_header.len() + udp_segment_len as usize);
    packet.extend_from_slice(&ip_header);
    packet.extend_from_slice(&udp_header);
    packet.extend_from_slice(payload);
    packet
}

/// Solve the Evil Bit puzzle
///
/// Uses raw libc syscalls to send a UDP packet with the evil bit set, and
/// returns the hidden port for the puzzle.
pub fn solve(ip: Ipv4Addr, port: u16, secret: &SecretResult) -> io::Result<EvilResult> {
    let recv_sock = UdpSocket::bind("0.0.0.0:0")?;
    recv_sock.connect(SocketAddrV4::new(ip, port))?;
    recv_sock.set_read_timeout(Some(Duration::from_secs(2)))?;

    let local_addr = match recv_sock.local_addr()? {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => unreachable!("bound to an IPv4 wildcard address"),
    };
    let src_ip = *local_addr.ip();
    let src_port = local_addr.port();

    let mut signed = Vec::with_capacity(5);
    signed.push(secret.group_id);
    signed.extend_from_slice(&secret.sigil);

    let packet = build_packet(src_ip.octets(), ip.octets(), src_port, port, &signed, true);

    // Send sigil and group ID with evil bit set
    send_raw_packet(ip, &packet)?;

    let mut buf = [0u8; 2048];
    let n = recv_sock.recv(&mut buf)?;
    let reply = buf[..n].to_vec();

    let hidden_port_chars = &reply[reply.len() - 4..reply.len()];
    let hidden_port_string = String::from_utf8_lossy(hidden_port_chars).to_string();
    let hidden_port = hidden_port_string.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hidden port {hidden_port_string}"),
        )
    })?;

    println!("\n[EVIL] solved evil port: {hidden_port}");

    Ok(EvilResult {
        hidden_port,
        phrase: String::from_utf8_lossy(&reply).to_string(),
    })
}
