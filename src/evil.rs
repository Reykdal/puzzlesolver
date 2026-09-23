use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::secret::SecretResult;

#[derive(Debug)]
pub struct EvilResult {
    pub hidden_port: u16,
    pub phrase: String,
}

/// Accumulates a byte slice into a running checksum sum, treating the bytes
/// as big-endian 16-bit words. Does not fold carry
fn accumulate(sum: &mut u32, data: &[u8]) {
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        *sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Odd-length input: pad the trailing byte with an implicit zero low byte.
    if let [last] = chunks.remainder() {
        *sum += (*last as u32) << 8;
    }
}

/// Folds carry bits down to 16 bits and returns the
/// one's complement of the result
fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 header checksum (RFC 791). `header` is the raw header bytes
/// (checksum field assumed to be zero while computing).
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    accumulate(&mut sum, header);
    fold_checksum(sum)
}

/// UDP checksum (RFC 768), including the IPv4 pseudo-header (RFC 793 §3.1).
/// `udp_segment` is the UDP header + payload, with the header's checksum
/// field assumed to be zero while computing.
fn udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_segment: &[u8]) -> u16 {
    const UDP_PROTOCOL: u8 = 17;
    let mut sum = 0u32;

    // Pseudo-header: src IP, dst IP, zero byte + protocol (one word), UDP length.
    accumulate(&mut sum, &src_ip);
    accumulate(&mut sum, &dst_ip);
    sum += UDP_PROTOCOL as u32; // (0x00 << 8) | protocol
    accumulate(&mut sum, &(udp_segment.len() as u16).to_be_bytes());

    // UDP header + payload.
    accumulate(&mut sum, udp_segment);

    let checksum = fold_checksum(sum);
    // RFC 768: a computed checksum of 0 is sent as all-ones, since 0 in the
    // header means "no checksum used".
    if checksum == 0 {
        0xFFFF
    } else {
        checksum
    }
}

fn build_ipv4_header(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    udp_segment_len: u16,
    evil: bool,
) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 0x45; // version 4, IHL 5 (20-byte header, no options)
    h[1] = 0x00; // DSCP/ECN

    let total_len: u16 = 20 + udp_segment_len; // IP header + everything after it (UDP header+payload)
    h[2..4].copy_from_slice(&total_len.to_be_bytes());

    h[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification

    let flags_frag: u16 = if evil { 1 << 15 } else { 0 };
    h[6..8].copy_from_slice(&flags_frag.to_be_bytes());

    h[8] = 64; // TTL
    h[9] = 17; // protocol = UDP

    h[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder

    h[12..16].copy_from_slice(&src_ip);
    h[16..20].copy_from_slice(&dst_ip);

    let csum = ipv4_checksum(&h);
    h[10..12].copy_from_slice(&csum.to_be_bytes());
    h
}

fn build_udp_header(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0..2].copy_from_slice(&src_port.to_be_bytes());
    h[2..4].copy_from_slice(&dst_port.to_be_bytes());

    let udp_len: u16 = 8 + payload.len() as u16;
    h[4..6].copy_from_slice(&udp_len.to_be_bytes());
    // checksum field left as 0 while we compute it below

    // The checksum covers the UDP header itself (with checksum=0) plus the
    // payload, so build that segment before hashing it.
    let mut segment = Vec::with_capacity(h.len() + payload.len());
    segment.extend_from_slice(&h);
    segment.extend_from_slice(payload);

    let csum = udp_checksum(src_ip, dst_ip, &segment);
    h[6..8].copy_from_slice(&csum.to_be_bytes());
    h
}

pub fn build_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    evil: bool,
) -> Vec<u8> {
    let udp_header = build_udp_header(src_ip, dst_ip, src_port, dst_port, payload);
    let udp_segment_len = (udp_header.len() + payload.len()) as u16;
    let ip_header = build_ipv4_header(src_ip, dst_ip, udp_segment_len, evil);

    let mut packet = Vec::with_capacity(ip_header.len() + udp_segment_len as usize);
    packet.extend_from_slice(&ip_header);
    packet.extend_from_slice(&udp_header);
    packet.extend_from_slice(payload);
    packet
}

fn send_raw_packet(dst_ip: Ipv4Addr, packet: &[u8]) -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // IP_HDRINCL = We've set our own header
        let on: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &on as *const libc::c_int as *const libc::c_void,
            mem::size_of_val(&on) as libc::socklen_t,
        );
        if ret < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }

        let mut addr: libc::sockaddr_in = mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from_ne_bytes(dst_ip.octets());

        let sent = libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );

        libc::close(fd);

        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Solve the Evil Bit puzzle
///
/// Uses raw libc syscalls to send a UDP packet with the evil bit set, and
/// returns the hidden port for the puzzle.
pub fn solve(ip: Ipv4Addr, port: u16, secret: SecretResult) -> io::Result<EvilResult> {
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
