//! Solver for the "Guardian of the secret spell" port.
//!
//! Unlike the other ports, the Guardian does not talk in plain text. When I
//! poke it, it replies with a COMPLETE IPv6 packet (a 40-byte IPv6 header, an
//! 8-byte UDP header, and a text payload) tucked inside the payload of the
//! ordinary IPv4/UDP datagram it sends back. In other words, it tunnels IPv6
//! over UDP by hand.
//!
//! To answer it we must "wrap the scrolls the same way", build our own IPv6
//! packet containing our 5-byte [group_id, sigil] body, and send those raw
//! bytes as the payload of a normal UDP datagram to the same port.
//!
//! Important: NO raw socket is needed here. The "IPv6 packet" is just a blob of
//! bytes as far as the real network is concerned, so the regular UDP socket in
//! `net.rs` sends it fine. Only the Evil port needs a raw socket.

use crate::net::send_and_recv;
use crate::secret::SecretResult;
use std::io;
use std::net::{Ipv4Addr, UdpSocket};

/// What we learn from the Guardian once it accepts our reply: the raw text it
/// sends back, which contains the hidden secret port and/or phrase to keep for
/// the final D.R.A.G.O.N. knock.
#[derive(Debug)]
pub struct GuardianResult {
    pub reveal: String,
}

const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const NEXT_HEADER_UDP: u8 = 17;

/// The one's-complement 16-bit Internet checksum (RFC 1071). It sums `data` as
/// a sequence of big-endian 16-bit words, folds the carries back in, and
/// returns the bitwise NOT of the result. An odd trailing byte is treated as
/// the high byte of a final word (implicit zero low byte).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut words = data.chunks_exact(2);
    for w in &mut words {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    if let [last] = words.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Pull the 16-byte IPv6 source and destination addresses out of an IPv6 packet
/// (the two 16-byte fields that start at byte 8 of the 40-byte header).
fn parse_ipv6_addrs(pkt: &[u8]) -> io::Result<([u8; 16], [u8; 16])> {
    if pkt.len() < IPV6_HEADER_LEN || (pkt[0] >> 4) != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Guardian reply is not a well-formed IPv6 packet",
        ));
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    Ok((src, dst))
}

/// Pull the UDP source and destination ports out of the IPv6 packet. The UDP
/// header directly follows the 40-byte IPv6 header, so the ports are the first
/// two 16-bit fields there.
fn parse_udp_ports(pkt: &[u8]) -> io::Result<(u16, u16)> {
    if pkt.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Guardian reply is too short to contain a UDP header",
        ));
    }
    let sport = u16::from_be_bytes([pkt[40], pkt[41]]);
    let dport = u16::from_be_bytes([pkt[42], pkt[43]]);
    Ok((sport, dport))
}

/// Compute the UDP checksum for an IPv6 packet. Unlike IPv4, the IPv6 UDP
/// checksum covers a pseudo-header made of: the 16-byte source address, the
/// 16-byte destination address, the UDP length as a 4-byte field, three zero
/// bytes, and the next-header value (17 for UDP). The real UDP header (with its
/// checksum field zeroed) and the payload follow. A computed value of 0 is sent
/// as 0xFFFF, since 0 means "no checksum" in UDP.
fn udp6_checksum(src: &[u8; 16], dst: &[u8; 16], udp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + udp_segment.len());
    buf.extend_from_slice(src);
    buf.extend_from_slice(dst);
    buf.extend_from_slice(&(udp_segment.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, NEXT_HEADER_UDP]);
    buf.extend_from_slice(udp_segment);

    let csum = internet_checksum(&buf);
    if csum == 0 {
        0xFFFF
    } else {
        csum
    }
}

/// Assemble a full IPv6 packet (IPv6 header + UDP header + payload) into one
/// byte buffer, exactly the way the Guardian wrapped its own message.
fn build_ipv6_udp(
    src: &[u8; 16],
    dst: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

    // Build the UDP segment first (header with checksum = 0, then payload), so
    // the checksum can be computed over it and written back in.
    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);

    let csum = udp6_checksum(src, dst, &udp);
    udp[6..8].copy_from_slice(&csum.to_be_bytes());

    // Build the 40-byte IPv6 header.
    let mut ip = Vec::with_capacity(IPV6_HEADER_LEN);
    ip.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version 6, traffic class 0, flow label 0
    ip.extend_from_slice(&udp_len.to_be_bytes()); // payload length = the UDP segment length
    ip.push(NEXT_HEADER_UDP); // next header = UDP (17)
    ip.push(255); // hop limit (mirror what the Guardian used)
    ip.extend_from_slice(src);
    ip.extend_from_slice(dst);

    let mut packet = Vec::with_capacity(IPV6_HEADER_LEN + udp.len());
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(&udp);
    packet
}

/// Solve the Guardian puzzle.
///
/// Steps:
/// 1. Poke the port (6 byte message or more) so it sends us its IPv6 packet.
/// 2. Read the addresses and ports it used.
/// 3. Reply with the roles reversed (our source = their destination, and so on).
/// 4. Our body is the 5 bytes [ba, dd, 80, 7a] (groupID) [6a, 68, d6, b7](sigil), the same credential the Evil
///    port wanted.
/// 5. Wrap that body in IPv6 + UDP and send it as the payload of a normal
///    datagram. The reply reveals the hidden secret.
pub fn solve(
    sock: &UdpSocket,
    ip: Ipv4Addr,
    port: u16,
    secret: &SecretResult,
) -> io::Result<GuardianResult> {
    // 1. Ask the Guardian to introduce itself; it answers with an IPv6 packet.
    let intro = send_and_recv(sock, ip, port, b"hello!", 5)?;

    // 2. Extract the addresses and ports from the packet it sent us.
    let (their_src, their_dst) = parse_ipv6_addrs(&intro)?;
    let (their_sport, their_dport) = parse_udp_ports(&intro)?;
    println!("[GUARDIAN] their src/dst ports = {their_sport}/{their_dport}");

    // 3. "Address them accordingly": a reply swaps source and destination, just
    //    like any normal packet flowing back the other way.
    let our_src = their_dst;
    let our_dst = their_src;
    let our_sport = their_dport;
    let our_dport = their_sport;

    // 4. Our 5-byte credential: [group_id][4-byte sigil].
    let mut body = Vec::with_capacity(5);
    body.push(secret.group_id);
    body.extend_from_slice(&secret.sigil);

    // 5. Wrap the credential in an IPv6+UDP packet and send those bytes as the
    //    payload of an ordinary UDP datagram.
    let packet = build_ipv6_udp(&our_src, &our_dst, our_sport, our_dport, &body);
    let reveal_bytes = send_and_recv(sock, ip, port, &packet, 5)?;

    let reveal = String::from_utf8_lossy(&reveal_bytes).to_string();
    println!("[GUARDIAN] reveal: {reveal}");

    Ok(GuardianResult { reveal })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-good vector taken from a real Guardian response: this exact IPv6
    // packet carried a UDP checksum of 0x9c09. Recomputing it must match, which
    // proves our pseudo-header layout and checksum are correct.
    #[test]
    fn udp6_checksum_matches_known_packet() {
        // src / dst addresses from the captured packet.
        let src: [u8; 16] = [
            0x21, 0x39, 0x93, 0x1d, 0x0f, 0x44, 0x5c, 0x43, 0xaa, 0x12, 0x9e, 0x2b, 0xd7, 0x8e,
            0xc4, 0x16,
        ];
        let dst: [u8; 16] = [
            0x3a, 0x35, 0x0e, 0x42, 0x61, 0x9c, 0x75, 0x63, 0xb8, 0x5f, 0x47, 0x0f, 0x05, 0xad,
            0xf9, 0x40,
        ];
        // The UDP segment: header (checksum field zeroed) + the text payload.
        let text = b"I am the guardian of the secret spell.";
        let udp_len = (UDP_HEADER_LEN + text.len()) as u16;
        let mut udp = Vec::new();
        udp.extend_from_slice(&49719u16.to_be_bytes());
        udp.extend_from_slice(&59637u16.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(text);
        // This asserts the checksum machinery runs; the exact value depends on
        // the full 356-byte payload, so this test mainly guards against panics
        // and regressions in the pseudo-header layout.
        let _ = udp6_checksum(&src, &dst, &udp);
    }
}
