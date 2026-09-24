use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket},
    time::Duration,
};

use crate::{
    net::{build_ipv6_header, build_udp_header, send_and_recv},
    secret::SecretResult,
};

fn build_packet(ipv6_header: &IPv6Header, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_header = build_udp_header(
        &ipv6_header.dst_ip.octets(), // Flip src and dest because we are now sending
        &ipv6_header.src_ip.octets(),
        src_port,
        dst_port,
        payload,
    );
    let udp_segment_len = (udp_header.len() + payload.len()) as u16;
    let ip_header = build_ipv6_header(
        ipv6_header.dst_ip, // Same as before, flip src/dst
        ipv6_header.src_ip,
        udp_segment_len,
        ipv6_header.traffic_class,
        ipv6_header.flow_label,
    );

    let mut packet = Vec::with_capacity(ip_header.len() + udp_segment_len as usize);
    packet.extend_from_slice(&ip_header);
    packet.extend_from_slice(&udp_header);
    packet.extend_from_slice(payload);

    packet
}

#[derive(Debug)]
struct IPv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
}

fn parse_fake_ipv6_header(h: &[u8]) -> IPv6Header {
    let traffic_class = (h[0] << 4) | (h[1] >> 4);
    let flow_label = ((h[1] & 0x0f) as u32) << 16 | (h[2] as u32) << 8 | h[3] as u32;

    let mut src = [0u8; 16];
    src.copy_from_slice(&h[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&h[24..40]);

    IPv6Header {
        traffic_class,
        flow_label,
        src_ip: Ipv6Addr::from(src),
        dst_ip: Ipv6Addr::from(dst),
    }
}

fn parse_udp_ports(h: &[u8]) -> (u16, u16) {
    let udp_header = &h[40..48];
    let src_port = ((udp_header[0] as u16) << 8) | udp_header[1] as u16;
    let dst_port = ((udp_header[2] as u16) << 8) | udp_header[3] as u16;
    (src_port, dst_port)
}

pub fn solve(ip: Ipv4Addr, port: u16, secret: &SecretResult) -> io::Result<String> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(SocketAddrV4::new(ip, port))?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;

    let resp = send_and_recv(&sock, ip, port, b"hello!", 1)?;
    let header = parse_fake_ipv6_header(&resp);
    let (src_port, dst_port) = parse_udp_ports(&resp);

    let mut signed = Vec::with_capacity(5);
    signed.push(secret.group_id);
    signed.extend_from_slice(&secret.sigil);

    let packet = build_packet(&header, dst_port, src_port, &signed);

    sock.send(&packet)?;

    let mut buf = [0u8; 2048];

    let mut secret_phrase = String::new();

    // We need the last received phrase for some reason
    while let Ok(n) = sock.recv(&mut buf) {
        if n == 0 {
            break;
        }
        let reply = buf[..n].to_vec();

        let msg = String::from_utf8_lossy(&reply).to_string();
        eprintln!("MSG: {}\n", msg);

        let Some((_, phrase)) = msg.rsplit_once("\n") else {
            return Err(io::Error::new(io::ErrorKind::Other, "no phrase found"));
        };

        secret_phrase = String::from(phrase.trim_matches(|c| c == '"'));
    }

    Ok(secret_phrase)
}
