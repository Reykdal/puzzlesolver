use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket},
    time::Duration,
};

use crate::{
    net::{build_ipv6_header, build_udp_header, send_raw_packet},
    secret::SecretResult,
};

fn build_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_header = build_udp_header(
        &src_ip.octets(),
        &dst_ip.octets(),
        src_port,
        dst_port,
        payload,
    );
    let udp_segment_len = (udp_header.len() + payload.len()) as u16;
    let ip_header = build_ipv6_header(src_ip, dst_ip, udp_segment_len);

    let mut packet = Vec::with_capacity(ip_header.len() + udp_segment_len as usize);
    packet.extend_from_slice(&ip_header);
    packet.extend_from_slice(&udp_header);
    packet.extend_from_slice(payload);

    packet
}

pub fn solve(
    ip_ipv6: Ipv6Addr,
    local_ipv6: Ipv6Addr,
    port: u16,
    secret: &SecretResult,
) -> io::Result<()> {
    let recv_sock = UdpSocket::bind("[::]:0")?;
    recv_sock.connect(SocketAddrV6::new(ip_ipv6, port, 0, 0))?;
    recv_sock.set_read_timeout(Some(Duration::from_secs(2)))?;

    let local_port = recv_sock.local_addr()?.port();

    let dst_ip = ip_ipv6;
    let src_ip = local_ipv6;

    let mut signed = Vec::with_capacity(5);
    signed.push(secret.group_id);
    signed.extend_from_slice(&secret.sigil);

    let packet = build_packet(src_ip, dst_ip, local_port, port, &signed);

    let mut buf = [0u8; 2048];

    for _ in 0..10 {
        send_raw_packet(dst_ip, &packet)?;
        let n = match recv_sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                eprintln!("send_raw_packet failed: {e}");
                continue;
            }
            Err(e) => return Err(e),
        };

        let reply = buf[..n].to_vec();

        let msg = String::from_utf8_lossy(&reply).to_string();
        println!("MSG: {}\n", msg);
        break;
    }

    Ok(())
}
