//! UDP networking helpers: one reusable socket plus a send-then-receive
//! that retries on timeout, since UDP datagrams can be silently dropped.

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// Creates a UDP socket bound to an ephemeral local port on all interfaces,
/// with a read timeout so a lost reply does not block forever.
pub fn make_socket() -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(sock)
}

/// Sends `payload` to ip:port and waits for one datagram in reply.
/// Retries up to `attempts` times on timeout. Returns the received bytes,
/// or the last error if every attempt times out.
pub fn send_and_recv(
    sock: &UdpSocket,
    ip: Ipv4Addr,
    port: u16,
    payload: &[u8],
    attempts: u32,
) -> io::Result<Vec<u8>> {
    let dest = SocketAddrV4::new(ip, port);
    let mut buf = [0u8; 2048];
    let mut last_err = io::Error::new(ErrorKind::TimedOut, "no response");

    for attempt in 1..=attempts {
        sock.send_to(payload, dest)?;
        match sock.recv_from(&mut buf) {
            Ok((n, _src)) => return Ok(buf[..n].to_vec()),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                eprintln!("  port {port}: timeout (attempt {attempt}/{attempts})");
                last_err = e;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

/// Prints a response as lossy UTF-8 text followed by a hex dump, so both
/// human-readable instructions and any raw bytes are visible.
pub fn dump_response(port: u16, data: &[u8]) {
    println!("=== response from port {port} ({} bytes) ===", data.len());
    println!("text: {}", String::from_utf8_lossy(data));
    print!("hex :");
    for b in data {
        print!(" {:02x}", b);
    }
    println!("\n");
}
