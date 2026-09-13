//! Solver for the S.E.C.R.E.T. port.
//! Flow: send our usernames + a chosen 32-bit secret, receive a 5-byte reply
//! {group_id, challenge}, answer with {group_id, sigil = challenge XOR secret},
//! then receive the hidden secret it guards.

use crate::net::send_and_recv;
use std::io;
use std::net::{Ipv4Addr, UdpSocket};

/// Values obtained from the S.E.C.R.E.T. port that later ports also require.
pub struct SecretResult {
    pub group_id: u8,
    pub sigil: [u8; 4],
    pub reveal: String, // the hidden secret text (a secret port and/or phrase)
}

/// Runs the full S.E.C.R.E.T. handshake and returns group_id, sigil and reveal.
pub fn solve(
    sock: &UdpSocket,
    ip: Ipv4Addr,
    port: u16,
    usernames: &[&str],
) -> io::Result<SecretResult> {
    // Step 1: our chosen 32-bit secret number.
    let secret: u32 = 0xD0B556CD;
    let secret_bytes = secret.to_be_bytes();
    println!("[SECRET] secret number = 0x{:08x}", secret);

    // Step 2: "S.E.C.R.E.T.:" + comma-separated usernames + secret as final 4 bytes.
    let mut msg = Vec::new();
    msg.extend_from_slice(b"S.E.C.R.E.T.:");
    msg.extend_from_slice(usernames.join(",").as_bytes());
    msg.extend_from_slice(&secret_bytes);

    // Step 3: send it, expect a 5-byte reply: [group_id][4-byte challenge].
    let reply = send_and_recv(sock, ip, port, &msg, 5)?;
    if reply.len() != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected 5-byte challenge, got {} bytes: {:02x?}",
                reply.len(),
                reply
            ),
        ));
    }
    let group_id = reply[0];
    let challenge = [reply[1], reply[2], reply[3], reply[4]];
    println!("[SECRET] group_id = {}, challenge = {:02x?}", group_id, challenge);

    // Step 4: sigil = challenge XOR secret, byte by byte.
    let mut sigil = [0u8; 4];
    for i in 0..4 {
        sigil[i] = challenge[i] ^ secret_bytes[i];
    }
    println!("[SECRET] sigil = {:02x?}", sigil);

    // Step 5: reply with [group_id][4-byte sigil].
    let mut signed = Vec::with_capacity(5);
    signed.push(group_id);
    signed.extend_from_slice(&sigil);
    let reveal_bytes = send_and_recv(sock, ip, port, &signed, 5)?;

    // Step 6: the port reveals its hidden secret.
    let reveal = String::from_utf8_lossy(&reveal_bytes).to_string();
    println!("[SECRET] reveal: {}", reveal);

    Ok(SecretResult {
        group_id,
        sigil,
        reveal,
    })
}
