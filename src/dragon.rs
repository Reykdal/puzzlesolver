use std::net::UdpSocket;

use crate::{net::send_and_recv, secret::SecretResult, Config};

pub fn solve(
    sock: &UdpSocket,
    ports: &[u16],
    cfg: &Config,
    port: u16,
    secret: &SecretResult,
    secret_phrase: &str,
) -> std::io::Result<()> {
    let ports_string = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let resp = send_and_recv(&sock, cfg.ip, port, ports_string.as_bytes(), 1)?;

    let msg = String::from_utf8_lossy(&resp);
    println!("GOT msg={msg}");

    let knocks: Vec<_> = msg
        .trim()
        .trim_matches(|c| c == '"')
        .split(',')
        .map(|s| s.trim().parse::<u16>().expect("invalid port"))
        .collect();

    let mut code = Vec::with_capacity(5 + secret_phrase.len());
    code.push(secret.group_id);
    code.extend_from_slice(&secret.sigil);
    code.extend_from_slice(secret_phrase.as_bytes());

    for knock in knocks {
        let resp = send_and_recv(&sock, cfg.ip, knock, &code, 1)?;
        let msg = String::from_utf8_lossy(&resp);
        println!("GOT ({knock}) msg={msg:?}");
    }

    Ok(())
}
