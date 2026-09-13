//! Usage: ./puzzlesolver <IP> <port1> <port2> <port3> <port4>
mod net;
mod secret;

use net::{make_socket, send_and_recv};
use std::net::{Ipv4Addr, UdpSocket};

/// Parsed command-line configuration for a run.
struct Config {
    ip: Ipv4Addr,
    ports: [u16; 4],
}

/// Parses and validates argv into a Config, or prints usage and exits.
fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err(format!(
            "Usage: {} <IP> <port1> <port2> <port3> <port4>",
            args[0]
        ));
    }

    let Ok(ip) = args[1].parse() else {
        return Err(format!("Invalid IP address: {}", args[1]));
    };

    let mut ports = [0u16; 4];
    for (i, arg) in args[2..6].iter().enumerate() {
        let Ok(port) = arg.parse() else {
            return Err(format!("Invalid port: {}", arg));
        };
        ports[i] = port;
    }

    Ok(Config { ip, ports })
}

fn probe(sock: &UdpSocket, ip: Ipv4Addr, port: u16) -> Option<String> {
    match send_and_recv(sock, ip, port, b"hello!", 4) {
        Ok(resp) => Some(String::from_utf8_lossy(&resp).to_string()),
        Err(e) => {
            eprintln!("port {port}: no response ({e})");
            None
        }
    }
}

fn main() -> Result<(), String> {
    let cfg = parse_args()?;
    let sock = make_socket().map_err(|e| format!("failed to create UDP socket: {e}"))?;

    // The ONLY thing hard-coded: our group members' RU usernames.
    let usernames = ["joels24", "enok24"];

    // Identify which port is which from its response to a default message.
    let mut secret_port: Option<u16> = None;
    for &port in &cfg.ports {
        if let Some(text) = probe(&sock, cfg.ip, port) {
            // "Sacred Elder Cipher" appears only in the S.E.C.R.E.T. reply,
            // so it won't collide with D.R.A.G.O.N., which also says "S.E.C.R.E.T.".
            if text.contains("Sacred Elder Cipher") {
                println!("port {port} => S.E.C.R.E.T.");
                secret_port = Some(port);
            }
        }
    }

    let sp = secret_port.ok_or("could not find the S.E.C.R.E.T. port")?;
    let res = secret::solve(&sock, cfg.ip, sp, &usernames)
        .map_err(|e| format!("S.E.C.R.E.T. handshake failed: {e}"))?;
    println!("\nGOT group_id={} sigil={:02x?}", res.group_id, res.sigil);

    Ok(())
}
