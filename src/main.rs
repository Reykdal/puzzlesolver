//! Usage: ./puzzlesolver <IP> <port1> <port2> <port3> <port4>
mod evil;
mod ipv6;
mod net;
mod secret;

use net::{make_socket, send_and_recv};
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

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

#[derive(Debug, Default, Clone, Copy)]
struct Ports {
    secret: u16,
    dragon: u16,
    ipv6: u16,
    evil: u16,
}

fn main() -> Result<(), String> {
    let cfg = parse_args()?;
    let sock = make_socket().map_err(|e| format!("failed to create UDP socket: {e}"))?;

    // The ONLY thing hard-coded: our group members' RU usernames.
    let usernames = ["joels24", "enok24"];

    let mut ports = Ports::default();

    // Identify which port is which from its response to a default message.
    for &port in &cfg.ports {
        if let Some(text) = probe(&sock, cfg.ip, port) {
            // "Sacred Elder Cipher" appears only in the S.E.C.R.E.T. reply,
            // so it won't collide with D.R.A.G.O.N., which also says "S.E.C.R.E.T.".
            if text.contains("Sacred Elder Cipher") {
                println!("port {port} => S.E.C.R.E.T.");
                ports.secret = port;
            } else if text.contains("Dwemer Relay Apparatu") {
                println!("port {port} => D.R.A.G.O.N.");
                ports.dragon = port;
            } else if text.contains("https://en.wikipedia.org/wiki/Evil_bit") {
                println!("port {port} => EVIL!");
                ports.evil = port;
            } else if text.contains("guardian of the secret spell") {
                println!("port {port} => IPv6");
                ports.ipv6 = port;
            }
        }
    }

    let server_ipv6_ip = server_ipv6_ip.ok_or("Could not get IPv6 source ip".to_owned())?;
    println!("{:?}", server_ipv6_ip);

    let local_ipv6_ip = local_ipv6_ip.ok_or("Could not get IPv6 local ip".to_owned())?;
    println!("{:?}", local_ipv6_ip);

    let res = secret::solve(&sock, cfg.ip, ports.secret, &usernames)
        .map_err(|e| format!("S.E.C.R.E.T. handshake failed: {e}"))?;
    println!("\nGOT group_id={} sigil={:02x?}", res.group_id, res.sigil);

    let evil_port = evil::solve(cfg.ip, ports.evil, &res)
        .map_err(|e| format!("evil port failed (raw sockets need root - try sudo): {e}"))?;

    println!(
        "\nGOT port={} phrase={}",
        evil_port.hidden_port, evil_port.phrase
    );

    let phrase = ipv6::solve(cfg.ip, ports.ipv6, &res)
        .map_err(|e| format!("ipv6 port failed (raw sockets need root - try sudo): {e}"))?;

    Ok(())
}
