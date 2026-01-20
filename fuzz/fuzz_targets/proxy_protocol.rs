#![no_main]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use libfuzzer_sys::fuzz_target;

use exfilguard::proxy::listener::fuzzing::{parse_proxy_v1_line, parse_proxy_v2_payload};

fuzz_target!(|data: &[u8]| {
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345));

    if !data.is_empty() {
        let line = String::from_utf8_lossy(data);
        let _ = parse_proxy_v1_line(line.as_ref(), peer);
    }

    if data.len() >= 16 {
        let mut header = [0u8; 16];
        header.copy_from_slice(&data[..16]);
        let length = u16::from_be_bytes([header[14], header[15]]) as usize;
        let payload_start: usize = 16;
        let payload_end = payload_start.saturating_add(length).min(data.len());
        let payload = &data[payload_start..payload_end];
        let _ = parse_proxy_v2_payload(&header, payload, peer);
    }
});
