#![no_main]

use libfuzzer_sys::fuzz_target;

use exfilguard::proxy::connect::fuzzing::parse_connect_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let payload = &data[1..];
    let split = (data[0] as usize) % (payload.len() + 1);
    let (target_bytes, host_bytes) = payload.split_at(split);
    let target = String::from_utf8_lossy(target_bytes);
    let host = String::from_utf8_lossy(host_bytes);
    let host_opt = if host.is_empty() {
        None
    } else {
        Some(host.as_ref())
    };

    let _ = parse_connect_target(target.as_ref(), host_opt);
    let _ = parse_connect_target(target.as_ref(), None);
});
