#![no_main]

use libfuzzer_sys::fuzz_target;

use exfilguard::proxy::connect::fuzzing::parse_connect_target;

mod corpus;
use corpus::decode_tracked_seed;

fuzz_target!(|data: &[u8]| {
    let data = decode_tracked_seed(data);
    if data.is_empty() {
        return;
    }

    let payload = &data[1..];
    let split = (data[0] as usize) % (payload.len() + 1);
    let (target_bytes, host_bytes) = payload.split_at(split);
    let target = String::from_utf8_lossy(target_bytes);
    let host = String::from_utf8_lossy(host_bytes);

    let _ = parse_connect_target(target.as_ref());
    let _ = parse_connect_target(host.as_ref());
});
