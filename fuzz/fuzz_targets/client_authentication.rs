#![no_main]

use libfuzzer_sys::fuzz_target;

mod corpus;

fuzz_target!(|data: &[u8]| {
    let data = corpus::decode_tracked_seed(data);
    exfilguard::authentication::fuzz_basic_header(&data);
    if let Ok(encoded) = std::str::from_utf8(&data) {
        let _ = exfilguard::authentication::PasswordHash::parse(encoded);
    }
});
