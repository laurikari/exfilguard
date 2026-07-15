use std::borrow::Cow;

/// Tracked text seeds use hex so CRLF and control-byte regressions remain explicit.
/// Arbitrary fuzzer-generated inputs continue to reach the parser unchanged.
pub(crate) fn decode_tracked_seed(data: &[u8]) -> Cow<'_, [u8]> {
    const HEX_PREFIX: &[u8] = b"hex:";
    let Some(encoded) = data.strip_prefix(HEX_PREFIX) else {
        return Cow::Borrowed(data);
    };
    let digits: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Cow::Borrowed(data);
    }

    let mut decoded = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let Some(high) = (pair[0] as char).to_digit(16) else {
            return Cow::Borrowed(data);
        };
        let Some(low) = (pair[1] as char).to_digit(16) else {
            return Cow::Borrowed(data);
        };
        decoded.push(((high << 4) | low) as u8);
    }
    Cow::Owned(decoded)
}
