use anyhow::{Result, bail};

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Build the canonical path used for policy evaluation from a raw request target.
pub(crate) fn canonicalize_request_path(raw_path: &str) -> Result<String> {
    if raw_path == "*" {
        return Ok("*".to_string());
    }

    let path = raw_path.split('?').next().unwrap_or("/");
    if path.is_empty() {
        return Ok("/".to_string());
    }
    if !path.starts_with('/') {
        bail!("request path must be absolute");
    }

    validate_request_path(path)?;
    let path = canonicalize_escapes(path)?;
    Ok(remove_literal_dot_segments(&path))
}

/// Validate a canonical policy pattern and return the regex that implements it.
///
/// Request-path characters are literal except for unescaped `*`. `\*` quotes a
/// literal asterisk; no other backslash escape is accepted.
pub(crate) fn pattern_regex(pattern: &str) -> Result<String> {
    if !pattern.starts_with('/') {
        bail!("path pattern must start with '/'");
    }
    if pattern.contains("//") {
        bail!("path pattern must not contain repeated '/' separators");
    }

    let mut regex = String::from("^/");
    let mut first_segment = true;
    for segment in pattern.split('/').skip(1) {
        if !first_segment {
            regex.push('/');
        }
        first_segment = false;

        if segment == "." || segment == ".." {
            bail!("path pattern must not contain '.' or '..' segments");
        }
        if segment == "**" {
            regex.push_str(".*");
            continue;
        }

        compile_pattern_segment(segment, &mut regex)?;
    }

    regex.push('$');
    Ok(regex)
}

fn compile_pattern_segment(segment: &str, regex: &mut String) -> Result<()> {
    let bytes = segment.as_bytes();
    let mut idx = 0usize;
    let mut literal = String::new();

    while idx < bytes.len() {
        match bytes[idx] {
            b'\\' => {
                if bytes.get(idx + 1) != Some(&b'*') {
                    bail!("path pattern backslash may only escape '*'");
                }
                literal.push('*');
                idx += 2;
            }
            b'*' => {
                if bytes.get(idx + 1) == Some(&b'*') {
                    bail!("'**' may only appear as its own segment");
                }
                flush_literal(regex, &mut literal);
                regex.push_str("[^/]*");
                idx += 1;
            }
            b'%' => {
                let decoded = decode_pattern_escape(bytes, idx)?;
                if is_rfc3986_unreserved(decoded) {
                    bail!(
                        "path pattern percent-escape '{}' is not canonical; use the literal character",
                        &segment[idx..idx + 3]
                    );
                }
                if decoded == b'\\' {
                    bail!("path pattern must not contain encoded backslashes");
                }
                if decoded.is_ascii_control() || decoded == 0x7f {
                    bail!("path pattern must not contain encoded control characters");
                }
                literal.push_str(&segment[idx..idx + 3]);
                idx += 3;
            }
            byte if is_rfc3986_pchar(byte) => {
                literal.push(char::from(byte));
                idx += 1;
            }
            _ => bail!("path segment '{}' contains invalid character", segment),
        }
    }

    flush_literal(regex, &mut literal);
    Ok(())
}

fn flush_literal(regex: &mut String, literal: &mut String) {
    if !literal.is_empty() {
        regex.push_str(&regex::escape(literal));
        literal.clear();
    }
}

fn decode_pattern_escape(bytes: &[u8], idx: usize) -> Result<u8> {
    if idx + 2 >= bytes.len() {
        bail!("path pattern contains invalid percent-escape");
    }
    let high = bytes[idx + 1];
    let low = bytes[idx + 2];
    if !is_upper_hex_digit(high) || !is_upper_hex_digit(low) {
        bail!("path pattern percent-escapes must use uppercase hexadecimal");
    }
    Ok((decode_hex_nibble(high)? << 4) | decode_hex_nibble(low)?)
}

fn is_upper_hex_digit(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
}

fn canonicalize_escapes(path: &str) -> Result<String> {
    let bytes = path.as_bytes();
    let mut canonical = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] != b'%' {
            canonical.push(bytes[idx]);
            idx += 1;
            continue;
        }

        if idx + 2 >= bytes.len() {
            bail!("request path contains invalid percent-escape");
        }
        let decoded = decode_hex_byte(bytes[idx + 1], bytes[idx + 2])?;
        if is_rfc3986_unreserved(decoded) {
            canonical.push(decoded);
        } else {
            canonical.push(b'%');
            canonical.push(UPPER_HEX[usize::from(decoded >> 4)]);
            canonical.push(UPPER_HEX[usize::from(decoded & 0x0f)]);
        }
        idx += 3;
    }

    Ok(String::from_utf8(canonical)
        .expect("canonical path preserves UTF-8 and decodes only ASCII bytes"))
}

fn validate_request_path(path: &str) -> Result<()> {
    if path.contains("//") {
        bail!("request path must not contain repeated slashes");
    }
    for segment in path.split('/') {
        validate_request_segment(segment)?;
    }
    Ok(())
}

fn validate_request_segment(segment: &str) -> Result<()> {
    let bytes = segment.as_bytes();
    let mut idx = 0usize;
    let mut only_dots = true;
    let mut dot_count = 0usize;
    let mut used_encoded_dot = false;

    while idx < bytes.len() {
        match bytes[idx] {
            b'%' => {
                if idx + 2 >= bytes.len() {
                    bail!("request path contains invalid percent-escape");
                }
                let decoded = decode_hex_byte(bytes[idx + 1], bytes[idx + 2])?;
                if decoded == b'\\' {
                    bail!("request path must not contain encoded backslashes");
                }
                if decoded.is_ascii_control() || decoded == 0x7f {
                    bail!("request path must not contain encoded control characters");
                }
                if decoded == b'.' {
                    used_encoded_dot = true;
                    dot_count += 1;
                } else {
                    only_dots = false;
                }
                idx += 3;
            }
            b'\\' => bail!("request path must not contain backslashes"),
            b'.' => {
                dot_count += 1;
                idx += 1;
            }
            byte if is_rfc3986_pchar(byte) => {
                only_dots = false;
                idx += 1;
            }
            _ => bail!("request path contains a character outside RFC 3986 path syntax"),
        }
    }

    if used_encoded_dot && only_dots && (dot_count == 1 || dot_count == 2) {
        bail!("request path must not contain encoded dot segments");
    }

    Ok(())
}

fn is_rfc3986_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_rfc3986_pchar(byte: u8) -> bool {
    is_rfc3986_unreserved(byte)
        || matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn decode_hex_byte(high: u8, low: u8) -> Result<u8> {
    Ok((decode_hex_nibble(high)? << 4) | decode_hex_nibble(low)?)
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("request path contains invalid percent-escape"),
    }
}

fn remove_literal_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut output = String::new();

    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest;
            continue;
        }
        if let Some(rest) = input.strip_prefix("./") {
            input = rest;
            continue;
        }
        if input.starts_with("/./") {
            input = &input[2..];
            continue;
        }
        if input == "/." {
            input = "/";
            continue;
        }
        if input.starts_with("/../") {
            input = &input[3..];
            remove_last_path_segment(&mut output);
            continue;
        }
        if input == "/.." {
            input = "/";
            remove_last_path_segment(&mut output);
            continue;
        }
        if input == "." || input == ".." {
            input = "";
            continue;
        }

        let next = next_path_segment_end(input);
        output.push_str(&input[..next]);
        input = &input[next..];
    }

    if output.is_empty() {
        "/".to_string()
    } else {
        output
    }
}

fn next_path_segment_end(input: &str) -> usize {
    if let Some(rest) = input.strip_prefix('/') {
        match rest.find('/') {
            Some(offset) => offset + 1,
            None => input.len(),
        }
    } else {
        input.find('/').unwrap_or(input.len())
    }
}

fn remove_last_path_segment(output: &mut String) {
    if output.is_empty() {
        return;
    }
    if let Some(idx) = output.rfind('/') {
        output.truncate(idx);
    } else {
        output.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_request_path, pattern_regex};
    use regex::Regex;

    #[test]
    fn literal_pattern_can_represent_every_canonical_path_character() {
        let raw = "/AZaz09-._~!$&'()*+,;=:@/%25/%2A/%3F/%23/%80/%FF";
        let canonical = canonicalize_request_path(raw).unwrap();
        assert_eq!(canonical, raw);

        let literal_pattern = canonical.replace('*', r"\*");
        let matcher = Regex::new(&pattern_regex(&literal_pattern).unwrap()).unwrap();
        assert!(matcher.is_match(&canonical));
        assert!(!matcher.is_match("/AZaz09-._~!$&'()x+,;=:@/%25/%2A/%3F/%23/%80/%FF"));
    }

    #[test]
    fn every_accepted_percent_encoded_byte_has_an_exact_pattern() {
        for byte in 0u8..=u8::MAX {
            let raw = format!("/%{byte:02X}x");
            let result = canonicalize_request_path(&raw);
            if byte == b'\\' || byte.is_ascii_control() || byte == 0x7f {
                assert!(result.is_err(), "unexpectedly accepted {raw}");
                continue;
            }

            let canonical = result.unwrap_or_else(|error| panic!("rejected {raw}: {error:#}"));
            let literal_pattern = canonical.replace('*', r"\*");
            let matcher = Regex::new(&pattern_regex(&literal_pattern).unwrap()).unwrap();
            assert!(
                matcher.is_match(&canonical),
                "{literal_pattern} did not match {canonical}"
            );
        }
    }

    #[test]
    fn raw_encoded_and_textual_asterisks_remain_distinct() {
        let cases = [
            ("/files/*", r"/files/\*"),
            ("/files/%2A", "/files/%2A"),
            ("/files/%252A", "/files/%252A"),
        ];

        for (raw, pattern) in cases {
            let canonical = canonicalize_request_path(raw).unwrap();
            let matcher = Regex::new(&pattern_regex(pattern).unwrap()).unwrap();
            assert!(
                matcher.is_match(&canonical),
                "{pattern} did not match {canonical}"
            );
        }
    }

    #[test]
    fn literal_and_encoded_semicolons_remain_distinct_path_data() {
        let literal = canonicalize_request_path("/items;color=red?filter=a;b").unwrap();
        let encoded = canonicalize_request_path("/items%3bcolor=red?filter=a;b").unwrap();
        assert_eq!(literal, "/items;color=red");
        assert_eq!(encoded, "/items%3Bcolor=red");

        let literal_matcher = Regex::new(&pattern_regex("/items;color=red").unwrap()).unwrap();
        assert!(literal_matcher.is_match(&literal));
        assert!(!literal_matcher.is_match(&encoded));

        let encoded_matcher = Regex::new(&pattern_regex("/items%3Bcolor=red").unwrap()).unwrap();
        assert!(encoded_matcher.is_match(&encoded));
        assert!(!encoded_matcher.is_match(&literal));
    }

    #[test]
    fn encoded_slash_remains_distinct_path_data() {
        let encoded = canonicalize_request_path("/@scope%2fname").unwrap();
        let literal = canonicalize_request_path("/@scope/name").unwrap();
        let double_encoded = canonicalize_request_path("/@scope%252fname").unwrap();
        assert_eq!(encoded, "/@scope%2Fname");
        assert_eq!(literal, "/@scope/name");
        assert_eq!(double_encoded, "/@scope%252fname");

        let matcher = Regex::new(&pattern_regex("/@scope%2F*").unwrap()).unwrap();
        assert!(matcher.is_match(&encoded));
        assert!(!matcher.is_match(&literal));
        assert!(!matcher.is_match(&double_encoded));
    }

    #[test]
    fn reject_noncanonical_pattern_escapes() {
        for pattern in ["/files/%7E", "/files/%2a", "/files/%5C"] {
            assert!(pattern_regex(pattern).is_err(), "accepted {pattern}");
        }
    }

    #[test]
    fn reject_unsupported_backslash_escapes() {
        for pattern in [r"/files/\q", r"/files/\", r"/files/a**b"] {
            assert!(pattern_regex(pattern).is_err(), "accepted {pattern}");
        }
    }
}
