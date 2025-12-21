#![no_main]

use libfuzzer_sys::fuzz_target;

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};

use exfilguard::proxy::http2::fuzzing::sanitize_request_for_fuzz;

fn take<'a>(data: &'a [u8], idx: &mut usize, len: usize) -> &'a [u8] {
    let start = *idx;
    let end = start.saturating_add(len).min(data.len());
    *idx = end;
    &data[start..end]
}

fn build_host(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "example.com".to_string();
    }
    let mut host = String::new();
    for (i, b) in bytes.iter().enumerate() {
        let ch = match b % 36 {
            0..=25 => (b'a' + (b % 26)) as char,
            _ => (b'0' + (b % 10)) as char,
        };
        host.push(ch);
        if i % 6 == 5 {
            host.push('.');
        }
    }
    if host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() {
        "example.com".to_string()
    } else {
        host
    }
}

fn build_path(bytes: &[u8]) -> String {
    let mut path = String::from("/");
    for b in bytes {
        let ch = match b % 52 {
            0..=25 => (b'a' + (b % 26)) as char,
            26..=35 => (b'0' + (b % 10)) as char,
            36 => '-',
            37 => '_',
            38 => '.',
            39 => '~',
            40 => '/',
            41 => '?',
            42 => '&',
            43 => '=',
            _ => 'x',
        };
        path.push(ch);
    }
    if path.len() == 1 {
        path.push('x');
    }
    path
}

fn build_header_name(bytes: &[u8]) -> Option<HeaderName> {
    if bytes.is_empty() {
        return None;
    }
    let mut name = String::new();
    for b in bytes {
        let ch = match b % 38 {
            0..=25 => (b'a' + (b % 26)) as char,
            26..=35 => (b'0' + (b % 10)) as char,
            _ => '-',
        };
        if name.is_empty() && ch == '-' {
            continue;
        }
        name.push(ch);
    }
    let name = name.trim_matches('-');
    if name.is_empty() {
        return None;
    }
    HeaderName::from_bytes(name.as_bytes()).ok()
}

fn build_header_value(bytes: &[u8]) -> Option<HeaderValue> {
    if bytes.is_empty() {
        return Some(HeaderValue::from_static(""));
    }
    let mut value = Vec::with_capacity(bytes.len());
    for b in bytes {
        value.push(0x20 + (b % 0x5f));
    }
    HeaderValue::from_bytes(&value).ok()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    let mut idx = 0usize;
    let method_len = (data[idx] as usize) % 16;
    idx += 1;
    let uri_len = (data[idx] as usize) % 64;
    idx += 1;
    let header_count = (data[idx] as usize) % 8;
    idx += 1;

    let method_bytes = take(data, &mut idx, method_len);
    let uri_bytes = take(data, &mut idx, uri_len);

    let method = Method::from_bytes(method_bytes).unwrap_or(Method::GET);

    let (host_bytes, path_bytes) = uri_bytes.split_at(uri_bytes.len() / 2);
    let host = build_host(host_bytes);
    let path = build_path(path_bytes);

    let uri = if data[0] & 0x10 != 0 {
        Uri::from_static("/")
    } else {
        Uri::builder()
            .scheme("https")
            .authority(host.as_str())
            .path_and_query(path.as_str())
            .build()
            .unwrap_or_else(|_| Uri::from_static("https://example.com/"))
    };

    let mut headers = HeaderMap::new();
    if data[0] & 0x01 != 0 {
        headers.insert(http::header::EXPECT, HeaderValue::from_static("100-continue"));
    }
    if data[0] & 0x02 != 0 {
        headers.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
    }
    if data[0] & 0x04 != 0 {
        headers.insert(http::header::HOST, HeaderValue::from_static("example.com"));
    }

    for _ in 0..header_count {
        if idx + 2 > data.len() {
            break;
        }
        let name_len = (data[idx] as usize) % 20;
        idx += 1;
        let value_len = (data[idx] as usize) % 64;
        idx += 1;
        let name_bytes = take(data, &mut idx, name_len);
        let value_bytes = take(data, &mut idx, value_len);

        if let (Some(name), Some(value)) = (
            build_header_name(name_bytes),
            build_header_value(value_bytes),
        ) {
            headers.append(name, value);
        }
    }

    let max_header_bytes = data.len().max(1).min(16 * 1024);
    let _ = sanitize_request_for_fuzz(&method, &uri, &headers, max_header_bytes);
});
