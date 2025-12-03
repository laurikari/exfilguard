use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderDisposition {
    Connection,
    Host,
    ContentLength,
    TransferEncoding,
    Skip,
    Forward,
}

/// Returns true when the header conveys forwarding metadata that should be stripped.
pub fn is_forwarding_header(name: &str) -> bool {
    if name.starts_with("x-forwarded-") {
        return true;
    }
    matches!(
        name,
        "forwarded"
            | "x-real-ip"
            | "x-client-ip"
            | "x-cluster-client-ip"
            | "true-client-ip"
            | "cf-connecting-ip"
            | "fastly-client-ip"
            | "fly-client-ip"
            | "x-forwarded-client-cert"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-forwarded-host"
    ) || name.ends_with("-client-ip")
}

pub fn classify_request_header(name: &str) -> HeaderDisposition {
    if name == "connection" {
        HeaderDisposition::Connection
    } else if name == "host" {
        HeaderDisposition::Host
    } else if name == "content-length" {
        HeaderDisposition::ContentLength
    } else if name == "transfer-encoding" {
        HeaderDisposition::TransferEncoding
    } else if name.starts_with("proxy-")
        || matches!(name, "keep-alive" | "upgrade" | "proxy-connection" | "te")
        || is_forwarding_header(name)
    {
        HeaderDisposition::Skip
    } else {
        HeaderDisposition::Forward
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAction {
    Forward,
    Skip,
}

const HEADER_OVERHEAD: usize = 4; // ': ' plus CRLF

#[derive(Debug, Clone)]
pub struct RequestHeaderSanitizer {
    max_bytes: usize,
    consumed: usize,
    host: Option<String>,
    content_length: Option<usize>,
    chunked: bool,
    connection_tokens: HashSet<String>,
    connection_seen: bool,
    transfer_encoding_seen: bool,
}

impl RequestHeaderSanitizer {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            consumed: 0,
            host: None,
            content_length: None,
            chunked: false,
            connection_tokens: HashSet::new(),
            connection_seen: false,
            transfer_encoding_seen: false,
        }
    }

    pub fn reserve(&mut self, byte_len: usize) -> Result<()> {
        self.consumed = self
            .consumed
            .checked_add(byte_len)
            .ok_or_else(|| anyhow!("header section exceeds configured limit"))?;
        ensure!(
            self.consumed <= self.max_bytes,
            "header section exceeds configured limit"
        );
        Ok(())
    }

    pub fn record(&mut self, name: &str, value: &str, byte_len: usize) -> Result<HeaderAction> {
        self.reserve(byte_len)?;

        let name_lower = name.to_ascii_lowercase();
        match classify_request_header(&name_lower) {
            HeaderDisposition::Connection => {
                if self.connection_seen {
                    anyhow::bail!("duplicate Connection header");
                }
                self.connection_seen = true;
                self.record_connection_tokens(value);
                Ok(HeaderAction::Skip)
            }
            HeaderDisposition::Host => {
                if self.host.is_some() {
                    anyhow::bail!("duplicate Host header");
                }
                ensure!(!value.is_empty(), "Host header must not be empty");
                self.host = Some(value.to_ascii_lowercase());
                Ok(HeaderAction::Skip)
            }
            HeaderDisposition::ContentLength => {
                if self.chunked {
                    anyhow::bail!(
                        "request must not include both Content-Length and Transfer-Encoding"
                    );
                }
                if self.content_length.is_some() {
                    anyhow::bail!("multiple Content-Length headers are not supported");
                }
                let length: usize = value
                    .parse()
                    .with_context(|| format!("invalid Content-Length value '{value}'"))?;
                self.content_length = Some(length);
                Ok(HeaderAction::Skip)
            }
            HeaderDisposition::TransferEncoding => {
                if self.transfer_encoding_seen {
                    anyhow::bail!("duplicate Transfer-Encoding header");
                }
                self.transfer_encoding_seen = true;
                let encodings: Vec<String> = value
                    .split(',')
                    .map(|item| item.trim().to_ascii_lowercase())
                    .filter(|item| !item.is_empty())
                    .collect();
                if encodings.is_empty() || encodings.len() != 1 || encodings[0] != "chunked" {
                    anyhow::bail!("unsupported Transfer-Encoding '{value}'");
                }
                if self.content_length.is_some() {
                    anyhow::bail!(
                        "request must not include both Content-Length and Transfer-Encoding"
                    );
                }
                self.chunked = true;
                Ok(HeaderAction::Skip)
            }
            HeaderDisposition::Skip => Ok(HeaderAction::Skip),
            HeaderDisposition::Forward => Ok(HeaderAction::Forward),
        }
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn content_length(&self) -> Option<usize> {
        self.content_length
    }

    pub fn is_chunked(&self) -> bool {
        self.chunked
    }

    pub fn total_bytes(&self) -> usize {
        self.consumed
    }

    pub fn connection_tokens(&self) -> &HashSet<String> {
        &self.connection_tokens
    }

    fn record_connection_tokens(&mut self, value: &str) {
        for token in value.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            self.connection_tokens.insert(trimmed.to_ascii_lowercase());
        }
    }

    pub fn record_name_value(&mut self, name: &str, value: &str) -> Result<HeaderAction> {
        let byte_len = name
            .len()
            .checked_add(value.len())
            .and_then(|len| len.checked_add(HEADER_OVERHEAD))
            .ok_or_else(|| anyhow!("header section exceeds configured limit"))?;
        self.record(name, value, byte_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_host() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Host", "example.com", 16),
            Ok(HeaderAction::Skip)
        ));
        let err = sanitizer
            .record("Host", "other.example.com", 32)
            .expect_err("expected duplicate host to error");
        assert!(
            err.to_string().contains("duplicate Host"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn allows_duplicate_set_cookie() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Set-Cookie", "a=1", 18),
            Ok(HeaderAction::Forward)
        ));
        assert!(matches!(
            sanitizer.record("Set-Cookie", "b=2", 18),
            Ok(HeaderAction::Forward)
        ));
    }

    #[test]
    fn allows_duplicate_standard_headers() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Accept", "text/plain", 24),
            Ok(HeaderAction::Forward)
        ));
        assert!(matches!(
            sanitizer.record("Accept", "application/json", 32),
            Ok(HeaderAction::Forward)
        ));
    }

    #[test]
    fn rejects_conflicting_content_length_and_transfer_encoding() {
        let mut sanitizer = RequestHeaderSanitizer::new(256);
        assert!(matches!(
            sanitizer.record("Transfer-Encoding", "chunked", 32),
            Ok(HeaderAction::Skip)
        ));
        let err = sanitizer
            .record("Content-Length", "10", 24)
            .expect_err("expected conflict to error");
        assert!(
            err.to_string()
                .contains("must not include both Content-Length and Transfer-Encoding"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_exceeding_max_bytes() {
        let mut sanitizer = RequestHeaderSanitizer::new(16);
        let err = sanitizer
            .record("User-Agent", "toolong", 32)
            .expect_err("expected oversize header to error");
        assert!(
            err.to_string()
                .contains("header section exceeds configured limit"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn skip_connection_tokens_and_track_close() {
        let mut sanitizer = RequestHeaderSanitizer::new(128);
        assert!(matches!(
            sanitizer.record("Connection", "keep-alive, Close", 32),
            Ok(HeaderAction::Skip)
        ));
        assert!(sanitizer.connection_tokens().contains("close"));
        assert!(matches!(
            sanitizer.record("Foo", "bar", 16),
            Ok(HeaderAction::Forward)
        ));
    }
}
