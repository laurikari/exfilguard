use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use tokio::io::AsyncRead;
use tokio::net::{TcpListener, TcpStream};
use tokio::{
    io::AsyncReadExt,
    time::{sleep, timeout},
};
use tracing::{debug, error, info, warn};

use super::{AppContext, http};
use crate::settings::ProxyProtocolMode;

const MAX_PROXY_LINE_LENGTH: usize = 256;
const MAX_PROXY_V2_LENGTH: usize = 512;
const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

pub async fn start_listener(app: AppContext) -> Result<()> {
    let bind_addr = app.settings.listen;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind listener on {}", bind_addr))?;
    let local_addr = listener.local_addr().unwrap_or(bind_addr);
    info!(address = %local_addr, "proxy listener started");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                error!(error = %err, "failed to accept incoming connection");
                continue;
            }
        };
        debug!(peer = %peer_addr, "accepted connection");
        if let Err(err) = stream.set_nodelay(true) {
            debug!(peer = %peer_addr, error = %err, "failed to set TCP_NODELAY on downstream stream");
        }
        let connection_app = app.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer_addr, connection_app).await {
                debug!(peer = %peer_addr, error = %err, "connection closed with error");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, peer: SocketAddr, app: AppContext) -> Result<()> {
    let original_peer = peer;
    let peer = match app.settings.proxy_protocol {
        ProxyProtocolMode::Off => peer,
        mode => {
            if !app.settings.proxy_protocol_allows_peer(peer.ip()) {
                peer
            } else {
                match detect_proxy_header(&stream, peer, app.settings.request_header_timeout())
                    .await
                {
                    Ok(ProxyHeaderKind::V1) => match read_proxy_v1_header(
                        &mut stream,
                        peer,
                        app.settings.request_header_timeout(),
                    )
                    .await
                    {
                        Ok(proxy_peer) => proxy_peer,
                        Err(err) => {
                            warn!(peer = %peer, error = %err, "invalid proxy protocol v1 header");
                            return Ok(());
                        }
                    },
                    Ok(ProxyHeaderKind::V2) => match read_proxy_v2_header(
                        &mut stream,
                        peer,
                        app.settings.request_header_timeout(),
                    )
                    .await
                    {
                        Ok(proxy_peer) => proxy_peer,
                        Err(err) => {
                            warn!(peer = %peer, error = %err, "invalid proxy protocol v2 header");
                            return Ok(());
                        }
                    },
                    Ok(ProxyHeaderKind::None) => {
                        if mode == ProxyProtocolMode::Required {
                            warn!(peer = %peer, "proxy protocol header required");
                            return Ok(());
                        }
                        peer
                    }
                    Err(err) => {
                        warn!(peer = %peer, error = %err, "invalid proxy protocol header");
                        return Ok(());
                    }
                }
            }
        }
    };
    if peer != original_peer {
        debug!(
            peer = %original_peer,
            proxy_peer = %peer,
            "accepted proxy protocol header"
        );
    }
    http::handle_http(stream, peer, app).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyHeaderKind {
    None,
    V1,
    V2,
}

async fn detect_proxy_header(
    stream: &TcpStream,
    peer: SocketAddr,
    read_timeout: Duration,
) -> Result<ProxyHeaderKind> {
    let deadline = Instant::now() + read_timeout;
    let mut buf = [0u8; 12];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for proxy protocol header from {peer}");
        }
        let n = match timeout(remaining, stream.peek(&mut buf)).await {
            Ok(result) => result.context("peeking proxy protocol header")?,
            Err(_) => bail!("timed out waiting for proxy protocol header from {peer}"),
        };
        if n == 0 {
            bail!("connection closed while waiting for proxy protocol header from {peer}");
        }
        if n >= 5 && &buf[..5] == b"PROXY" {
            return Ok(ProxyHeaderKind::V1);
        }
        if n >= 12 {
            if buf[..12] == PROXY_V2_SIGNATURE {
                return Ok(ProxyHeaderKind::V2);
            }
            return Ok(ProxyHeaderKind::None);
        }
        sleep(Duration::from_millis(1)).await;
    }
}

async fn read_proxy_v1_header<R>(
    reader: &mut R,
    peer: SocketAddr,
    read_timeout: Duration,
) -> Result<SocketAddr>
where
    R: AsyncRead + Unpin,
{
    let line = match timeout(read_timeout, read_proxy_line(reader)).await {
        Ok(line) => line?,
        Err(_) => bail!("timed out waiting for proxy protocol header from {peer}"),
    };
    let line = std::str::from_utf8(&line).context("proxy protocol line is not valid utf-8")?;
    parse_proxy_v1_line(line, peer)
}

async fn read_proxy_v2_header<R>(
    reader: &mut R,
    peer: SocketAddr,
    read_timeout: Duration,
) -> Result<SocketAddr>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 16];
    match timeout(read_timeout, reader.read_exact(&mut header)).await {
        Ok(result) => result.context("reading proxy protocol v2 header")?,
        Err(_) => bail!("timed out waiting for proxy protocol v2 header from {peer}"),
    };
    let length = u16::from_be_bytes([header[14], header[15]]) as usize;
    ensure!(
        length <= MAX_PROXY_V2_LENGTH,
        "proxy protocol v2 length exceeds {} bytes",
        MAX_PROXY_V2_LENGTH
    );
    let mut payload = vec![0u8; length];
    if length > 0 {
        match timeout(read_timeout, reader.read_exact(&mut payload)).await {
            Ok(result) => result.context("reading proxy protocol v2 payload")?,
            Err(_) => bail!("timed out waiting for proxy protocol v2 payload from {peer}"),
        };
    }
    parse_proxy_v2_payload(&header, &payload, peer)
}

fn parse_proxy_v2_payload(
    header: &[u8; 16],
    payload: &[u8],
    peer: SocketAddr,
) -> Result<SocketAddr> {
    ensure!(
        header[..12] == PROXY_V2_SIGNATURE,
        "missing proxy protocol v2 signature"
    );
    let expected_len = u16::from_be_bytes([header[14], header[15]]) as usize;
    ensure!(
        payload.len() == expected_len,
        "proxy protocol v2 payload length mismatch"
    );
    let version = header[12] >> 4;
    let command = header[12] & 0x0f;
    ensure!(
        version == 0x2,
        "unsupported proxy protocol version {version}"
    );
    if command == 0x0 {
        return Ok(peer);
    }
    ensure!(
        command == 0x1,
        "unsupported proxy protocol v2 command {command}"
    );
    let family = header[13] >> 4;
    let protocol = header[13] & 0x0f;
    if family == 0x0 && protocol == 0x0 {
        return Ok(peer);
    }
    ensure!(
        protocol == 0x1,
        "unsupported proxy protocol v2 transport {protocol}"
    );
    match family {
        0x1 => parse_proxy_v2_ipv4(payload),
        0x2 => parse_proxy_v2_ipv6(payload),
        _ => bail!("unsupported proxy protocol v2 address family {family}"),
    }
}

fn parse_proxy_v2_ipv4(payload: &[u8]) -> Result<SocketAddr> {
    ensure!(
        payload.len() >= 12,
        "proxy protocol v2 IPv4 payload too short"
    );
    let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        payload[0], payload[1], payload[2], payload[3],
    ));
    let src_port = u16::from_be_bytes([payload[8], payload[9]]);
    Ok(SocketAddr::new(src_ip, src_port))
}

fn parse_proxy_v2_ipv6(payload: &[u8]) -> Result<SocketAddr> {
    ensure!(
        payload.len() >= 36,
        "proxy protocol v2 IPv6 payload too short"
    );
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&payload[..16]);
    let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
    let src_port = u16::from_be_bytes([payload[32], payload[33]]);
    Ok(SocketAddr::new(src_ip, src_port))
}

async fn read_proxy_line<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let byte = reader
            .read_u8()
            .await
            .context("reading proxy protocol header")?;
        if byte == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            break;
        }
        line.push(byte);
        if line.len() > MAX_PROXY_LINE_LENGTH {
            bail!(
                "proxy protocol line exceeds {} bytes",
                MAX_PROXY_LINE_LENGTH
            );
        }
    }
    Ok(line)
}

fn parse_proxy_v1_line(line: &str, peer: SocketAddr) -> Result<SocketAddr> {
    let mut parts = line.split_whitespace();
    let prefix = parts.next().unwrap_or_default();
    ensure!(prefix == "PROXY", "missing PROXY prefix");
    let transport = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing proxy protocol transport"))?;
    if transport == "UNKNOWN" {
        ensure!(
            parts.next().is_none(),
            "unexpected proxy protocol fields after UNKNOWN"
        );
        return Ok(peer);
    }
    ensure!(
        transport == "TCP4" || transport == "TCP6",
        "unsupported proxy protocol transport {transport}"
    );
    let src_ip: IpAddr = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing proxy protocol source ip"))?
        .parse()
        .context("invalid proxy protocol source ip")?;
    let dst_ip: IpAddr = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing proxy protocol destination ip"))?
        .parse()
        .context("invalid proxy protocol destination ip")?;
    let src_port: u16 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing proxy protocol source port"))?
        .parse()
        .context("invalid proxy protocol source port")?;
    let _dst_port: u16 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing proxy protocol destination port"))?
        .parse()
        .context("invalid proxy protocol destination port")?;
    if transport == "TCP4" {
        ensure!(
            src_ip.is_ipv4() && dst_ip.is_ipv4(),
            "proxy protocol TCP4 addresses must be IPv4"
        );
    } else {
        ensure!(
            src_ip.is_ipv6() && dst_ip.is_ipv6(),
            "proxy protocol TCP6 addresses must be IPv6"
        );
    }
    ensure!(
        parts.next().is_none(),
        "unexpected extra fields in proxy protocol header"
    );
    Ok(SocketAddr::new(src_ip, src_port))
}

#[cfg(test)]
mod tests {
    use super::{PROXY_V2_SIGNATURE, parse_proxy_v1_line, parse_proxy_v2_payload};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn parse_proxy_v1_line_tcp4() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let parsed =
            parse_proxy_v1_line("PROXY TCP4 203.0.113.10 203.0.113.11 4567 443", peer).unwrap();
        assert_eq!(parsed.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(parsed.port(), 4567);
    }

    #[test]
    fn parse_proxy_v1_line_unknown_uses_peer() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let parsed = parse_proxy_v1_line("PROXY UNKNOWN", peer).unwrap();
        assert_eq!(parsed, peer);
    }

    #[test]
    fn parse_proxy_v1_line_rejects_invalid_prefix() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let err = parse_proxy_v1_line("GET / HTTP/1.1", peer).unwrap_err();
        assert!(format!("{err}").contains("missing PROXY prefix"));
    }

    #[test]
    fn parse_proxy_v1_line_rejects_missing_fields() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let err = parse_proxy_v1_line("PROXY TCP4 203.0.113.10", peer).unwrap_err();
        assert!(format!("{err}").contains("missing proxy protocol destination ip"));
    }

    #[test]
    fn parse_proxy_v1_line_rejects_invalid_ports() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let err =
            parse_proxy_v1_line("PROXY TCP4 203.0.113.10 203.0.113.11 nope 443", peer).unwrap_err();
        assert!(format!("{err}").contains("invalid proxy protocol source port"));
    }

    #[test]
    fn parse_proxy_v1_line_rejects_tcp4_ipv6_addresses() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let err =
            parse_proxy_v1_line("PROXY TCP4 2001:db8::1 2001:db8::2 5555 443", peer).unwrap_err();
        assert!(format!("{err}").contains("TCP4 addresses must be IPv4"));
    }

    #[test]
    fn parse_proxy_v2_ipv4() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(&PROXY_V2_SIGNATURE);
        header[12] = 0x21; // v2, PROXY
        header[13] = 0x11; // INET, STREAM
        header[14..16].copy_from_slice(&(12u16.to_be_bytes()));
        let payload = [
            203, 0, 113, 10, // src
            192, 0, 2, 1, // dst
            0x15, 0xb3, // src port 5555
            0x0c, 0x38, // dst port 3128
        ];
        let parsed = parse_proxy_v2_payload(&header, &payload, peer).unwrap();
        assert_eq!(parsed.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(parsed.port(), 5555);
    }

    #[test]
    fn parse_proxy_v2_local_uses_peer() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(&PROXY_V2_SIGNATURE);
        header[12] = 0x20; // v2, LOCAL
        header[13] = 0x00;
        header[14..16].copy_from_slice(&(0u16.to_be_bytes()));
        let parsed = parse_proxy_v2_payload(&header, &[], peer).unwrap();
        assert_eq!(parsed, peer);
    }

    #[test]
    fn parse_proxy_v2_unspec_uses_peer() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(&PROXY_V2_SIGNATURE);
        header[12] = 0x21; // v2, PROXY
        header[13] = 0x00; // UNSPEC
        header[14..16].copy_from_slice(&(0u16.to_be_bytes()));
        let parsed = parse_proxy_v2_payload(&header, &[], peer).unwrap();
        assert_eq!(parsed, peer);
    }
}

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use std::net::SocketAddr;

    use anyhow::Result;

    pub fn parse_proxy_v1_line(line: &str, peer: SocketAddr) -> Result<SocketAddr> {
        super::parse_proxy_v1_line(line, peer)
    }

    pub fn parse_proxy_v2_payload(
        header: &[u8; 16],
        payload: &[u8],
        peer: SocketAddr,
    ) -> Result<SocketAddr> {
        super::parse_proxy_v2_payload(header, payload, peer)
    }
}
