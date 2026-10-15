mod cache;
mod forward;
mod request;
mod server;
mod upstream;

pub use server::serve_bumped_http2;
pub use upstream::PrimedHttp2Upstream;

#[cfg(test)]
mod test_support {
    use tokio::io::{AsyncReadExt, DuplexStream};

    // Read the SETTINGS and connection WINDOW_UPDATE frames sent to the peer.
    // The test sends no DATA and releases no receive capacity.
    pub(super) async fn assert_receive_windows(
        peer: &mut DuplexStream,
        stream_window: u32,
        connection_window: u32,
    ) {
        let mut settings_seen = false;
        let mut connection_credit = 65_535;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !settings_seen || connection_credit != connection_window {
                let mut header = [0; 9];
                peer.read_exact(&mut header).await.unwrap();
                let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                assert!(len <= 16_384);
                let mut payload = vec![0; len];
                peer.read_exact(&mut payload).await.unwrap();
                match header[3] {
                    4 if header[4] & 1 == 0 => {
                        let advertised = payload
                            .as_chunks::<6>()
                            .0
                            .iter()
                            .find(|setting| setting[..2] == [0, 4])
                            .map(|setting| u32::from_be_bytes(setting[2..].try_into().unwrap()))
                            .unwrap_or(65_535);
                        assert_eq!(advertised, stream_window);
                        settings_seen = true;
                    }
                    8 => {
                        assert_eq!(&header[5..], &[0; 4]);
                        connection_credit += u32::from_be_bytes(payload.try_into().unwrap());
                        assert!(connection_credit <= connection_window);
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("receive windows were not advertised");
    }
}

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    pub use super::request::sanitize_request_for_fuzz;
}
