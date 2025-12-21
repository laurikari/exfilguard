mod forward;
mod request;
mod server;
mod upstream;

pub use server::serve_bumped_http2;
pub use upstream::PrimedHttp2Upstream;

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    pub use super::request::sanitize_request_for_fuzz;
}
