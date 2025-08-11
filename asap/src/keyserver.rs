use std::future::Future;
use std::ops::Deref;

pub type Result<T> = std::result::Result<T, Error>;

pub trait Keyserver: Send + Sync {
    fn get_public_key(&self, kid: &str) -> impl Future<Output = Result<jwt::DecodingKey>> + Send;
}

impl<T: Deref<Target: Keyserver> + Send + Sync> Keyserver for T {
    async fn get_public_key(&self, kid: &str) -> Result<jwt::DecodingKey> {
        self.deref().get_public_key(kid).await
    }
}

#[derive(Debug, Clone, Copy, derive_more::Display)]
#[non_exhaustive]
pub enum ErrorKind {
    #[display("invalid configuration")]
    InvalidConfig,
    #[display("invalid response")]
    InvalidResponse,
    #[display("key not found")]
    KeyNotFound,
    #[display("other error")]
    Other,
}

#[derive(Debug, derive_more::Display)]
enum ErrorData {
    Source(Box<dyn std::error::Error + Send + Sync>),
    Message(String),
    None,
}

#[derive(Debug, thiserror::Error)]
#[error("keyserver error: {kind}{}", match .data { ErrorData::None => "".to_string(), ed => ": ".to_string() + &ed.to_string()})]
pub struct Error {
    kind: ErrorKind,
    data: ErrorData,
}

impl ErrorKind {
    pub fn source<E: std::error::Error + Send + Sync + 'static>(self, error: E) -> Error {
        Error {
            kind: self,
            data: ErrorData::Source(Box::new(error)),
        }
    }

    pub fn message(self, message: String) -> Error {
        Error {
            kind: self,
            data: ErrorData::Message(message),
        }
    }
}

impl Into<Error> for ErrorKind {
    fn into(self) -> Error {
        Error {
            kind: self,
            data: ErrorData::None,
        }
    }
}

#[cfg(feature = "http-keyserver")]
pub use http::HttpKeyserver;

#[cfg(feature = "http-keyserver")]
mod http {
    use super::*;
    use reqwest::{Client, StatusCode, Url};
    use std::time::Duration;

    pub struct HttpKeyserver {
        client: Client,
        timeout: Option<Duration>,
        urls: Vec<String>,
    }

    impl HttpKeyserver {
        const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
        const HTTP_USER_AGENT: &str =
            concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

        pub fn new(urls: Vec<String>) -> Self {
            let client = Client::builder()
                .user_agent(Self::HTTP_USER_AGENT)
                .timeout(Self::DEFAULT_TIMEOUT)
                .build()
                .expect("Failed to create HTTP client");

            HttpKeyserver {
                client,
                timeout: None,
                urls,
            }
        }

        pub fn append_url(&mut self, url: String) {
            self.urls.push(url);
        }

        pub fn set_timeout(&mut self, timeout: Duration) {
            if timeout == Duration::ZERO {
                self.timeout = None
            } else {
                self.timeout = Some(timeout)
            };
        }

        async fn get_key_from_url(&self, server_url: &str, kid: &str) -> Result<jwt::DecodingKey> {
            if !server_url.ends_with('/') {
                return Err(ErrorKind::InvalidConfig
                    .message(format!("URL does not end with `/`: {:?}", server_url)));
            }

            let url = Url::parse(server_url)
                .and_then(|u| u.join(kid))
                .map_err(|e| ErrorKind::InvalidConfig.source(e))?;

            let mut req = self.client.get(url);
            if let Some(to) = self.timeout {
                req = req.timeout(to);
            }

            let response = req
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| match e.status() {
                    Some(StatusCode::NOT_FOUND) => ErrorKind::KeyNotFound.into(),
                    _ => ErrorKind::InvalidResponse.source(e),
                })?;

            let body = response
                .bytes()
                .await
                .map_err(|e| ErrorKind::InvalidResponse.source(e))?;

            Ok(jwt::DecodingKey::from_rsa_der(&body))
        }
    }

    impl Keyserver for HttpKeyserver {
        async fn get_public_key(&self, kid: &str) -> Result<jwt::DecodingKey> {
            for srv_url in self.urls.iter() {
                if let Ok(key) = self.get_key_from_url(srv_url, kid).await {
                    return Ok(key);
                }
            }

            Err(ErrorKind::KeyNotFound.into())
        }
    }
}
