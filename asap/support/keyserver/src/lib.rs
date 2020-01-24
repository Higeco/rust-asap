use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Error, Method, Request, Response, Server, StatusCode};
use tokio::sync::oneshot;

/// Keyserver that can be used for testing. Shuts down when dropped.
pub struct Keyserver {
    url: String,
    // As long as the ShutdownHandle is alive, the server is running.
    // Dropping it shuts down the server.
    _handle: ShutdownHandle,
}

impl Keyserver {
    pub fn start() -> Keyserver {
        // 0 means random port
        Keyserver::start_on_port(0)
    }

    pub fn start_on_port(port: u16) -> Keyserver {
        let addr = ([127, 0, 0, 1], port).into();
        let (bound_addr, server, shutdown_handle) = server(&addr);
        tokio::spawn(async {
            server
                .await
                .unwrap_or_else(|e| eprintln!("server error: {}", e))
        });
        let url = format!("http://localhost:{}/", bound_addr.port());
        Keyserver {
            url,
            _handle: shutdown_handle,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn count(&self) -> String {
        reqwest::get(&format!("{}count", self.url()))
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    }
}

pub fn server(addr: &SocketAddr) -> (SocketAddr, impl Future<Output = Result<(), Error>>, ShutdownHandle) {
    let counter = Arc::new(AtomicUsize::new(0));
    // the function passed to make_service_fn is called once per connection
    let new_service = make_service_fn(move |_socket| {
        let counter = counter.clone();
        async {
            // the function passed to make_service is called once per connection
            Ok::<_, Infallible>(service_fn(move |r| {
                let counter = counter.clone();
                async move { Ok::<_, Infallible>(service(r, &counter).await) }
            }))
        }
    });

    let (tx, rx) = oneshot::channel::<()>();

    let server = Server::bind(addr).serve(new_service);
    let local_addr = server.local_addr();
    let server = server.with_graceful_shutdown(async {
        rx.await.ok();
    });
    (local_addr, server, ShutdownHandle { tx: Some(tx) })
}

pub struct ShutdownHandle {
    tx: Option<oneshot::Sender<()>>,
}

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        if let Some(sender) = self.tx.take() {
            sender.send(());
        }
    }
}

// Where the keys are stored.
const KEYS_PATH: &str = "support/keys/";

async fn service(request: Request<Body>, counter: &AtomicUsize) -> Response<Body> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/count") => {
            Response::new(Body::from(counter.load(Ordering::Relaxed).to_string()))
        }

        (&Method::GET, key_path) => {
            let relative = Path::new(key_path).strip_prefix("/").unwrap();
            match fs::read(&Path::new(KEYS_PATH).join(&relative)) {
                Ok(content) => {
                    counter.fetch_add(1, Ordering::Relaxed);
                    Response::builder()
                        .header("Content-Type", "application/x-pem-file")
                        .body(Body::from(content))
                        .unwrap()
                }
                Err(e) => match e.kind() {
                    ErrorKind::NotFound => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty())
                        .unwrap(),
                    _ => {
                        eprintln!("Error reading file with path {:?}: {}", &key_path, e);
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::empty())
                            .unwrap()
                    }
                },
            }
        }

        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap(),
    }
}
