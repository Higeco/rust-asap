extern crate hyper;
extern crate reqwest;
extern crate tokio_threadpool;

use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hyper::rt::Future;
use hyper::service::service_fn_ok;
use hyper::{Body, Error, Method, Request, Response, Server, StatusCode};
use tokio_threadpool::ThreadPool;

/// Keyserver that can be used for testing. Shuts down when dropped.
pub struct Keyserver {
    url: String,
    // As long as the ThreadPool is alive, the server is running.
    // Dropping it shuts down the server.
    _thread_pool: ThreadPool,
}

impl Keyserver {
    pub fn start() -> Keyserver {
        // 0 means random port
        Keyserver::start_on_port(0)
    }

    pub fn start_on_port(port: u16) -> Keyserver {
        let addr = ([127, 0, 0, 1], port).into();
        let thread_pool = ThreadPool::new();
        let (bound_addr, server) = server(&addr);
        thread_pool.spawn(server.map_err(|e| eprintln!("server error: {}", e)));
        let url = format!("http://localhost:{}/", bound_addr.port());
        Keyserver {
            url,
            _thread_pool: thread_pool,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn count(&self) -> String {
        reqwest::get(&format!("{}count", self.url()))
            .unwrap()
            .text()
            .unwrap()
    }
}

pub fn server(addr: &SocketAddr) -> (SocketAddr, impl Future<Item = (), Error = Error>) {
    let counter = Arc::new(AtomicUsize::new(0));

    let new_service = move || {
        let counter = counter.clone();
        service_fn_ok(move |r| service(r, &counter))
    };

    let server = Server::bind(addr).serve(new_service);
    let local_addr = server.local_addr();
    (local_addr, server)
}

// Where the keys are stored.
const KEYS_PATH: &'static str = "support/keys/";

fn service(request: Request<Body>, counter: &Arc<AtomicUsize>) -> Response<Body> {
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
