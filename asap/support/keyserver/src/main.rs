extern crate hyper;
extern crate asap_deps_keyserver as keyserver;

use hyper::rt::Future;

fn main() {
    let addr = ([127, 0, 0, 1], 8000).into();
    let (local_addr, server) = keyserver::server(&addr);

    println!("Running keyserver on {}", local_addr);
    hyper::rt::run(server.map_err(|e| eprintln!("server error: {}", e)));
}
