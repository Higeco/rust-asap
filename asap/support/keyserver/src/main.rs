extern crate asap_deps_keyserver as keyserver;

#[tokio::main]
async fn main() {
    let addr = ([127, 0, 0, 1], 8000).into();
    let (local_addr, server) = keyserver::server(&addr);

    println!("Running keyserver on {}", local_addr);
    server
        .await
        .unwrap_or_else(|e| eprintln!("server error: {}", e));
}
