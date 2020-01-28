extern crate asap_deps_keyserver as keyserver;

#[tokio::main]
async fn main() {
    let addr = ([127, 0, 0, 1], 8000).into();
    let (local_addr, server, shutdown_handle) = keyserver::server(&addr);

    println!("Running keyserver on {}", local_addr);
    server
        .await
        .unwrap_or_else(|e| eprintln!("server error: {}", e));
    // We manually drop the shutdown handle just to document
    // that we won't want to drop it before now or the server
    // would shutdown before it even started serving
    drop(shutdown_handle);
}
