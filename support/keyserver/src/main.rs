#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rocket::State;
use rocket::http::ContentType;
use rocket::response::content::Content;

// Where the keys are stored.
const KEYS_PATH: &'static str = "support/keys/";

struct HitCount(AtomicUsize);

// Fetch the file at the given key path.
#[get("/<key_path..>")]
fn files(hit_count: State<HitCount>, key_path: PathBuf) -> Option<Content<File>> {
    match File::open(&Path::new(KEYS_PATH).join(&key_path)) {
        Ok(file) => {
            hit_count.0.fetch_add(1, Ordering::Relaxed);
            Some(Content(ContentType::new("application", "x-pem-file"), file))
        },
        Err(e) => {
            eprintln!("{} {:?}", e, &key_path);
            None
        }
    }
}

// Get the current hit count.
#[get("/count")]
fn count(hit_count: State<HitCount>) -> String {
    hit_count.0.load(Ordering::Relaxed).to_string()
}

// Reset the hit count.
#[get("/reset")]
fn reset(hit_count: State<HitCount>) {
    hit_count.0.store(0, Ordering::Relaxed);
}

fn main() {
    rocket::ignite()
        .mount("/", routes![count, reset, files])
        .manage(HitCount(AtomicUsize::new(0)))
        .launch();
}
