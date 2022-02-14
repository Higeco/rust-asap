extern crate asap;
extern crate clap;
extern crate directories;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate human_panic;
extern crate pem;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

mod config;
mod curl;
mod errors;
mod init;
mod opt;
mod token;

use crate::config::{Config, ConfigError};
use crate::errors::Result;
use crate::opt::{Opt, SubCommand};
use clap::Parser;

fn check_result<T>(result: Result<T>) {
    match result {
        Ok(_) => (),
        Err(err) => eprintln!("failed to run subcommand: {}", err),
    }
}

fn main() {
    // Setup `human_panic`'s error handling.
    setup_panic!();

    let opt = Opt::parse();
    if opt.subcommand == SubCommand::Init {
        check_result(init::run())
    } else {
        // Build config from arguments.
        let config = match Config::from_opt(&opt) {
            Ok(config) => config,
            Err(err) => {
                if let Some(ConfigError::NotFound(_)) = err.downcast_ref::<ConfigError>() {
                    eprintln!("No ASAP configuration found! Have you run `asap init`?");
                } else {
                    eprintln!("{:?}", err);
                }
                ::std::process::exit(1);
            }
        };

        // Run the desired subcommand.
        check_result(match opt.subcommand {
            SubCommand::Init => Ok(()),
            SubCommand::Curl { args } => curl::run(&config, args),
            SubCommand::Token {
                auth_header,
                full_header,
            } => token::run(&config, full_header, auth_header),
        });
    }
}
