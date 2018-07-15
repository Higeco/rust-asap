extern crate asap;
extern crate clap;
extern crate failure;
extern crate pem;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate structopt;

mod config;
mod curl;
mod errors;
mod init;
mod opt;
mod token;

use config::Config;
use opt::{Opt, SubCommand};
use structopt::StructOpt;

fn main() -> errors::Result<()> {
    let opt = Opt::from_args();

    if opt.subcommand == SubCommand::Init {
        init::run()
    } else {
        let config = Config::from_opt(&opt);
        match opt.subcommand {
            SubCommand::Init => Ok(()),
            SubCommand::CURL { args } => curl::run(&config, args),
            SubCommand::Token {
                auth_header,
                full_header,
            } => token::run(&config, full_header, auth_header),
        }
    }
}
