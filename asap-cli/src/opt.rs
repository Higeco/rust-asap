use clap;
use std::path::PathBuf;

#[derive(StructOpt, Debug)]
#[structopt(author = "", raw(setting = "clap::AppSettings::ColoredHelp"))]
/// CLI interface for ASAP
pub struct Opt {
    /// Path of the configuration file to use when generating tokens
    #[structopt(long = "config", short = "c", parse(from_os_str))]
    pub config_path: Option<PathBuf>,

    /// Provide extra claims to be inserted into the token
    #[structopt(long = "extra-claims", short = "e", name = "JSON")]
    pub extra_claims_json: Option<String>,
    /// Use a custom target audience (`aud`) for the token
    #[structopt(long = "audience", short = "a")]
    pub audience: Option<String>,
    /// Use a custom issuer (`iss`) for the token
    #[structopt(long = "issuer", short = "i")]
    pub issuer: Option<String>,
    /// Use a custom key_id (`kid`) for the token
    #[structopt(long = "key-id", short = "k")]
    pub key_id: Option<String>,
    /// Use a custom private_key (as a PEM file) for the token
    #[structopt(long = "private-key", short = "p", parse(from_os_str))]
    pub private_key: Option<PathBuf>,

    /// The subcommand to run
    #[structopt(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(StructOpt, Debug, PartialEq)]
pub enum SubCommand {
    /// Create a config file that may be used when generating tokens
    #[structopt(name = "init", raw(setting = "clap::AppSettings::ColoredHelp"))]
    Init,
    /// Generate and print an ASAP token
    #[structopt(name = "token", raw(setting = "clap::AppSettings::ColoredHelp"))]
    Token {
        /// Print the token as an Authorization header value
        #[structopt(long = "auth-header", short = "b")]
        auth_header: bool,
        /// Print the token as a full Authorization header
        #[structopt(long = "full-header", short = "H")]
        full_header: bool,
    },
    /// Use `curl` with an auto-injected authorization header
    #[structopt(
        name = "curl",
        raw(setting = "clap::AppSettings::TrailingVarArg"),
        raw(setting = "clap::AppSettings::AllowLeadingHyphen")
    )]
    Curl { args: Vec<String> },
}
