use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(
    version,
    after_help = "For issues, see: https://bitbucket.org/atlassianlabs/rust-asap/issues"
)]
/// Simple and easy ASAP tokens on the commands line.
pub struct Opt {
    /// Path of the configuration file to use when generating tokens
    #[clap(long = "config", short = 'c')]
    pub config_path: Option<PathBuf>,

    /// Provide extra claims to be inserted into the token
    #[clap(long = "extra-claims", short = 'e', name = "JSON")]
    pub extra_claims_json: Option<String>,
    /// Use a custom target audience (`aud`) for the token
    #[clap(long = "audience", short = 'a')]
    pub audience: Option<String>,
    /// Use a custom issuer (`iss`) for the token
    #[clap(long = "issuer", short = 'i')]
    pub issuer: Option<String>,
    /// Use a custom key_id (`kid`) for the token
    #[clap(long = "key-id", short = 'k')]
    pub key_id: Option<String>,
    /// Use a custom private_key (as a PEM file) for the token
    #[clap(long = "private-key", short = 'p')]
    pub private_key: Option<PathBuf>,

    /// The subcommand to run
    #[clap(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Parser, PartialEq)]
pub enum SubCommand {
    /// Create a config file that may be used when generating tokens
    #[clap(name = "init")]
    Init,
    /// Generate and print an ASAP token
    #[clap(name = "token")]
    Token {
        /// Print the token as an Authorization header value
        #[clap(long = "auth-header", short = 'b')]
        auth_header: bool,
        /// Print the token as a full Authorization header
        #[clap(long = "full-header", short = 'H')]
        full_header: bool,
    },
    /// Use `curl` with an auto-injected authorization header
    #[clap(name = "curl", trailing_var_arg = true, allow_hyphen_values = true)]
    Curl { args: Vec<String> },
}
