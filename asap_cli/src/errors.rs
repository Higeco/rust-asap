use anyhow::Error;
use std::result::Result as StdResult;

// A handy alias for `Result` that carries a generic error type.
pub type Result<T> = StdResult<T, Error>;
