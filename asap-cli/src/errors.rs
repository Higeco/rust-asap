use failure::Error;

// A handy alias for `Result` that carries a generic error type.
pub type Result<T> = ::std::result::Result<T, Error>;
