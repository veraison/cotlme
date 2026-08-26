//! Error types for the `cotlme` library.

use corim_rs::{CorimError, CotlError};

/// Top-level error type for all library operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A CoTL-specific failure from the `corim-rs` crate.
    #[error("CoTL error: {0}")]
    Cotl(#[from] CotlError),

    /// A CoRIM-specific failure from the `corim-rs` crate.
    #[error("CoRIM error: {0}")]
    Corim(#[from] CorimError),

    /// A generic failure surfaced by the `corim-rs` crate root error type.
    #[error("corim-rs error: {0}")]
    CorimRs(#[from] corim_rs::Error),

    /// An OpenSSL failure during key handling.
    #[error("openssl error: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),

    /// A generic message carrying context about the failure.
    #[error("{0}")]
    Custom(String),
}

/// Convenience [`Result`] alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Creates an [`Error::Custom`] from any displayable value.
    pub fn custom(msg: impl Into<String>) -> Self {
        Self::Custom(msg.into())
    }
}
