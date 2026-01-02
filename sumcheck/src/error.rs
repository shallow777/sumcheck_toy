//! Error types for the sumcheck protocol

/// Errors that can occur during sumcheck verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A round check failed (g(0) + g(1) != claim)
    InvalidProof(&'static str),
    /// Transcript state mismatch
    TranscriptMismatch(&'static str),
    /// Dimension mismatch (e.g., wrong number of rounds)
    DimensionMismatch(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidProof(msg) => write!(f, "invalid proof: {}", msg),
            Error::TranscriptMismatch(msg) => write!(f, "transcript mismatch: {}", msg),
            Error::DimensionMismatch(msg) => write!(f, "dimension mismatch: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Result type for sumcheck operations
pub type Result<T> = core::result::Result<T, Error>;
