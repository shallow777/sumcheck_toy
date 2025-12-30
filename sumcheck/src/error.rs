#[derive(Debug)]
pub enum Error {
    InvalidProof(&'static str),
    TranscriptMismatch(&'static str),
     DimensionMismatch(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;