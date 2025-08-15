use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid tag size: {0}")]
    InvalidTagSize(usize),
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("invalid round")]
    InvalidRound,
    #[error("invalid key size: {0}")]
    InvalidKeySize(usize),
    #[error("invalid iv size: {0}")]
    InvalidIvSize(usize),
    #[error("counter overflow")]
    CounterOverflow,
    #[error("invalid input size")]
    InvalidLength,
    #[error("invalid buffer overlap")]
    InvalidBufferOverlap,
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("invalid tag")]
    AuthenticationFailed,
    #[error("invalid hash state")]
    InvalidHashState,
    #[error("invalid hash identifier")]
    InvalidHashIdentifier,
    #[error("invalid hash size")]
    StringError(String),
    #[error("invalid UTF-8 sequence")]
    Utf8Error(#[from] std::str::Utf8Error),
}

impl From<String> for CryptoError {
    fn from(err: String) -> Self {
        CryptoError::StringError(err)
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;
