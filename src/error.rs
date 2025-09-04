use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported block size: {0}")]
    UnsupportedBlockSize(usize),
    #[error("invalid cipher")]
    MessageTooLarge,
    #[error("invalid hash size: {0}")]
    InvalidHashSize(usize),
    #[cfg(feature = "alloc")]
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("invalid round: {0}")]
    InvalidRound(usize),
    #[error("invalid nonce length: {0}")]
    InvalidNonceSize(usize),
    #[error("invalid tag size: {0}")]
    InvalidTagSize(usize),
    #[error("invalid block size: {0}")]
    InvalidBlockSize(usize),
    #[cfg(feature = "alloc")]
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("invalid parameter: {0}")]
    InvalidParameterStr(&'static str),
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
    #[cfg(feature = "alloc")]
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("invalid tag")]
    AuthenticationFailed,
    #[error("invalid hash state")]
    InvalidHashState,
    #[error("invalid hash identifier")]
    InvalidHashIdentifier,
    #[cfg(feature = "alloc")]
    #[error("invalid hash size")]
    StringError(String),
    #[error("invalid UTF-8 sequence")]
    Utf8Error(#[from] core::str::Utf8Error),
    #[error("io eof")]
    IoEof,
}

#[cfg(feature = "alloc")]
impl From<String> for CryptoError {
    fn from(err: String) -> Self {
        CryptoError::StringError(err)
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;
