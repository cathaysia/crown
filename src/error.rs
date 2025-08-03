use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
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
}

pub type CryptoResult<T> = Result<T, CryptoError>;
