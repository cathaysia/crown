#[cfg(feature = "alloc")]
use alloc::string::String;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Clone)]
pub enum CryptoError {
    #[error("invalid hasher")]
    InvalidHasher,

    #[error("buffer too small")]
    BufferTooSmall,
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
    #[error("invalid nonce length, expected {expected}, got {actual}")]
    InvalidNonceSize {
        expected: &'static str,
        actual: usize,
    },
    #[error("invalid tag size, expected {expected}, got {actual}")]
    InvalidTagSize {
        expected: &'static str,
        actual: usize,
    },
    #[error("invalid block size: {0}")]
    InvalidBlockSize(usize),
    #[error("invalid parameter: {0}")]
    InvalidParameterStr(&'static str),
    #[error("invalid key size, expected: {expected}, got: {actual}")]
    InvalidKeySize {
        expected: &'static str,
        actual: usize,
    },
    #[error("invalid iv size: {0}")]
    InvalidIvSize(usize),
    #[error("counter overflow")]
    CounterOverflow,
    #[error("invalid input size")]
    InvalidLength,
    #[error("invalid tag")]
    AuthenticationFailed,
    #[error("invalid hash state")]
    InvalidHashState,
    #[error("invalid hash identifier")]
    InvalidHashIdentifier,
    #[error("invalid hash size")]
    StrError(&'static str),

    #[error("invalid UTF-8 sequence")]
    Utf8Error(#[from] core::str::Utf8Error),
    #[error("io eof")]
    IoEof,

    #[error("mismatched hash and password")]
    MismatchedHashAndPassword,
    #[error("hash too short")]
    HashTooShort,
    #[error("hash version too new: {0}")]
    HashVersionTooNew(u8),
    #[error("invalid hash prefix: {0}")]
    InvalidHashPrefix(u8),
    #[error("invalid cost: {0}")]
    InvalidCost(u32),
    #[error("password too long")]
    PasswordTooLong,

    #[error("unpad error")]
    UnpadError,
    #[error("pad error")]
    PadError,
}

pub type CryptoResult<T> = Result<T, CryptoError>;
