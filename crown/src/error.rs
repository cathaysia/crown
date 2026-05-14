#[cfg(feature = "alloc")]
use alloc::string::String;

#[derive(Debug, PartialEq, Clone)]
pub enum CryptoError {
    InvalidHasher,

    BufferTooSmall,
    UnsupportedBlockSize(usize),
    MessageTooLarge,
    InvalidHashSize(usize),
    #[cfg(feature = "alloc")]
    UnsupportedOperation(String),
    InvalidRound(usize),
    InvalidNonceSize {
        expected: &'static str,
        actual: usize,
    },
    InvalidTagSize {
        expected: &'static str,
        actual: usize,
    },
    InvalidBlockSize(usize),
    InvalidParameterStr(&'static str),
    InvalidKeySize {
        expected: &'static str,
        actual: usize,
    },
    InvalidIvSize(usize),
    CounterOverflow,
    InvalidLength,
    InvalidBufferOverlap,
    AuthenticationFailed,
    InvalidHashState,
    InvalidHashIdentifier,
    StrError(&'static str),

    Utf8Error(core::str::Utf8Error),
    IoEof,

    MismatchedHashAndPassword,
    HashTooShort,
    HashVersionTooNew(u8),
    InvalidHashPrefix(u8),
    InvalidCost(u32),
    PasswordTooLong,

    UnpadError,
    PadError,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidHasher => write!(f, "invalid hasher"),
            CryptoError::BufferTooSmall => write!(f, "buffer too small"),
            CryptoError::UnsupportedBlockSize(size) => write!(f, "unsupported block size: {}", size),
            CryptoError::MessageTooLarge => write!(f, "invalid cipher"),
            CryptoError::InvalidHashSize(size) => write!(f, "invalid hash size: {}", size),
            #[cfg(feature = "alloc")]
            CryptoError::UnsupportedOperation(op) => write!(f, "unsupported operation: {}", op),
            CryptoError::InvalidRound(round) => write!(f, "invalid round: {}", round),
            CryptoError::InvalidNonceSize { expected, actual } => {
                write!(f, "invalid nonce length, expected {}, got {}", expected, actual)
            }
            CryptoError::InvalidTagSize { expected, actual } => {
                write!(f, "invalid tag size, expected {}, got {}", expected, actual)
            }
            CryptoError::InvalidBlockSize(size) => write!(f, "invalid block size: {}", size),
            CryptoError::InvalidParameterStr(s) => write!(f, "invalid parameter: {}", s),
            CryptoError::InvalidKeySize { expected, actual } => {
                write!(f, "invalid key size, expected: {}, got: {}", expected, actual)
            }
            CryptoError::InvalidIvSize(size) => write!(f, "invalid iv size: {}", size),
            CryptoError::CounterOverflow => write!(f, "counter overflow"),
            CryptoError::InvalidLength => write!(f, "invalid input size"),
            CryptoError::InvalidBufferOverlap => write!(f, "invalid buffer overlap"),
            CryptoError::AuthenticationFailed => write!(f, "invalid tag"),
            CryptoError::InvalidHashState => write!(f, "invalid hash state"),
            CryptoError::InvalidHashIdentifier => write!(f, "invalid hash identifier"),
            CryptoError::StrError(_) => write!(f, "invalid hash size"),
            CryptoError::Utf8Error(_) => write!(f, "invalid UTF-8 sequence"),
            CryptoError::IoEof => write!(f, "io eof"),
            CryptoError::MismatchedHashAndPassword => write!(f, "mismatched hash and password"),
            CryptoError::HashTooShort => write!(f, "hash too short"),
            CryptoError::HashVersionTooNew(v) => write!(f, "hash version too new: {}", v),
            CryptoError::InvalidHashPrefix(v) => write!(f, "invalid hash prefix: {}", v),
            CryptoError::InvalidCost(v) => write!(f, "invalid cost: {}", v),
            CryptoError::PasswordTooLong => write!(f, "password too long"),
            CryptoError::UnpadError => write!(f, "unpad error"),
            CryptoError::PadError => write!(f, "pad error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::Utf8Error(err) => Some(err),
            _ => None,
        }
    }
}

impl From<core::str::Utf8Error> for CryptoError {
    fn from(err: core::str::Utf8Error) -> Self {
        CryptoError::Utf8Error(err)
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;
