use thiserror::Error;

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("invalid round")]
    InvalidRound,
    #[error("invalid key size: {0}")]
    InvalidKeySize(usize),
}

pub type CipherResult<T> = Result<T, CipherError>;
