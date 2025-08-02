use thiserror::Error;

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("invalid round")]
    InvalidRound,
    #[error("invalid key size")]
    InvalidKeySize,
}

pub type CipherResult<T> = Result<T, CipherError>;
