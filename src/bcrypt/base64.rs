use crate::bcrypt::BcryptError;
use base64::{alphabet::Alphabet, engine::general_purpose::GeneralPurpose, Engine};

const BCRYPT_ALPHABET: &str = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn get_bcrypt_engine() -> GeneralPurpose {
    let alphabet = Alphabet::new(BCRYPT_ALPHABET).unwrap();
    GeneralPurpose::new(&alphabet, base64::engine::general_purpose::NO_PAD)
}

pub(super) fn base64_encode(src: &[u8]) -> Vec<u8> {
    let engine = get_bcrypt_engine();
    let encoded = engine.encode(src);
    encoded.into_bytes()
}

pub(super) fn base64_decode(src: &[u8]) -> Result<Vec<u8>, BcryptError> {
    let engine = get_bcrypt_engine();
    let src_str = std::str::from_utf8(src).map_err(|_| BcryptError::InvalidHashPrefix(0))?;

    engine
        .decode(src_str)
        .map_err(|_| BcryptError::InvalidHashPrefix(0))
}
