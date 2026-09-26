//! SSH key derivation from the SSH Transport Layer Protocol exchange
//! (RFC 4253 section 7.2), ported from OpenSSL
//! `providers/implementations/kdfs/sshkdf.c`.
//!
//! K1 = HASH(K || H || X || session_id) and Ki = HASH(K || H || K(i-1)),
//! where K is the shared secret, H the exchange hash and X the character
//! selecting the purpose of the derived key.

#[cfg(test)]
mod tests;

use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::HashFactory;
use alloc::vec::Vec;

/// The purpose of the derived key, encoded as the single character `X` in
/// the KDF input (`A`–`F` per RFC 4253 / OpenSSL's SSHKDF types).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshKdfType {
    /// Initial IV client to server.
    A,
    /// Initial IV server to client.
    B,
    /// Encryption key client to server.
    C,
    /// Encryption key server to client.
    D,
    /// Integrity key client to server.
    E,
    /// Integrity key server to client.
    F,
}

impl SshKdfType {
    fn as_char(self) -> u8 {
        match self {
            SshKdfType::A => b'A',
            SshKdfType::B => b'B',
            SshKdfType::C => b'C',
            SshKdfType::D => b'D',
            SshKdfType::E => b'E',
            SshKdfType::F => b'F',
        }
    }
}

/// Derive `key_len` bytes of session key material from the shared secret,
/// exchange hash, session id and purpose.
pub fn derive(
    hash: HashFactory,
    key: &[u8],
    xcghash: &[u8],
    session_id: &[u8],
    ty: SshKdfType,
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    if key_len == 0 {
        return Err(CryptoError::InvalidLength);
    }

    let mut out = Vec::with_capacity(key_len);
    let mut h = hash()?;
    h.write(key)?;
    h.write(xcghash)?;
    h.write(&[ty.as_char()])?;
    h.write(session_id)?;
    let mut block = h.sum();
    let dsize = block.len();

    out.extend_from_slice(&block[..core::cmp::min(key_len, dsize)]);
    let mut have = out.len();
    while have < key_len {
        let mut h = hash()?;
        h.write(key)?;
        h.write(xcghash)?;
        h.write(&block)?;
        block = h.sum();

        let take = core::cmp::min(dsize, key_len - have);
        out.extend_from_slice(&block[..take]);
        have += take;
    }

    Ok(out)
}
