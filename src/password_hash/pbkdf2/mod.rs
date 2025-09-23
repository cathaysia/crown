//! Module pbkdf2(Password-Based Key Derivation Function) implements the key
//! derivation function PBKDF2 as defined in RFC 2898 / PKCS #5 v2.0.
//!
//! A key derivation function is useful when encrypting data based on a password
//! or any other not-fully-random data. It uses a pseudorandom function to derive
//! a secure encryption key based on the password.
//!
//! While v2.0 of the standard defines only one pseudorandom function to use,
//! HMAC-SHA1, the drafted v2.1 specification allows use of all five FIPS Approved
//! Hash Functions SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 for HMAC. To
//! choose, you can pass the `New` functions from the different SHA packages to
//! pbkdf2.Key.

#[cfg(test)]
mod tests;

use crate::{
    core::CoreWrite,
    hash::{Hash, HashUser},
    mac::hmac::{Marshalable, HMAC},
};
use alloc::vec;
use alloc::vec::Vec;
/// Key derives a key from the password, salt and iteration count, returning a
/// []byte of length keylen that can be used as cryptographic key. The key is
/// derived based on the method described as PBKDF2 with the HMAC variant using
/// the supplied hash function.
///
/// For example, to use a HMAC-SHA-1 based PBKDF2 key derivation function, you
/// can get a derived key for e.g. AES-256 (which needs a 32-byte key) by
/// doing:
///
/// ```go
/// dk := pbkdf2.Key([]byte("some password"), salt, 4096, 32, sha1.New)
/// ```
/// Remember to get a good random salt. At least 8 bytes is recommended by the
/// RFC.
///
/// Using a higher iteration count will increase the cost of an exhaustive
/// search but will also make derivation proportionally slower.
pub fn key<const N: usize, H, F>(
    password: &[u8],
    salt: &[u8],
    iter: u32,
    key_len: usize,
    hash_fn: F,
) -> Vec<u8>
where
    H: Hash<N> + Marshalable,
    F: Fn() -> H,
{
    // Create HMAC with password as key
    let mut prf = HMAC::new(&hash_fn, password);
    let hash_len = prf.size();
    let num_blocks = key_len.div_ceil(hash_len);

    let mut buf = [0u8; 4];
    let mut dk = Vec::with_capacity(num_blocks * hash_len);
    let mut u = vec![0u8; hash_len];

    for block in 1..=num_blocks {
        // N.B.: || means concatenation, ^ means XOR
        // for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
        // U_1 = PRF(password, salt || uint(i))
        prf.reset();
        prf.write_all(salt).expect("HMAC write should not fail");

        // Convert block number to big-endian bytes
        buf[0] = (block >> 24) as u8;
        buf[1] = (block >> 16) as u8;
        buf[2] = (block >> 8) as u8;
        buf[3] = block as u8;

        prf.write_all(&buf).expect("HMAC write should not fail");
        let sum = prf.sum();
        dk.extend_from_slice(&sum);

        // Get the last hash_len bytes as T
        let t_start = dk.len() - hash_len;
        let t = &mut dk[t_start..];
        u.copy_from_slice(t);

        // U_n = PRF(password, U_(n-1))
        for _ in 2..=iter {
            prf.reset();
            prf.write_all(&u).expect("HMAC write should not fail");
            let sum = prf.sum();
            u.copy_from_slice(&sum);

            // XOR with T
            for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
                *t_byte ^= u_byte;
            }
        }
    }

    // Return only the requested key length
    dk.truncate(key_len);
    dk
}
