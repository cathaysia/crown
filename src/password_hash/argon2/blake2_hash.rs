use crate::core::CoreWrite;
use crate::error::CryptoResult;
use crate::hash::blake2b::{Blake2bVariable, SIZE as BLAKE2B_SIZE};
use crate::hash::{HashUser, HashVariable};
use crate::utils::copy;

/// blake2b_hash computes an arbitrary long hash value of input
/// and writes the hash to output.
pub fn blake2b_hash(mut out: &mut [u8], input: &[u8]) -> CryptoResult<()> {
    let out_len = out.len();
    let hash_len = out_len.min(BLAKE2B_SIZE);

    // Create blake2b hasher based on output length
    let mut hasher = Blake2bVariable::new(None, hash_len)?;

    // Write output length as little-endian u32 to buffer
    let mut buffer = [0u8; BLAKE2B_SIZE];
    let out_len_bytes = (out_len as u32).to_le_bytes();
    buffer[..4].copy_from_slice(&out_len_bytes);

    // Hash the length prefix and input
    hasher
        .write_all(&buffer[..4])
        .map_err(|_| crate::error::CryptoError::InvalidParameterStr("write failed"))?;
    hasher
        .write_all(input)
        .map_err(|_| crate::error::CryptoError::InvalidParameterStr("write failed"))?;

    // If output fits in one blake2b hash, we're done
    if out_len <= BLAKE2B_SIZE {
        let hash = hasher.sum_vec();
        out.copy_from_slice(&hash[..out_len]);
        return Ok(());
    }

    hasher.sum(&mut buffer);
    hasher.reset();
    copy(out, &buffer[..32]);

    out = &mut out[32..];

    // Continue hashing for remaining output
    while out.len() > BLAKE2B_SIZE {
        hasher
            .write_all(&buffer)
            .map_err(|_| crate::error::CryptoError::InvalidParameterStr("write failed"))?;
        hasher.sum(&mut buffer);
        copy(out, &buffer[..32]);
        out = &mut out[32..];
        hasher.reset();
    }

    // Handle final partial block if needed
    if out_len % BLAKE2B_SIZE > 0 {
        let r = ((out_len + 31) / 32) - 2; // ⌈τ /32⌉-2
        let final_size = out_len - 32 * r;
        hasher = Blake2bVariable::new(None, final_size)?;
    }

    hasher
        .write_all(&buffer)
        .map_err(|_| crate::error::CryptoError::InvalidParameterStr("write failed"))?;
    hasher.sum(out);

    Ok(())
}
