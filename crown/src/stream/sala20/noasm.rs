// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out must overlap entirely or not at all. Counter
// contains the raw salsa20 counter bytes (both nonce and block counter).

use crate::{error::CryptoResult, stream::sala20::sala20_ref::generic_xor_key_stream};

pub fn xor_key_stream(
    inout: &mut [u8],
    counter: &mut [u8; 16],
    key: &[u8; 32],
) -> CryptoResult<()> {
    generic_xor_key_stream(inout, counter, key);
    Ok(())
}
