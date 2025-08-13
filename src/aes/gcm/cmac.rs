//! CMAC implements the CMAC mode from NIST SP 800-38B.
//!
//! It is optimized for use in Counter KDF (SP 800-108r1) and
//! [XAES-256-GCM](https://c2sp.org/XAES-256-GCM), rather than
//! for exposing it to applications
//! as a stand-alone MAC.

use crate::aes::{Aes, BLOCK_SIZE};
use crate::subtle::xor::xor_bytes;
use crate::utils::copy;

/// CMAC implements the CMAC mode from NIST SP 800-38B.
pub struct Cmac {
    b: Aes,
    k1: [u8; BLOCK_SIZE],
    k2: [u8; BLOCK_SIZE],
}

impl Cmac {
    /// Creates a new CMAC instance with the given AES block cipher.
    pub fn new(b: Aes) -> Self {
        let mut cmac = Cmac {
            b,
            k1: [0; BLOCK_SIZE],
            k2: [0; BLOCK_SIZE],
        };
        cmac.derive_subkeys();
        cmac
    }

    /// Derives the subkeys k1 and k2 according to CMAC specification.
    fn derive_subkeys(&mut self) {
        // Encrypt zero block to get L
        self.k1.copy_from_slice(&[0; BLOCK_SIZE]);
        self.b.encrypt_block_internal(&mut self.k1);

        // Derive k1 from L
        let msb = shift_left(&mut self.k1);
        self.k1[BLOCK_SIZE - 1] ^= msb * 0b10000111;

        // Derive k2 from k1
        self.k2 = self.k1;
        let msb = shift_left(&mut self.k2);
        self.k2[BLOCK_SIZE - 1] ^= msb * 0b10000111;
    }

    /// Computes the CMAC for the given message.
    pub fn mac(&self, m: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut x = [0u8; BLOCK_SIZE];

        if m.is_empty() {
            // Special-cased as a single empty partial final block.
            x = self.k2;
            x[0] ^= 0b10000000;
            self.b.encrypt_block_internal(&mut x);
            return x;
        }

        let mut remaining = m;
        while remaining.len() >= BLOCK_SIZE {
            // XOR current block with accumulator
            copy(&mut x, &self.k1);
            xor_bytes(&mut x, &remaining[..BLOCK_SIZE]);

            if remaining.len() == BLOCK_SIZE {
                // Final complete block - XOR with k1
                let y = x;
                copy(&mut x, &self.k1);
                xor_bytes(&mut x, &y);
            }

            // Encrypt the result
            self.b.encrypt_block_internal(&mut x);
            remaining = &remaining[BLOCK_SIZE..];
        }

        if !remaining.is_empty() {
            // Final incomplete block
            let src = x;
            copy(&mut x, remaining);
            xor_bytes(&mut x, &src);
            copy(&mut x, &self.k2);
            xor_bytes(&mut x, &src);
            x[remaining.len()] ^= 0b10000000;
            self.b.encrypt_block_internal(&mut x);
        }

        x
    }
}

/// Shifts the given block left by one bit and returns the MSB.
/// Sets x to x << 1, and returns MSB₁(x).
fn shift_left(x: &mut [u8; BLOCK_SIZE]) -> u8 {
    let mut msb = 0u8;
    for i in (0..BLOCK_SIZE).rev() {
        let new_msb = x[i] >> 7;
        x[i] = (x[i] << 1) | msb;
        msb = new_msb;
    }
    msb
}
