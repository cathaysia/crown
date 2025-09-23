//! CounterKDF implements a KDF in Counter Mode instantiated with CMAC-AES,
//! according to NIST SP 800-108 Revision 1 Update 1, Section 4.1.
//!
//! It produces a 256-bit output, and accepts a 8-bit Label and a 96-bit Context.
//! It uses a counter of 16 bits placed before the fixed data. The fixed data is
//! the sequence Label || 0x00 || Context. The L field is omitted, since the
//! output key length is fixed.
//!
//! It's optimized for use in [XAES-256-GCM](https://c2sp.org/XAES-256-GCM),
//! rather than for exposing it to applications as a stand-alone KDF.

use super::cmac::Cmac;
use crate::block::aes::Aes;

/// CounterKDF implements a KDF in Counter Mode instantiated with CMAC-AES.
pub struct CounterKDF {
    mac: Cmac,
}

impl CounterKDF {
    /// Creates a new CounterKDF with the given AES block cipher.
    pub fn new(b: Aes) -> Self {
        CounterKDF { mac: Cmac::new(b) }
    }

    /// Derives a key from the given label and context.
    ///
    /// # Arguments
    /// * `label` - An 8-bit label
    /// * `context` - A 96-bit (12-byte) context
    ///
    /// # Returns
    /// A 256-bit (32-byte) derived key
    pub fn derive_key(&self, label: u8, context: [u8; 12]) -> [u8; 32] {
        // Note: In the original Go code, there was a call to fips140.RecordApproved()
        // which is FIPS 140 compliance related. We omit this in the Rust version.

        let mut output = [0u8; 32];
        let mut input = [0u8; Aes::BLOCK_SIZE];

        // Set up the fixed data: counter (2 bytes) || label (1 byte) || 0x00 (1 byte) || context (12 bytes)
        input[2] = label;
        // input[3] is already 0x00 from initialization
        input[4..16].copy_from_slice(&context);

        // First iteration: i = 1
        input[1] = 0x01;
        let k1 = self.mac.mac(&input);

        // Second iteration: i = 2
        input[1] = 0x02;
        let k2 = self.mac.mac(&input);

        // Combine the results
        output[..Aes::BLOCK_SIZE].copy_from_slice(&k1);
        output[Aes::BLOCK_SIZE..].copy_from_slice(&k2);

        output
    }
}
