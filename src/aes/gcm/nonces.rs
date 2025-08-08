use crate::aes::AesCipher;
use crate::error::CryptoResult;
use crate::{aes::gcm::GCM, utils};

// Constants
const GCM_BLOCK_SIZE: usize = 16;
const GCM_STANDARD_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;

// SealWithRandomNonce encrypts plaintext to out, and writes a random nonce to
// nonce. nonce must be 12 bytes, and out must be 16 bytes longer than plaintext.
// out and plaintext may overlap exactly or not at all. additionalData and out
// must not overlap.
//
// This complies with FIPS 140-3 IG C.H Scenario 2.
//
// Note that this is NOT a [cipher.AEAD].Seal method.
pub fn seal_with_random_nonce(
    g: &GCM,
    nonce: &mut [u8],
    out: &mut [u8],
    plaintext: &[u8],
    additional_data: &[u8],
) {
    if plaintext.len() as u64 > (1u64 << 32) - 2 * GCM_BLOCK_SIZE as u64 {
        panic!("crypto/cipher: message too large for GCM");
    }
    if nonce.len() != GCM_STANDARD_NONCE_SIZE {
        panic!("crypto/cipher: incorrect nonce length given to GCMWithRandomNonce");
    }
    if out.len() != plaintext.len() + GCM_TAG_SIZE {
        panic!("crypto/cipher: incorrect output length given to GCMWithRandomNonce");
    }
    if utils::inexact_overlap(out, plaintext) {
        panic!("crypto/cipher: invalid buffer overlap of output and input");
    }
    if utils::inexact_overlap(out, additional_data) {
        panic!("crypto/cipher: invalid buffer overlap of output and additional data");
    }

    // fips140.RecordApproved() - Not applicable in Rust implementation
    rand::fill(nonce);
    super::seal(out, g, nonce, plaintext, additional_data);
}

// NewGCMWithCounterNonce returns a new AEAD that works like GCM, but enforces
// the construction of deterministic nonces. The nonce must be 96 bits, the
// first 32 bits must be an encoding of the module name, and the last 64 bits
// must be a counter.
//
// This complies with FIPS 140-3 IG C.H Scenario 3.
pub fn new_gcm_with_counter_nonce(cipher: AesCipher) -> Result<GCMWithCounterNonce, &'static str> {
    let g = super::GCM::new_gcm(cipher, GCM_STANDARD_NONCE_SIZE, GCM_TAG_SIZE).unwrap();
    Ok(GCMWithCounterNonce {
        g,
        ready: false,
        fixed_name: 0,
        start: 0,
        next: 0,
    })
}

pub struct GCMWithCounterNonce {
    g: GCM,
    ready: bool,
    fixed_name: u32,
    start: u64,
    next: u64,
}

impl GCMWithCounterNonce {
    pub fn nonce_size(&self) -> usize {
        GCM_STANDARD_NONCE_SIZE
    }

    pub fn overhead(&self) -> usize {
        GCM_TAG_SIZE
    }

    pub fn seal(
        &mut self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != GCM_STANDARD_NONCE_SIZE {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }

        let counter = u64::from_be_bytes([
            nonce[nonce.len() - 8],
            nonce[nonce.len() - 7],
            nonce[nonce.len() - 6],
            nonce[nonce.len() - 5],
            nonce[nonce.len() - 4],
            nonce[nonce.len() - 3],
            nonce[nonce.len() - 2],
            nonce[nonce.len() - 1],
        ]);

        if !self.ready {
            // The first invocation sets the fixed name encoding and start counter.
            self.ready = true;
            self.start = counter;
            self.fixed_name = u32::from_be_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        }

        if self.fixed_name != u32::from_be_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]) {
            panic!("crypto/cipher: incorrect module name given to GCMWithCounterNonce");
        }

        let counter = counter - self.start;

        // Ensure the counter is monotonically increasing.
        if counter == u64::MAX {
            panic!("crypto/cipher: counter wrapped");
        }
        if counter < self.next {
            panic!("crypto/cipher: counter decreased");
        }
        self.next = counter + 1;

        self.g
            .seal_after_indicator(dst, nonce, plaintext, data)
            .unwrap();
        Ok(())
    }

    pub fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        // fips140.RecordApproved() - Not applicable in Rust implementation
        self.g.open(dst, nonce, ciphertext, data)
    }
}

// NewGCMForTLS12 returns a new AEAD that works like GCM, but enforces the
// construction of nonces as specified in RFC 5288, Section 3 and RFC 9325,
// Section 7.2.1.
//
// This complies with FIPS 140-3 IG C.H Scenario 1.a.
pub fn new_gcm_for_tls12(cipher: AesCipher) -> CryptoResult<GCMForTLS12> {
    let g = GCM::new_gcm(cipher, GCM_STANDARD_NONCE_SIZE, GCM_TAG_SIZE)?;
    Ok(GCMForTLS12 { g, next: 0 })
}

pub struct GCMForTLS12 {
    g: GCM,
    next: u64,
}

impl GCMForTLS12 {
    pub fn nonce_size(&self) -> usize {
        GCM_STANDARD_NONCE_SIZE
    }

    pub fn overhead(&self) -> usize {
        GCM_TAG_SIZE
    }

    pub fn seal(
        &mut self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != GCM_STANDARD_NONCE_SIZE {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }

        let counter = u64::from_be_bytes([
            nonce[nonce.len() - 8],
            nonce[nonce.len() - 7],
            nonce[nonce.len() - 6],
            nonce[nonce.len() - 5],
            nonce[nonce.len() - 4],
            nonce[nonce.len() - 3],
            nonce[nonce.len() - 2],
            nonce[nonce.len() - 1],
        ]);

        // Ensure the counter is monotonically increasing.
        if counter == u64::MAX {
            panic!("crypto/cipher: counter wrapped");
        }
        if counter < self.next {
            panic!("crypto/cipher: counter decreased");
        }
        self.next = counter + 1;

        // fips140.RecordApproved() - Not applicable in Rust implementation
        self.g.seal_after_indicator(dst, nonce, plaintext, data)
    }

    pub fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        // fips140.RecordApproved() - Not applicable in Rust implementation
        self.g.open(dst, nonce, ciphertext, data)
    }
}

// NewGCMForTLS13 returns a new AEAD that works like GCM, but enforces the
// construction of nonces as specified in RFC 8446, Section 5.3.
pub fn new_gcm_for_tls13(cipher: AesCipher) -> CryptoResult<GCMForTLS13> {
    let g = GCM::new_gcm(cipher, GCM_STANDARD_NONCE_SIZE, GCM_TAG_SIZE)?;
    Ok(GCMForTLS13 {
        g,
        ready: false,
        mask: 0,
        next: 0,
    })
}

pub struct GCMForTLS13 {
    g: GCM,
    ready: bool,
    mask: u64,
    next: u64,
}

impl GCMForTLS13 {
    pub fn nonce_size(&self) -> usize {
        GCM_STANDARD_NONCE_SIZE
    }

    pub fn overhead(&self) -> usize {
        GCM_TAG_SIZE
    }

    pub fn seal(
        &mut self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != GCM_STANDARD_NONCE_SIZE {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }

        let mut counter = u64::from_be_bytes([
            nonce[nonce.len() - 8],
            nonce[nonce.len() - 7],
            nonce[nonce.len() - 6],
            nonce[nonce.len() - 5],
            nonce[nonce.len() - 4],
            nonce[nonce.len() - 3],
            nonce[nonce.len() - 2],
            nonce[nonce.len() - 1],
        ]);

        if !self.ready {
            // In the first call, the counter is zero, so we learn the XOR mask.
            self.ready = true;
            self.mask = counter;
        }
        counter ^= self.mask;

        // Ensure the counter is monotonically increasing.
        if counter == u64::MAX {
            panic!("crypto/cipher: counter wrapped");
        }
        if counter < self.next {
            panic!("crypto/cipher: counter decreased");
        }
        self.next = counter + 1;

        // fips140.RecordApproved() - Not applicable in Rust implementation
        self.g.seal_after_indicator(dst, nonce, plaintext, data)
    }

    pub fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        // fips140.RecordApproved() - Not applicable in Rust implementation
        self.g.open(dst, nonce, ciphertext, data)
    }
}

// NewGCMForSSH returns a new AEAD that works like GCM, but enforces the
// construction of nonces as specified in RFC 5647.
//
// This complies with FIPS 140-3 IG C.H Scenario 1.d.
pub fn new_gcm_for_ssh(cipher: AesCipher) -> CryptoResult<GCMForSSH> {
    let g = GCM::new_gcm(cipher, GCM_STANDARD_NONCE_SIZE, GCM_TAG_SIZE)?;
    Ok(GCMForSSH {
        g,
        ready: false,
        start: 0,
        next: 0,
    })
}

pub struct GCMForSSH {
    g: GCM,
    ready: bool,
    start: u64,
    next: u64,
}

impl GCMForSSH {
    pub fn nonce_size(&self) -> usize {
        GCM_STANDARD_NONCE_SIZE
    }

    pub fn overhead(&self) -> usize {
        GCM_TAG_SIZE
    }

    pub fn seal(
        &mut self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != GCM_STANDARD_NONCE_SIZE {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }

        let counter = u64::from_be_bytes([
            nonce[nonce.len() - 8],
            nonce[nonce.len() - 7],
            nonce[nonce.len() - 6],
            nonce[nonce.len() - 5],
            nonce[nonce.len() - 4],
            nonce[nonce.len() - 3],
            nonce[nonce.len() - 2],
            nonce[nonce.len() - 1],
        ]);

        if !self.ready {
            // In the first call we learn the start value.
            self.ready = true;
            self.start = counter;
        }
        let counter = counter - self.start;

        // Ensure the counter is monotonically increasing.
        if counter == u64::MAX {
            panic!("crypto/cipher: counter wrapped");
        }
        if counter < self.next {
            panic!("crypto/cipher: counter decreased");
        }
        self.next = counter + 1;

        // fips140.RecordApproved() - Not applicable in Rust implementation
        self.g.seal_after_indicator(dst, nonce, plaintext, data)
    }

    pub fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        // fips140.RecordApproved() - Not applicable in Rust implementation
        self.g.open(dst, nonce, ciphertext, data)
    }
}
