use crate::aes::gcm::GCM;
use crate::aes::Aes;
use crate::cipher::Aead;
use crate::error::CryptoResult;

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
#[cfg(feature = "std")]
pub fn seal_with_random_nonce(
    g: &GCM,
    nonce: &mut [u8],
    inout: &mut [u8],
    additional_data: &[u8],
) -> [u8; GCM_TAG_SIZE] {
    if inout.len() as u64 > (1u64 << 32) - 2 * GCM_BLOCK_SIZE as u64 {
        panic!("crypto/cipher: message too large for GCM");
    }
    if nonce.len() != GCM_STANDARD_NONCE_SIZE {
        panic!("crypto/cipher: incorrect nonce length given to GCMWithRandomNonce");
    }

    if crate::utils::inexact_overlap(inout, inout) {
        panic!("crypto/cipher: invalid buffer overlap of output and input");
    }
    if crate::utils::inexact_overlap(inout, additional_data) {
        panic!("crypto/cipher: invalid buffer overlap of output and additional data");
    }

    crate::utils::rand::fill(nonce);
    super::seal(inout, g, nonce, additional_data)
}

// NewGCMWithCounterNonce returns a new AEAD that works like GCM, but enforces
// the construction of deterministic nonces. The nonce must be 96 bits, the
// first 32 bits must be an encoding of the module name, and the last 64 bits
// must be a counter.
//
// This complies with FIPS 140-3 IG C.H Scenario 3.
pub fn new_gcm_with_counter_nonce(cipher: Aes) -> Result<GCMWithCounterNonce, &'static str> {
    let g = super::GCM::new(cipher).unwrap();
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
        inout: &mut [u8],
        nonce: &[u8],
        data: &[u8],
    ) -> CryptoResult<[u8; GCM_TAG_SIZE]> {
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

        self.g.seal_after_indicator(inout, nonce, data)
    }

    pub fn open(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> CryptoResult<()> {
        self.g.open_in_place_separate_tag(inout, nonce, data, tag)
    }
}

// NewGCMForTLS12 returns a new AEAD that works like GCM, but enforces the
// construction of nonces as specified in RFC 5288, Section 3 and RFC 9325,
// Section 7.2.1.
//
// This complies with FIPS 140-3 IG C.H Scenario 1.a.
pub fn new_gcm_for_tls12(cipher: Aes) -> CryptoResult<GCMForTLS12> {
    let g = GCM::new(cipher)?;
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
        inout: &mut [u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<[u8; GCM_BLOCK_SIZE]> {
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
        self.g.seal_after_indicator(inout, nonce, aad)
    }

    pub fn open(&self, inout: &mut [u8], nonce: &[u8], aad: &[u8], tag: &[u8]) -> CryptoResult<()> {
        self.g.open_in_place_separate_tag(inout, nonce, aad, tag)
    }
}

// NewGCMForTLS13 returns a new AEAD that works like GCM, but enforces the
// construction of nonces as specified in RFC 8446, Section 5.3.
pub fn new_gcm_for_tls13(cipher: Aes) -> CryptoResult<GCMForTLS13> {
    let g = GCM::new(cipher)?;
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
        inout: &mut [u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<[u8; GCM_TAG_SIZE]> {
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
        self.g.seal_after_indicator(inout, nonce, aad)
    }

    pub fn open(&self, inout: &mut [u8], nonce: &[u8], aad: &[u8], tag: &[u8]) -> CryptoResult<()> {
        // fips140.RecordApproved() - Not applicable in Rust implementation
        self.g.open_in_place_separate_tag(inout, nonce, aad, tag)
    }
}

// NewGCMForSSH returns a new AEAD that works like GCM, but enforces the
// construction of nonces as specified in RFC 5647.
//
// This complies with FIPS 140-3 IG C.H Scenario 1.d.
pub fn new_gcm_for_ssh(cipher: Aes) -> CryptoResult<GCMForSSH> {
    let g = GCM::new(cipher)?;
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
        inout: &mut [u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<[u8; GCM_TAG_SIZE]> {
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

        self.g.seal_after_indicator(inout, nonce, aad)
    }

    pub fn open(&self, inout: &mut [u8], nonce: &[u8], aad: &[u8], tag: &[u8]) -> CryptoResult<()> {
        self.g.open_in_place_separate_tag(inout, nonce, aad, tag)
    }
}
