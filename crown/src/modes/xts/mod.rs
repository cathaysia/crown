//! XTS tweakable wide-block encryption mode (IEEE Std 1619-2007 / NIST SP
//! 800-38E), ported from OpenSSL `crypto/modes/xts128.c` and the
//! `cipher_aes_xts`/`cipher_sm4_xts` providers.
//!
//! A data unit is encrypted under two independent keys: the data key `K1`
//! (first half of the combined key) and the tweak key `K2` (second half). The
//! tweak (IV) is encrypted with `K2` and doubled in GF(2^128) after every
//! full block; a final partial block is handled with ciphertext stealing, so
//! any input of at least one full block is accepted.
//!
//! OpenSSL enforces two extra rules that are mirrored here:
//!
//! * the two key halves must differ (Rogaway 2004 / FIPS 140-2 IG A.9),
//! * a data unit holds at most 2^20 blocks (IEEE Std 1619-2018).
//!
//! SM4-XTS additionally exists in the GB/T 17964-2021 variant
//! (`encrypt_gb`/`decrypt_gb`), which only differs in the tweak doubling
//! convention (OpenSSL `crypto/modes/xts128gb.c`).

#[cfg(test)]
mod tests;

use crate::block::aes::Aes;
use crate::block::sm4::Sm4;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::subtle::constant_time_eq;

const BLOCK_SIZE: usize = 16;

/// IEEE Std 1619-2018: a data unit holds at most 2^20 blocks.
const MAX_DATA_UNIT_SIZE: usize = (1 << 20) * BLOCK_SIZE;

/// Tweak-doubling convention. `Ieee` shifts towards the most significant
/// byte with the 0x87 reduction; the SM4 `Gb` variant (GB/T 17964-2021)
/// shifts towards the least significant byte with the 0xe1 reduction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standard {
    Ieee,
    Gb,
}

/// A cipher that can be used as an XTS key: constructible from one half of
/// the combined XTS key. OpenSSL only registers AES-128/256-XTS and
/// SM4-XTS, so AES-192 halves are rejected here as well.
pub trait XtsCipher: BlockCipher + Sized {
    fn from_xts_half(key: &[u8]) -> CryptoResult<Self>;

    /// Bulk hook for the whole data unit under the IEEE tweak convention:
    /// returns true when an assembly routine processed `inout`. `key1` is the
    /// data key, `key2` the tweak key; `inout.len()` is at least one block.
    #[cfg(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    ))]
    fn bulk_data_unit(
        _key1: &Self,
        _key2: &Self,
        _iv: &[u8; BLOCK_SIZE],
        _inout: &mut [u8],
        _enc: bool,
    ) -> bool {
        false
    }
}

impl XtsCipher for Aes {
    fn from_xts_half(key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            16 | 32 => Aes::new(key),
            len => Err(CryptoError::InvalidKeySize {
                expected: "16 | 32",
                actual: len,
            }),
        }
    }

    #[cfg(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    ))]
    fn bulk_data_unit(
        key1: &Self,
        key2: &Self,
        iv: &[u8; BLOCK_SIZE],
        inout: &mut [u8],
        enc: bool,
    ) -> bool {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        {
            if !crate::block::aes::aesni::supported() {
                false
            } else {
                let k1 = key1.bulk_schedule(enc);
                let k2 = key2.bulk_schedule(true);
                if crate::block::aes::xts_avx512::xts_crypt(inout, k1, k2, iv, enc) {
                    true
                } else {
                    crate::block::aes::aesni::xts_crypt(inout, k1, k2, iv, enc);
                    true
                }
            }
        }

        #[cfg(crown_aarch64_asm)]
        {
            if !crate::block::aes::aesv8::supported() {
                false
            } else {
                let k1 = key1.bulk_schedule(enc);
                let k2 = key2.bulk_schedule(true);
                crate::block::aes::aesv8::xts_crypt(inout, k1, k2, iv, enc);
                true
            }
        }

        #[cfg(crown_riscv64_asm)]
        {
            // aes-riscv64-zvbb-zvkg-zvkned.pl covers the whole data unit,
            // ciphertext stealing included; without Zvbb+Zvkg+Zvkned the
            // portable XTS stays in charge (with the tier's block bodies).
            let k1 = key1.bulk_schedule(enc);
            let k2 = key2.bulk_schedule(true);
            crate::block::aes::riscv64::xts_crypt(inout, k1, k2, iv, enc)
        }
    }
}

impl XtsCipher for Sm4 {
    fn from_xts_half(key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            16 => Sm4::new(key),
            len => Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: len,
            }),
        }
    }
}

impl XtsCipher for crate::block::aria::Aria {
    fn from_xts_half(key: &[u8]) -> CryptoResult<Self> {
        crate::block::aria::Aria::new(key)
    }
}

impl XtsCipher for crate::block::camellia::Camellia {
    fn from_xts_half(key: &[u8]) -> CryptoResult<Self> {
        crate::block::camellia::Camellia::new(key, None)
    }
}

impl XtsCipher for crate::block::kseed::Kseed {
    fn from_xts_half(key: &[u8]) -> CryptoResult<Self> {
        crate::block::kseed::Kseed::new(key)
    }
}

/// XTS instance holding the two keyed ciphers.
pub struct Xts<C: BlockCipher> {
    k1: C,
    k2: C,
}

impl<C: XtsCipher> Xts<C> {
    /// Create an XTS instance from the combined key: the first half keys the
    /// data cipher, the second half keys the tweak cipher. The halves must
    /// differ.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let half = key.len() / 2;
        if key.len() != half * 2 {
            return Err(CryptoError::InvalidKeySize {
                expected: "even length",
                actual: key.len(),
            });
        }
        if constant_time_eq(&key[..half], &key[half..]) {
            return Err(CryptoError::StrError("xts: duplicated keys"));
        }

        Ok(Xts {
            k1: C::from_xts_half(&key[..half])?,
            k2: C::from_xts_half(&key[half..])?,
        })
    }
}

impl<C: BlockCipher> Xts<C> {
    /// Create an XTS instance from two already keyed ciphers.
    pub fn from_keys(k1: C, k2: C) -> Self {
        Xts { k1, k2 }
    }
}

impl<C: XtsCipher> Xts<C> {
    /// Encrypt `inout` in place under the given 16-byte tweak. The length
    /// must be at least one block and at most 2^20 blocks.
    pub fn encrypt(&self, tweak: &[u8], inout: &mut [u8]) -> CryptoResult<()> {
        xts_crypt(&self.k1, &self.k2, tweak, inout, true, Standard::Ieee)
    }

    /// Decrypt `inout` in place under the given 16-byte tweak.
    pub fn decrypt(&self, tweak: &[u8], inout: &mut [u8]) -> CryptoResult<()> {
        xts_crypt(&self.k1, &self.k2, tweak, inout, false, Standard::Ieee)
    }
}

impl Xts<Sm4> {
    /// SM4-XTS per GB/T 17964-2021 (OpenSSL `XTSStandard = GB`).
    pub fn encrypt_gb(&self, tweak: &[u8], inout: &mut [u8]) -> CryptoResult<()> {
        xts_crypt(&self.k1, &self.k2, tweak, inout, true, Standard::Gb)
    }

    /// SM4-XTS decryption per GB/T 17964-2021.
    pub fn decrypt_gb(&self, tweak: &[u8], inout: &mut [u8]) -> CryptoResult<()> {
        xts_crypt(&self.k1, &self.k2, tweak, inout, false, Standard::Gb)
    }
}

fn dbl(tweak: &mut [u8; BLOCK_SIZE], standard: Standard) {
    match standard {
        Standard::Ieee => {
            // Byte 0 is the least significant end: shift towards byte 15,
            // reduce with 0x87 at byte 0 (xts128.c, both endianness paths).
            let mut carry = 0u8;
            for b in tweak.iter_mut() {
                let bit = *b >> 7;
                *b = (*b << 1) | carry;
                carry = bit;
            }
            if carry != 0 {
                tweak[0] ^= 0x87;
            }
        }
        Standard::Gb => {
            // Transliteration of the little-endian branch in xts128gb.c: the
            // two byte-swapped halves shift towards each other, then the
            // halves are byte-swapped back into each other's place, and the
            // 0xe1 reduction lands on byte 15 in between.
            let u0 = u64::from_le_bytes(tweak[..8].try_into().unwrap());
            let u1 = u64::from_le_bytes(tweak[8..].try_into().unwrap());
            let hi = u0.swap_bytes();
            let lo = u1.swap_bytes();
            let res = (lo & 1) as u8;

            let a = (lo >> 1) | (hi << 63);
            let b = hi >> 1;
            let u1_mid = if res != 0 { b ^ (0xe1u64 << 56) } else { b };
            tweak[..8].copy_from_slice(&u1_mid.swap_bytes().to_le_bytes());
            tweak[8..].copy_from_slice(&a.swap_bytes().to_le_bytes());
        }
    }
}

fn xts_crypt<C: XtsCipher>(
    k1: &C,
    k2: &C,
    tweak: &[u8],
    inout: &mut [u8],
    enc: bool,
    standard: Standard,
) -> CryptoResult<()> {
    if tweak.len() != BLOCK_SIZE {
        return Err(CryptoError::InvalidIvSize(tweak.len()));
    }
    let total = inout.len();
    if total < BLOCK_SIZE {
        return Err(CryptoError::InvalidLength);
    }
    if total > MAX_DATA_UNIT_SIZE {
        return Err(CryptoError::StrError("xts: data unit is too large"));
    }

    #[cfg(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    ))]
    {
        // The assembly bodies implement the IEEE tweak doubling only.
        if standard == Standard::Ieee {
            let mut iv = [0u8; BLOCK_SIZE];
            iv.copy_from_slice(tweak);
            if C::bulk_data_unit(k1, k2, &iv, inout, enc) {
                return Ok(());
            }
        }
    }

    let mut t = [0u8; BLOCK_SIZE];
    t.copy_from_slice(tweak);
    k2.encrypt_block(&mut t);

    let mut len = total;
    if !enc && !len.is_multiple_of(BLOCK_SIZE) {
        len -= BLOCK_SIZE;
    }

    let mut scratch = [0u8; BLOCK_SIZE];
    let mut pos = 0;
    while pos + BLOCK_SIZE <= len {
        for i in 0..BLOCK_SIZE {
            scratch[i] = inout[pos + i] ^ t[i];
        }
        if enc {
            k1.encrypt_block(&mut scratch);
        } else {
            k1.decrypt_block(&mut scratch);
        }
        for i in 0..BLOCK_SIZE {
            inout[pos + i] = scratch[i] ^ t[i];
        }
        pos += BLOCK_SIZE;

        if pos == len {
            return Ok(());
        }
        dbl(&mut t, standard);
    }

    // Ciphertext stealing on the final partial block: 0 < tail < 16.
    let tail = len - pos;

    if enc {
        // The tail ciphertext is the first `tail` bytes of the last full
        // ciphertext block; those bytes are replaced by the tail plaintext
        // and the block is re-encrypted under the next tweak.
        let (full, tail_buf) = inout.split_at_mut(pos);
        let last = &mut full[pos - BLOCK_SIZE..pos];
        for i in 0..tail {
            core::mem::swap(&mut tail_buf[i], &mut last[i]);
        }
        for i in 0..BLOCK_SIZE {
            scratch[i] = last[i] ^ t[i];
        }
        k1.encrypt_block(&mut scratch);
        for i in 0..BLOCK_SIZE {
            last[i] = scratch[i] ^ t[i];
        }
    } else {
        // The last full ciphertext block is decrypted under the doubled
        // tweak, yielding the tail plaintext and the stolen ciphertext.
        let mut t1 = t;
        dbl(&mut t1, standard);

        let mut stolen = [0u8; BLOCK_SIZE];
        stolen[..tail].copy_from_slice(&inout[pos + BLOCK_SIZE..pos + BLOCK_SIZE + tail]);

        scratch.copy_from_slice(&inout[pos..pos + BLOCK_SIZE]);
        for i in 0..BLOCK_SIZE {
            scratch[i] ^= t1[i];
        }
        k1.decrypt_block(&mut scratch);
        for i in 0..BLOCK_SIZE {
            scratch[i] ^= t1[i];
        }

        for i in 0..tail {
            inout[pos + BLOCK_SIZE + i] = scratch[i];
            scratch[i] = stolen[i];
        }
        for i in 0..BLOCK_SIZE {
            scratch[i] ^= t[i];
        }
        k1.decrypt_block(&mut scratch);
        for i in 0..BLOCK_SIZE {
            inout[pos + i] = scratch[i] ^ t[i];
        }
    }

    Ok(())
}
