use crate::{
    aead::{Aead, AeadUser},
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
    utils::subtle::constant_time_eq,
};

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
use crate::block::aes::aesni;
use crate::block::aes::Aes;

const CCM_BLOCK_SIZE: usize = 16;
const CCM_MIN_NONCE_SIZE: usize = 7;
const CCM_MAX_NONCE_SIZE: usize = 13;

// Shared building blocks of the mode, used by both the portable driver and
// the AES-NI one (crypto/modes/ccm128.c has the same split).

/// Size of the length field `q`, `15 - nonce_size` bytes.
fn q_size(nonce_size: usize) -> usize {
    CCM_BLOCK_SIZE - 1 - nonce_size
}

fn validate_params(block_size: usize, tag_size: usize, nonce_size: usize) -> CryptoResult<()> {
    if block_size != CCM_BLOCK_SIZE {
        return Err(CryptoError::UnsupportedBlockSize(block_size));
    }

    if !(CCM_MIN_NONCE_SIZE..=CCM_MAX_NONCE_SIZE).contains(&nonce_size) {
        return Err(CryptoError::InvalidNonceSize {
            expected: "7..=13",
            actual: nonce_size,
        });
    }

    if !(4..=CCM_BLOCK_SIZE).contains(&tag_size) || !tag_size.is_multiple_of(2) {
        return Err(CryptoError::InvalidTagSize {
            expected: "4, 6, 8, 10, 12, 14, or 16",
            actual: tag_size,
        });
    }

    Ok(())
}

fn validate_nonce_and_len(
    nonce: &[u8],
    msg_len: usize,
    nonce_size: usize,
    q: usize,
) -> CryptoResult<()> {
    if nonce.len() != nonce_size {
        return Err(CryptoError::InvalidNonceSize {
            expected: "NONCE_SIZE",
            actual: nonce.len(),
        });
    }

    let max_msg_len = if q == core::mem::size_of::<u64>() {
        u64::MAX
    } else {
        (1u64 << (8 * q)) - 1
    };
    if msg_len as u64 > max_msg_len {
        return Err(CryptoError::MessageTooLarge);
    }

    Ok(())
}

fn encode_len_into(block: &mut [u8; CCM_BLOCK_SIZE], q: usize, value: u64) {
    for i in 0..q {
        block[CCM_BLOCK_SIZE - 1 - i] = (value >> (8 * i)) as u8;
    }
}

/// `B0`: the flags/`q` byte, the nonce and the message length.
fn b0_block(
    nonce: &[u8],
    msg_len: u64,
    has_aad: bool,
    tag_size: usize,
    q: usize,
) -> [u8; CCM_BLOCK_SIZE] {
    let mut block = [0u8; CCM_BLOCK_SIZE];
    block[0] = ((has_aad as u8) << 6) | ((((tag_size - 2) / 2) as u8) << 3) | (q as u8 - 1);
    block[1..1 + nonce.len()].copy_from_slice(nonce);
    encode_len_into(&mut block, q, msg_len);
    block
}

/// `A_i`: the counter block carrying `value` in its `q` trailing bytes.
fn counter_block(nonce: &[u8], value: u64, q: usize) -> [u8; CCM_BLOCK_SIZE] {
    let mut block = [0u8; CCM_BLOCK_SIZE];
    block[0] = q as u8 - 1;
    block[1..1 + nonce.len()].copy_from_slice(nonce);
    encode_len_into(&mut block, q, value);
    block
}

/// CBC-MAC accumulator: fills 16-byte blocks and hands every complete one to
/// the caller's encryption step.
struct MacBlocks<F: FnMut(&[u8; CCM_BLOCK_SIZE])> {
    block: [u8; CCM_BLOCK_SIZE],
    offset: usize,
    mac_block: F,
}

impl<F: FnMut(&[u8; CCM_BLOCK_SIZE])> MacBlocks<F> {
    fn new(mac_block: F) -> Self {
        Self {
            block: [0u8; CCM_BLOCK_SIZE],
            offset: 0,
            mac_block,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.block[self.offset] = byte;
            self.offset += 1;
            if self.offset == CCM_BLOCK_SIZE {
                (self.mac_block)(&self.block);
                self.block.fill(0);
                self.offset = 0;
            }
        }
    }

    fn finish(mut self) {
        if self.offset != 0 {
            (self.mac_block)(&self.block);
        }
    }
}

/// CBC-MAC the associated data, prefixed with its CCM length encoding.
fn mac_aad_with<F: FnMut(&[u8; CCM_BLOCK_SIZE])>(aad: &[u8], mac_block: F) {
    if aad.is_empty() {
        return;
    }

    let mut m = MacBlocks::new(mac_block);
    if aad.len() < 0xff00 {
        m.write(&(aad.len() as u16).to_be_bytes());
    } else if u32::try_from(aad.len()).is_ok() {
        m.write(&[0xff, 0xfe]);
        m.write(&(aad.len() as u32).to_be_bytes());
    } else {
        m.write(&[0xff, 0xff]);
        m.write(&(aad.len() as u64).to_be_bytes());
    }
    m.write(aad);
    m.finish();
}

/// Tag = CBC-MAC state XOR `E_K(A_0)`.
fn mask_tag_with<const TAG_SIZE: usize, F: FnMut(&mut [u8; CCM_BLOCK_SIZE])>(
    tag: &[u8; CCM_BLOCK_SIZE],
    nonce: &[u8],
    q: usize,
    mut encrypt_block: F,
) -> [u8; TAG_SIZE] {
    let mut s0 = counter_block(nonce, 0, q);
    encrypt_block(&mut s0);

    let mut result = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        result[i] = tag[i] ^ s0[i];
    }
    result
}

/// `ctr64_add` of `crypto/modes/ccm128.c`: add `inc` to the big-endian
/// 64-bit counter in the trailing bytes. `validate_nonce_and_len` keeps the
/// counter inside its `q` bytes, so this never carries into the nonce.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
fn ctr64_add(counter: &mut [u8; CCM_BLOCK_SIZE], inc: usize) {
    let mut inc = inc;
    let mut val = 0usize;
    let mut n = 8usize;
    loop {
        n -= 1;
        val += counter[8 + n] as usize + (inc & 0xff);
        counter[8 + n] = val as u8;
        val >>= 8;
        inc >>= 8;
        if n == 0 || (inc == 0 && val == 0) {
            break;
        }
    }
}

pub trait Ccm {
    fn to_ccm<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>>;
}

/// Ciphers that use the portable CCM driver. `Aes` implements [`Ccm`]
/// directly so it can reach the fused AES-NI body; every other cipher
/// reaches CCM through this marker.
pub trait CcmMarker {}
impl<T: BlockCipherMarker> CcmMarker for T {}

impl Ccm for Aes {
    fn to_ccm<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>> {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        {
            AesCcm::<TAG_SIZE, NONCE_SIZE>::new(self)
        }
        #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
        {
            CcmImpl::<Aes, TAG_SIZE, NONCE_SIZE>::new(self)
        }
    }
}

impl<T> Ccm for T
where
    T: BlockCipher + CcmMarker + 'static,
{
    fn to_ccm<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>> {
        CcmImpl::<T, TAG_SIZE, NONCE_SIZE>::new(self)
    }
}

struct CcmImpl<B: BlockCipher, const TAG_SIZE: usize, const NONCE_SIZE: usize> {
    cipher: B,
}

impl<B: BlockCipher, const TAG_SIZE: usize, const NONCE_SIZE: usize>
    CcmImpl<B, TAG_SIZE, NONCE_SIZE>
{
    fn new(cipher: B) -> CryptoResult<Self> {
        validate_params(cipher.block_size(), TAG_SIZE, NONCE_SIZE)?;
        Ok(Self { cipher })
    }

    fn q_size() -> usize {
        q_size(NONCE_SIZE)
    }

    fn validate_nonce_and_len(&self, nonce: &[u8], msg_len: usize) -> CryptoResult<()> {
        validate_nonce_and_len(nonce, msg_len, NONCE_SIZE, Self::q_size())
    }

    fn b0(nonce: &[u8], msg_len: usize, has_aad: bool) -> [u8; CCM_BLOCK_SIZE] {
        b0_block(nonce, msg_len as u64, has_aad, TAG_SIZE, Self::q_size())
    }

    fn counter(nonce: &[u8], value: usize) -> [u8; CCM_BLOCK_SIZE] {
        counter_block(nonce, value as u64, Self::q_size())
    }

    fn mac_block(&self, state: &mut [u8; CCM_BLOCK_SIZE], block: &[u8; CCM_BLOCK_SIZE]) {
        for i in 0..CCM_BLOCK_SIZE {
            state[i] ^= block[i];
        }
        self.cipher.encrypt_block(state);
    }

    fn mac_aad(&self, state: &mut [u8; CCM_BLOCK_SIZE], aad: &[u8]) {
        mac_aad_with(aad, |block| self.mac_block(state, block));
    }

    fn raw_tag(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> [u8; CCM_BLOCK_SIZE] {
        let mut state = [0u8; CCM_BLOCK_SIZE];
        let block = Self::b0(nonce, plaintext.len(), !additional_data.is_empty());
        self.mac_block(&mut state, &block);
        self.mac_aad(&mut state, additional_data);

        for chunk in plaintext.chunks(CCM_BLOCK_SIZE) {
            let mut block = [0u8; CCM_BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            self.mac_block(&mut state, &block);
        }

        state
    }

    fn apply_ctr(&self, inout: &mut [u8], nonce: &[u8]) -> CryptoResult<()> {
        let mut counter = 1usize;
        for chunk in inout.chunks_mut(CCM_BLOCK_SIZE) {
            let mut mask = Self::counter(nonce, counter);
            self.cipher.encrypt_block(&mut mask);
            for i in 0..chunk.len() {
                chunk[i] ^= mask[i];
            }
            counter = counter.checked_add(1).ok_or(CryptoError::CounterOverflow)?;
        }

        Ok(())
    }

    fn mask_tag(&self, tag: &[u8; CCM_BLOCK_SIZE], nonce: &[u8]) -> [u8; TAG_SIZE] {
        mask_tag_with(tag, nonce, Self::q_size(), |block| {
            self.cipher.encrypt_block(block)
        })
    }
}

impl<B: BlockCipher, const TAG_SIZE: usize, const NONCE_SIZE: usize> AeadUser
    for CcmImpl<B, TAG_SIZE, NONCE_SIZE>
{
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

impl<B: BlockCipher, const TAG_SIZE: usize, const NONCE_SIZE: usize> Aead<TAG_SIZE>
    for CcmImpl<B, TAG_SIZE, NONCE_SIZE>
{
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; TAG_SIZE]> {
        self.validate_nonce_and_len(nonce, inout.len())?;

        let tag = self.raw_tag(inout, nonce, additional_data);
        self.apply_ctr(inout, nonce)?;
        Ok(self.mask_tag(&tag, nonce))
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.validate_nonce_and_len(nonce, inout.len())?;
        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "TAG_SIZE",
                actual: tag.len(),
            });
        }

        self.apply_ctr(inout, nonce)?;
        let expected_tag = self.mask_tag(&self.raw_tag(inout, nonce, additional_data), nonce);
        if !constant_time_eq(&expected_tag, tag) {
            inout.fill(0);
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(())
    }
}

// ---- AES-NI fused body -------------------------------------------------

/// AES-CCM with the AES-NI fused CBC-MAC + CTR body. The driver mirrors
/// `CRYPTO_ccm128_{encrypt,decrypt}_ccm64` (`crypto/modes/ccm128.c`): the
/// assembly handles whole 16-byte blocks, the partial tail and the tag mask
/// stay here, and the counter block is advanced by `ctr64_add` because the
/// body routine does not write it back.
///
/// A CPU without AES-NI keeps the portable driver: `Aes::enc_schedule`
/// reports whether the schedule is in the AES-NI format the body needs.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
struct AesCcm<const TAG_SIZE: usize, const NONCE_SIZE: usize> {
    portable: CcmImpl<Aes, TAG_SIZE, NONCE_SIZE>,
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
impl<const TAG_SIZE: usize, const NONCE_SIZE: usize> AesCcm<TAG_SIZE, NONCE_SIZE> {
    fn new(cipher: Aes) -> CryptoResult<Self> {
        Ok(Self {
            portable: CcmImpl::new(cipher)?,
        })
    }

    fn fused_key(&self) -> Option<aesni::AesKey> {
        let (key, is_aesni) = self.portable.cipher.enc_schedule();
        if is_aesni {
            Some(key)
        } else {
            None
        }
    }

    fn seal_fused(
        &self,
        key: &aesni::AesKey,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> [u8; TAG_SIZE] {
        let q = q_size(NONCE_SIZE);

        // CBC-MAC step: XOR the block into the state and encrypt it.
        let mac = |state: &mut [u8; CCM_BLOCK_SIZE], block: &[u8; CCM_BLOCK_SIZE]| {
            for i in 0..CCM_BLOCK_SIZE {
                state[i] ^= block[i];
            }
            aesni::encrypt_block(state, key);
        };

        let mut state = [0u8; CCM_BLOCK_SIZE];
        let b0 = b0_block(
            nonce,
            inout.len() as u64,
            !additional_data.is_empty(),
            TAG_SIZE,
            q,
        );
        mac(&mut state, &b0);
        mac_aad_with(additional_data, |block| mac(&mut state, block));

        let blocks = inout.len() / CCM_BLOCK_SIZE;
        let mut counter = counter_block(nonce, 1, q);
        let (body, tail) = inout.split_at_mut(blocks * CCM_BLOCK_SIZE);
        if blocks > 0 {
            aesni::ccm64_crypt(body, blocks, key, &counter, &mut state, true);
            ctr64_add(&mut counter, blocks);
        }
        if !tail.is_empty() {
            for i in 0..tail.len() {
                state[i] ^= tail[i];
            }
            aesni::encrypt_block(&mut state, key);
            let mut mask = counter;
            aesni::encrypt_block(&mut mask, key);
            for i in 0..tail.len() {
                tail[i] ^= mask[i];
            }
        }

        mask_tag_with(&state, nonce, q, |block| aesni::encrypt_block(block, key))
    }

    fn open_fused(
        &self,
        key: &aesni::AesKey,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        let q = q_size(NONCE_SIZE);

        let mac = |state: &mut [u8; CCM_BLOCK_SIZE], block: &[u8; CCM_BLOCK_SIZE]| {
            for i in 0..CCM_BLOCK_SIZE {
                state[i] ^= block[i];
            }
            aesni::encrypt_block(state, key);
        };

        let mut state = [0u8; CCM_BLOCK_SIZE];
        let b0 = b0_block(
            nonce,
            inout.len() as u64,
            !additional_data.is_empty(),
            TAG_SIZE,
            q,
        );
        mac(&mut state, &b0);
        mac_aad_with(additional_data, |block| mac(&mut state, block));

        let blocks = inout.len() / CCM_BLOCK_SIZE;
        let mut counter = counter_block(nonce, 1, q);
        let (body, tail) = inout.split_at_mut(blocks * CCM_BLOCK_SIZE);
        if blocks > 0 {
            // The decrypt body also updates the CBC-MAC, with the *decrypted*
            // plaintext (crypto/modes/ccm128.c).
            aesni::ccm64_crypt(body, blocks, key, &counter, &mut state, false);
            ctr64_add(&mut counter, blocks);
        }
        if !tail.is_empty() {
            let mut mask = counter;
            aesni::encrypt_block(&mut mask, key);
            for i in 0..tail.len() {
                let plain = mask[i] ^ tail[i];
                tail[i] = plain;
                state[i] ^= plain;
            }
            aesni::encrypt_block(&mut state, key);
        }

        let expected: [u8; TAG_SIZE] =
            mask_tag_with(&state, nonce, q, |block| aesni::encrypt_block(block, key));
        if !constant_time_eq(&expected, tag) {
            inout.fill(0);
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(())
    }
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
impl<const TAG_SIZE: usize, const NONCE_SIZE: usize> AeadUser for AesCcm<TAG_SIZE, NONCE_SIZE> {
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
impl<const TAG_SIZE: usize, const NONCE_SIZE: usize> Aead<TAG_SIZE>
    for AesCcm<TAG_SIZE, NONCE_SIZE>
{
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; TAG_SIZE]> {
        self.portable.validate_nonce_and_len(nonce, inout.len())?;
        match self.fused_key() {
            Some(key) => Ok(self.seal_fused(&key, inout, nonce, additional_data)),
            None => self
                .portable
                .seal_in_place_separate_tag(inout, nonce, additional_data),
        }
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.portable.validate_nonce_and_len(nonce, inout.len())?;
        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "TAG_SIZE",
                actual: tag.len(),
            });
        }
        match self.fused_key() {
            Some(key) => self.open_fused(&key, inout, tag, nonce, additional_data),
            None => self
                .portable
                .open_in_place_separate_tag(inout, tag, nonce, additional_data),
        }
    }
}

#[cfg(all(test, feature = "asm", target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::block::aes::Aes;
    use alloc::vec::Vec;

    /// The fused AES-NI body must agree with the portable driver on every
    /// message length, including the empty message and the partial-block tail
    /// (on a CPU without AES-NI the fused path falls back, so this then
    /// compares the portable driver with itself).
    #[test]
    fn aesni_fused_matches_portable() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 11];
        let aad = [0x33u8; 20];

        let fused = AesCcm::<16, 11>::new(Aes::new(&key).unwrap()).unwrap();
        let portable = CcmImpl::<Aes, 16, 11>::new(Aes::new(&key).unwrap()).unwrap();

        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100] {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();

            let mut x = msg.clone();
            let mut y = msg.clone();
            let tag_fused = fused
                .seal_in_place_separate_tag(&mut x, &nonce, &aad)
                .unwrap();
            let tag_portable = portable
                .seal_in_place_separate_tag(&mut y, &nonce, &aad)
                .unwrap();
            assert_eq!(x, y, "ciphertext differs at len={len}");
            assert_eq!(tag_fused, tag_portable, "tag differs at len={len}");

            fused
                .open_in_place_separate_tag(&mut x, &tag_fused, &nonce, &aad)
                .unwrap();
            assert_eq!(x, msg, "roundtrip differs at len={len}");
        }
    }
}
