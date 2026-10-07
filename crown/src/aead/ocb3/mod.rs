#[cfg(test)]
mod tests;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
use crate::block::aes::aesni;
use crate::block::aes::Aes;
use crate::{
    aead::{Aead, AeadUser},
    block::{BlockCipher, MAX_BLOCK_SIZE},
    error::{CryptoError, CryptoResult},
};

/// One OCB block; `MAX_BLOCK_SIZE` covers every supported cipher, the active
/// prefix is `block_size()` bytes.
type Block = tinyvec::ArrayVec<[u8; MAX_BLOCK_SIZE]>;

pub trait Ocb3 {
    fn to_ocb3<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>>;
}

impl Ocb3 for Aes {
    fn to_ocb3<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>> {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        {
            AesOcb::<TAG_SIZE, NONCE_SIZE>::new(self)
        }
        #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
        {
            Ok(Ocb3Impl::<TAG_SIZE, NONCE_SIZE, Aes>::new(self))
        }
    }
}

pub trait Ocb3Marker {}

impl<T> Ocb3 for T
where
    T: BlockCipher + Ocb3Marker,
{
    fn to_ocb3<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>> {
        Ok(Ocb3Impl::<TAG_SIZE, NONCE_SIZE, _>::new(self))
    }
}

struct Ocb3Impl<const TAG_SIZE: usize, const NONCE_SIZE: usize, T: BlockCipher> {
    cipher: T,
    l_star: [u8; MAX_BLOCK_SIZE],
    l_dollar: [u8; MAX_BLOCK_SIZE],
    l: [[u8; MAX_BLOCK_SIZE]; 64],
}

impl<const TAG_SIZE: usize, const NONCE_SIZE: usize, T: BlockCipher>
    Ocb3Impl<TAG_SIZE, NONCE_SIZE, T>
{
    pub fn new(cipher: T) -> Self {
        assert!(TAG_SIZE <= cipher.block_size());
        assert!((1..cipher.block_size()).contains(&NONCE_SIZE));

        let block_size = cipher.block_size();

        let mut l_star = [0u8; MAX_BLOCK_SIZE];
        l_star[..block_size].fill(0);
        cipher.encrypt_block(&mut l_star[..block_size]);

        let mut l_dollar = [0u8; MAX_BLOCK_SIZE];
        l_dollar[..block_size].copy_from_slice(&l_star[..block_size]);
        Self::double(&mut l_dollar[..block_size]);

        let mut l = [[0u8; MAX_BLOCK_SIZE]; 64];
        let mut current = [0u8; MAX_BLOCK_SIZE];
        current[..block_size].copy_from_slice(&l_dollar[..block_size]);
        Self::double(&mut current[..block_size]);
        l[0][..block_size].copy_from_slice(&current[..block_size]);

        (1..64).for_each(|i| {
            Self::double(&mut current[..block_size]);
            l[i][..block_size].copy_from_slice(&current[..block_size]);
        });

        Self {
            cipher,
            l_star,
            l_dollar,
            l,
        }
    }

    fn double(block: &mut [u8]) {
        let mut carry = 0u8;
        for i in (0..block.len()).rev() {
            let new_carry = (block[i] & 0x80) >> 7;
            block[i] = (block[i] << 1) | carry;
            carry = new_carry;
        }
        if carry != 0 {
            block[block.len() - 1] ^= 0x87;
        }
    }

    fn ntz(n: usize) -> usize {
        if n == 0 {
            return 64;
        }
        n.trailing_zeros() as usize
    }

    fn get_l(&self, i: usize) -> &[u8] {
        let ntz = Self::ntz(i);
        if ntz < 64 {
            &self.l[ntz][..self.cipher.block_size()]
        } else {
            &self.l_star[..self.cipher.block_size()]
        }
    }

    fn xor_blocks(dst: &mut [u8], src: &[u8]) {
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
    }

    fn process_nonce(&self, nonce: &[u8]) -> tinyvec::ArrayVec<[u8; MAX_BLOCK_SIZE]> {
        let block_size = self.cipher.block_size();
        let mut nonce_formatted = new_array(block_size);
        let mut stretch = [0u8; 24];

        let nonce_len = nonce.len();

        nonce_formatted[0] = (((TAG_SIZE * 8) % 128) as u8) << 1;
        nonce_formatted[block_size - nonce_len..block_size].copy_from_slice(nonce);
        nonce_formatted[block_size - nonce_len - 1] |= 1;

        let mut ktop = nonce_formatted;
        ktop[block_size - 1] &= 0xc0;
        self.cipher.encrypt_block(&mut ktop);

        stretch[..16].copy_from_slice(&ktop[..16]);
        for i in 0..8 {
            stretch[16 + i] = ktop[i] ^ ktop[i + 1];
        }

        let bottom = nonce_formatted[block_size - 1] & 0x3f;
        let shift = bottom % 8;
        let byte_offset = (bottom / 8) as usize;

        let mut offset = new_array(block_size);

        for i in 0..block_size {
            let src_idx = byte_offset + i;
            if src_idx < 24 {
                offset[i] = stretch[src_idx];
            }
        }

        if shift > 0 {
            let mut carry = 0u8;
            for i in (0..block_size).rev() {
                let new_carry = offset[i] >> (8 - shift);
                offset[i] = (offset[i] << shift) | carry;
                carry = new_carry;
            }

            if byte_offset + block_size < 24 {
                let mask = 0xff << (8 - shift);
                offset[block_size - 1] |= (stretch[byte_offset + block_size] & mask) >> (8 - shift);
            }
        }

        offset
    }

    /// `HASH(K, A)`: fold the additional data into `sum`. AAD keeps its own
    /// offset chain, so the message offset is untouched.
    fn aad_sum(&self, additional_data: &[u8], sum: &mut Block) {
        if additional_data.is_empty() {
            return;
        }

        let block_size = self.cipher.block_size();
        let mut ad_offset = new_array(block_size);
        let ad_full_blocks = additional_data.len() / block_size;

        for i in 0..ad_full_blocks {
            let start = i * block_size;
            let end = start + block_size;
            let mut block = new_array(block_size);
            block[..block_size].copy_from_slice(&additional_data[start..end]);

            Self::xor_blocks(&mut ad_offset, self.get_l(i + 1));
            Self::xor_blocks(&mut block, &ad_offset);
            self.cipher.encrypt_block(&mut block);
            Self::xor_blocks(sum, &block);
        }

        let remaining = additional_data.len() % block_size;
        if remaining > 0 {
            Self::xor_blocks(&mut ad_offset, &self.l_star[..block_size]);
            let mut block = new_array(block_size);
            let start = ad_full_blocks * block_size;
            block[..remaining].copy_from_slice(&additional_data[start..start + remaining]);
            block[remaining] = 0x80;
            Self::xor_blocks(&mut block, &ad_offset);
            self.cipher.encrypt_block(&mut block);
            Self::xor_blocks(sum, &block);
        }
    }

    /// Portable whole-block loop: `Offset_i = Offset_{i-1} xor L_{ntz(i)}`,
    /// the checksum accumulates the plaintext, the offset is written back.
    fn portable_block_loop(
        &self,
        inout: &mut [u8],
        offset: &mut Block,
        checksum: &mut Block,
        enc: bool,
    ) {
        let block_size = self.cipher.block_size();
        let full_blocks = inout.len() / block_size;

        for i in 0..full_blocks {
            let start = i * block_size;
            let end = start + block_size;
            let block = &mut inout[start..end];

            Self::xor_blocks(offset, self.get_l(i + 1));

            if enc {
                for j in 0..block_size {
                    checksum[j] ^= block[j];
                }
            }

            Self::xor_blocks(block, offset);
            if enc {
                self.cipher.encrypt_block(block);
            } else {
                self.cipher.decrypt_block(block);
            }
            Self::xor_blocks(block, offset);

            if !enc {
                for j in 0..block_size {
                    checksum[j] ^= block[j];
                }
            }
        }
    }

    /// The trailing partial block, if any: `Offset_* = Offset_m xor L_*`,
    /// `Pad = E_K(Offset_*)`, and the checksum's `0x80` padding bit.
    fn tail(&self, inout: &mut [u8], offset: &mut Block, checksum: &mut Block, enc: bool) {
        let block_size = self.cipher.block_size();
        let full_blocks = inout.len() / block_size;
        let remaining = inout.len() % block_size;
        if remaining == 0 {
            return;
        }

        Self::xor_blocks(offset, &self.l_star[..block_size]);
        let mut pad = *offset;
        self.cipher.encrypt_block(&mut pad);

        let start = full_blocks * block_size;
        if enc {
            for i in 0..remaining {
                checksum[i] ^= inout[start + i];
                inout[start + i] ^= pad[i];
            }
        } else {
            for i in 0..remaining {
                inout[start + i] ^= pad[i];
                checksum[i] ^= inout[start + i];
            }
        }
        checksum[remaining] ^= 0x80;
    }

    /// `Tag = E_K(Checksum xor Offset_m xor L_$ ) xor HASH(K, A)`, truncated.
    fn finalize_tag(&self, checksum: &mut Block, offset: &Block, sum: &Block) -> [u8; TAG_SIZE] {
        let block_size = self.cipher.block_size();
        Self::xor_blocks(checksum, &offset[..block_size]);
        Self::xor_blocks(checksum, &self.l_dollar[..block_size]);
        self.cipher.encrypt_block(checksum);
        Self::xor_blocks(checksum, &sum[..block_size]);

        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&checksum[..TAG_SIZE]);
        tag
    }
}

impl<const TAG_SIZE: usize, const NONCE_SIZE: usize, T: BlockCipher> AeadUser
    for Ocb3Impl<TAG_SIZE, NONCE_SIZE, T>
{
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

impl<const TAG_SIZE: usize, const NONCE_SIZE: usize, T: BlockCipher> Aead<TAG_SIZE>
    for Ocb3Impl<TAG_SIZE, NONCE_SIZE, T>
{
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; TAG_SIZE]> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "NONCE_SIZE",
                actual: nonce.len(),
            });
        }

        let block_size = self.cipher.block_size();
        let mut offset = self.process_nonce(nonce);
        let mut checksum = new_array(block_size);
        let mut sum = new_array(block_size);

        self.aad_sum(additional_data, &mut sum);
        self.portable_block_loop(inout, &mut offset, &mut checksum, true);
        self.tail(inout, &mut offset, &mut checksum, true);

        Ok(self.finalize_tag(&mut checksum, &offset, &sum))
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "NONCE_SIZE",
                actual: nonce.len(),
            });
        }

        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "TAG_SIZE",
                actual: tag.len(),
            });
        }

        let block_size = self.cipher.block_size();
        let mut offset = self.process_nonce(nonce);
        let mut checksum = new_array(block_size);
        let mut sum = new_array(block_size);

        self.aad_sum(additional_data, &mut sum);
        self.portable_block_loop(inout, &mut offset, &mut checksum, false);
        self.tail(inout, &mut offset, &mut checksum, false);

        let computed_tag = self.finalize_tag(&mut checksum, &offset, &sum);
        if computed_tag.as_slice() != tag {
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(())
    }
}

fn new_array(block_size: usize) -> tinyvec::ArrayVec<[u8; MAX_BLOCK_SIZE]> {
    let mut arr = tinyvec::array_vec!([u8; MAX_BLOCK_SIZE]);
    arr.set_len(block_size);

    arr
}

// ---- AES-NI fused body -------------------------------------------------

/// AES-OCB using the fused whole-block body of `aesni-x86_64.pl`. The driver
/// mirrors `CRYPTO_ocb128_{encrypt,decrypt}` (`crypto/modes/ocb128.c`): the
/// routine walks the full blocks, the AAD, the partial block and the tag stay
/// here. A CPU without AES-NI (or a non-AES cipher, which never reaches this
/// type) keeps the portable loop.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
struct AesOcb<const TAG_SIZE: usize, const NONCE_SIZE: usize> {
    inner: Ocb3Impl<TAG_SIZE, NONCE_SIZE, Aes>,
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
impl<const TAG_SIZE: usize, const NONCE_SIZE: usize> AesOcb<TAG_SIZE, NONCE_SIZE> {
    fn new(cipher: Aes) -> CryptoResult<Self> {
        assert!(TAG_SIZE <= cipher.block_size());
        assert!((1..cipher.block_size()).contains(&NONCE_SIZE));
        Ok(Self {
            inner: Ocb3Impl::new(cipher),
        })
    }

    fn validate_nonce(&self, nonce: &[u8]) -> CryptoResult<()> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "NONCE_SIZE",
                actual: nonce.len(),
            });
        }
        Ok(())
    }

    /// The AES-NI schedule for `enc`, or `None` when the fused body is not
    /// available. OCB decryption runs the inverse cipher.
    fn fused_key(&self, enc: bool) -> Option<aesni::AesKey> {
        if !aesni::supported() {
            return None;
        }
        Some(*self.inner.cipher.bulk_schedule(enc))
    }

    /// Whole-block loop: the fused body when available, the portable loop
    /// otherwise. `Offset_i = Offset_{i-1} xor L_{ntz(i)}` for the 1-based
    /// block index, so `start_block_num` is 1.
    fn block_loop(&self, inout: &mut [u8], offset: &mut Block, checksum: &mut Block, enc: bool) {
        let block_size = self.inner.cipher.block_size();
        let full_blocks = inout.len() / block_size;
        if full_blocks == 0 {
            return;
        }

        let Some(key) = self.fused_key(enc) else {
            self.inner.portable_block_loop(inout, offset, checksum, enc);
            return;
        };

        // The assembly wants the `L_i` table at a 16-byte stride; the stored
        // table is `MAX_BLOCK_SIZE` wide so that one OCB3 type serves every
        // cipher.
        let mut l = [[0u8; 16]; 64];
        for (i, entry) in self.inner.l.iter().enumerate() {
            l[i].copy_from_slice(&entry[..16]);
        }

        let mut off = [0u8; 16];
        off.copy_from_slice(&offset[..16]);
        let mut ck = [0u8; 16];
        ck.copy_from_slice(&checksum[..16]);

        aesni::ocb_crypt(
            &mut inout[..full_blocks * 16],
            full_blocks,
            &key,
            1,
            &mut off,
            &l,
            &mut ck,
            enc,
        );

        offset[..16].copy_from_slice(&off);
        checksum[..16].copy_from_slice(&ck);
    }
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
impl<const TAG_SIZE: usize, const NONCE_SIZE: usize> AeadUser for AesOcb<TAG_SIZE, NONCE_SIZE> {
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
impl<const TAG_SIZE: usize, const NONCE_SIZE: usize> Aead<TAG_SIZE>
    for AesOcb<TAG_SIZE, NONCE_SIZE>
{
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; TAG_SIZE]> {
        self.validate_nonce(nonce)?;

        let block_size = self.inner.cipher.block_size();
        let mut offset = self.inner.process_nonce(nonce);
        let mut checksum = new_array(block_size);
        let mut sum = new_array(block_size);

        self.inner.aad_sum(additional_data, &mut sum);
        self.block_loop(inout, &mut offset, &mut checksum, true);
        self.inner.tail(inout, &mut offset, &mut checksum, true);

        Ok(self.inner.finalize_tag(&mut checksum, &offset, &sum))
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.validate_nonce(nonce)?;
        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "TAG_SIZE",
                actual: tag.len(),
            });
        }

        let block_size = self.inner.cipher.block_size();
        let mut offset = self.inner.process_nonce(nonce);
        let mut checksum = new_array(block_size);
        let mut sum = new_array(block_size);

        self.inner.aad_sum(additional_data, &mut sum);
        self.block_loop(inout, &mut offset, &mut checksum, false);
        self.inner.tail(inout, &mut offset, &mut checksum, false);

        if self
            .inner
            .finalize_tag(&mut checksum, &offset, &sum)
            .as_slice()
            != tag
        {
            inout.fill(0);
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "asm", target_arch = "x86_64"))]
mod asm_tests {
    use super::*;
    use crate::block::aes::Aes;
    use alloc::vec::Vec;

    /// The fused AES-NI body must agree with the portable loop on every
    /// message length, including the empty message and the partial-block tail.
    /// On a CPU without AES-NI both sides take the portable loop, so this
    /// then compares that with itself.
    #[test]
    fn aesni_fused_matches_portable() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let aad = [0x33u8; 24];

        let fused = AesOcb::<16, 12>::new(Aes::new(&key).unwrap()).unwrap();
        let portable = Ocb3Impl::<16, 12, Aes>::new(Aes::new(&key).unwrap());

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
