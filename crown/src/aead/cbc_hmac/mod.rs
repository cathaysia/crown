//! TLS `AES-CBC-HMAC-SHA1` / `AES-CBC-HMAC-SHA256` AEADs (the stitched
//! `aesni_cbc_sha{1,256}_enc` ciphers, `e_aes_cbc_hmac_sha{1,256}.c`).
//!
//! These are record-protocol constructions, not generic AEADs: the tag is
//! carried inside the CBC-encrypted region and the "nonce" is the explicit
//! IV prefix of the record body, so the API follows the EVP surface
//! (`EVP_CTRL_AEAD_TLS1_AAD`) rather than the generic [`crate::aead::Aead`]
//! trait:
//!
//! * `header` is the 13-byte TLS record header
//!   `seq(8) || type(1) || version(2) || length(2)`, where `length` is the
//!   wire record length including the explicit IV (TLS 1.1+) or the payload
//!   length (TLS 1.0). The MAC covers the header with the length field
//!   rewritten to the payload length, exactly like OpenSSL.
//! * TLS 1.1+ mode: the seal output (and the `open` input) is
//!   `explicit_iv(16) || CBC(payload || mac || padding)`; the CBC chain
//!   starts from the fixed IV carried in the key. TLS 1.0 mode omits the
//!   explicit IV entirely.
//! * Padding is TLS-style: `pad` bytes all equal to `pad - 1`, sized so the
//!   body is a multiple of 16 bytes.
//!
//! The bulk of `seal` runs through the stitched `aesni_cbc_sha1_enc` /
//! `aesni_cbc_sha256_enc` asm on x86_64 when AES-NI is available (the
//! byte-for-byte call pattern of `aesni_cbc_hmac_sha1_cipher`); every other
//! configuration uses the portable software path. The software `open`
//! verifies padding and MAC in constant time but — like OpenSSL's
//! non-stitched reference path — the HMAC computation itself runs over the
//! recovered payload length.
//!
//! Golden vectors were generated against the system OpenSSL EVP interface
//! (see `vectors.rs`).

use crate::block::aes::Aes;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::subtle::constant_time_eq;
use alloc::vec;
use alloc::vec::Vec;

#[cfg(test)]
pub mod vectors;

/// Length of the TLS record header covered by the MAC.
pub const TLS_AAD_LEN: usize = 13;
/// HMAC-SHA1 tag length.
pub const SHA1_MAC_LEN: usize = 20;
/// HMAC-SHA256 tag length.
pub const SHA256_MAC_LEN: usize = 32;

const TLS1_1_VERSION: u16 = 0x0302;

/// SHA-1 compression (FIPS 180-4). The state is carried in the wider
/// 8-word form; SHA-1 uses the first 5 words.
fn sha1_compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// SHA-256 compression (FIPS 180-4).
fn sha256_compress(h: &mut [u32; 8], block: &[u8; 64]) {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Digest selector for the two TLS CBC-HMAC variants.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Sha1,
    Sha256,
}

impl Kind {
    fn words(self) -> usize {
        match self {
            Kind::Sha1 => 5,
            Kind::Sha256 => 8,
        }
    }

    fn out(self) -> usize {
        match self {
            Kind::Sha1 => SHA1_MAC_LEN,
            Kind::Sha256 => SHA256_MAC_LEN,
        }
    }

    fn initial(self) -> [u32; 8] {
        match self {
            Kind::Sha1 => {
                let mut s = [0u32; 8];
                s[..5].copy_from_slice(&[
                    0x6745_2301,
                    0xefcd_ab89,
                    0x98ba_dcfe,
                    0x1032_5476,
                    0xc3d2_e1f0,
                ]);
                s
            }
            Kind::Sha256 => [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
        }
    }

    fn compress(self, state: &mut [u32; 8], block: &[u8; 64]) {
        match self {
            Kind::Sha1 => sha1_compress(state, block),
            Kind::Sha256 => sha256_compress(state, block),
        }
    }
}

/// Streaming SHA-1/SHA-256 with injectable midstate, enough for the
/// TLS-CBC-HMAC MAC: `head` state over `aad || payload`, then `tail` state
/// over the inner digest.
struct Sha {
    kind: Kind,
    state: [u32; 8],
    buf: [u8; 64],
    num: usize,
    total: u64,
}

impl Sha {
    fn from_state(kind: Kind, state: [u32; 8], total: u64) -> Self {
        Self {
            kind,
            state,
            buf: [0u8; 64],
            num: 0,
            total,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.num > 0 {
            let want = 64 - self.num;
            let take = want.min(data.len());
            self.buf[self.num..self.num + take].copy_from_slice(&data[..take]);
            self.num += take;
            data = &data[take..];
            if self.num == 64 {
                let block = self.buf;
                self.kind.compress(&mut self.state, &block);
                self.num = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut b = [0u8; 64];
            b.copy_from_slice(block);
            self.kind.compress(&mut self.state, &b);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.num = data.len();
        }
    }

    /// Digest so far with standard finalization. The state is consumed.
    fn finalize(mut self) -> Vec<u8> {
        let bit_len = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.num != 56 {
            self.update(&[0]);
        }
        let mut len_block = [0u8; 8];
        len_block.copy_from_slice(&bit_len.to_be_bytes());
        self.update(&len_block);
        let mut out = vec![0u8; self.kind.out()];
        for (i, w) in self.state.iter().take(self.kind.words()).enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

/// HMAC via precomputed ipad/opad midstates (the `head`/`tail` states of
/// `e_aes_cbc_hmac_sha1.c`).
struct Hmac {
    kind: Kind,
    head: [u32; 8],
    tail: [u32; 8],
}

impl Hmac {
    fn new(kind: Kind, mac_key: &[u8]) -> Self {
        // HMAC key preparation: keys longer than the block are hashed.
        let mut block = [0u8; 64];
        if mac_key.len() > 64 {
            let mut h = Sha::from_state(kind, kind.initial(), 0);
            h.update(mac_key);
            let d = h.finalize();
            block[..d.len()].copy_from_slice(&d);
        } else {
            block[..mac_key.len()].copy_from_slice(mac_key);
        }
        let mut ipad = block;
        let mut opad = block;
        for i in 0..64 {
            ipad[i] ^= 0x36;
            opad[i] ^= 0x5c;
        }
        let mut head = kind.initial();
        kind.compress(&mut head, &ipad);
        let mut tail = kind.initial();
        kind.compress(&mut tail, &opad);
        Self { kind, head, tail }
    }

    /// MAC over the TLS AAD (with its length field already rewritten) and
    /// the payload.
    fn mac(&self, aad: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut inner = Sha::from_state(self.kind, self.head, 64);
        inner.update(aad);
        inner.update(payload);
        let d = inner.finalize();
        let mut outer = Sha::from_state(self.kind, self.tail, 64);
        outer.update(&d);
        outer.finalize()
    }
}

/// TLS `AES-CBC-HMAC-SHA1` AEAD (`EVP_aes_128_cbc_hmac_sha1` and
/// `EVP_aes_256_cbc_hmac_sha1`).
pub struct CbcHmacSha1 {
    inner: CbcHmacCore,
}

/// TLS `AES-CBC-HMAC-SHA256` AEAD (`EVP_aes_128_cbc_hmac_sha256` and
/// `EVP_aes_256_cbc_hmac_sha256`).
pub struct CbcHmacSha256 {
    inner: CbcHmacCore,
}

struct CbcHmacCore {
    kind: Kind,
    aes: Aes,
    /// AES key bytes, kept for the x86_64 stitched dispatch.
    #[cfg_attr(not(all(feature = "asm", target_arch = "x86_64")), allow(dead_code))]
    key: Vec<u8>,
    fixed_iv: [u8; 16],
    hmac: Hmac,
}

impl CbcHmacCore {
    fn new(kind: Kind, key: &[u8], fixed_iv: [u8; 16], mac_key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            16 | 32 => {}
            _ => {
                return Err(CryptoError::InvalidKeySize {
                    expected: "16 or 32",
                    actual: key.len(),
                })
            }
        }
        Ok(Self {
            kind,
            aes: Aes::new(key)?,
            key: key.to_vec(),
            fixed_iv,
            hmac: Hmac::new(kind, mac_key),
        })
    }

    /// Rewrite the header length field to the payload length, as OpenSSL's
    /// `EVP_CTRL_AEAD_TLS1_AAD` does before hashing the AAD.
    fn mac_aad(&self, header: &[u8; TLS_AAD_LEN], payload_len: usize) -> [u8; TLS_AAD_LEN] {
        let mut aad = *header;
        aad[11] = (payload_len >> 8) as u8;
        aad[12] = payload_len as u8;
        aad
    }

    /// Seal a record: returns the wire body
    /// `[explicit_iv] || CBC(payload || mac || padding)`.
    pub fn seal(
        &self,
        header: &[u8; TLS_AAD_LEN],
        payload: &[u8],
        explicit_iv: Option<&[u8; 16]>,
    ) -> CryptoResult<Vec<u8>> {
        let mac_len = self.kind.out();
        let has_iv = explicit_iv.is_some();
        let reclen = payload.len() + if has_iv { 16 } else { 0 };
        // OpenSSL ctrl return: pad = ((payload + mac + 16) & !15) - payload.
        let pad = ((payload.len() + mac_len + 16) & !15) - payload.len();
        let body_len = reclen + pad;
        let pad_val = (pad - mac_len - 1) as u8;

        let mac = self.hmac.mac(&self.mac_aad(header, payload.len()), payload);

        // Input buffer laid out like the EVP caller's: [iv] || payload.
        let mut inp = vec![0u8; reclen];
        if let Some(iv) = explicit_iv {
            inp[..16].copy_from_slice(iv);
        }
        inp[reclen - payload.len()..].copy_from_slice(payload);

        let mut out = vec![0u8; body_len];
        out[..reclen].copy_from_slice(&inp);
        out[reclen..reclen + mac_len].copy_from_slice(&mac);
        for b in out[reclen + mac_len..].iter_mut() {
            *b = pad_val;
        }

        // x86_64: run the bulk through the stitched asm when available.
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        if let Some(stitched) = self.seal_stitched(header, payload, explicit_iv, &inp) {
            return Ok(stitched);
        }

        // CBC-encrypt the whole body from the fixed IV.
        self.cbc_encrypt(&mut out, &self.fixed_iv);
        Ok(out)
    }

    /// x86_64 stitched dispatch: run the bulk of the record through
    /// `aesni_cbc_sha{1,256}_enc`, mirroring the call pattern of
    /// `aesni_cbc_hmac_sha1_cipher`. Returns `None` when the runtime or
    /// compile-time preconditions are not met (the caller then uses the
    /// portable path).
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn seal_stitched(
        &self,
        header: &[u8; TLS_AAD_LEN],
        payload: &[u8],
        explicit_iv: Option<&[u8; 16]>,
        inp: &[u8],
    ) -> Option<Vec<u8>> {
        if !crate::block::aes::aesni::supported() {
            return None;
        }
        // `aesni_cbc_sha1_enc` falls back to its SSSE3 body, but the SHA-256
        // stitch traps when the CPU has no XOP/AVX/AVX2/SHA-NI body.
        if matches!(self.kind, Kind::Sha256) && !crate::aead::aesni_sha256::supported() {
            return None;
        }
        let mac_len = self.kind.out();
        let has_iv = explicit_iv.is_some();
        let iv_off = if has_iv { 16 } else { 0 };
        let plen = inp.len();

        // AAD first; the payload is then fed in 64-byte chunks that the
        // stitch overlaps with the CBC encryption.
        let mut md = Sha::from_state(self.kind, self.hmac.head, 64);
        md.update(&self.mac_aad(header, payload.len()));
        let sha_off = 64 - md.num;
        if plen <= sha_off + iv_off {
            return None;
        }
        let blocks = (plen - sha_off - iv_off) / 64;
        if blocks == 0 {
            return None;
        }
        md.update(&inp[iv_off..iv_off + sha_off]);
        let hash_start = iv_off + sha_off;

        let pad = ((payload.len() + mac_len + 16) & !15) - payload.len();
        let body_len = plen + pad;
        let pad_val = (pad - mac_len - 1) as u8;
        let aes_off = blocks * 64;

        let mut out = vec![0u8; body_len];
        let mut iv = self.fixed_iv;
        let key = crate::block::aes::aesni::set_encrypt_key(&self.key);
        match self.kind {
            Kind::Sha1 => {
                let mut st5 = [0u32; 5];
                st5.copy_from_slice(&md.state[..5]);
                crate::aead::aesni_sha1::cbc_sha1_enc(
                    &inp[..aes_off],
                    &inp[hash_start..hash_start + aes_off],
                    &mut out[..aes_off],
                    &key,
                    &mut iv,
                    &mut st5,
                );
                md.state[..5].copy_from_slice(&st5);
            }
            Kind::Sha256 => {
                crate::aead::aesni_sha256::cbc_sha256_enc(
                    &inp[..aes_off],
                    &inp[hash_start..hash_start + aes_off],
                    &mut out[..aes_off],
                    &key,
                    &mut iv,
                    &mut md.state,
                );
            }
        }
        md.total += aes_off as u64;
        md.update(&inp[hash_start + aes_off..]);

        let inner = md.finalize();
        let mut outer = Sha::from_state(self.kind, self.hmac.tail, 64);
        outer.update(&inner);
        let mac = outer.finalize();

        out[aes_off..plen].copy_from_slice(&inp[aes_off..]);
        out[plen..plen + mac_len].copy_from_slice(&mac);
        for b in out[plen + mac_len..].iter_mut() {
            *b = pad_val;
        }
        crate::block::aes::aesni::cbc_encrypt(&mut out[aes_off..], &key, &mut iv, true);
        Some(out)
    }

    /// Open a record body produced by [`CbcHmacCore::seal`]; returns the
    /// payload.
    pub fn open(&self, header: &[u8; TLS_AAD_LEN], body: &[u8]) -> CryptoResult<Vec<u8>> {
        let mac_len = self.kind.out();
        let ver = u16::from_be_bytes([header[9], header[10]]);
        let has_iv = ver >= TLS1_1_VERSION;
        let min_len = if has_iv {
            16 + mac_len + 1
        } else {
            mac_len + 1
        };
        if body.len() < min_len || !body.len().is_multiple_of(16) {
            return Err(CryptoError::AuthenticationFailed);
        }
        let mut iv = [0u8; 16];
        let (iv_src, enc) = if has_iv {
            (&body[..16], &body[16..])
        } else {
            (&self.fixed_iv[..], body)
        };
        iv.copy_from_slice(iv_src);

        let mut plain = enc.to_vec();
        self.cbc_decrypt(&mut plain, &iv);

        // Constant-time padding validation (Lucky13-style structure).
        let len = plain.len();
        let pad = plain[len - 1] as usize;
        let maxpad = len.saturating_sub(mac_len + 1).min(255);
        let pad_ok = (pad <= maxpad) as u8;
        let pad = if pad_ok == 1 { pad } else { maxpad };
        let inp_len = len.saturating_sub(mac_len + pad + 1);

        // All `pad + 1` trailing bytes must equal `pad`.
        let mut pad_diff = 0u8;
        for i in len - pad..len {
            pad_diff |= plain[i] ^ (pad as u8);
        }
        // Use a well-defined length when the padding was invalid; the MAC
        // comparison below still runs over in-bounds indices.
        let inp_len = if pad_ok == 1 { inp_len } else { 0 };

        let payload = &plain[..inp_len];
        let mac = self.hmac.mac(&self.mac_aad(header, inp_len), payload);
        let expected = &plain[inp_len..inp_len + mac_len];
        if pad_diff != 0 || !constant_time_eq(&mac, expected) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(plain[..inp_len].to_vec())
    }

    /// Portable CBC-encrypt over an exact multiple of the block size.
    fn cbc_encrypt(&self, buf: &mut [u8], iv: &[u8; 16]) {
        let mut prev = *iv;
        for chunk in buf.as_chunks_mut::<16>().0 {
            for i in 0..16 {
                chunk[i] ^= prev[i];
            }
            self.aes.encrypt_block(chunk);
            prev.copy_from_slice(chunk);
        }
    }

    /// Portable CBC-decrypt over an exact multiple of the block size.
    fn cbc_decrypt(&self, buf: &mut [u8], iv: &[u8; 16]) {
        let mut prev = *iv;
        let mut cur = [0u8; 16];
        for chunk in buf.as_chunks_mut::<16>().0 {
            cur.copy_from_slice(chunk);
            self.aes.decrypt_block(chunk);
            for i in 0..16 {
                chunk[i] ^= prev[i];
            }
            prev = cur;
        }
    }
}

impl CbcHmacSha1 {
    /// Create from the AES key (16 or 32 bytes), the fixed IV from the key
    /// block and the HMAC-SHA1 MAC key.
    pub fn new(key: &[u8], fixed_iv: [u8; 16], mac_key: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            inner: CbcHmacCore::new(Kind::Sha1, key, fixed_iv, mac_key)?,
        })
    }

    /// Seal a record; see the module docs for the wire format.
    pub fn seal(
        &self,
        header: &[u8; TLS_AAD_LEN],
        payload: &[u8],
        explicit_iv: Option<&[u8; 16]>,
    ) -> CryptoResult<Vec<u8>> {
        self.inner.seal(header, payload, explicit_iv)
    }

    /// Open a record body produced by [`CbcHmacSha1::seal`].
    pub fn open(&self, header: &[u8; TLS_AAD_LEN], body: &[u8]) -> CryptoResult<Vec<u8>> {
        self.inner.open(header, body)
    }
}

impl CbcHmacSha256 {
    /// Create from the AES key (16 or 32 bytes), the fixed IV from the key
    /// block and the HMAC-SHA256 MAC key.
    pub fn new(key: &[u8], fixed_iv: [u8; 16], mac_key: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            inner: CbcHmacCore::new(Kind::Sha256, key, fixed_iv, mac_key)?,
        })
    }

    /// Seal a record; see the module docs for the wire format.
    pub fn seal(
        &self,
        header: &[u8; TLS_AAD_LEN],
        payload: &[u8],
        explicit_iv: Option<&[u8; 16]>,
    ) -> CryptoResult<Vec<u8>> {
        self.inner.seal(header, payload, explicit_iv)
    }

    /// Open a record body produced by [`CbcHmacSha256::seal`].
    pub fn open(&self, header: &[u8; TLS_AAD_LEN], body: &[u8]) -> CryptoResult<Vec<u8>> {
        self.inner.open(header, body)
    }
}

#[cfg(test)]
mod tests {
    use super::vectors::{Vectors, VECTORS};
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn run(v: &Vectors) {
        let key = hex(v.key);
        let mac_key = hex(v.mac_key);
        let fixed_iv = hex(v.fixed_iv);
        let seq = hex(v.seq);
        let payload = hex(v.payload);
        let body = hex(v.body);
        assert_eq!(v.key256, key.len() == 32, "{} key256 flag", v.name);
        let mut header = [0u8; TLS_AAD_LEN];
        header[..8].copy_from_slice(&seq);
        header[8] = 0x16;
        header[9] = (v.version >> 8) as u8;
        header[10] = v.version as u8;
        // The seal-side header length field is the pre-MAC record length:
        // explicit IV (16) + payload for TLS 1.1+, payload for TLS 1.0.
        let has_iv = v.version >= TLS1_1_VERSION;
        let reclen = payload.len() + if has_iv { 16 } else { 0 };
        header[11] = (reclen >> 8) as u8;
        header[12] = reclen as u8;

        let mut explicit_iv = [0u8; 16];
        let eiv = if has_iv {
            explicit_iv.copy_from_slice(&fixed_iv);
            Some(&explicit_iv)
        } else {
            None
        };

        if v.sha256 {
            let c = CbcHmacSha256::new(&key, fixed_iv.try_into().unwrap(), &mac_key).unwrap();
            let got = c.seal(&header, &payload, eiv).unwrap();
            assert_eq!(got, body, "{} seal", v.name);
            let pt = c.open(&header, &body).unwrap();
            assert_eq!(pt, payload, "{} open", v.name);
        } else {
            let c = CbcHmacSha1::new(&key, fixed_iv.try_into().unwrap(), &mac_key).unwrap();
            let got = c.seal(&header, &payload, eiv).unwrap();
            assert_eq!(got, body, "{} seal", v.name);
            let pt = c.open(&header, &body).unwrap();
            assert_eq!(pt, payload, "{} open", v.name);
        }
    }

    #[test]
    fn openssl_golden_vectors() {
        for v in VECTORS {
            run(v);
        }
    }

    /// Tampering with any body byte must fail the open.
    #[test]
    fn tampered_body_rejected() {
        let fixed_iv = [0xc0u8; 16];
        let c = CbcHmacSha1::new(&[0x10u8; 16], fixed_iv, &[0xa0u8; 32]).unwrap();
        let mut header = [0u8; TLS_AAD_LEN];
        header[9] = 0x03;
        header[10] = 0x03;
        let payload = b"hello tls world";
        let reclen = payload.len() + 16;
        header[11] = (reclen >> 8) as u8;
        header[12] = reclen as u8;
        let eiv = [0x55u8; 16];
        let body = c.seal(&header, payload, Some(&eiv)).unwrap();
        assert_eq!(c.open(&header, &body).unwrap(), payload);
        for flip in [0usize, 7, 16, body.len() / 2, body.len() - 1] {
            let mut bad = body.clone();
            bad[flip] ^= 0x01;
            assert!(c.open(&header, &bad).is_err(), "flip {flip}");
        }
        // Wrong MAC key fails.
        let c2 = CbcHmacSha1::new(&[0x10u8; 16], fixed_iv, &[0xa1u8; 32]).unwrap();
        assert!(c2.open(&header, &body).is_err());
    }

    /// Every payload size in a wide range seals and opens across both
    /// digest variants and both TLS modes.
    #[test]
    fn roundtrip_all_sizes() {
        for sha256 in [false, true] {
            for has_iv in [false, true] {
                for len in [0usize, 1, 15, 16, 17, 31, 32, 63, 64, 100, 511, 512] {
                    let payload: Vec<u8> = (0..len as u8).collect();
                    let fixed_iv = [0xc0u8; 16];
                    let mut header = [0u8; TLS_AAD_LEN];
                    header[9] = 0x03;
                    header[10] = if has_iv { 0x03 } else { 0x01 };
                    let reclen = len + if has_iv { 16 } else { 0 };
                    header[11] = (reclen >> 8) as u8;
                    header[12] = reclen as u8;
                    let eiv = [0x77u8; 16];
                    let eiv = if has_iv { Some(&eiv) } else { None };
                    if sha256 {
                        let c = CbcHmacSha256::new(&[0x11u8; 32], fixed_iv, &[0xa0u8; 32]).unwrap();
                        let body = c.seal(&header, &payload, eiv).unwrap();
                        assert_eq!(c.open(&header, &body).unwrap(), payload);
                    } else {
                        let c = CbcHmacSha1::new(&[0x11u8; 16], fixed_iv, &[0xa0u8; 32]).unwrap();
                        let body = c.seal(&header, &payload, eiv).unwrap();
                        assert_eq!(c.open(&header, &body).unwrap(), payload);
                    }
                }
            }
        }
    }
}
