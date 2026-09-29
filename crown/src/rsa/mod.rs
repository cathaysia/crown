//! RSA (RFC 8017), ported from OpenSSL `crypto/rsa` (`rsa_ossl.c`,
//! `rsa_pkcs1.c`, `rsa_pss.c`, `rsa_oaep.c`, `rsa_gen.c`) on top of the
//! [`crate::bn`] big-number layer.
//!
//! Supported operations, all software only:
//!
//! * raw encrypt/decrypt (modular exponentiation; the private path uses
//!   the Chinese Remainder Theorem when CRT parameters are present),
//! * PKCS#1 v1.5 and OAEP encryption,
//! * PKCS#1 v1.5 and PSS signatures (PSS salt length is explicit),
//! * key generation (OpenSSL-style: top-two-bits-set primes, trial
//!   division by small primes, 64 Miller-Rabin rounds for <= 2048-bit
//!   primes, FIPS 186-4 |p - q| distance, d = e^-1 mod (p-1)(q-1)).
//!
//! Randomness is injected: every operation that needs fresh bytes takes an
//! [`Rng`] argument, keeping the crate free of a built-in entropy source.

pub mod der;
mod prime;
#[cfg(test)]
mod tests;

use crate::bn::Bn;
use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::HashUser;
use crate::kdf::HashFactory;
use alloc::vec::Vec;

pub use crate::rng::Rng;

impl Rng for dyn FnMut(&mut [u8]) + '_ {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self(out);
    }
}

fn digest(hash: HashFactory, parts: &[&[u8]]) -> CryptoResult<Vec<u8>> {
    let mut h = hash()?;
    for part in parts {
        h.write_all(part)?;
    }
    Ok(h.sum())
}

/// RSA public key: modulus and public exponent.
#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    n: Bn,
    e: Bn,
}

/// RSA private key with optional CRT parameters.
#[derive(Clone, Debug)]
pub struct RsaPrivateKey {
    public: RsaPublicKey,
    d: Bn,
    p: Option<Bn>,
    q: Option<Bn>,
    dp: Option<Bn>,
    dq: Option<Bn>,
    qinv: Option<Bn>,
}

impl RsaPublicKey {
    /// Build from big-endian component bytes.
    pub fn from_components(n: &[u8], e: &[u8]) -> CryptoResult<Self> {
        let n = Bn::from_be_bytes(n);
        let e = Bn::from_be_bytes(e);
        if n.is_zero() || e.is_zero() {
            return Err(CryptoError::StrError("rsa: zero modulus or exponent"));
        }
        Ok(RsaPublicKey { n, e })
    }

    /// The modulus size in bytes.
    pub fn size(&self) -> usize {
        self.n.byte_len()
    }

    pub fn n(&self) -> Vec<u8> {
        self.n.to_be_bytes()
    }

    pub fn e(&self) -> Vec<u8> {
        self.e.to_be_bytes()
    }

    /// Raw RSA primitive: `m^e mod n`. `m` is big-endian and must be
    /// shorter than the modulus.
    pub fn encrypt_raw(&self, m: &[u8]) -> CryptoResult<Vec<u8>> {
        let m_bn = Bn::from_be_bytes(m);
        if !m_bn.lt(&self.n) {
            return Err(CryptoError::StrError("rsa: value out of range"));
        }
        let c = m_bn.mod_pow(&self.e, &self.n)?;
        c.to_be_bytes_padded(self.size())
    }

    /// PKCS#1 v1.5 encryption (EME-PKCS1-v1_5).
    pub fn encrypt_pkcs1v15(&self, rng: &mut impl Rng, msg: &[u8]) -> CryptoResult<Vec<u8>> {
        let em = eme_pkcs1_encode(rng, msg, self.size())?;
        self.encrypt_raw(&em)
    }

    /// OAEP encryption (EME-OAEP with the given hash and empty label).
    pub fn encrypt_oaep(
        &self,
        hash: HashFactory,
        rng: &mut impl Rng,
        msg: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let em = eme_oaep_encode(hash, rng, msg, self.size(), &[])?;
        self.encrypt_raw(&em)
    }

    /// Verify a PKCS#1 v1.5 signature over `msg`.
    pub fn verify_pkcs1v15(&self, hash: HashFactory, msg: &[u8], sig: &[u8]) -> CryptoResult<bool> {
        let em = self.recover(sig)?;
        let expected = emsa_pkcs1_encode(hash, msg, em.len())?;
        Ok(constant_time_eq(&em, &expected))
    }

    /// Verify a PSS signature over `msg` with the given salt length.
    pub fn verify_pss(
        &self,
        hash: HashFactory,
        msg: &[u8],
        sig: &[u8],
        salt_len: usize,
    ) -> CryptoResult<bool> {
        let em = self.recover(sig)?;
        let em_bits = self.n.bit_len() - 1;
        emsa_pss_verify(hash, msg, &em, em_bits, salt_len)
    }

    /// Apply the public exponent to `sig` and left-pad to the modulus
    /// size.
    fn recover(&self, sig: &[u8]) -> CryptoResult<Vec<u8>> {
        if sig.len() != self.size() {
            return Err(CryptoError::StrError("rsa: signature length mismatch"));
        }
        let s_bn = Bn::from_be_bytes(sig);
        if !s_bn.lt(&self.n) {
            return Err(CryptoError::StrError("rsa: signature out of range"));
        }
        let m = s_bn.mod_pow(&self.e, &self.n)?;
        m.to_be_bytes_padded(self.size())
    }
}

impl RsaPrivateKey {
    /// Build from big-endian component bytes. CRT parameters (`p`, `q`,
    /// `dmp1`, `dmq1`, `iqmp`) are optional; without them the private
    /// operation uses `d` directly.
    #[allow(clippy::too_many_arguments)]
    pub fn from_components(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: Option<&[u8]>,
        q: Option<&[u8]>,
        dp: Option<&[u8]>,
        dq: Option<&[u8]>,
        qinv: Option<&[u8]>,
    ) -> CryptoResult<Self> {
        let public = RsaPublicKey::from_components(n, e)?;
        let d = Bn::from_be_bytes(d);
        if d.is_zero() {
            return Err(CryptoError::StrError("rsa: zero private exponent"));
        }
        let opt = |v: Option<&[u8]>| v.map(Bn::from_be_bytes);
        Ok(RsaPrivateKey {
            public,
            d,
            p: opt(p),
            q: opt(q),
            dp: opt(dp),
            dq: opt(dq),
            qinv: opt(qinv),
        })
    }

    pub fn public(&self) -> &RsaPublicKey {
        &self.public
    }

    /// Generate a `bits`-bit key pair with public exponent `e`
    /// (OpenSSL-style prime generation; see [`prime`]).
    pub fn generate(bits: usize, e: u64, rng: &mut impl Rng) -> CryptoResult<Self> {
        if bits < 512 || !bits.is_multiple_of(2) {
            return Err(CryptoError::StrError(
                "rsa: key size must be an even number >= 512",
            ));
        }
        if e < 3 || e.is_multiple_of(2) {
            return Err(CryptoError::StrError("rsa: exponent must be odd and >= 3"));
        }

        let half = bits / 2;
        let e_bn = Bn::from_u64(e);

        let p = prime::generate_prime(half, e, rng)?;
        // FIPS 186-4 B.3.3: |p - q| must be large.
        let q = loop {
            let q = prime::generate_prime(half, e, rng)?;
            let (lo, hi) = if p.lt(&q) { (&p, &q) } else { (&q, &p) };
            let diff = hi.sub(lo)?;
            if diff.bit_len() >= half - 100 {
                break q;
            }
        };

        // Keep p > q like OpenSSL's key generator.
        let (p, q) = if p.lt(&q) { (q, p) } else { (p, q) };

        let n = p.mul(&q);
        let p1 = p.sub(&Bn::one())?;
        let q1 = q.sub(&Bn::one())?;
        let phi = p1.mul(&q1);
        let d = e_bn.mod_inverse(&phi)?;
        let dp = d.modulus(&p1);
        let dq = d.modulus(&q1);
        let qinv = q.mod_inverse(&p)?;

        Ok(RsaPrivateKey {
            public: RsaPublicKey { n, e: e_bn },
            d,
            p: Some(p),
            q: Some(q),
            dp: Some(dp),
            dq: Some(dq),
            qinv: Some(qinv),
        })
    }

    /// Raw RSA private primitive. Uses CRT when the factors are present
    /// (mirroring `rsa_ossl_private_encrypt`'s CRT path), otherwise `d`.
    pub fn decrypt_raw(&self, c: &[u8]) -> CryptoResult<Vec<u8>> {
        let k = self.public.size();
        if c.len() != k {
            return Err(CryptoError::StrError("rsa: ciphertext length mismatch"));
        }
        let c_bn = Bn::from_be_bytes(c);
        if !c_bn.lt(&self.public.n) {
            return Err(CryptoError::StrError("rsa: ciphertext out of range"));
        }

        let m = match (&self.p, &self.q, &self.dp, &self.dq, &self.qinv) {
            (Some(p), Some(q), Some(dp), Some(dq), Some(qinv)) => {
                let m1 = c_bn.modulus(p).mod_pow_odd_consttime(dp, p)?;
                let m2 = c_bn.modulus(q).mod_pow_odd_consttime(dq, q)?;
                // h = qinv * (m1 - m2) mod p; add p to stay positive.
                let diff = if m1.lt(&m2) {
                    let t = m2.sub(&m1)?;
                    p.sub(&t)?
                } else {
                    m1.sub(&m2)?
                };
                let h = qinv.mul(&diff).modulus(p);
                m2.add(&h.mul(q))
            }
            _ => c_bn.mod_pow_odd_consttime(&self.d, &self.public.n)?,
        };
        m.to_be_bytes_padded(k)
    }

    /// PKCS#1 v1.5 decryption.
    pub fn decrypt_pkcs1v15(&self, ct: &[u8]) -> CryptoResult<Vec<u8>> {
        let em = self.decrypt_raw(ct)?;
        eme_pkcs1_decode(&em)
    }

    /// OAEP decryption with the given hash and empty label.
    pub fn decrypt_oaep(&self, hash: HashFactory, ct: &[u8]) -> CryptoResult<Vec<u8>> {
        let em = self.decrypt_raw(ct)?;
        eme_oaep_decode(hash, &em, &[])
    }

    /// PKCS#1 v1.5 signature over `msg` (EMSA-PKCS1-v1_5).
    pub fn sign_pkcs1v15(&self, hash: HashFactory, msg: &[u8]) -> CryptoResult<Vec<u8>> {
        let em = emsa_pkcs1_encode(hash, msg, self.public.size())?;
        self.decrypt_raw(&em)
    }

    /// PSS signature over `msg` with the given salt length.
    pub fn sign_pss(
        &self,
        hash: HashFactory,
        msg: &[u8],
        salt_len: usize,
        rng: &mut impl Rng,
    ) -> CryptoResult<Vec<u8>> {
        let em_bits = self.public.n.bit_len() - 1;
        let em = emsa_pss_encode(hash, msg, em_bits, salt_len, rng)?;
        self.decrypt_raw(&em)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// MGF1 and the PKCS#1 padding encodings (rsa_pkcs1.c / rsa_pss.c /
// rsa_oaep.c).

/// MGF1 mask generation (RFC 8017 appendix B.2.1).
fn mgf1(hash: HashFactory, seed: &[u8], mask_len: usize) -> CryptoResult<Vec<u8>> {
    let h_len = hash()?.size();
    let mut out = Vec::with_capacity(mask_len);
    let mut counter = 0u32;
    while out.len() < mask_len {
        let c = counter.to_be_bytes();
        let block = digest(hash, &[seed, &c])?;
        let take = core::cmp::min(h_len, mask_len - out.len());
        out.extend_from_slice(&block[..take]);
        counter += 1;
    }
    Ok(out)
}

/// EME-PKCS1-v1_5 encoding: `00 02 || PS || 00 || msg` with at least 8
/// nonzero padding bytes drawn from the RNG.
fn eme_pkcs1_encode(rng: &mut impl Rng, msg: &[u8], k: usize) -> CryptoResult<Vec<u8>> {
    if msg.len() > k - 11 {
        return Err(CryptoError::StrError("rsa: message too long"));
    }
    let mut em = alloc::vec![0u8; k];
    em[0] = 0x00;
    em[1] = 0x02;
    let ps_len = k - msg.len() - 3;
    // Nonzero padding bytes: redraw zeros (loop counts leak nothing about
    // the message, and the padding is fresh randomness).
    for byte in &mut em[2..2 + ps_len] {
        loop {
            rng.fill_bytes(core::slice::from_mut(byte));
            if *byte != 0 {
                break;
            }
        }
    }
    em[2 + ps_len] = 0x00;
    em[3 + ps_len..].copy_from_slice(msg);
    Ok(em)
}

/// EME-PKCS1-v1_5 decoding with structural checks.
fn eme_pkcs1_decode(em: &[u8]) -> CryptoResult<Vec<u8>> {
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x02 {
        return Err(CryptoError::StrError("rsa: decryption error"));
    }
    let sep = em[2..]
        .iter()
        .position(|b| *b == 0x00)
        .ok_or(CryptoError::StrError("rsa: decryption error"))?;
    if sep < 8 {
        return Err(CryptoError::StrError("rsa: decryption error"));
    }
    Ok(em[3 + sep..].to_vec())
}

/// DigestInfo prefixes for the digests usable with PKCS#1 v1.5
/// signatures, keyed by digest size (RFC 8017 section 9.2 note 1).
fn digestinfo_prefix(hash_len: usize) -> CryptoResult<&'static [u8]> {
    match hash_len {
        16 => Ok(&[
            0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
            0x05, 0x00, 0x04, 0x10,
        ]),
        20 => Ok(&[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ]),
        28 => Ok(&[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1c,
        ]),
        32 => Ok(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
        48 => Ok(&[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ]),
        64 => Ok(&[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ]),
        _ => Err(CryptoError::StrError("rsa: unsupported digest")),
    }
}

/// EMSA-PKCS1-v1_5 encoding (RFC 8017 section 9.2).
fn emsa_pkcs1_encode(hash: HashFactory, msg: &[u8], em_len: usize) -> CryptoResult<Vec<u8>> {
    let mut h = hash()?;
    h.write_all(msg)?;
    let h_len = h.size();

    let prefix = digestinfo_prefix(h_len)?;
    let t_len = prefix.len() + h_len;
    if em_len < t_len + 11 {
        return Err(CryptoError::StrError("rsa: message too long"));
    }

    let mut em = alloc::vec![0u8; em_len];
    em[0] = 0x00;
    em[1] = 0x01;
    for b in &mut em[2..em_len - t_len - 1] {
        *b = 0xff;
    }
    em[em_len - t_len - 1] = 0x00;
    em[em_len - t_len..em_len - h_len].copy_from_slice(prefix);
    h.reset();
    h.write_all(msg)?;
    let digest = h.sum();
    em[em_len - h_len..].copy_from_slice(&digest);
    Ok(em)
}

/// EMSA-PSS encoding (RFC 8017 section 9.1.1) with empty trailer label.
fn emsa_pss_encode(
    hash: HashFactory,
    msg: &[u8],
    em_bits: usize,
    salt_len: usize,
    rng: &mut impl Rng,
) -> CryptoResult<Vec<u8>> {
    let mut h = hash()?;
    h.write_all(msg)?;
    let m_hash = h.sum();
    let h_len = m_hash.len();
    let em_len = em_bits.div_ceil(8);
    if em_len < h_len + salt_len + 2 {
        return Err(CryptoError::StrError("rsa: encoding error (salt too long)"));
    }

    let mut salt = alloc::vec![0u8; salt_len];
    rng.fill_bytes(&mut salt);

    // M' = 0x00 * 8 || mHash || salt
    let m_prime_hash = {
        let zeros = [0u8; 8];
        digest(hash, &[&zeros, &m_hash, &salt])?
    };

    // Capacity covers the whole EM so `db` can be moved into `em` without
    // a reallocating copy.
    let mut db = Vec::with_capacity(em_len);
    db.resize(em_len - h_len - 1, 0);
    let db_len = db.len();
    db[db_len - salt_len - 1] = 0x01;
    db[db_len - salt_len..].copy_from_slice(&salt);
    let db_mask = mgf1(hash, &m_prime_hash, db.len())?;
    for (b, m) in db.iter_mut().zip(db_mask.iter()) {
        *b ^= m;
    }

    // Clear the leftmost 8*emLen - emBits bits.
    let top_bits = 8 * em_len - em_bits;
    if top_bits > 0 {
        db[0] &= 0xff >> top_bits;
    }

    let mut em = db;
    em.extend_from_slice(&m_prime_hash);
    em.push(0xbc);
    Ok(em)
}

/// EMSA-PSS verification (RFC 8017 section 9.1.2).
fn emsa_pss_verify(
    hash: HashFactory,
    msg: &[u8],
    em: &[u8],
    em_bits: usize,
    salt_len: usize,
) -> CryptoResult<bool> {
    let mut h = hash()?;
    h.write_all(msg)?;
    let m_hash = h.sum();
    let h_len = m_hash.len();
    let em_len = em_bits.div_ceil(8);
    if em_len < h_len + salt_len + 2 || em.len() != em_len || em[em.len() - 1] != 0xbc {
        return Ok(false);
    }

    let db = &em[..em_len - h_len - 1];
    let h_prime = &em[em_len - h_len - 1..em_len - 1];

    // RFC 8017 9.1.2 step 8: the unused leading bits of maskedDB must be
    // zero; only DB (after unmasking, step 11) may have them cleared.
    let top_bits = 8 * em_len - em_bits;
    if top_bits > 0 && db[0] >> (8 - top_bits) != 0 {
        return Ok(false);
    }

    let db_mask = mgf1(hash, h_prime, db.len())?;
    let mut masked_db = db.to_vec();
    for (b, m) in masked_db.iter_mut().zip(db_mask.iter()) {
        *b ^= m;
    }
    if top_bits > 0 {
        masked_db[0] &= 0xff >> top_bits;
    }

    // DB must be 0x00..00 01 salt.
    for b in &masked_db[..masked_db.len() - salt_len - 1] {
        if *b != 0x00 {
            return Ok(false);
        }
    }
    if masked_db[masked_db.len() - salt_len - 1] != 0x01 {
        return Ok(false);
    }
    let salt = &masked_db[masked_db.len() - salt_len..];

    let zeros = [0u8; 8];
    let m_prime_hash = digest(hash, &[&zeros, &m_hash, salt])?;
    Ok(constant_time_eq(&m_prime_hash, h_prime))
}

/// EME-OAEP encoding (RFC 8017 section 7.1.1) with the given label.
fn eme_oaep_encode(
    hash: HashFactory,
    rng: &mut impl Rng,
    msg: &[u8],
    k: usize,
    label: &[u8],
) -> CryptoResult<Vec<u8>> {
    let h_len = hash()?.size();
    // Capacity may be negative for small keys and large digests.
    let capacity = match k.checked_sub(2 * h_len + 2) {
        Some(c) => c,
        None => return Err(CryptoError::StrError("rsa: message too long")),
    };
    if msg.len() > capacity {
        return Err(CryptoError::StrError("rsa: message too long"));
    }

    let l_hash = digest(hash, &[label])?;

    // Build EM = 0x00 || maskedSeed || maskedDB in a single buffer; the
    // seed and DB regions are masked in place.
    let mut em = alloc::vec![0u8; k];
    let (seed, db) = em[1..].split_at_mut(h_len);
    let db_len = db.len();
    db[..h_len].copy_from_slice(&l_hash);
    db[db_len - msg.len() - 1] = 0x01;
    db[db_len - msg.len()..].copy_from_slice(msg);

    rng.fill_bytes(seed);

    let db_mask = mgf1(hash, seed, db_len)?;
    for (b, m) in db.iter_mut().zip(db_mask.iter()) {
        *b ^= m;
    }
    let seed_mask = mgf1(hash, db, h_len)?;
    for (b, m) in seed.iter_mut().zip(seed_mask.iter()) {
        *b ^= m;
    }
    Ok(em)
}

/// EME-OAEP decoding with the given label.
fn eme_oaep_decode(hash: HashFactory, em: &[u8], label: &[u8]) -> CryptoResult<Vec<u8>> {
    let h_len = hash()?.size();
    if em.len() < 2 * h_len + 2 || em[0] != 0x00 {
        return Err(CryptoError::StrError("rsa: decryption error"));
    }
    let masked_seed = &em[1..1 + h_len];
    let masked_db = &em[1 + h_len..];

    let seed_mask = mgf1(hash, masked_db, h_len)?;
    let mut seed = masked_seed.to_vec();
    for (b, m) in seed.iter_mut().zip(seed_mask.iter()) {
        *b ^= m;
    }
    let db_mask = mgf1(hash, &seed, masked_db.len())?;
    let mut db = masked_db.to_vec();
    for (b, m) in db.iter_mut().zip(db_mask.iter()) {
        *b ^= m;
    }

    let l_hash = digest(hash, &[label])?;
    if !constant_time_eq(&db[..h_len], &l_hash) {
        return Err(CryptoError::StrError("rsa: decryption error"));
    }
    // Locate the 0x01 separator after the zero padding.
    let idx = db[h_len..]
        .iter()
        .position(|b| *b == 0x01)
        .ok_or(CryptoError::StrError("rsa: decryption error"))?;
    if db[h_len..h_len + idx].iter().any(|b| *b != 0x00) {
        return Err(CryptoError::StrError("rsa: decryption error"));
    }
    db.drain(..h_len + idx + 1);
    Ok(db)
}
