//! SLH-DSA (FIPS 205) stateless hash-based signatures.
//!
//! SLH-DSA is the NIST-standardized variant of SPHINCS+. Security relies only
//! on the collision resistance of the underlying hash function, and keys are
//! tiny compared to ML-DSA — at the cost of large signatures and relatively
//! slow signing.
//!
//! Twelve parameter sets are supported (FIPS 205 Table 2): the SHA2 family
//! ([`SlhDsaVariant::Sha2_128s`], …) and the SHAKE family
//! ([`SlhDsaVariant::Shake_128s`], …), each in a small-signature (`s`) and a
//! fast-signing (`f`) flavour at security categories 1, 3 and 5.
//!
//! # Example
//!
//! ```ignore
//! use crown::slh_dsa::{keygen, sign, verify, SlhDsaVariant};
//!
//! let seed = [0x2au8; 48]; // 3n bytes of entropy
//! let (pk, sk) = keygen(SlhDsaVariant::Sha2_128s, &seed).unwrap();
//! let sig = sign(&sk, b"hello", b"ctx", false).unwrap();
//! assert!(verify(&pk, b"hello", b"ctx", &sig).unwrap());
//! ```
//!
//! # Message encoding
//!
//! With `prehash = false` the pure SLH-DSA encoding of FIPS 205 Algorithm 22
//! is used: `M' = 0x00 || len(ctx) || ctx || M`. With `prehash = true` the
//! HashSLH-DSA encoding of Algorithm 23 is used:
//! `M' = 0x01 || len(ctx) || ctx || OID || PH(M)`, where `PH` is chosen to
//! match the security category of the parameter set (SHA-256 / SHAKE128 for
//! category 1, SHA-512 / SHAKE256 for categories 3 and 5).

mod adrs;
mod fors;
mod hash;
mod ht;
mod params;
mod wots;
mod xmss;

#[cfg(test)]
mod tests;

pub use params::SlhDsaVariant;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::{CryptoError, CryptoResult};

use adrs::{Adrs, TYPE_FORS_TREE};
use params::{Params, MAX_N};

/// Maximum length of the context string `ctx` (FIPS 205 Algorithms 22–25).
pub const MAX_CONTEXT_STRING_LEN: usize = 255;

/// An SLH-DSA public key.
///
/// The wire format is `PK.seed || PK.root`, `2n` bytes (FIPS 205 Figure 16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaPublicKey {
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

/// An SLH-DSA private key.
///
/// The wire format is `SK.seed || SK.prf || PK.seed || PK.root`, `4n` bytes
/// (FIPS 205 Figure 15). The public components are stored inside the private
/// key because `PK.root` cannot be recomputed without them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaPrivateKey {
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

impl SlhDsaPublicKey {
    /// Construct a public key from its `2n`-byte encoding.
    pub fn from_bytes(variant: SlhDsaVariant, bytes: &[u8]) -> CryptoResult<Self> {
        let n = variant.params().n;
        if bytes.len() != 2 * n {
            return Err(CryptoError::InvalidKeySize {
                expected: "2n bytes",
                actual: bytes.len(),
            });
        }
        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }

    /// The `2n`-byte encoding `PK.seed || PK.root`.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parameter set of this key.
    pub fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    fn pk_seed(&self) -> &[u8] {
        let n = self.variant.params().n;
        &self.bytes[..n]
    }

    fn pk_root(&self) -> &[u8] {
        let n = self.variant.params().n;
        &self.bytes[n..]
    }
}

impl SlhDsaPrivateKey {
    /// Construct a private key from its `4n`-byte encoding
    /// `SK.seed || SK.prf || PK.seed || PK.root`.
    pub fn from_bytes(variant: SlhDsaVariant, bytes: &[u8]) -> CryptoResult<Self> {
        let n = variant.params().n;
        if bytes.len() != 4 * n {
            return Err(CryptoError::InvalidKeySize {
                expected: "4n bytes",
                actual: bytes.len(),
            });
        }
        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }

    /// The `4n`-byte encoding `SK.seed || SK.prf || PK.seed || PK.root`.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parameter set of this key.
    pub fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    fn sk_seed(&self) -> &[u8] {
        let n = self.variant.params().n;
        &self.bytes[..n]
    }

    fn sk_prf(&self) -> &[u8] {
        let n = self.variant.params().n;
        &self.bytes[n..2 * n]
    }

    fn pk_seed(&self) -> &[u8] {
        let n = self.variant.params().n;
        &self.bytes[2 * n..3 * n]
    }

    fn pk_root(&self) -> &[u8] {
        let n = self.variant.params().n;
        &self.bytes[3 * n..]
    }

    /// The public key corresponding to this private key.
    pub fn public_key(&self) -> SlhDsaPublicKey {
        let n = self.variant.params().n;
        SlhDsaPublicKey {
            variant: self.variant,
            bytes: self.bytes[2 * n..].to_vec(),
        }
    }
}

/// Generate an SLH-DSA key pair from deterministic entropy (FIPS 205
/// Algorithm 21).
///
/// `seed` supplies `SK.seed || SK.prf || PK.seed` and must be exactly `3n`
/// bytes long: 48 bytes for the 128-bit sets, 72 for 192-bit, 96 for 256-bit.
/// The public key root is derived from these seeds by hashing the top XMSS
/// tree of the hypertree.
///
/// (The fixed `&[u8; 48]` sketch only fits the category-1 sets; the length is
/// validated against the chosen variant instead.)
pub fn keygen(
    variant: SlhDsaVariant,
    seed: &[u8],
) -> CryptoResult<(SlhDsaPublicKey, SlhDsaPrivateKey)> {
    let p = variant.params();
    let n = p.n;
    if seed.len() != 3 * n {
        return Err(CryptoError::InvalidKeySize {
            expected: "3n bytes",
            actual: seed.len(),
        });
    }
    let sk_seed = &seed[..n];
    let sk_prf = &seed[n..2 * n];
    let pk_seed = &seed[2 * n..3 * n];

    // PK.root = xmss_node(0, h') at layer d-1 (Algorithm 18 / Algorithm 21).
    let mut adrs = Adrs::new(!p.is_shake);
    adrs.zero();
    adrs.set_layer_address(p.d - 1);
    let mut pk_root = [0u8; MAX_N];
    xmss::xmss_node(p, sk_seed, 0, p.hm, pk_seed, &mut adrs, &mut pk_root);

    let mut sk_bytes = Vec::with_capacity(4 * n);
    sk_bytes.extend_from_slice(sk_seed);
    sk_bytes.extend_from_slice(sk_prf);
    sk_bytes.extend_from_slice(pk_seed);
    sk_bytes.extend_from_slice(&pk_root[..n]);

    let pk_bytes = sk_bytes[2 * n..].to_vec();
    Ok((
        SlhDsaPublicKey {
            variant,
            bytes: pk_bytes,
        },
        SlhDsaPrivateKey {
            variant,
            bytes: sk_bytes,
        },
    ))
}

/// Hash function identifiers for the HashSLH-DSA (prehash) encoding.
enum PrehashId {
    Sha256,
    Sha512,
    Shake128,
    Shake256,
}

impl PrehashId {
    /// DER OID encoding including tag and length (FIPS 205 Algorithm 23).
    fn oid(&self) -> &'static [u8] {
        match self {
            PrehashId::Sha256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            PrehashId::Sha512 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            PrehashId::Shake128 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b],
            PrehashId::Shake256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c],
        }
    }
}

fn prehash_id(p: &Params) -> PrehashId {
    if p.is_shake {
        if p.n == 16 {
            PrehashId::Shake128
        } else {
            PrehashId::Shake256
        }
    } else if p.n == 16 {
        PrehashId::Sha256
    } else {
        PrehashId::Sha512
    }
}

/// PH(M) for the prehash encoding: 32 bytes for category 1, 64 for 3 and 5.
fn prehash_digest(p: &Params, msg: &[u8]) -> Vec<u8> {
    use crate::core::CoreWrite;
    use crate::hash::{sha256, sha512};
    match prehash_id(p) {
        PrehashId::Sha256 => sha256::sum256(msg).to_vec(),
        PrehashId::Sha512 => sha512::sum512(msg).to_vec(),
        PrehashId::Shake128 => {
            let mut x = crate::hash::sha3::new_shake128();
            x.write_all(msg).expect("shake write");
            let mut out = [0u8; 32];
            use crate::core::CoreRead;
            x.read(&mut out).expect("shake read");
            out.to_vec()
        }
        PrehashId::Shake256 => {
            let mut x = crate::hash::sha3::new_shake256();
            x.write_all(msg).expect("shake write");
            let mut out = [0u8; 64];
            use crate::core::CoreRead;
            x.read(&mut out).expect("shake read");
            out.to_vec()
        }
    }
}

/// Build M' (FIPS 205 Algorithms 22 and 23).
fn encode_message(
    p: &Params,
    msg: &[u8],
    ctx: &[u8],
    prehash: bool,
) -> CryptoResult<Vec<u8>> {
    if ctx.len() > MAX_CONTEXT_STRING_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let mut out = Vec::with_capacity(2 + ctx.len() + msg.len() + 74);
    if prehash {
        out.push(0x01);
        out.push(ctx.len() as u8);
        out.extend_from_slice(ctx);
        out.extend_from_slice(prehash_id(p).oid());
        out.extend_from_slice(&prehash_digest(p, msg));
    } else {
        out.push(0x00);
        out.push(ctx.len() as u8);
        out.extend_from_slice(ctx);
        out.extend_from_slice(msg);
    }
    Ok(out)
}

/// Split the trailing `m - md_len` digest bytes into tree and leaf indices
/// (FIPS 205 Algorithm 19, steps 7–10).
fn tree_and_leaf_ids(p: &Params, digest_tail: &[u8]) -> (u64, u32) {
    let tree_id_len = ((p.h - p.hm + 7) / 8) as usize;
    let leaf_id_len = ((p.hm + 7) / 8) as usize;
    let mut tree_id: u64 = 0;
    for &b in &digest_tail[..tree_id_len] {
        tree_id = (tree_id << 8) + b as u64;
    }
    tree_id &= u64::MAX >> (64 - (p.h - p.hm));
    let mut leaf_id: u64 = 0;
    for &b in &digest_tail[tree_id_len..tree_id_len + leaf_id_len] {
        leaf_id = (leaf_id << 8) + b as u64;
    }
    leaf_id &= (1u64 << p.hm) - 1;
    (tree_id, leaf_id as u32)
}

/// FIPS 205 Algorithm 19 `slh_sign_internal` (deterministic variant: the
/// optional randomness `addrnd` is `PK.seed`).
fn sign_internal(p: &Params, sk: &SlhDsaPrivateKey, m_prime: &[u8]) -> Vec<u8> {
    let n = p.n;
    let md_len = p.md_len();
    let pk_seed = sk.pk_seed();
    let sk_seed = sk.sk_seed();

    let mut sig = vec![0u8; p.sig_len];

    // R = PRF_msg(SK.prf, PK.seed, M')
    let mut r = [0u8; MAX_N];
    hash::prf_msg(p, sk.sk_prf(), pk_seed, m_prime, &mut r[..n]);
    sig[..n].copy_from_slice(&r[..n]);

    // M_digest = H_msg(R, PK.seed, PK.root, M')
    let mut digest = [0u8; 49]; // max m across the parameter sets
    hash::h_msg(p, &r[..n], pk_seed, sk.pk_root(), m_prime, &mut digest[..p.m]);

    let (tree_id, leaf_id) = tree_and_leaf_ids(p, &digest[md_len..p.m]);

    // FORS tree address (Algorithm 19, steps 11–13).
    let mut adrs = Adrs::new(!p.is_shake);
    adrs.zero();
    adrs.set_tree_address(tree_id);
    adrs.set_type_and_clear(TYPE_FORS_TREE);
    adrs.set_keypair_address(leaf_id);

    let off = fors::fors_sign(
        p,
        &digest[..md_len],
        sk_seed,
        pk_seed,
        &mut adrs,
        &mut sig,
        n,
    );

    // Recover the FORS public key from the signature just produced and sign
    // it with the hypertree (Algorithm 19, steps 14–16).
    let mut pk_fors = [0u8; MAX_N];
    fors::fors_pk_from_sig(
        p,
        &sig,
        n,
        &digest[..md_len],
        pk_seed,
        &mut adrs,
        &mut pk_fors,
    );
    ht::ht_sign(p, &pk_fors[..n], sk_seed, pk_seed, tree_id, leaf_id, &mut sig, off);
    sig
}

/// FIPS 205 Algorithm 20 `slh_verify_internal`.
fn verify_internal(p: &Params, pk: &SlhDsaPublicKey, m_prime: &[u8], sig: &[u8]) -> bool {
    let n = p.n;
    if sig.len() != p.sig_len {
        return false;
    }
    let md_len = p.md_len();
    let pk_seed = pk.pk_seed();

    let r = &sig[..n];
    let mut digest = [0u8; 49];
    hash::h_msg(p, r, pk_seed, pk.pk_root(), m_prime, &mut digest[..p.m]);
    let (tree_id, leaf_id) = tree_and_leaf_ids(p, &digest[md_len..p.m]);

    let mut adrs = Adrs::new(!p.is_shake);
    adrs.zero();
    adrs.set_tree_address(tree_id);
    adrs.set_type_and_clear(TYPE_FORS_TREE);
    adrs.set_keypair_address(leaf_id);

    let mut pk_fors = [0u8; MAX_N];
    let off = fors::fors_pk_from_sig(
        p,
        sig,
        n,
        &digest[..md_len],
        pk_seed,
        &mut adrs,
        &mut pk_fors,
    );

    let done = ht::ht_verify(
        p,
        &pk_fors[..n],
        sig,
        off,
        pk_seed,
        tree_id,
        leaf_id,
        pk.pk_root(),
    );
    match done {
        Some(end) => end == sig.len(),
        None => false,
    }
}

/// Sign a message with SLH-DSA (FIPS 205 Algorithms 22 and 23).
///
/// * `ctx` — context string, at most 255 bytes; may be empty.
/// * `prehash` — `false` for pure SLH-DSA (Algorithm 22), `true` for
///   HashSLH-DSA (Algorithm 23) where `PH(M)` is taken with the hash that
///   matches the parameter set's security category.
///
/// Signing is deterministic: the optional randomness is set to `PK.seed`.
pub fn sign(
    sk: &SlhDsaPrivateKey,
    message: &[u8],
    ctx: &[u8],
    prehash: bool,
) -> CryptoResult<Vec<u8>> {
    let p = sk.variant.params();
    let m_prime = encode_message(p, message, ctx, prehash)?;
    Ok(sign_internal(p, sk, &m_prime))
}

/// Verify an SLH-DSA signature (FIPS 205 Algorithms 24 and 25).
///
/// Returns `Ok(true)` when the signature is valid. A malformed signature
/// (wrong length) yields `Ok(false)`; only parameter misuse (over-long `ctx`)
/// returns an error.
pub fn verify(
    pk: &SlhDsaPublicKey,
    message: &[u8],
    ctx: &[u8],
    sig: &[u8],
    prehash: bool,
) -> CryptoResult<bool> {
    let p = pk.variant.params();
    if sig.len() != p.sig_len {
        return Ok(false);
    }
    let m_prime = encode_message(p, message, ctx, prehash)?;
    Ok(verify_internal(p, pk, &m_prime, sig))
}

