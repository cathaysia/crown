//! ANS X9.42 KDF (used by ECDH/CMS key agreement), ported from OpenSSL
//! `providers/implementations/kdfs/x942kdf.c`.
//!
//! The fixed info is the DER-encoded X9.42 OtherInfo structure:
//!
//! ```text
//! OtherInfo ::= SEQUENCE {
//!     keyInfo     KeySpecificInfo,      -- { OID(cek), OCTET STRING counter }
//!     partyUInfo  [0] OCTET STRING OPTIONAL,
//!     partyVInfo  [1] OCTET STRING OPTIONAL,
//!     suppPubInfo [2] OCTET STRING OPTIONAL,  -- key length in bits
//!     suppPrivInfo [3] OCTET STRING OPTIONAL }
//! ```
//!
//! The counter (4 bytes, starting at 1) is placed inside the KeySpecificInfo
//! and incremented for every hash block of output. When `use_keybits` is
//! true the derived key length in bits is encoded as `suppPubInfo`.

#[cfg(test)]
mod tests;

use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::HashFactory;
use alloc::vec::Vec;

const MAX_IN_LEN: usize = 1 << 30;

/// Key wrapping algorithms with the DER OIDs recognised by OpenSSL's
/// `CEKALG` parameter and their KEK lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CekAlg {
    Aes128Wrap,
    Aes192Wrap,
    Aes256Wrap,
    Des3Wrap,
}

impl CekAlg {
    /// The complete DER-encoded OBJECT IDENTIFIER (including the `06` tag)
    /// used in the OtherInfo, matching OpenSSL's precompiled OIDs.
    pub fn der_oid(self) -> &'static [u8] {
        match self {
            CekAlg::Aes128Wrap => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05,
            ],
            CekAlg::Aes192Wrap => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06,
            ],
            CekAlg::Aes256Wrap => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2d,
            ],
            CekAlg::Des3Wrap => &[
                0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x06,
            ],
        }
    }

    /// The KEK length in bytes associated with the wrapping algorithm.
    pub fn kek_len(self) -> usize {
        match self {
            CekAlg::Aes128Wrap => 16,
            CekAlg::Aes192Wrap => 24,
            CekAlg::Aes256Wrap => 32,
            CekAlg::Des3Wrap => 24,
        }
    }
}

/// Derive `key_len` bytes of KEK from the shared secret and the X9.42
/// OtherInfo fields. The per-call OtherInfo is built with the counter
/// starting at 1, mirroring `x942_encode_otherinfo`.
#[allow(clippy::too_many_arguments)]
pub fn derive(
    hash: HashFactory,
    secret: &[u8],
    cek_alg: CekAlg,
    partyu: &[u8],
    partyv: &[u8],
    supp_pub: &[u8],
    supp_priv: &[u8],
    use_keybits: bool,
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    if secret.len() > MAX_IN_LEN || key_len > MAX_IN_LEN || key_len == 0 {
        return Err(CryptoError::InvalidLength);
    }
    // The two options encode to the same field.
    if use_keybits && !supp_pub.is_empty() {
        return Err(CryptoError::StrError(
            "x942kdf: supp_pub conflicts with use_keybits",
        ));
    }
    if partyu.len() >= MAX_IN_LEN {
        return Err(CryptoError::StrError("x942kdf: ukm length too large"));
    }

    // The suppPubInfo carries 8 * the KEK length of the wrapping algorithm
    // (OpenSSL's dkm_len), independent of the requested output length.
    let keylen_bits = if use_keybits {
        8 * cek_alg.kek_len() as u32
    } else {
        0
    };

    let mut out = Vec::with_capacity(key_len);
    let mut counter = 1u32;
    while out.len() < key_len {
        let other_info = encode_otherinfo(
            cek_alg,
            partyu,
            partyv,
            supp_pub,
            supp_priv,
            keylen_bits,
            counter,
        );
        let mut h = hash()?;
        h.write(secret)?;
        h.write(&other_info)?;
        let block = h.sum();
        let remaining = key_len - out.len();
        out.extend_from_slice(&block[..core::cmp::min(remaining, block.len())]);
        counter += 1;
    }
    Ok(out)
}

/// DER-encode the X9.42 OtherInfo with the given counter value. The fields
/// appear in RFC 3565 order (keyInfo, partyUInfo, partyVInfo, suppPubInfo,
/// suppPrivInfo); OpenSSL builds the same layout by writing backwards.
fn encode_otherinfo(
    cek_alg: CekAlg,
    partyu: &[u8],
    partyv: &[u8],
    supp_pub: &[u8],
    supp_priv: &[u8],
    keylen_bits: u32,
    counter: u32,
) -> Vec<u8> {
    let mut body = Vec::new();

    // KeySpecificInfo ::= SEQUENCE { algorithm OID, counter OCTET STRING(4) }
    let mut keyinfo = cek_alg.der_oid().to_vec();
    keyinfo.extend_from_slice(&tagged(0x04, &counter.to_be_bytes()));
    body.extend(tagged(0x30, &keyinfo));

    if !partyu.is_empty() {
        body.extend(tagged_octet_string(0xa0, partyu));
    }
    if !partyv.is_empty() {
        body.extend(tagged_octet_string(0xa1, partyv));
    }
    if keylen_bits != 0 {
        // [2] { OCTET STRING(4) } carrying the key length in bits.
        body.extend(tagged_octet_string(0xa2, &keylen_bits.to_be_bytes()));
    } else if !supp_pub.is_empty() {
        body.extend(tagged_octet_string(0xa2, supp_pub));
    }
    if !supp_priv.is_empty() {
        body.extend(tagged_octet_string(0xa3, supp_priv));
    }

    tagged(0x30, &body)
}

/// Context-specific constructed tag wrapping a plain value.
fn tagged(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5);
    out.push(tag);
    out.extend_from_slice(&der_len(data.len()));
    out.extend_from_slice(data);
    out
}

/// Context tag wrapping an explicit OCTET STRING, e.g. `A0 08 04 06 <data>`.
fn tagged_octet_string(tag: u8, data: &[u8]) -> Vec<u8> {
    let inner = tagged(0x04, data);
    tagged(tag, &inner)
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        alloc::vec![len as u8]
    } else if len <= 0xff {
        alloc::vec![0x81, len as u8]
    } else {
        alloc::vec![0x82, (len >> 8) as u8, len as u8]
    }
}
