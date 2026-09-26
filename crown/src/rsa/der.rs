//! Minimal DER support for PKCS#1 RSAPublicKey/RSAPrivateKey structures
//! (RFC 8017), enough to interoperate with OpenSSL's `rsa_asn1.c` encoders.

use crate::error::{CryptoError, CryptoResult};
use alloc::vec::Vec;

/// The eight PKCS#1 private key components: n, e, d, p, q, dp, dq, qinv.
pub type RsaPrivateComponents = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        alloc::vec![len as u8]
    } else if len <= 0xff {
        alloc::vec![0x81, len as u8]
    } else {
        alloc::vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// DER-encode a non-negative INTEGER from its big-endian magnitude
/// (prepends a zero byte when the top bit is set).
pub fn encode_integer(magnitude: &[u8]) -> Vec<u8> {
    let mut content = magnitude;
    // strip leading zeros
    while content.len() > 1 && content[0] == 0 {
        content = &content[1..];
    }
    let mut v = Vec::with_capacity(content.len() + 1);
    if content[0] & 0x80 != 0 {
        v.push(0x00);
    }
    v.extend_from_slice(content);
    if content == [0] {
        v = alloc::vec![0x00];
    }
    encode_tlv(0x02, &v)
}

/// A minimal recursive DER parser.
pub struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Parser { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Read one TLV; returns `(tag, content)`.
    pub fn next_tlv(&mut self) -> CryptoResult<(u8, &'a [u8])> {
        if self.data.len() < 2 {
            return Err(CryptoError::StrError("der: truncated"));
        }
        let tag = self.data[0];
        let b1 = self.data[1] as usize;
        let (len_len, len) = if b1 < 0x80 {
            (1, b1)
        } else {
            let n = b1 & 0x7f;
            if n == 0 || n > 2 || self.data.len() < 1 + 1 + n {
                return Err(CryptoError::StrError("der: bad length"));
            }
            let mut v = 0usize;
            for i in 0..n {
                v = (v << 8) | self.data[2 + i] as usize;
            }
            (1 + n, v)
        };
        let start = 1 + len_len;
        if self.data.len() < start + len {
            return Err(CryptoError::StrError("der: truncated"));
        }
        let content = &self.data[start..start + len];
        self.data = &self.data[start + len..];
        Ok((tag, content))
    }

    /// Read a SEQUENCE and return a sub-parser over its content.
    pub fn read_sequence(&mut self) -> CryptoResult<Parser<'a>> {
        let (tag, content) = self.next_tlv()?;
        if tag != 0x30 {
            return Err(CryptoError::StrError("der: expected sequence"));
        }
        Ok(Parser { data: content })
    }

    /// Read an INTEGER and return its big-endian magnitude.
    pub fn read_integer(&mut self) -> CryptoResult<Vec<u8>> {
        self.read_integer_of_tag(0x02)
    }

    /// Read a TLV with the given tag and return its content.
    pub fn read_integer_of_tag(&mut self, expect: u8) -> CryptoResult<Vec<u8>> {
        let (tag, content) = self.next_tlv()?;
        if tag != expect {
            return Err(CryptoError::StrError("der: unexpected tag"));
        }
        let mut v = content;
        while expect == 0x02 && v.len() > 1 && v[0] == 0x00 && v[1] & 0x80 == 0 {
            v = &v[1..];
        }
        Ok(v.to_vec())
    }
}

/// RSAPublicKey ::= SEQUENCE { modulus, publicExponent }
pub fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut body = encode_integer(n);
    body.extend(encode_integer(e));
    encode_tlv(0x30, &body)
}

/// RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
#[allow(clippy::too_many_arguments)]
pub fn rsa_private_key_der(
    n: &[u8],
    e: &[u8],
    d: &[u8],
    p: &[u8],
    q: &[u8],
    dp: &[u8],
    dq: &[u8],
    qinv: &[u8],
) -> Vec<u8> {
    let mut body = encode_integer(&[0]);
    for part in [n, e, d, p, q, dp, dq, qinv] {
        body.extend(encode_integer(part));
    }
    encode_tlv(0x30, &body)
}

pub fn parse_rsa_public_key(der: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let mut top = Parser::new(der);
    let mut seq = top.read_sequence()?;
    let n = seq.read_integer()?;
    let e = seq.read_integer()?;
    Ok((n, e))
}

#[allow(clippy::type_complexity)]
pub fn parse_rsa_private_key(
    der: &[u8],
) -> CryptoResult<(
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
)> {
    let mut top = Parser::new(der);
    let mut seq = top.read_sequence()?;
    let version = seq.read_integer()?;
    if version != [0] {
        return Err(CryptoError::StrError("der: unsupported rsa key version"));
    }
    let n = seq.read_integer()?;
    let e = seq.read_integer()?;
    let d = seq.read_integer()?;
    let p = seq.read_integer()?;
    let q = seq.read_integer()?;
    let dp = seq.read_integer()?;
    let dq = seq.read_integer()?;
    let qinv = seq.read_integer()?;
    Ok((n, e, d, p, q, dp, dq, qinv))
}

/// Unwrap a PKCS#8 PrivateKeyInfo (RFC 5958) carrying an RSA key and
/// return the inner PKCS#1 RSAPrivateKey parse.
///
/// PrivateKeyInfo ::= SEQUENCE {
///     version INTEGER (0),
///     privateKeyAlgorithm AlgorithmIdentifier (rsaEncryption),
///     privateKey OCTET STRING }  -- contains RSAPrivateKey
pub fn parse_pkcs8_rsa_private_key(der: &[u8]) -> CryptoResult<RsaPrivateComponents> {
    let mut top = Parser::new(der);
    let mut seq = top.read_sequence()?;
    let version = seq.read_integer()?;
    if version != [0] {
        return Err(CryptoError::StrError("der: unsupported pkcs8 version"));
    }
    let (tag, alg) = seq.next_tlv()?;
    if tag != 0x30 {
        return Err(CryptoError::StrError("der: expected algorithm identifier"));
    }
    let mut alg_parser = Parser::new(alg);
    let oid = alg_parser.read_integer_of_tag(0x06)?;
    // rsaEncryption = 1.2.840.113549.1.1.1
    if oid != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] {
        return Err(CryptoError::StrError("der: not an rsa key"));
    }
    let (tag, key) = seq.next_tlv()?;
    if tag != 0x04 {
        return Err(CryptoError::StrError("der: expected octet string"));
    }
    parse_rsa_private_key(key)
}
