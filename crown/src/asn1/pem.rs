//! PEM (RFC 7468) armour.
//!
//! [`encode`] wraps DER bytes into the usual `-----BEGIN X-----` form with
//! 64-character base64 lines. [`parse`] extracts every block from a text
//! buffer, tolerating CRLF line endings, blank lines and RFC 1421 header
//! lines. Base64 is implemented here so the PKI modules do not need the
//! optional `base64` dependency of the `password` feature.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{CryptoError, CryptoResult};

/// A decoded PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// The label between `BEGIN` and `END`.
    pub label: String,
    /// The decoded DER payload.
    pub data: Vec<u8>,
}

/// Encode `data` as a PEM block with the given label.
///
/// The label must be non-empty printable ASCII.
pub fn encode(label: &str, data: &[u8]) -> String {
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let body = base64_encode(data);
    for chunk in body.as_bytes().chunks(64) {
        // The body is pure ASCII base64.
        out.push_str(core::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Parse every PEM block in `input`.
pub fn parse(input: &str) -> CryptoResult<Vec<PemBlock>> {
    let mut blocks = Vec::new();
    let mut lines = input.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("-----BEGIN ") else {
            continue;
        };
        let Some(label) = rest.strip_suffix("-----") else {
            return Err(CryptoError::StrError("pem: malformed begin line"));
        };
        let mut body = String::new();
        loop {
            let Some(line) = lines.next() else {
                return Err(CryptoError::StrError("pem: missing end line"));
            };
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("-----END ") {
                let end_label = rest
                    .strip_suffix("-----")
                    .ok_or(CryptoError::StrError("pem: malformed end line"))?;
                if end_label != label {
                    return Err(CryptoError::StrError("pem: mismatched end label"));
                }
                break;
            }
            // RFC 1421 headers (e.g. Proc-Type) carry a colon; skip them.
            if line.contains(':') {
                continue;
            }
            for c in line.chars() {
                if !c.is_whitespace() {
                    body.push(c);
                }
            }
        }
        blocks.push(PemBlock {
            label: label.to_string(),
            data: base64_decode(&body)?,
        });
    }
    if blocks.is_empty() {
        return Err(CryptoError::StrError("pem: no block found"));
    }
    Ok(blocks)
}

/// Parse the first PEM block in `input`.
pub fn parse_first(input: &str) -> CryptoResult<PemBlock> {
    parse(input)?
        .into_iter()
        .next()
        .ok_or(CryptoError::StrError("pem: no block found"))
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64_ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(BASE64_ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[(triple >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[triple as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Standard base64 decoder; whitespace is ignored and padding is required.
pub(crate) fn base64_decode(text: &str) -> CryptoResult<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for &c in text.as_bytes() {
        if c == b'=' {
            padding += 1;
            continue;
        }
        if padding != 0 {
            return Err(CryptoError::StrError("pem: base64 data after padding"));
        }
        let v = value(c).ok_or(CryptoError::StrError("pem: invalid base64 character"))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // 6/12 leftover bits are valid (one/two padding octets); 2/4 leftover
    // bits mean the input was malformed.
    if bits >= 6 || acc & ((1 << bits) - 1) != 0 {
        return Err(CryptoError::StrError("pem: invalid base64 length"));
    }
    Ok(out)
}
