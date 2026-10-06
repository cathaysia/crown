//! DER (ASN.1 Distinguished Encoding Rules) reader and writer.
//!
//! The parser is intentionally small and strict about structure: definite
//! lengths only, tags decoded in both the low and the high-tag-number form,
//! and every read bounds-checked against the input. DER canonicality rules
//! that do not affect parsing (minimal length encodings, minimal INTEGER
//! encodings) are tolerated on input, matching OpenSSL's BER-tolerant
//! `d2i_*` behaviour, but the writer always emits canonical DER.
//!
//! ```
//! use crown::asn1::der::{self, Reader, INTEGER, SEQUENCE};
//!
//! let der = der::sequence(&der::integer(&[0x2a]));
//! let mut r = Reader::new(&der);
//! let mut seq = r.read_sequence().unwrap();
//! assert_eq!(seq.read_integer().unwrap(), &[0x2a]);
//! assert_eq!(r.remaining(), 0);
//! # Ok::<(), crown::error::CryptoError>(())
//! ```

use alloc::vec::Vec;

use crate::error::{CryptoError, CryptoResult};

use super::oid::ObjectIdentifier;
use super::time::Asn1Time;

/// ASN.1 tag class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Universal (native ASN.1 types).
    Universal,
    /// Application-specific.
    Application,
    /// Context-specific (used by IMPLICIT/EXPLICIT tagging).
    ContextSpecific,
    /// Private.
    Private,
}

/// A decoded ASN.1 tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// Tag class.
    pub class: Class,
    /// Whether the encoding is constructed.
    pub constructed: bool,
    /// Tag number.
    pub number: u32,
}

impl Tag {
    /// Universal primitive tag with the given number.
    pub const fn universal(number: u32) -> Self {
        Tag {
            class: Class::Universal,
            constructed: false,
            number,
        }
    }

    /// Universal constructed tag with the given number.
    pub const fn universal_constructed(number: u32) -> Self {
        Tag {
            class: Class::Universal,
            constructed: true,
            number,
        }
    }

    /// Context-specific primitive tag with the given number.
    pub const fn context(number: u32) -> Self {
        Tag {
            class: Class::ContextSpecific,
            constructed: false,
            number,
        }
    }

    /// Context-specific constructed tag with the given number.
    pub const fn context_constructed(number: u32) -> Self {
        Tag {
            class: Class::ContextSpecific,
            constructed: true,
            number,
        }
    }

    /// Append the tag's identifier octets to `out`.
    pub fn write(self, out: &mut Vec<u8>) {
        let class_bits = match self.class {
            Class::Universal => 0u8,
            Class::Application => 0x40,
            Class::ContextSpecific => 0x80,
            Class::Private => 0xc0,
        };
        let constructed_bit = if self.constructed { 0x20 } else { 0 };
        if self.number < 0x1f {
            out.push(class_bits | constructed_bit | self.number as u8);
        } else {
            out.push(class_bits | constructed_bit | 0x1f);
            let mut tmp = [0u8; 5];
            let mut i = tmp.len();
            let mut n = self.number;
            loop {
                i -= 1;
                tmp[i] = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    break;
                }
            }
            let last = tmp.len() - 1;
            for (j, &b) in tmp[i..].iter().enumerate() {
                let is_last = i + j == last;
                out.push(if is_last { b } else { b | 0x80 });
            }
        }
    }

    /// Encode the tag's identifier octets.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }
}

/// BOOLEAN.
pub const BOOLEAN: Tag = Tag::universal(0x01);
/// INTEGER.
pub const INTEGER: Tag = Tag::universal(0x02);
/// BIT STRING.
pub const BIT_STRING: Tag = Tag::universal(0x03);
/// OCTET STRING.
pub const OCTET_STRING: Tag = Tag::universal(0x04);
/// NULL.
pub const NULL: Tag = Tag::universal(0x05);
/// OBJECT IDENTIFIER.
pub const OBJECT_IDENTIFIER: Tag = Tag::universal(0x06);
/// UTF8String.
pub const UTF8_STRING: Tag = Tag::universal(0x0c);
/// SEQUENCE (constructed).
pub const SEQUENCE: Tag = Tag::universal_constructed(0x10);
/// SET (constructed).
pub const SET: Tag = Tag::universal_constructed(0x11);
/// PrintableString.
pub const PRINTABLE_STRING: Tag = Tag::universal(0x13);
/// TeletexString (T61String).
pub const TELETEX_STRING: Tag = Tag::universal(0x14);
/// IA5String.
pub const IA5_STRING: Tag = Tag::universal(0x16);
/// UTCTime.
pub const UTC_TIME: Tag = Tag::universal(0x17);
/// GeneralizedTime.
pub const GENERALIZED_TIME: Tag = Tag::universal(0x18);
/// VisibleString (ISO646String).
pub const VISIBLE_STRING: Tag = Tag::universal(0x1a);
/// BMPString.
pub const BMP_STRING: Tag = Tag::universal(0x1e);

/// DER reader over a byte slice.
///
/// All read methods advance the reader; slices returned borrow the original
/// input. Reading past the end or encountering a mismatched tag yields
/// [`CryptoError::StrError`].
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Create a reader over `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    /// Whether all input has been consumed.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Bytes left in the reader.
    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    /// Error unless the reader is exhausted.
    pub fn expect_end(&self) -> CryptoResult<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(CryptoError::StrError("asn1: trailing data"))
        }
    }

    /// The tag of the next element without consuming it.
    pub fn peek_tag(&self) -> CryptoResult<Tag> {
        let (tag, _, _) = Self::read_header(self.data)?;
        Ok(tag)
    }

    /// Read the next TLV, returning its tag and content.
    pub fn read_tlv(&mut self) -> CryptoResult<(Tag, &'a [u8])> {
        let (tag, content, rest) = Self::read_header(self.data)?;
        self.data = rest;
        Ok((tag, content))
    }

    /// Read the next TLV including tag and length octets.
    pub fn read_raw_tlv(&mut self) -> CryptoResult<&'a [u8]> {
        let (_, content, rest) = Self::read_header(self.data)?;
        let full_len = self.data.len() - rest.len();
        let full = &self.data[..full_len];
        let _ = content;
        self.data = rest;
        Ok(full)
    }

    /// Read the next element, requiring exactly `tag`.
    pub fn read_expected(&mut self, tag: Tag) -> CryptoResult<&'a [u8]> {
        let (actual, content) = self.read_tlv()?;
        if actual == tag {
            Ok(content)
        } else {
            Err(CryptoError::StrError("asn1: unexpected tag"))
        }
    }

    /// Read a SEQUENCE and return a reader over its content.
    pub fn read_sequence(&mut self) -> CryptoResult<Reader<'a>> {
        Ok(Reader::new(self.read_expected(SEQUENCE)?))
    }

    /// Read a SET and return a reader over its content.
    pub fn read_set(&mut self) -> CryptoResult<Reader<'a>> {
        Ok(Reader::new(self.read_expected(SET)?))
    }

    /// Read an INTEGER and return its unsigned magnitude.
    ///
    /// A single leading zero octet (DER's encoding of a positive value whose
    /// top bit would otherwise be set) is stripped; an INTEGER whose top bit
    /// is set without that padding is rejected as negative, since every
    /// unsigned use in the supported PKI structures (serial numbers, key
    /// components, versions) requires a non-negative value.
    pub fn read_integer(&mut self) -> CryptoResult<&'a [u8]> {
        let content = self.read_expected(INTEGER)?;
        match content {
            [] => Err(CryptoError::StrError("asn1: empty integer")),
            [0] => Ok(&[]),
            [0, rest @ ..] => Ok(rest),
            [first, ..] if first & 0x80 != 0 => {
                Err(CryptoError::StrError("asn1: negative integer"))
            }
            _ => Ok(content),
        }
    }

    /// Read an INTEGER as a signed [`i64`].
    pub fn read_integer_i64(&mut self) -> CryptoResult<i64> {
        let (tag, content) = self.read_tlv()?;
        if tag != INTEGER {
            return Err(CryptoError::StrError("asn1: unexpected tag"));
        }
        if content.is_empty() || content.len() > 8 {
            return Err(CryptoError::StrError("asn1: integer out of range"));
        }
        let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in content {
            value = (value << 8) | b as i64;
        }
        Ok(value)
    }

    /// Read a BOOLEAN. DER canonical values are `0x00` and `0xff`, but any
    /// non-zero single octet is accepted as true, matching OpenSSL.
    pub fn read_boolean(&mut self) -> CryptoResult<bool> {
        let content = self.read_expected(BOOLEAN)?;
        match content {
            [0x00] => Ok(false),
            [_] => Ok(true),
            _ => Err(CryptoError::StrError("asn1: invalid boolean")),
        }
    }

    /// Read an OCTET STRING.
    pub fn read_octet_string(&mut self) -> CryptoResult<&'a [u8]> {
        self.read_expected(OCTET_STRING)
    }

    /// Read an OCTET STRING, tolerating BER's constructed form (an OCTET
    /// STRING split into segments and terminated by end-of-contents).
    ///
    /// The common case returns a borrowed slice; use this when parsing
    /// real-world BER files.
    pub fn read_octet_string_owned(&mut self) -> CryptoResult<Vec<u8>> {
        let (tag, content) = self.read_tlv()?;
        Self::collect_octets(tag, content, 0)
    }

    fn collect_octets(tag: Tag, content: &[u8], depth: usize) -> CryptoResult<Vec<u8>> {
        if depth > 64 {
            return Err(CryptoError::StrError("asn1: nesting too deep"));
        }
        if tag.class != Class::Universal || tag.number != 0x04 {
            return Err(CryptoError::StrError("asn1: unexpected tag"));
        }
        if !tag.constructed {
            return Ok(content.to_vec());
        }
        let mut segments = Reader::new(content);
        let mut out = Vec::new();
        while !segments.is_empty() {
            let (segment_tag, segment) = segments.read_tlv()?;
            out.extend_from_slice(&Self::collect_octets(segment_tag, segment, depth + 1)?);
        }
        Ok(out)
    }

    /// Read a BIT STRING, returning `(unused_bits, data)`.
    pub fn read_bit_string(&mut self) -> CryptoResult<(u8, &'a [u8])> {
        let content = self.read_expected(BIT_STRING)?;
        let (unused, data) = content
            .split_first()
            .ok_or(CryptoError::StrError("asn1: empty bit string"))?;
        if *unused > 7 {
            return Err(CryptoError::StrError("asn1: invalid bit string"));
        }
        if data.is_empty() && *unused != 0 {
            return Err(CryptoError::StrError("asn1: invalid bit string"));
        }
        Ok((*unused, data))
    }

    /// Read a BIT STRING whose unused-bit count must be zero.
    pub fn read_bit_string_bytes(&mut self) -> CryptoResult<&'a [u8]> {
        let (unused, data) = self.read_bit_string()?;
        if unused != 0 {
            return Err(CryptoError::StrError(
                "asn1: unsupported bit string padding",
            ));
        }
        Ok(data)
    }

    /// Read a NULL and require empty content.
    pub fn read_null(&mut self) -> CryptoResult<()> {
        let content = self.read_expected(NULL)?;
        if content.is_empty() {
            Ok(())
        } else {
            Err(CryptoError::StrError("asn1: invalid null"))
        }
    }

    /// Read an OBJECT IDENTIFIER.
    pub fn read_oid(&mut self) -> CryptoResult<ObjectIdentifier> {
        let content = self.read_expected(OBJECT_IDENTIFIER)?;
        ObjectIdentifier::from_der_content(content)
    }

    /// Read a string type, converting it to UTF-8.
    ///
    /// PrintableString/IA5String/UTF8String are decoded directly; BMPString
    /// is decoded from UTF-16BE; TeletexString is decoded as Latin-1, which
    /// is what OpenSSL does for the PKI fixtures in practice.
    pub fn read_directory_string(&mut self) -> CryptoResult<alloc::string::String> {
        let (tag, content) = self.read_tlv()?;
        decode_string(tag, content)
    }

    /// Read a UTCTime.
    pub fn read_utc_time(&mut self) -> CryptoResult<Asn1Time> {
        let content = self.read_expected(UTC_TIME)?;
        Asn1Time::parse_utc(content)
    }

    /// Read a GeneralizedTime.
    pub fn read_generalized_time(&mut self) -> CryptoResult<Asn1Time> {
        let content = self.read_expected(GENERALIZED_TIME)?;
        Asn1Time::parse_generalized(content)
    }

    /// Read either a UTCTime or a GeneralizedTime.
    pub fn read_time(&mut self) -> CryptoResult<Asn1Time> {
        match self.peek_tag()? {
            tag if tag == UTC_TIME => self.read_utc_time(),
            tag if tag == GENERALIZED_TIME => self.read_generalized_time(),
            _ => Err(CryptoError::StrError("asn1: invalid time")),
        }
    }

    /// Read `[number] EXPLICIT` content and return a reader over the inner
    /// element(s).
    pub fn read_explicit(&mut self, number: u32) -> CryptoResult<Reader<'a>> {
        let content = self.read_expected(Tag::context_constructed(number))?;
        Ok(Reader::new(content))
    }

    /// Read `[number] IMPLICIT` content for a primitive type.
    pub fn read_implicit(&mut self, number: u32, constructed: bool) -> CryptoResult<&'a [u8]> {
        self.read_expected(Tag {
            class: Class::ContextSpecific,
            constructed,
            number,
        })
    }

    /// Read `[number] IMPLICIT` content for a constructed type and return a
    /// reader over it.
    pub fn read_implicit_constructed(&mut self, number: u32) -> CryptoResult<Reader<'a>> {
        Ok(Reader::new(self.read_implicit(number, true)?))
    }

    /// Parse tag, length and content, returning the tag, content slice and
    /// the remaining input.
    ///
    /// Definite-length DER is the normal case; BER's indefinite length is
    /// also accepted for constructed values (the content ends at the
    /// matching end-of-contents octets), which real-world PKCS#7 files
    /// still use.
    fn read_header(input: &'a [u8]) -> CryptoResult<(Tag, &'a [u8], &'a [u8])> {
        Self::read_header_depth(input, 0)
    }

    fn read_header_depth(input: &'a [u8], depth: usize) -> CryptoResult<(Tag, &'a [u8], &'a [u8])> {
        const MAX_DEPTH: usize = 96;
        if depth > MAX_DEPTH {
            return Err(CryptoError::StrError("asn1: nesting too deep"));
        }
        let (&first, after_first) = input
            .split_first()
            .ok_or(CryptoError::StrError("asn1: truncated"))?;
        let class = match first >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        };
        let constructed = first & 0x20 != 0;
        let (number, after_tag): (u32, &'a [u8]) = if first & 0x1f == 0x1f {
            let mut number: u32 = 0;
            let mut rest = after_first;
            let mut count = 0;
            loop {
                let (&b, next) = rest
                    .split_first()
                    .ok_or(CryptoError::StrError("asn1: truncated"))?;
                number = number
                    .checked_mul(128)
                    .and_then(|n| n.checked_add((b & 0x7f) as u32))
                    .ok_or(CryptoError::StrError("asn1: tag too large"))?;
                count += 1;
                rest = next;
                if b & 0x80 == 0 {
                    break;
                }
                if count > 4 {
                    return Err(CryptoError::StrError("asn1: tag too large"));
                }
            }
            (number, rest)
        } else {
            ((first & 0x1f) as u32, after_first)
        };

        let (&first_len, after_len) = after_tag
            .split_first()
            .ok_or(CryptoError::StrError("asn1: truncated"))?;
        let (length, content): (usize, &'a [u8]) = if first_len & 0x80 == 0 {
            (first_len as usize, after_len)
        } else {
            let n = (first_len & 0x7f) as usize;
            if n == 0 {
                // BER indefinite length: only constructed values may use it.
                if !constructed {
                    return Err(CryptoError::StrError("asn1: indefinite length"));
                }
                let (content, rest) = Self::skip_indefinite(after_len, depth)?;
                return Ok((
                    Tag {
                        class,
                        constructed,
                        number,
                    },
                    content,
                    rest,
                ));
            }
            if n > core::mem::size_of::<usize>() {
                return Err(CryptoError::StrError("asn1: length too large"));
            }
            let mut length: usize = 0;
            let mut rest = after_len;
            for _ in 0..n {
                let (&b, next) = rest
                    .split_first()
                    .ok_or(CryptoError::StrError("asn1: truncated"))?;
                length = (length << 8) | b as usize;
                rest = next;
            }
            (length, rest)
        };
        if content.len() < length {
            return Err(CryptoError::StrError("asn1: truncated"));
        }
        let (value, rest) = content.split_at(length);
        Ok((
            Tag {
                class,
                constructed,
                number,
            },
            value,
            rest,
        ))
    }

    /// Scan a BER indefinite-length content up to the matching
    /// end-of-contents octets, returning `(content, rest)`.
    fn skip_indefinite(input: &'a [u8], depth: usize) -> CryptoResult<(&'a [u8], &'a [u8])> {
        let mut rest = input;
        loop {
            if rest.len() < 2 {
                return Err(CryptoError::StrError("asn1: truncated"));
            }
            if rest[0] == 0 && rest[1] == 0 {
                let consumed = input.len() - rest.len();
                return Ok((&input[..consumed], &rest[2..]));
            }
            let (_, _, after) = Self::read_header_depth(rest, depth + 1)?;
            rest = after;
        }
    }
}

/// Append a DER length encoding to `out`.
pub fn write_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
}

/// Decode a string value given its tag.
pub fn decode_string(tag: Tag, content: &[u8]) -> CryptoResult<alloc::string::String> {
    use alloc::string::String;
    match tag {
        t if t == UTF8_STRING => core::str::from_utf8(content)
            .map(String::from)
            .map_err(|_| CryptoError::StrError("asn1: invalid utf8 string")),
        t if t == PRINTABLE_STRING || t == IA5_STRING || t == VISIBLE_STRING => {
            if content.is_ascii() {
                Ok(content.iter().map(|&b| b as char).collect())
            } else {
                Err(CryptoError::StrError("asn1: invalid ascii string"))
            }
        }
        t if t == TELETEX_STRING => Ok(content.iter().map(|&b| b as char).collect()),
        t if t == BMP_STRING => {
            if !content.len().is_multiple_of(2) {
                return Err(CryptoError::StrError("asn1: invalid bmp string"));
            }
            let units: Vec<u16> = content
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units)
                .map_err(|_| CryptoError::StrError("asn1: invalid bmp string"))
        }
        _ => Err(CryptoError::StrError("asn1: unsupported string type")),
    }
}

/// Encode `content` as a TLV with the given tag.
pub fn tlv(tag: Tag, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    tag.write(&mut out);
    write_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Encode an unsigned INTEGER from its big-endian magnitude.
pub fn integer(magnitude: &[u8]) -> Vec<u8> {
    let significant = match magnitude.iter().position(|&b| b != 0) {
        Some(i) => &magnitude[i..],
        None => &[][..],
    };
    let mut content = Vec::with_capacity(significant.len() + 1);
    if significant.is_empty() {
        content.push(0);
    } else {
        if significant[0] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(significant);
    }
    tlv(INTEGER, &content)
}

/// Encode a signed INTEGER from an [`i64`].
pub fn integer_i64(value: i64) -> Vec<u8> {
    if value >= 0 {
        return integer(&value.to_be_bytes());
    }
    let mut bytes = value.to_be_bytes().to_vec();
    // Strip redundant 0xff octets, keeping the sign bit.
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0 {
        start += 1;
    }
    bytes.drain(..start);
    tlv(INTEGER, &bytes)
}

/// Encode a BOOLEAN.
pub fn boolean(value: bool) -> Vec<u8> {
    tlv(BOOLEAN, if value { &[0xff] } else { &[0x00] })
}

/// Encode a NULL.
pub fn null() -> Vec<u8> {
    tlv(NULL, &[])
}

/// Encode an OCTET STRING.
pub fn octet_string(data: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, data)
}

/// Encode a BIT STRING with `unused` unused trailing bits.
pub fn bit_string(unused: u8, data: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(data.len() + 1);
    content.push(unused);
    content.extend_from_slice(data);
    tlv(BIT_STRING, &content)
}

/// The content octets of a BIT STRING with no unused bits, for IMPLICIT
/// tagging.
pub fn bit_string_payload(data: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(data.len() + 1);
    content.push(0);
    content.extend_from_slice(data);
    content
}

/// Encode an OBJECT IDENTIFIER.
pub fn oid(oid: &ObjectIdentifier) -> Vec<u8> {
    tlv(OBJECT_IDENTIFIER, &oid.to_der_content())
}

/// Encode a SEQUENCE from already-encoded content.
pub fn sequence(content: &[u8]) -> Vec<u8> {
    tlv(SEQUENCE, content)
}

/// Encode a SET from already-encoded content.
pub fn set(content: &[u8]) -> Vec<u8> {
    tlv(SET, content)
}

/// Encode a UTF8String.
pub fn utf8_string(value: &str) -> Vec<u8> {
    tlv(UTF8_STRING, value.as_bytes())
}

/// Encode a PrintableString.
pub fn printable_string(value: &str) -> Vec<u8> {
    tlv(PRINTABLE_STRING, value.as_bytes())
}

/// Encode an IA5String.
pub fn ia5_string(value: &str) -> Vec<u8> {
    tlv(IA5_STRING, value.as_bytes())
}

/// Encode a raw string with the given universal tag.
pub fn string_with_tag(tag: Tag, value: &[u8]) -> Vec<u8> {
    tlv(tag, value)
}

/// Encode a UTCTime.
pub fn utc_time(time: &Asn1Time) -> Vec<u8> {
    tlv(UTC_TIME, &time.encode_utc())
}

/// Encode a GeneralizedTime.
pub fn generalized_time(time: &Asn1Time) -> Vec<u8> {
    tlv(GENERALIZED_TIME, &time.encode_generalized())
}

/// Encode a time using its preferred wire form, falling back to
/// GeneralizedTime when the year does not fit UTCTime.
pub fn time(time: &Asn1Time) -> Vec<u8> {
    if time.utc && (1950..=2049).contains(&time.year) {
        utc_time(time)
    } else {
        generalized_time(time)
    }
}

/// Encode `[number] EXPLICIT` around already-encoded inner content.
pub fn explicit(number: u32, content: &[u8]) -> Vec<u8> {
    tlv(Tag::context_constructed(number), content)
}

/// Encode `[number] IMPLICIT` around raw content.
pub fn implicit(number: u32, constructed: bool, content: &[u8]) -> Vec<u8> {
    tlv(
        Tag {
            class: Class::ContextSpecific,
            constructed,
            number,
        },
        content,
    )
}

/// Encode an AlgorithmIdentifier: `SEQUENCE { OID, parameters OPTIONAL }`.
pub fn algorithm_identifier(oid: &ObjectIdentifier, parameters: Option<&[u8]>) -> Vec<u8> {
    let mut content = self::oid(oid);
    if let Some(parameters) = parameters {
        content.extend_from_slice(parameters);
    }
    sequence(&content)
}
