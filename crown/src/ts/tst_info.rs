//! RFC 3161 `TSTInfo` and `Accuracy`.

use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::ObjectIdentifier;
use crate::asn1::time::Asn1Time;
use crate::error::{CryptoError, CryptoResult};
use crate::x509::extensions::{Extension, GeneralName};

use super::request::MessageImprint;

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER
/// (1..999) OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Accuracy {
    /// Seconds of accuracy.
    pub seconds: Option<u32>,
    /// Milliseconds of accuracy, 1..=999.
    pub millis: Option<u16>,
    /// Microseconds of accuracy, 1..=999.
    pub micros: Option<u16>,
}

impl Accuracy {
    /// Parse an `Accuracy`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let seconds = if !seq.is_empty() && seq.peek_tag()? == der::INTEGER {
            let value = seq.read_integer_i64()?;
            Some(
                u32::try_from(value)
                    .map_err(|_| CryptoError::StrError("ts: invalid accuracy seconds"))?,
            )
        } else {
            None
        };
        let millis = read_accuracy_component(&mut seq, 0)?;
        let micros = read_accuracy_component(&mut seq, 1)?;
        seq.expect_end()?;
        Ok(Accuracy {
            seconds,
            millis,
            micros,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(seconds) = self.seconds {
            content.extend_from_slice(&der::integer(&seconds.to_be_bytes()));
        }
        if let Some(millis) = self.millis {
            content.extend_from_slice(&der::implicit(0, false, &integer_content(millis as u64)));
        }
        if let Some(micros) = self.micros {
            content.extend_from_slice(&der::implicit(1, false, &integer_content(micros as u64)));
        }
        der::sequence(&content)
    }
}

/// Read an `[n] IMPLICIT INTEGER (1..999)` accuracy component.
fn read_accuracy_component(reader: &mut Reader<'_>, number: u32) -> CryptoResult<Option<u16>> {
    if reader.is_empty() || reader.peek_tag()? != der::Tag::context(number) {
        return Ok(None);
    }
    let content = reader.read_implicit(number, false)?;
    let integer_der = der::tlv(der::INTEGER, content);
    let mut integer = Reader::new(&integer_der);
    let value = integer.read_integer_i64()?;
    if !(1..=999).contains(&value) {
        return Err(CryptoError::StrError("ts: invalid accuracy component"));
    }
    Ok(Some(value as u16))
}

/// The content octets of a DER INTEGER for a non-negative value.
pub(crate) fn integer_content(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = Vec::with_capacity(bytes.len() - first + 1);
    if bytes[first] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes[first..]);
    content
}

/// Parse an `[n] IMPLICIT Extensions` value.
pub(crate) fn parse_extensions_implicit(
    reader: &mut Reader<'_>,
    number: u32,
) -> CryptoResult<Vec<Extension>> {
    let content = reader.read_implicit(number, true)?;
    // The declared form is IMPLICIT, so the extensions are direct elements.
    if let Ok(extensions) = parse_extension_elements(content) {
        return Ok(extensions);
    }
    // Tolerate an explicit SEQUENCE wrapper seen in some encoders.
    let mut inner = Reader::new(content);
    let mut seq = inner.read_sequence()?;
    inner.expect_end()?;
    parse_extension_elements_bytes(&mut seq)
}

fn parse_extension_elements(content: &[u8]) -> CryptoResult<Vec<Extension>> {
    let mut reader = Reader::new(content);
    let extensions = parse_extension_elements_bytes(&mut reader)?;
    reader.expect_end()?;
    Ok(extensions)
}

fn parse_extension_elements_bytes(reader: &mut Reader<'_>) -> CryptoResult<Vec<Extension>> {
    let mut extensions = Vec::new();
    while !reader.is_empty() {
        extensions.push(Extension::parse(reader)?);
    }
    Ok(extensions)
}

/// Encode an `[n] IMPLICIT Extensions` value.
pub(crate) fn encode_extensions_implicit(extensions: &[Extension], number: u32) -> Vec<u8> {
    let mut content = Vec::new();
    for extension in extensions {
        content.extend_from_slice(&extension.encode());
    }
    der::implicit(number, true, &content)
}

/// `TSTInfo ::= SEQUENCE { version INTEGER { v1(1) }, policy TSAPolicyId,
/// messageImprint MessageImprint, serialNumber INTEGER, genTime
/// GeneralizedTime, accuracy Accuracy OPTIONAL, ordering BOOLEAN DEFAULT
/// FALSE, nonce INTEGER OPTIONAL, tsa [0] GeneralName OPTIONAL, extensions
/// [1] IMPLICIT Extensions OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TstInfo {
    /// Protocol version, always 1.
    pub version: u8,
    /// The TSA policy under which the token was issued.
    pub policy: ObjectIdentifier,
    /// Copy of the request's message imprint.
    pub message_imprint: MessageImprint,
    /// The token's serial number magnitude.
    pub serial_number: Vec<u8>,
    /// The generation time (always a GeneralizedTime on the wire).
    pub gen_time: Asn1Time,
    /// Accuracy of `gen_time`.
    pub accuracy: Option<Accuracy>,
    /// Whether the TSA guarantees monotonic ordering.
    pub ordering: bool,
    /// Copy of the request's nonce, when one was supplied.
    pub nonce: Option<Vec<u8>>,
    /// The TSA name.
    pub tsa: Option<GeneralName>,
    /// Token extensions.
    pub extensions: Option<Vec<Extension>>,
}

impl TstInfo {
    /// Parse a DER `TSTInfo`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let info = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(info)
    }

    /// Parse a `TSTInfo` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("ts: invalid TSTInfo version"))?;
        if version != 1 {
            return Err(CryptoError::StrError("ts: unsupported TSTInfo version"));
        }
        let policy = seq.read_oid()?;
        let message_imprint = MessageImprint::parse(&mut seq)?;
        let serial_number = seq.read_integer()?.to_vec();
        let gen_time = seq.read_generalized_time()?;
        let accuracy = if !seq.is_empty() && seq.peek_tag()? == der::SEQUENCE {
            Some(Accuracy::parse(&mut seq)?)
        } else {
            None
        };
        let ordering = if !seq.is_empty() && seq.peek_tag()? == der::BOOLEAN {
            seq.read_boolean()?
        } else {
            false
        };
        let nonce = if !seq.is_empty() && seq.peek_tag()? == der::INTEGER {
            Some(seq.read_integer()?.to_vec())
        } else {
            None
        };
        let tsa = if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
            let mut inner = seq.read_explicit(0)?;
            let name = GeneralName::parse(&mut inner)?;
            inner.expect_end()?;
            Some(name)
        } else {
            None
        };
        let extensions = if !seq.is_empty() {
            Some(parse_extensions_implicit(&mut seq, 1)?)
        } else {
            None
        };
        seq.expect_end()?;
        Ok(TstInfo {
            version,
            policy,
            message_imprint,
            serial_number,
            gen_time,
            accuracy,
            ordering,
            nonce,
            tsa,
            extensions,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&der::oid(&self.policy));
        content.extend_from_slice(&self.message_imprint.encode());
        content.extend_from_slice(&der::integer(&self.serial_number));
        // genTime is always a GeneralizedTime (RFC 3161).
        content.extend_from_slice(&der::generalized_time(&self.gen_time));
        if let Some(accuracy) = &self.accuracy {
            content.extend_from_slice(&accuracy.encode());
        }
        if self.ordering {
            content.extend_from_slice(&der::boolean(true));
        }
        if let Some(nonce) = &self.nonce {
            content.extend_from_slice(&der::integer(nonce));
        }
        if let Some(tsa) = &self.tsa {
            content.extend_from_slice(&der::explicit(0, &tsa.encode()));
        }
        if let Some(extensions) = &self.extensions {
            content.extend_from_slice(&encode_extensions_implicit(extensions, 1));
        }
        der::sequence(&content)
    }
}
