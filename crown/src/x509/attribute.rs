//! PKCS#9-style `Attribute` values, shared by PKCS#10 and CMS.

use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::ObjectIdentifier;
use crate::error::{CryptoError, CryptoResult};

/// `Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }`.
///
/// Values are kept as full DER TLVs so callers can decode the specific
/// syntax they expect (digest, time, string, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Attribute type OID.
    pub oid: ObjectIdentifier,
    /// The attribute values, each a complete DER element.
    pub values: Vec<Vec<u8>>,
}

impl Attribute {
    /// Build an attribute from raw DER values.
    pub fn new(oid: ObjectIdentifier, values: Vec<Vec<u8>>) -> Self {
        Attribute { oid, values }
    }

    /// Parse an `Attribute`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let oid = seq.read_oid()?;
        let mut set = seq.read_set()?;
        let mut values = Vec::new();
        while !set.is_empty() {
            values.push(set.read_raw_tlv()?.to_vec());
        }
        seq.expect_end()?;
        Ok(Attribute { oid, values })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.oid);
        let mut set_content = Vec::new();
        for value in &self.values {
            set_content.extend_from_slice(value);
        }
        content.extend_from_slice(&der::set(&set_content));
        der::sequence(&content)
    }

    /// The first value decoded as text, when it is a string type.
    pub fn first_text(&self) -> Option<alloc::string::String> {
        let value = self.values.first()?;
        let mut reader = Reader::new(value);
        reader.read_directory_string().ok()
    }
}

/// Parse a `SET OF Attribute`.
pub fn parse_attributes(reader: &mut Reader<'_>) -> CryptoResult<Vec<Attribute>> {
    let mut set = reader.read_set()?;
    let mut attributes = Vec::new();
    while !set.is_empty() {
        attributes.push(Attribute::parse(&mut set)?);
    }
    Ok(attributes)
}

/// Encode a `SET OF Attribute`.
pub fn encode_attributes(attributes: &[Attribute]) -> Vec<u8> {
    let mut content = Vec::new();
    for attribute in attributes {
        content.extend_from_slice(&attribute.encode());
    }
    der::set(&content)
}

/// Build a `messageDigest` attribute (PKCS#9).
pub fn message_digest(digest: &[u8]) -> Attribute {
    Attribute::new(
        ObjectIdentifier::new(crate::asn1::oid::OID_PKCS9_MESSAGE_DIGEST).expect("static oid"),
        alloc::vec![der::octet_string(digest)],
    )
}

/// Build a `contentType` attribute (PKCS#9).
pub fn content_type(content_type: &ObjectIdentifier) -> Attribute {
    Attribute::new(
        ObjectIdentifier::new(crate::asn1::oid::OID_PKCS9_CONTENT_TYPE).expect("static oid"),
        alloc::vec![der::oid(content_type)],
    )
}

/// Build a `signingTime` attribute (PKCS#9).
pub fn signing_time(time: &crate::asn1::time::Asn1Time) -> Attribute {
    Attribute::new(
        ObjectIdentifier::new(crate::asn1::oid::OID_PKCS9_SIGNING_TIME).expect("static oid"),
        alloc::vec![der::utc_time(time)],
    )
}

/// Build a `friendlyName` attribute (PKCS#9).
pub fn friendly_name(name: &str) -> Attribute {
    Attribute::new(
        ObjectIdentifier::new(crate::asn1::oid::OID_PKCS9_FRIENDLY_NAME).expect("static oid"),
        alloc::vec![der::utf8_string(name)],
    )
}

/// Build a `localKeyId` attribute (PKCS#9).
pub fn local_key_id(id: &[u8]) -> Attribute {
    Attribute::new(
        ObjectIdentifier::new(crate::asn1::oid::OID_PKCS9_LOCAL_KEY_ID).expect("static oid"),
        alloc::vec![der::octet_string(id)],
    )
}

/// Decode an `Attribute`'s first value as an OCTET STRING.
pub fn octet_string_value(attribute: &Attribute) -> CryptoResult<&[u8]> {
    let value = attribute
        .values
        .first()
        .ok_or(CryptoError::StrError("pkcs: empty attribute"))?;
    let mut reader = Reader::new(value);
    reader.read_octet_string()
}
