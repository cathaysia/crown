//! X.500 distinguished names.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::asn1::der::{self, Reader, Tag};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::error::{CryptoError, CryptoResult};

/// A single `AttributeTypeAndValue` (`SEQUENCE { type OID, value ANY }`).
///
/// The value keeps its original string tag and bytes so re-encoding a parsed
/// name is byte-exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeTypeAndValue {
    /// Attribute type OID.
    pub oid: ObjectIdentifier,
    /// The string type's universal tag.
    pub tag: Tag,
    /// Raw string content octets.
    pub value: Vec<u8>,
}

impl AttributeTypeAndValue {
    /// Build a UTF8String-valued attribute.
    pub fn from_utf8(oid: ObjectIdentifier, value: &str) -> Self {
        AttributeTypeAndValue {
            oid,
            tag: der::UTF8_STRING,
            value: value.as_bytes().to_vec(),
        }
    }

    /// Build a PrintableString-valued attribute.
    pub fn from_printable(oid: ObjectIdentifier, value: &str) -> Self {
        AttributeTypeAndValue {
            oid,
            tag: der::PRINTABLE_STRING,
            value: value.as_bytes().to_vec(),
        }
    }

    /// Parse an `AttributeTypeAndValue`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let oid = seq.read_oid()?;
        let (tag, value) = seq.read_tlv()?;
        if !matches!(tag.class, der::Class::Universal) || tag.constructed {
            return Err(CryptoError::StrError("x509: invalid name attribute"));
        }
        seq.expect_end()?;
        Ok(AttributeTypeAndValue {
            oid,
            tag,
            value: value.to_vec(),
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.oid);
        content.extend_from_slice(&der::string_with_tag(self.tag, &self.value));
        der::sequence(&content)
    }

    /// The value decoded as text.
    pub fn text(&self) -> CryptoResult<String> {
        der::decode_string(self.tag, &self.value)
    }
}

/// A relative distinguished name: `SET OF AttributeTypeAndValue`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rdn {
    /// The attributes in this RDN.
    pub attributes: Vec<AttributeTypeAndValue>,
}

/// An X.500 `Name`: `SEQUENCE OF RelativeDistinguishedName`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Name {
    /// The RDNs, most-significant first.
    pub rdns: Vec<Rdn>,
}

impl Name {
    /// Build a name from a single common-name attribute.
    pub fn from_common_name(common_name: &str) -> Self {
        Name {
            rdns: alloc::vec![Rdn {
                attributes: alloc::vec![AttributeTypeAndValue::from_utf8(
                    ObjectIdentifier::new(oid::OID_AT_COMMON_NAME).expect("static oid"),
                    common_name,
                )],
            }],
        }
    }

    /// Parse a `Name`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let mut rdns = Vec::new();
        while !seq.is_empty() {
            let mut set = seq.read_set()?;
            let mut attributes = Vec::new();
            while !set.is_empty() {
                attributes.push(AttributeTypeAndValue::parse(&mut set)?);
            }
            rdns.push(Rdn { attributes });
        }
        Ok(Name { rdns })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for rdn in &self.rdns {
            let mut set_content = Vec::new();
            for attribute in &rdn.attributes {
                set_content.extend_from_slice(&attribute.encode());
            }
            content.extend_from_slice(&der::set(&set_content));
        }
        der::sequence(&content)
    }

    /// All attributes in order.
    pub fn iter_attributes(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.rdns.iter().flat_map(|rdn| rdn.attributes.iter())
    }

    /// The first attribute with the given OID.
    pub fn get(&self, arcs: &[u64]) -> Option<&AttributeTypeAndValue> {
        self.iter_attributes().find(|attr| attr.oid.matches(arcs))
    }

    /// Every attribute with the given OID.
    pub fn get_all(&self, arcs: &[u64]) -> Vec<&AttributeTypeAndValue> {
        self.iter_attributes()
            .filter(|attr| attr.oid.matches(arcs))
            .collect()
    }

    /// The common name, decoded as text.
    pub fn common_name(&self) -> Option<String> {
        self.get(oid::OID_AT_COMMON_NAME)
            .and_then(|attr| attr.text().ok())
    }

    /// The organization name, decoded as text.
    pub fn organization(&self) -> Option<String> {
        self.get(oid::OID_AT_ORGANIZATION)
            .and_then(|attr| attr.text().ok())
    }

    /// The country name, decoded as text.
    pub fn country(&self) -> Option<String> {
        self.get(oid::OID_AT_COUNTRY)
            .and_then(|attr| attr.text().ok())
    }

    /// The email address, decoded as text.
    pub fn email_address(&self) -> Option<String> {
        self.get(oid::OID_AT_EMAIL_ADDRESS)
            .and_then(|attr| attr.text().ok())
    }
}

impl fmt::Display for Name {
    /// Render in the RFC 4514 style, e.g. `CN=example.com,O=Example`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for rdn in &self.rdns {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            let mut first_attr = true;
            for attribute in &rdn.attributes {
                if !first_attr {
                    f.write_str("+")?;
                }
                first_attr = false;
                match short_name(&attribute.oid) {
                    Some(name) => f.write_str(name)?,
                    None => {
                        let dotted = attribute.oid.to_string();
                        f.write_str(&dotted)?;
                    }
                }
                f.write_str("=")?;
                let value = attribute.text().unwrap_or_else(|_| String::new());
                f.write_str(&escape_rfc4514(&value))?;
            }
        }
        Ok(())
    }
}

/// The conventional short name for a name attribute OID.
fn short_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    let table: &[(&[u64], &str)] = &[
        (oid::OID_AT_COMMON_NAME, "CN"),
        (oid::OID_AT_COUNTRY, "C"),
        (oid::OID_AT_LOCALITY, "L"),
        (oid::OID_AT_STATE, "ST"),
        (oid::OID_AT_ORGANIZATION, "O"),
        (oid::OID_AT_ORGANIZATIONAL_UNIT, "OU"),
        (oid::OID_AT_SERIAL_NUMBER, "SERIALNUMBER"),
        (oid::OID_AT_STREET, "STREET"),
        (oid::OID_AT_TITLE, "T"),
        (oid::OID_AT_SURNAME, "SN"),
        (oid::OID_AT_GIVEN_NAME, "GN"),
        (oid::OID_AT_INITIALS, "I"),
        (oid::OID_AT_DN_QUALIFIER, "dnQualifier"),
        (oid::OID_AT_EMAIL_ADDRESS, "emailAddress"),
        (oid::OID_AT_DOMAIN_COMPONENT, "DC"),
        (oid::OID_AT_USER_ID, "UID"),
    ];
    table
        .iter()
        .find(|(arcs, _)| oid.matches(arcs))
        .map(|(_, name)| *name)
}

/// Escape a value following RFC 4514 section 2.4.
fn escape_rfc4514(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        let first = i == 0;
        let last = i + c.len_utf8() == value.len();
        let needs_escape = matches!(c, '"' | '+' | ',' | ';' | '<' | '>' | '\\')
            || (first && (c == ' ' || c == '#'))
            || (last && c == ' ');
        if needs_escape {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
