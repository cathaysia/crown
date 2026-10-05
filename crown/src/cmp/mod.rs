//! CMP (RFC 4210 / RFC 9481 / RFC 9810) message structures and protection.
//!
//! This module implements the CMP message layer:
//!
//! - [`PkiMessage`] with its [`PkiHeader`], [`PkiBody`] and optional
//!   `extraCerts`, DER and PEM encoded;
//! - [`PkiBody`] variants for the requests an end entity sends (`ir`, `cr`,
//!   `kur`, `p10cr`, `rr`, `ccr`, `genm`) and the messages it receives or
//!   sends (`genp`, `error`, `certConf`, `pkiconf`, `pollReq`, `pollRep`);
//!   unknown body tags are preserved as [`PkiBody::Other`];
//! - [`InfoTypeAndValue`] general-info helpers for `implicitConfirm`,
//!   `confirmWaitTime`, `certProfile` and `caCerts`;
//! - [`PkiStatusInfo`] with the RFC 4210 status names and failure-info bits;
//! - message protection per RFC 4210 section 5.1.3: signature protection
//!   ([`PkiMessage::protect_signature`] / [`PkiMessage::verify_signature`])
//!   and password-based MAC protection
//!   ([`PkiMessage::protect_password`] / [`PkiMessage::verify_password`])
//!   using `id-PasswordBasedMac` with a [`crate::crmf::PbmParameter`].
//!
//! The protected part is `SEQUENCE { header, body }` exactly as specified in
//! RFC 4210 section 5.1.3 (extraCerts are *not* covered), which is also what
//! OpenSSL's `cmp` app computes. `pvno` values 1 (`cmp1999`), 2 (`cmp2000`)
//! and 3 (`cmp2021`, the version introduced for `EnvelopedData` support by
//! RFC 9480/9810) are accepted.
//!
//! ```
//! use crown::cmp::PkiMessage;
//!
//! # fn main() -> Result<(), crown::error::CryptoError> {
//! let der = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/cmp_ir_secret.der"));
//! # let der = der.unwrap_or_default();
//! let message = PkiMessage::parse(&der)?;
//! assert_eq!(message.header.pvno, 2);
//! assert!(message.verify_password(b"test")?);
//! # Ok(())
//! # }
//! ```
//!
//! Server-side transaction state machines (polling, confirmation sequencing,
//! enrollment policy) are out of scope; this is the message layer only.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::ObjectIdentifier;
use crate::asn1::pem;
use crate::asn1::time::Asn1Time;
use crate::crmf::{CertReqMessages, PbmParameter, OID_ID_PASSWORD_BASED_MAC};
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash, SignatureAlgorithm};
use crate::x509::cert::Certificate;
use crate::x509::csr::CertificationRequest;
use crate::x509::extensions::{Extension, GeneralName};
use crate::x509::keys::PrivateKey;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// CMP 1999 (`pvno` 1).
pub const PVNO_CMP1999: u8 = 1;
/// CMP 2000, the RFC 4210 protocol version (`pvno` 2).
pub const PVNO_CMP2000: u8 = 2;
/// CMP 2021, the `EnvelopedData`-capable version from RFC 9480/9810 (`pvno` 3).
pub const PVNO_CMP2021: u8 = 3;

/// `id-it-implicitConfirm` (1.3.6.1.5.5.7.4.13).
pub const OID_IT_IMPLICIT_CONFIRM: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 4, 13];
/// `id-it-confirmWaitTime` (1.3.6.1.5.5.7.4.14).
pub const OID_IT_CONFIRM_WAIT_TIME: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 4, 14];
/// `id-it-caCerts` (1.3.6.1.5.5.7.4.17, RFC 9480).
pub const OID_IT_CA_CERTS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 4, 17];
/// `id-it-certProfile` (1.3.6.1.5.5.7.4.21, RFC 9480).
pub const OID_IT_CERT_PROFILE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 4, 21];

/// PKI status value `accepted`.
pub const PKI_STATUS_ACCEPTED: u8 = 0;
/// PKI status value `grantedWithMods`.
pub const PKI_STATUS_GRANTED_WITH_MODS: u8 = 1;
/// PKI status value `rejection`.
pub const PKI_STATUS_REJECTION: u8 = 2;
/// PKI status value `waiting`.
pub const PKI_STATUS_WAITING: u8 = 3;
/// PKI status value `revocationWarning`.
pub const PKI_STATUS_REVOCATION_WARNING: u8 = 4;
/// PKI status value `revocationNotification`.
pub const PKI_STATUS_REVOCATION_NOTIFICATION: u8 = 5;
/// PKI status value `keyUpdateWarning`.
pub const PKI_STATUS_KEY_UPDATE_WARNING: u8 = 6;

/// The RFC 4210 name of a PKI status value.
pub fn pki_status_name(status: u8) -> &'static str {
    match status {
        PKI_STATUS_ACCEPTED => "accepted",
        PKI_STATUS_GRANTED_WITH_MODS => "grantedWithMods",
        PKI_STATUS_REJECTION => "rejection",
        PKI_STATUS_WAITING => "waiting",
        PKI_STATUS_REVOCATION_WARNING => "revocationWarning",
        PKI_STATUS_REVOCATION_NOTIFICATION => "revocationNotification",
        PKI_STATUS_KEY_UPDATE_WARNING => "keyUpdateWarning",
        _ => "unknown",
    }
}

const FAIL_INFO_NAMES: [&str; 27] = [
    "badAlg",
    "badMessageCheck",
    "badRequest",
    "badTime",
    "badCertId",
    "badDataFormat",
    "wrongAuthority",
    "incorrectData",
    "missingTimeStamp",
    "badPOP",
    "certRevoked",
    "certConfirmed",
    "wrongIntegrity",
    "badRecipientNonce",
    "timeNotAvailable",
    "unacceptedPolicy",
    "unacceptedExtension",
    "addInfoNotAvailable",
    "badSenderNonce",
    "badCertTemplate",
    "signerNotTrusted",
    "transactionIdInUse",
    "unsupportedVersion",
    "notAuthorized",
    "systemUnavail",
    "systemFailure",
    "duplicateCertReq",
];

/// Build an [`ObjectIdentifier`] from trusted literal arcs.
fn oid_of(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("static oid")
}

// ---------------------------------------------------------------------------
// InfoTypeAndValue
// ---------------------------------------------------------------------------

/// `InfoTypeAndValue ::= SEQUENCE { infoType OID, infoValue ANY OPTIONAL }`.
///
/// The value is kept as the raw DER of the value element; the typed
/// accessors decode the well-known `id-it-*` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoTypeAndValue {
    /// The `infoType` OID.
    pub info_type: ObjectIdentifier,
    /// Raw DER of `infoValue`, when present.
    pub info_value: Option<Vec<u8>>,
}

impl InfoTypeAndValue {
    /// Build an info-type-and-value pair.
    pub fn new(info_type: ObjectIdentifier, info_value: Option<Vec<u8>>) -> Self {
        InfoTypeAndValue {
            info_type,
            info_value,
        }
    }

    /// The `implicitConfirm` general info (`NULL` value).
    pub fn implicit_confirm() -> Self {
        InfoTypeAndValue {
            info_type: oid_of(OID_IT_IMPLICIT_CONFIRM),
            info_value: Some(der::null()),
        }
    }

    /// The `confirmWaitTime` general info (`GeneralizedTime` value).
    pub fn confirm_wait_time(time: &Asn1Time) -> Self {
        InfoTypeAndValue {
            info_type: oid_of(OID_IT_CONFIRM_WAIT_TIME),
            info_value: Some(der::generalized_time(time)),
        }
    }

    /// The `certProfile` general info (`SEQUENCE OF UTF8String` value).
    pub fn cert_profile(profiles: &[&str]) -> Self {
        let mut content = Vec::new();
        for profile in profiles {
            content.extend_from_slice(&der::utf8_string(profile));
        }
        InfoTypeAndValue {
            info_type: oid_of(OID_IT_CERT_PROFILE),
            info_value: Some(der::sequence(&content)),
        }
    }

    /// The `caCerts` general info (`SEQUENCE OF CMPCertificate` value).
    pub fn ca_certs(certs: &[Certificate]) -> Self {
        let mut content = Vec::new();
        for cert in certs {
            content.extend_from_slice(&cert.encode());
        }
        InfoTypeAndValue {
            info_type: oid_of(OID_IT_CA_CERTS),
            info_value: Some(der::sequence(&content)),
        }
    }

    /// Parse an `InfoTypeAndValue`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let info_type = seq.read_oid()?;
        let info_value = if seq.is_empty() {
            None
        } else {
            Some(seq.read_raw_tlv()?.to_vec())
        };
        seq.expect_end()?;
        Ok(InfoTypeAndValue {
            info_type,
            info_value,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.info_type);
        if let Some(value) = &self.info_value {
            content.extend_from_slice(value);
        }
        der::sequence(&content)
    }

    /// Whether this is an `implicitConfirm` entry.
    pub fn is_implicit_confirm(&self) -> bool {
        self.info_type.matches(OID_IT_IMPLICIT_CONFIRM)
    }

    /// The `confirmWaitTime` value, when present and well formed.
    pub fn confirm_wait_time_value(&self) -> CryptoResult<Option<Asn1Time>> {
        if !self.info_type.matches(OID_IT_CONFIRM_WAIT_TIME) {
            return Ok(None);
        }
        let Some(value) = &self.info_value else {
            return Ok(None);
        };
        let mut reader = Reader::new(value);
        Ok(Some(reader.read_time()?))
    }

    /// The `certProfile` values, when present and well formed.
    pub fn cert_profile_value(&self) -> CryptoResult<Vec<String>> {
        if !self.info_type.matches(OID_IT_CERT_PROFILE) {
            return Ok(Vec::new());
        }
        let Some(value) = &self.info_value else {
            return Ok(Vec::new());
        };
        let mut reader = Reader::new(value);
        let mut seq = reader.read_sequence()?;
        let mut profiles = Vec::new();
        while !seq.is_empty() {
            profiles.push(seq.read_directory_string()?);
        }
        Ok(profiles)
    }

    /// The `caCerts` certificates, when present and well formed.
    pub fn ca_certs_value(&self) -> CryptoResult<Vec<Certificate>> {
        if !self.info_type.matches(OID_IT_CA_CERTS) {
            return Ok(Vec::new());
        }
        let Some(value) = &self.info_value else {
            return Ok(Vec::new());
        };
        let mut reader = Reader::new(value);
        let mut seq = reader.read_sequence()?;
        let mut certs = Vec::new();
        while !seq.is_empty() {
            certs.push(Certificate::parse(seq.read_raw_tlv()?)?);
        }
        Ok(certs)
    }
}

/// Parse `SEQUENCE OF InfoTypeAndValue`.
fn parse_info_values(reader: &mut Reader<'_>) -> CryptoResult<Vec<InfoTypeAndValue>> {
    let mut seq = reader.read_sequence()?;
    let mut values = Vec::new();
    while !seq.is_empty() {
        values.push(InfoTypeAndValue::parse(&mut seq)?);
    }
    Ok(values)
}

/// Encode `SEQUENCE OF InfoTypeAndValue`.
fn encode_info_values(values: &[InfoTypeAndValue]) -> Vec<u8> {
    let mut content = Vec::new();
    for value in values {
        content.extend_from_slice(&value.encode());
    }
    der::sequence(&content)
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// `PKIHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiHeader {
    /// Protocol version: 1 (`cmp1999`), 2 (`cmp2000`) or 3 (`cmp2021`).
    pub pvno: u8,
    /// Sender general name.
    pub sender: GeneralName,
    /// Recipient general name.
    pub recipient: GeneralName,
    /// `[0] messageTime`.
    pub message_time: Option<Asn1Time>,
    /// `[1] protectionAlg`.
    pub protection_alg: Option<AlgorithmIdentifier>,
    /// `[2] senderKID`.
    pub sender_kid: Option<Vec<u8>>,
    /// `[3] recipKID`.
    pub recip_kid: Option<Vec<u8>>,
    /// `[4] transactionID`.
    pub transaction_id: Option<Vec<u8>>,
    /// `[5] senderNonce`.
    pub sender_nonce: Option<Vec<u8>>,
    /// `[6] recipNonce`.
    pub recip_nonce: Option<Vec<u8>>,
    /// `[7] freeText` (the first string when several are present).
    pub free_text: Option<String>,
    /// `[8] generalInfo`.
    pub general_info: Vec<InfoTypeAndValue>,
}

impl PkiHeader {
    /// A CMP 2000 header between two general names.
    pub fn new(sender: GeneralName, recipient: GeneralName) -> Self {
        PkiHeader {
            pvno: PVNO_CMP2000,
            sender,
            recipient,
            message_time: None,
            protection_alg: None,
            sender_kid: None,
            recip_kid: None,
            transaction_id: None,
            sender_nonce: None,
            recip_nonce: None,
            free_text: None,
            general_info: Vec::new(),
        }
    }

    /// Parse a `PKIHeader`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let pvno_value = seq.read_integer_i64()?;
        let pvno =
            u8::try_from(pvno_value).map_err(|_| CryptoError::StrError("cmp: invalid pvno"))?;
        let sender = GeneralName::parse(&mut seq)?;
        let recipient = GeneralName::parse(&mut seq)?;
        let mut header = PkiHeader::new(sender, recipient);
        header.pvno = pvno;
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag.class != der::Class::ContextSpecific || !tag.constructed {
                return Err(CryptoError::StrError("cmp: invalid PKIHeader"));
            }
            match tag.number {
                0 => {
                    let mut inner = seq.read_explicit(0)?;
                    header.message_time = Some(inner.read_time()?);
                }
                1 => {
                    let mut inner = seq.read_explicit(1)?;
                    header.protection_alg = Some(AlgorithmIdentifier::parse(&mut inner)?);
                }
                2 => {
                    let mut inner = seq.read_explicit(2)?;
                    header.sender_kid = Some(inner.read_octet_string()?.to_vec());
                }
                3 => {
                    let mut inner = seq.read_explicit(3)?;
                    header.recip_kid = Some(inner.read_octet_string()?.to_vec());
                }
                4 => {
                    let mut inner = seq.read_explicit(4)?;
                    header.transaction_id = Some(inner.read_octet_string()?.to_vec());
                }
                5 => {
                    let mut inner = seq.read_explicit(5)?;
                    header.sender_nonce = Some(inner.read_octet_string()?.to_vec());
                }
                6 => {
                    let mut inner = seq.read_explicit(6)?;
                    header.recip_nonce = Some(inner.read_octet_string()?.to_vec());
                }
                7 => {
                    let mut inner = seq.read_explicit(7)?;
                    let mut strings = inner.read_sequence()?;
                    while !strings.is_empty() {
                        let text = strings.read_directory_string()?;
                        if header.free_text.is_none() {
                            header.free_text = Some(text);
                        }
                    }
                }
                8 => {
                    let mut inner = seq.read_explicit(8)?;
                    header.general_info = parse_info_values(&mut inner)?;
                }
                _ => return Err(CryptoError::StrError("cmp: invalid PKIHeader")),
            }
        }
        Ok(header)
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.pvno]);
        content.extend_from_slice(&self.sender.encode());
        content.extend_from_slice(&self.recipient.encode());
        if let Some(time) = &self.message_time {
            content.extend_from_slice(&der::explicit(0, &der::time(time)));
        }
        if let Some(alg) = &self.protection_alg {
            content.extend_from_slice(&der::explicit(1, &alg.encode()));
        }
        if let Some(kid) = &self.sender_kid {
            content.extend_from_slice(&der::explicit(2, &der::octet_string(kid)));
        }
        if let Some(kid) = &self.recip_kid {
            content.extend_from_slice(&der::explicit(3, &der::octet_string(kid)));
        }
        if let Some(id) = &self.transaction_id {
            content.extend_from_slice(&der::explicit(4, &der::octet_string(id)));
        }
        if let Some(nonce) = &self.sender_nonce {
            content.extend_from_slice(&der::explicit(5, &der::octet_string(nonce)));
        }
        if let Some(nonce) = &self.recip_nonce {
            content.extend_from_slice(&der::explicit(6, &der::octet_string(nonce)));
        }
        if let Some(text) = &self.free_text {
            content.extend_from_slice(&der::explicit(7, &der::sequence(&der::utf8_string(text))));
        }
        if !self.general_info.is_empty() {
            content.extend_from_slice(&der::explicit(8, &encode_info_values(&self.general_info)));
        }
        der::sequence(&content)
    }

    /// The general-info entry with the given OID.
    pub fn general_info_entry(&self, arcs: &[u64]) -> Option<&InfoTypeAndValue> {
        self.general_info
            .iter()
            .find(|value| value.info_type.matches(arcs))
    }

    /// Whether the header requests implicit confirmation.
    pub fn implicit_confirm(&self) -> bool {
        self.general_info
            .iter()
            .any(InfoTypeAndValue::is_implicit_confirm)
    }

    /// The `confirmWaitTime`, when present.
    pub fn confirm_wait_time(&self) -> CryptoResult<Option<Asn1Time>> {
        match self.general_info_entry(OID_IT_CONFIRM_WAIT_TIME) {
            Some(value) => value.confirm_wait_time_value(),
            None => Ok(None),
        }
    }

    /// The `certProfile` values, when present.
    pub fn cert_profiles(&self) -> CryptoResult<Vec<String>> {
        match self.general_info_entry(OID_IT_CERT_PROFILE) {
            Some(value) => value.cert_profile_value(),
            None => Ok(Vec::new()),
        }
    }

    /// The `caCerts` certificates, when present.
    pub fn ca_certs(&self) -> CryptoResult<Vec<Certificate>> {
        match self.general_info_entry(OID_IT_CA_CERTS) {
            Some(value) => value.ca_certs_value(),
            None => Ok(Vec::new()),
        }
    }

    /// Add a general-info entry (replacing an existing entry of the same
    /// type).
    pub fn set_general_info(&mut self, value: InfoTypeAndValue) {
        self.general_info
            .retain(|existing| existing.info_type != value.info_type);
        self.general_info.push(value);
    }
}

// ---------------------------------------------------------------------------
// Body
// ---------------------------------------------------------------------------

/// `RevDetails ::= SEQUENCE { certDetails CertTemplate, crlEntryDetails
/// Extensions OPTIONAL }` (RFC 4210 section 5.3.9).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RevDetails {
    /// The certificate template identifying the certificate.
    pub cert_details: crate::crmf::CertTemplate,
    /// Requested CRL entry extensions.
    pub crl_entry_details: Vec<Extension>,
}

impl RevDetails {
    /// Parse a `RevDetails`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_details = crate::crmf::CertTemplate::parse_reader(&mut seq)?;
        let crl_entry_details = if seq.is_empty() {
            Vec::new()
        } else {
            let mut extensions = seq.read_sequence()?;
            let mut details = Vec::new();
            while !extensions.is_empty() {
                details.push(Extension::parse(&mut extensions)?);
            }
            details
        };
        seq.expect_end()?;
        Ok(RevDetails {
            cert_details,
            crl_entry_details,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.cert_details.encode();
        if !self.crl_entry_details.is_empty() {
            let mut extensions = Vec::new();
            for extension in &self.crl_entry_details {
                extensions.extend_from_slice(&extension.encode());
            }
            content.extend_from_slice(&der::sequence(&extensions));
        }
        der::sequence(&content)
    }
}

/// `RevReqContent ::= SEQUENCE OF RevDetails`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RevReqContent {
    /// The revocation request details.
    pub details: Vec<RevDetails>,
}

impl RevReqContent {
    /// Parse a `RevReqContent` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut details = Vec::new();
        while !seq.is_empty() {
            details.push(RevDetails::parse(&mut seq)?);
        }
        reader.expect_end()?;
        Ok(RevReqContent { details })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for detail in &self.details {
            content.extend_from_slice(&detail.encode());
        }
        der::sequence(&content)
    }
}

/// `GenMsgContent ::= SEQUENCE OF InfoTypeAndValue`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GenMsgContent {
    /// Requested general info types.
    pub values: Vec<InfoTypeAndValue>,
}

impl GenMsgContent {
    /// Parse a `GenMsgContent` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let values = parse_info_values(&mut reader)?;
        reader.expect_end()?;
        Ok(GenMsgContent { values })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        encode_info_values(&self.values)
    }
}

/// `GenRepContent ::= SEQUENCE OF InfoTypeAndValue`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GenRepContent {
    /// Returned general info values.
    pub values: Vec<InfoTypeAndValue>,
}

impl GenRepContent {
    /// Parse a `GenRepContent` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let values = parse_info_values(&mut reader)?;
        reader.expect_end()?;
        Ok(GenRepContent { values })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        encode_info_values(&self.values)
    }
}

/// `PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText
/// OPTIONAL, failInfo PKIFailInfo OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PkiStatusInfo {
    /// Status value (see [`pki_status_name`]).
    pub status: u8,
    /// Human-readable status strings.
    pub status_string: Vec<String>,
    /// `PKIFailInfo` BIT STRING payload.
    pub fail_info: Option<Vec<u8>>,
}

impl PkiStatusInfo {
    /// Build a status-info with the given status value and no strings.
    pub fn new(status: u8) -> Self {
        PkiStatusInfo {
            status,
            status_string: Vec::new(),
            fail_info: None,
        }
    }

    /// Whether the status is `accepted`.
    pub fn is_accepted(&self) -> bool {
        self.status == PKI_STATUS_ACCEPTED
    }

    /// The RFC 4210 name of the status value.
    pub fn status_name(&self) -> &'static str {
        pki_status_name(self.status)
    }

    /// The names of the set `PKIFailInfo` bits.
    pub fn fail_info_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        let Some(bits) = &self.fail_info else {
            return names;
        };
        for (byte_index, byte) in bits.iter().enumerate() {
            for bit in 0..8 {
                // Named bit 0 is the most significant bit of the first octet.
                if byte & (0x80 >> bit) != 0 {
                    let number = byte_index * 8 + bit;
                    if let Some(name) = FAIL_INFO_NAMES.get(number) {
                        names.push(*name);
                    }
                }
            }
        }
        names
    }

    /// Parse a `PKIStatusInfo`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let status_value = seq.read_integer_i64()?;
        let status = u8::try_from(status_value)
            .map_err(|_| CryptoError::StrError("cmp: invalid PKIStatus"))?;
        let mut status_string = Vec::new();
        let mut fail_info = None;
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag == der::BIT_STRING {
                fail_info = Some(seq.read_bit_string_bytes()?.to_vec());
            } else {
                let mut strings = seq.read_sequence()?;
                while !strings.is_empty() {
                    status_string.push(strings.read_directory_string()?);
                }
            }
        }
        Ok(PkiStatusInfo {
            status,
            status_string,
            fail_info,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.status]);
        if !self.status_string.is_empty() {
            let mut strings = Vec::new();
            for text in &self.status_string {
                strings.extend_from_slice(&der::utf8_string(text));
            }
            content.extend_from_slice(&der::sequence(&strings));
        }
        if let Some(fail_info) = &self.fail_info {
            content.extend_from_slice(&der::bit_string(0, fail_info));
        }
        der::sequence(&content)
    }
}

/// `ErrorMsgContent ::= SEQUENCE { pKIStatusInfo PKIStatusInfo, errorCode
/// INTEGER OPTIONAL, errorDetails PKIFreeText OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorMsgContent {
    /// The status information.
    pub pki_status_info: PkiStatusInfo,
    /// Optional error code.
    pub error_code: Option<i64>,
    /// Human-readable error details.
    pub error_details: Vec<String>,
}

impl ErrorMsgContent {
    /// Build an error message content for a status value.
    pub fn new(status: u8) -> Self {
        ErrorMsgContent {
            pki_status_info: PkiStatusInfo::new(status),
            error_code: None,
            error_details: Vec::new(),
        }
    }

    /// Parse an `ErrorMsgContent`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let pki_status_info = PkiStatusInfo::parse(&mut seq)?;
        let error_code = if !seq.is_empty() && seq.peek_tag()? == der::INTEGER {
            Some(seq.read_integer_i64()?)
        } else {
            None
        };
        let mut error_details = Vec::new();
        if !seq.is_empty() {
            let mut strings = seq.read_sequence()?;
            while !strings.is_empty() {
                error_details.push(strings.read_directory_string()?);
            }
        }
        reader.expect_end()?;
        seq.expect_end()?;
        Ok(ErrorMsgContent {
            pki_status_info,
            error_code,
            error_details,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.pki_status_info.encode();
        if let Some(code) = self.error_code {
            content.extend_from_slice(&der::integer_i64(code));
        }
        if !self.error_details.is_empty() {
            let mut strings = Vec::new();
            for text in &self.error_details {
                strings.extend_from_slice(&der::utf8_string(text));
            }
            content.extend_from_slice(&der::sequence(&strings));
        }
        der::sequence(&content)
    }
}

/// `CertStatus ::= SEQUENCE { certHash OCTET STRING, certReqId INTEGER,
/// statusInfo PKIStatusInfo OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertStatus {
    /// Hash of the confirmed certificate.
    pub cert_hash: Vec<u8>,
    /// Matching `certReqId` magnitude.
    pub cert_req_id: Vec<u8>,
    /// Optional status information.
    pub status_info: Option<PkiStatusInfo>,
}

impl CertStatus {
    /// Build a certificate status from a hash and request id.
    pub fn new(cert_hash: Vec<u8>, cert_req_id: Vec<u8>) -> Self {
        CertStatus {
            cert_hash,
            cert_req_id,
            status_info: None,
        }
    }

    /// Parse a `CertStatus`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_hash = seq.read_octet_string()?.to_vec();
        let cert_req_id = seq.read_integer()?.to_vec();
        let status_info = if seq.is_empty() {
            None
        } else {
            Some(PkiStatusInfo::parse(&mut seq)?)
        };
        seq.expect_end()?;
        Ok(CertStatus {
            cert_hash,
            cert_req_id,
            status_info,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::octet_string(&self.cert_hash);
        content.extend_from_slice(&der::integer(&self.cert_req_id));
        if let Some(status) = &self.status_info {
            content.extend_from_slice(&status.encode());
        }
        der::sequence(&content)
    }
}

/// `CertConfirmContent ::= SEQUENCE OF CertStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertConfirmContent {
    /// Confirmed certificate statuses.
    pub statuses: Vec<CertStatus>,
}

impl CertConfirmContent {
    /// Parse a `CertConfirmContent` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut statuses = Vec::new();
        while !seq.is_empty() {
            statuses.push(CertStatus::parse(&mut seq)?);
        }
        reader.expect_end()?;
        Ok(CertConfirmContent { statuses })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for status in &self.statuses {
            content.extend_from_slice(&status.encode());
        }
        der::sequence(&content)
    }
}

/// `PollReq ::= SEQUENCE { certReqId INTEGER }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PollReq {
    /// Request id being polled.
    pub cert_req_id: Vec<u8>,
}

impl PollReq {
    /// Build a poll request for a request id.
    pub fn new(cert_req_id: Vec<u8>) -> Self {
        PollReq { cert_req_id }
    }

    fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_req_id = seq.read_integer()?.to_vec();
        seq.expect_end()?;
        Ok(PollReq { cert_req_id })
    }

    fn encode(&self) -> Vec<u8> {
        der::sequence(&der::integer(&self.cert_req_id))
    }
}

/// `PollRepContent ::= SEQUENCE OF PollRep`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PollReqContent {
    /// The poll requests.
    pub requests: Vec<PollReq>,
}

impl PollReqContent {
    /// Parse a `PollReqContent` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut requests = Vec::new();
        while !seq.is_empty() {
            requests.push(PollReq::parse(&mut seq)?);
        }
        reader.expect_end()?;
        Ok(PollReqContent { requests })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for request in &self.requests {
            content.extend_from_slice(&request.encode());
        }
        der::sequence(&content)
    }
}

/// `PollRep ::= SEQUENCE { certReqId INTEGER, checkAfter INTEGER, reason
/// PKIFreeText OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PollRep {
    /// Request id being answered.
    pub cert_req_id: Vec<u8>,
    /// Seconds the requester should wait before polling again.
    pub check_after: i64,
    /// Optional reason strings.
    pub reason: Vec<String>,
}

impl PollRep {
    /// Build a poll response.
    pub fn new(cert_req_id: Vec<u8>, check_after: i64) -> Self {
        PollRep {
            cert_req_id,
            check_after,
            reason: Vec::new(),
        }
    }

    fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_req_id = seq.read_integer()?.to_vec();
        let check_after = seq.read_integer_i64()?;
        let mut reason = Vec::new();
        if !seq.is_empty() {
            let mut strings = seq.read_sequence()?;
            while !strings.is_empty() {
                reason.push(strings.read_directory_string()?);
            }
        }
        seq.expect_end()?;
        Ok(PollRep {
            cert_req_id,
            check_after,
            reason,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&self.cert_req_id);
        content.extend_from_slice(&der::integer_i64(self.check_after));
        if !self.reason.is_empty() {
            let mut strings = Vec::new();
            for text in &self.reason {
                strings.extend_from_slice(&der::utf8_string(text));
            }
            content.extend_from_slice(&der::sequence(&strings));
        }
        der::sequence(&content)
    }
}

/// `PollRepContent ::= SEQUENCE OF PollRep`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PollRepContent {
    /// The poll responses.
    pub responses: Vec<PollRep>,
}

impl PollRepContent {
    /// Parse a `PollRepContent` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut responses = Vec::new();
        while !seq.is_empty() {
            responses.push(PollRep::parse(&mut seq)?);
        }
        reader.expect_end()?;
        Ok(PollRepContent { responses })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for response in &self.responses {
            content.extend_from_slice(&response.encode());
        }
        der::sequence(&content)
    }
}

/// `PKIBody`, the tagged choice of CMP message contents.
///
/// Variants hold the decoded structures directly (matching the ASN.1
/// choices); `P10Cr` carries a full PKCS#10 request, which is much larger
/// than the request-id-based bodies.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum PkiBody {
    /// `[0] ir` initial registration.
    Ir(CertReqMessages),
    /// `[2] cr` certificate request.
    Cr(CertReqMessages),
    /// `[4] p10cr` PKCS#10 request.
    P10Cr(CertificationRequest),
    /// `[7] kur` key update request.
    Kur(CertReqMessages),
    /// `[11] rr` revocation request.
    Rr(RevReqContent),
    /// `[13] ccr` cross-certification request.
    Ccr(CertReqMessages),
    /// `[19] pkiconf` confirmation (`NULL`).
    Pkiconf,
    /// `[21] genm` general message.
    Genm(GenMsgContent),
    /// `[22] genp` general response.
    Genp(GenRepContent),
    /// `[23] error` error message.
    Error(ErrorMsgContent),
    /// `[24] certConf` certificate confirmation.
    CertConf(CertConfirmContent),
    /// `[25] pollReq` polling request.
    PollReq(PollReqContent),
    /// `[26] pollRep` polling response.
    PollRep(PollRepContent),
    /// Any other body tag, kept as a raw explicit-tag payload.
    Other {
        /// Context-specific tag number.
        tag: u32,
        /// The content of the explicit tag.
        value: Vec<u8>,
    },
}

impl PartialEq for PkiBody {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PkiBody::Ir(a), PkiBody::Ir(b))
            | (PkiBody::Cr(a), PkiBody::Cr(b))
            | (PkiBody::Kur(a), PkiBody::Kur(b))
            | (PkiBody::Ccr(a), PkiBody::Ccr(b)) => a == b,
            (PkiBody::P10Cr(a), PkiBody::P10Cr(b)) => a.encode() == b.encode(),
            (PkiBody::Rr(a), PkiBody::Rr(b)) => a == b,
            (PkiBody::Pkiconf, PkiBody::Pkiconf) => true,
            (PkiBody::Genm(a), PkiBody::Genm(b)) => a == b,
            (PkiBody::Genp(a), PkiBody::Genp(b)) => a == b,
            (PkiBody::Error(a), PkiBody::Error(b)) => a == b,
            (PkiBody::CertConf(a), PkiBody::CertConf(b)) => a == b,
            (PkiBody::PollReq(a), PkiBody::PollReq(b)) => a == b,
            (PkiBody::PollRep(a), PkiBody::PollRep(b)) => a == b,
            (
                PkiBody::Other {
                    tag: tag_a,
                    value: value_a,
                },
                PkiBody::Other {
                    tag: tag_b,
                    value: value_b,
                },
            ) => tag_a == tag_b && value_a == value_b,
            _ => false,
        }
    }
}

impl PkiBody {
    /// The context-specific tag number of this body.
    pub fn tag(&self) -> u32 {
        match self {
            PkiBody::Ir(_) => 0,
            PkiBody::Cr(_) => 2,
            PkiBody::P10Cr(_) => 4,
            PkiBody::Kur(_) => 7,
            PkiBody::Rr(_) => 11,
            PkiBody::Ccr(_) => 13,
            PkiBody::Pkiconf => 19,
            PkiBody::Genm(_) => 21,
            PkiBody::Genp(_) => 22,
            PkiBody::Error(_) => 23,
            PkiBody::CertConf(_) => 24,
            PkiBody::PollReq(_) => 25,
            PkiBody::PollRep(_) => 26,
            PkiBody::Other { tag, .. } => *tag,
        }
    }

    /// The RFC 4210 name of this body type.
    pub fn name(&self) -> &'static str {
        match self {
            PkiBody::Ir(_) => "ir",
            PkiBody::Cr(_) => "cr",
            PkiBody::P10Cr(_) => "p10cr",
            PkiBody::Kur(_) => "kur",
            PkiBody::Rr(_) => "rr",
            PkiBody::Ccr(_) => "ccr",
            PkiBody::Pkiconf => "pkiconf",
            PkiBody::Genm(_) => "genm",
            PkiBody::Genp(_) => "genp",
            PkiBody::Error(_) => "error",
            PkiBody::CertConf(_) => "certConf",
            PkiBody::PollReq(_) => "pollReq",
            PkiBody::PollRep(_) => "pollRep",
            PkiBody::Other { .. } => "other",
        }
    }

    /// Parse a `PKIBody` choice.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag.class != der::Class::ContextSpecific || !tag.constructed {
            return Err(CryptoError::StrError("cmp: invalid PKIBody"));
        }
        Ok(match tag.number {
            0 => PkiBody::Ir(CertReqMessages::parse(&read_explicit_tlv(reader, 0)?)?),
            2 => PkiBody::Cr(CertReqMessages::parse(&read_explicit_tlv(reader, 2)?)?),
            4 => PkiBody::P10Cr(CertificationRequest::parse(&read_explicit_tlv(reader, 4)?)?),
            7 => PkiBody::Kur(CertReqMessages::parse(&read_explicit_tlv(reader, 7)?)?),
            11 => PkiBody::Rr(RevReqContent::parse(&read_explicit_tlv(reader, 11)?)?),
            13 => PkiBody::Ccr(CertReqMessages::parse(&read_explicit_tlv(reader, 13)?)?),
            19 => {
                let mut inner = reader.read_explicit(19)?;
                if !inner.is_empty() {
                    inner.read_null()?;
                }
                PkiBody::Pkiconf
            }
            21 => PkiBody::Genm(GenMsgContent::parse(&read_explicit_tlv(reader, 21)?)?),
            22 => PkiBody::Genp(GenRepContent::parse(&read_explicit_tlv(reader, 22)?)?),
            23 => PkiBody::Error(ErrorMsgContent::parse(&read_explicit_tlv(reader, 23)?)?),
            24 => PkiBody::CertConf(CertConfirmContent::parse(&read_explicit_tlv(reader, 24)?)?),
            25 => PkiBody::PollReq(PollReqContent::parse(&read_explicit_tlv(reader, 25)?)?),
            26 => PkiBody::PollRep(PollRepContent::parse(&read_explicit_tlv(reader, 26)?)?),
            number => PkiBody::Other {
                tag: number,
                value: read_explicit_tlv(reader, number)?,
            },
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PkiBody::Ir(messages) => der::explicit(0, &messages.encode()),
            PkiBody::Cr(messages) => der::explicit(2, &messages.encode()),
            PkiBody::P10Cr(request) => der::explicit(4, &request.encode()),
            PkiBody::Kur(messages) => der::explicit(7, &messages.encode()),
            PkiBody::Rr(content) => der::explicit(11, &content.encode()),
            PkiBody::Ccr(messages) => der::explicit(13, &messages.encode()),
            PkiBody::Pkiconf => der::explicit(19, &der::null()),
            PkiBody::Genm(content) => der::explicit(21, &content.encode()),
            PkiBody::Genp(content) => der::explicit(22, &content.encode()),
            PkiBody::Error(content) => der::explicit(23, &content.encode()),
            PkiBody::CertConf(content) => der::explicit(24, &content.encode()),
            PkiBody::PollReq(content) => der::explicit(25, &content.encode()),
            PkiBody::PollRep(content) => der::explicit(26, &content.encode()),
            PkiBody::Other { tag, value } => der::explicit(*tag, value),
        }
    }
}

/// Read `[n] EXPLICIT` and return the single inner element as a full TLV.
fn read_explicit_tlv(reader: &mut Reader<'_>, number: u32) -> CryptoResult<Vec<u8>> {
    let mut inner = reader.read_explicit(number)?;
    let raw = inner.read_raw_tlv()?.to_vec();
    inner.expect_end()?;
    Ok(raw)
}

// ---------------------------------------------------------------------------
// Message protection
// ---------------------------------------------------------------------------

/// The protection bits of a [`PkiMessage`] together with the algorithm
/// identifier from the header that produced them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionAlg {
    /// The header's `protectionAlg` value.
    pub alg_id: AlgorithmIdentifier,
    /// The `PKIProtection` BIT STRING payload (MAC or signature).
    pub value: Vec<u8>,
}

/// A CMP `PKIMessage`.
#[derive(Debug, Clone)]
pub struct PkiMessage {
    /// The message header.
    pub header: PkiHeader,
    /// The message body.
    pub body: PkiBody,
    /// `[0] protection`, present when the message is protected.
    pub protection: Option<ProtectionAlg>,
    /// `[1] extraCerts`.
    pub extra_certs: Vec<Certificate>,
}

impl PartialEq for PkiMessage {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.body == other.body
            && self.protection == other.protection
            && self.extra_certs.len() == other.extra_certs.len()
            && self
                .extra_certs
                .iter()
                .zip(other.extra_certs.iter())
                .all(|(a, b)| a.encode() == b.encode())
    }
}

impl PkiMessage {
    /// Build an unprotected message.
    pub fn new(header: PkiHeader, body: PkiBody) -> Self {
        PkiMessage {
            header,
            body,
            protection: None,
            extra_certs: Vec::new(),
        }
    }

    /// Parse a DER `PKIMessage`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let header = PkiHeader::parse(&mut seq)?;
        let body = PkiBody::parse(&mut seq)?;
        let mut protection = None;
        let mut extra_certs = Vec::new();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag.class != der::Class::ContextSpecific || !tag.constructed {
                return Err(CryptoError::StrError("cmp: invalid PKIMessage"));
            }
            match tag.number {
                0 => {
                    let raw = read_explicit_tlv(&mut seq, 0)?;
                    let mut inner = Reader::new(&raw);
                    let value = inner.read_bit_string_bytes()?.to_vec();
                    let alg_id = header.protection_alg.clone().ok_or(CryptoError::StrError(
                        "cmp: protection without protectionAlg",
                    ))?;
                    protection = Some(ProtectionAlg { alg_id, value });
                }
                1 => {
                    let mut inner = seq.read_explicit(1)?;
                    let mut certs = inner.read_sequence()?;
                    while !certs.is_empty() {
                        extra_certs.push(Certificate::parse(certs.read_raw_tlv()?)?);
                    }
                }
                _ => return Err(CryptoError::StrError("cmp: invalid PKIMessage")),
            }
        }
        reader.expect_end()?;
        Ok(PkiMessage {
            header,
            body,
            protection,
            extra_certs,
        })
    }

    /// Parse a PEM `CMP MESSAGE` block.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "CMP MESSAGE" {
            return Err(CryptoError::StrError("cmp: not a CMP MESSAGE PEM block"));
        }
        Self::parse(&block.data)
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.header.encode();
        content.extend_from_slice(&self.body.encode());
        if let Some(protection) = &self.protection {
            content.extend_from_slice(&der::explicit(0, &der::bit_string(0, &protection.value)));
        }
        if !self.extra_certs.is_empty() {
            let mut certs = Vec::new();
            for cert in &self.extra_certs {
                certs.extend_from_slice(&cert.encode());
            }
            content.extend_from_slice(&der::explicit(1, &der::sequence(&certs)));
        }
        der::sequence(&content)
    }

    /// Encode as PEM.
    ///
    /// OpenSSL's `cmp` app reads and writes DER by default; the
    /// `CMP MESSAGE` label is provided for tools that use PEM armour.
    pub fn to_pem(&self) -> String {
        pem::encode("CMP MESSAGE", &self.encode())
    }

    /// The DER of the RFC 4210 `ProtectedPart`:
    /// `SEQUENCE { header, body }`, where `header` carries `protectionAlg`
    /// but the `protection` field itself is not part of the message yet.
    ///
    /// `extraCerts` are not covered by the protection.
    pub fn protected_part(&self) -> Vec<u8> {
        let mut content = self.header.encode();
        content.extend_from_slice(&self.body.encode());
        der::sequence(&content)
    }

    /// Protect the message with a signature from `key`, locating the signer
    /// certificate in `extraCerts` (the certificate is appended when absent).
    ///
    /// `cert` must match `key`; the freshly computed signature is verified
    /// against the certificate before being installed.
    pub fn protect_signature(
        &mut self,
        cert: &Certificate,
        key: &PrivateKey,
        algorithm: SignatureAlgorithm,
        rng: &mut impl Rng,
    ) -> CryptoResult<()> {
        let identifier = algorithm.to_identifier();
        self.header.protection_alg = Some(identifier.clone());
        self.protection = None;
        let signed = self.protected_part();
        let signature = algorithm.sign(key, &signed, rng)?;
        if !algorithm.verify(cert.public_key(), &signed, &signature)? {
            return Err(CryptoError::StrError(
                "cmp: signer certificate does not match the private key",
            ));
        }
        self.protection = Some(ProtectionAlg {
            alg_id: identifier,
            value: signature,
        });
        if !self
            .extra_certs
            .iter()
            .any(|existing| existing.encode() == cert.encode())
        {
            self.extra_certs.push(cert.clone());
        }
        Ok(())
    }

    /// Verify a signature-protected message against the certificates in
    /// `extraCerts`, returning whether any of them verifies the signature.
    ///
    /// Returns `Ok(false)` when the message has no signature protection or
    /// no candidate verifies.
    pub fn verify_signature(&self) -> CryptoResult<bool> {
        let Some(protection) = &self.protection else {
            return Ok(false);
        };
        let Ok(algorithm) = SignatureAlgorithm::from_identifier(&protection.alg_id) else {
            return Ok(false);
        };
        let signed = self.protected_part();
        for cert in &self.extra_certs {
            if matches!(
                algorithm.verify(cert.public_key(), &signed, &protection.value),
                Ok(true)
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Protect the message with a password MAC using `id-PasswordBasedMac`,
    /// a 16-octet random salt, SHA-256 as the OWF, 500 iterations and
    /// HMAC-SHA-256 as the MAC (the defaults of RFC 9481-era implementations).
    pub fn protect_password(&mut self, password: &[u8], rng: &mut impl Rng) -> CryptoResult<()> {
        let mut salt = vec![0u8; 16];
        rng.fill_bytes(&mut salt);
        let parameters = PbmParameter::new(salt, Hash::Sha256, 500, Hash::Sha256);
        self.protect_password_with(password, &parameters)
    }

    /// Protect the message with a password MAC using explicit
    /// [`PbmParameter`] values.
    pub fn protect_password_with(
        &mut self,
        password: &[u8],
        parameters: &PbmParameter,
    ) -> CryptoResult<()> {
        let identifier =
            AlgorithmIdentifier::new(oid_of(OID_ID_PASSWORD_BASED_MAC), Some(parameters.encode()));
        self.header.protection_alg = Some(identifier.clone());
        self.protection = None;
        let signed = self.protected_part();
        let mac = parameters.mac(password, &signed)?;
        self.protection = Some(ProtectionAlg {
            alg_id: identifier,
            value: mac,
        });
        Ok(())
    }

    /// Verify password-based MAC protection.
    ///
    /// Returns `Ok(false)` when the message is unprotected or uses a
    /// different protection algorithm.
    pub fn verify_password(&self, password: &[u8]) -> CryptoResult<bool> {
        let Some(protection) = &self.protection else {
            return Ok(false);
        };
        if !protection.alg_id.oid.matches(OID_ID_PASSWORD_BASED_MAC) {
            return Ok(false);
        }
        let parameters_der = protection
            .alg_id
            .parameters
            .as_deref()
            .ok_or(CryptoError::StrError("cmp: missing PBMParameter"))?;
        let parameters = PbmParameter::parse(parameters_der)?;
        let signed = self.protected_part();
        let expected = parameters.mac(password, &signed)?;
        Ok(crate::utils::subtle::constant_time_eq(
            &expected,
            &protection.value,
        ))
    }
}

#[cfg(test)]
mod tests;
