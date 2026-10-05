//! RFC 3161 `TimeStampResp`, `PKIStatusInfo` and response verification.

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::pkcs7::{ContentInfo, SignedData, SignerInfo};
use crate::utils::subtle::constant_time_eq;
use crate::x509::algorithm::{Hash, SignatureAlgorithm};
use crate::x509::attribute::octet_string_value;
use crate::x509::cert::Certificate;
use crate::x509::extensions::ParsedExtension;

use super::ess::{SigningCertificate, SigningCertificateV2};
use super::request::TimeStampReq;
use super::tst_info::TstInfo;
use super::{
    oid_of, OID_ID_AA_SIGNING_CERTIFICATE, OID_ID_AA_SIGNING_CERTIFICATE_V2, OID_ID_CT_TST_INFO,
};

/// `PKIStatus.granted(0)`.
pub const PKI_STATUS_GRANTED: u8 = 0;
/// `PKIStatus.grantedWithMods(1)`.
pub const PKI_STATUS_GRANTED_WITH_MODS: u8 = 1;
/// `PKIStatus.rejection(2)`.
pub const PKI_STATUS_REJECTION: u8 = 2;
/// `PKIStatus.waiting(3)`.
pub const PKI_STATUS_WAITING: u8 = 3;
/// `PKIStatus.revocationWarning(4)`.
pub const PKI_STATUS_REVOCATION_WARNING: u8 = 4;
/// `PKIStatus.revocationNotification(5)`.
pub const PKI_STATUS_REVOCATION_NOTIFICATION: u8 = 5;

/// `PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText
/// OPTIONAL, failInfo PKIFailureInfo OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiStatusInfo {
    /// The status value; see the `PKI_STATUS_*` constants.
    pub status: u8,
    /// Human-readable status strings.
    pub status_string: Vec<String>,
    /// The failure BIT STRING payload, when present.
    pub fail_info: Option<Vec<u8>>,
}

impl PkiStatusInfo {
    /// A granted status with no strings or failure info.
    pub fn granted() -> Self {
        PkiStatusInfo {
            status: PKI_STATUS_GRANTED,
            status_string: Vec::new(),
            fail_info: None,
        }
    }

    /// Whether the status is `granted` or `grantedWithMods`.
    pub fn is_granted(&self) -> bool {
        self.status == PKI_STATUS_GRANTED || self.status == PKI_STATUS_GRANTED_WITH_MODS
    }

    /// Parse a `PKIStatusInfo`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let status = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("ts: invalid PKI status"))?;
        let mut status_string = Vec::new();
        if !seq.is_empty() && seq.peek_tag()? == der::SEQUENCE {
            let mut strings = seq.read_sequence()?;
            while !strings.is_empty() {
                status_string.push(strings.read_directory_string()?);
            }
        }
        let fail_info = if seq.is_empty() {
            None
        } else {
            Some(seq.read_bit_string()?.1.to_vec())
        };
        seq.expect_end()?;
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
            for string in &self.status_string {
                strings.extend_from_slice(&der::utf8_string(string));
            }
            content.extend_from_slice(&der::sequence(&strings));
        }
        if let Some(fail_info) = &self.fail_info {
            content.extend_from_slice(&der::bit_string(0, fail_info));
        }
        der::sequence(&content)
    }
}

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken
/// TimeStampToken OPTIONAL }`, where the token is a CMS `SignedData`
/// `ContentInfo`.
#[derive(Debug, Clone)]
pub struct TimeStampResp {
    /// The status information.
    pub status: PkiStatusInfo,
    /// The timestamp token, present for a granted response.
    pub time_stamp_token: Option<ContentInfo>,
}

impl TimeStampResp {
    /// Parse a DER `TimeStampResp`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let response = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(response)
    }

    /// Parse a `TimeStampResp` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let status = PkiStatusInfo::parse(&mut seq)?;
        let time_stamp_token = if seq.is_empty() {
            None
        } else {
            Some(ContentInfo::parse_reader(&mut seq)?)
        };
        seq.expect_end()?;
        Ok(TimeStampResp {
            status,
            time_stamp_token,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.status.encode();
        if let Some(token) = &self.time_stamp_token {
            content.extend_from_slice(&token.encode());
        }
        der::sequence(&content)
    }

    /// Parse the first PEM block, which must be a `TIME STAMP RESPONSE`.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "TIME STAMP RESPONSE" {
            return Err(CryptoError::StrError(
                "ts: not a timestamp response PEM block",
            ));
        }
        Self::parse(&block.data)
    }

    /// Encode as PEM with the `TIME STAMP RESPONSE` label.
    pub fn to_pem(&self) -> String {
        pem::encode("TIME STAMP RESPONSE", &self.encode())
    }

    /// Whether the response reports success.
    pub fn is_granted(&self) -> bool {
        self.status.is_granted()
    }

    /// The CMS token, when present.
    pub fn token(&self) -> CryptoResult<&ContentInfo> {
        self.time_stamp_token.as_ref().ok_or(CryptoError::StrError(
            "ts: response carries no timestamp token",
        ))
    }

    /// Extract the `TSTInfo` from the token without verifying the signature.
    pub fn basic(&self) -> CryptoResult<TstInfo> {
        let (_, info) = self.token_and_info()?;
        Ok(info)
    }

    /// Parse the token's `SignedData` and its `TSTInfo`.
    fn token_and_info(&self) -> CryptoResult<(SignedData, TstInfo)> {
        let token = self.token()?;
        if !token.is_signed_data() {
            return Err(CryptoError::UnsupportedOperation(alloc::format!(
                "ts: token content type is {} not id-signedData",
                token.content_type
            )));
        }
        let signed_data = SignedData::parse(&token.content)?;
        if !signed_data
            .encap_content_info
            .content_type
            .matches(OID_ID_CT_TST_INFO)
        {
            return Err(CryptoError::UnsupportedOperation(alloc::format!(
                "ts: encapsulated content type is {} not id-ct-TSTInfo",
                signed_data.encap_content_info.content_type
            )));
        }
        let content = signed_data
            .encap_content_info
            .content
            .as_deref()
            .ok_or(CryptoError::StrError("ts: timestamp token is detached"))?;
        let info = TstInfo::parse(content)?;
        Ok((signed_data, info))
    }

    /// Verify the token signature and return the `TSTInfo`.
    ///
    /// The signer certificate is taken from the token's embedded certificates
    /// when it contains one, otherwise `tsa` is used. It must carry a critical
    /// `id-kp-timeStamping` extended key usage, and the token must carry a
    /// `signingCertificate`/`signingCertificateV2` attribute matching that
    /// certificate (as OpenSSL's `ts -verify` enforces).
    pub fn verify(&self, tsa: &Certificate) -> CryptoResult<TstInfo> {
        let (signed_data, info) = self.token_and_info()?;
        if signed_data.signer_infos.len() != 1 {
            return Err(CryptoError::StrError(
                "ts: timestamp token does not have exactly one signer",
            ));
        }
        let signer = &signed_data.signer_infos[0];
        let certificate = signed_data.certificate_for(&signer.sid).unwrap_or(tsa);
        check_tsa_eku(certificate)?;
        verify_signer_with_certificate(&signed_data, signer, certificate)?;
        verify_signing_certificate(signer, certificate)?;
        Ok(info)
    }

    /// [`Self::verify`] plus message-imprint and nonce matching against the
    /// original request.
    pub fn verify_request(
        &self,
        tsa: &Certificate,
        request: &TimeStampReq,
    ) -> CryptoResult<TstInfo> {
        let info = self.verify(tsa)?;
        if info.message_imprint.hash_algorithm.oid != request.message_imprint.hash_algorithm.oid
            || !constant_time_eq(
                &info.message_imprint.hashed_message,
                &request.message_imprint.hashed_message,
            )
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        if let Some(nonce) = &request.nonce {
            match &info.nonce {
                Some(info_nonce) if constant_time_eq(info_nonce, nonce) => {}
                _ => return Err(CryptoError::AuthenticationFailed),
            }
        }
        Ok(info)
    }
}

/// Enforce the RFC 3161 TSA extended key usage: a critical `extKeyUsage`
/// extension containing `id-kp-timeStamping`.
fn check_tsa_eku(certificate: &Certificate) -> CryptoResult<()> {
    let extension = certificate
        .tbs()
        .extension(oid::OID_EXTENDED_KEY_USAGE)
        .ok_or(CryptoError::StrError(
            "ts: TSA certificate has no extendedKeyUsage",
        ))?;
    if !extension.critical {
        return Err(CryptoError::StrError(
            "ts: TSA extendedKeyUsage is not critical",
        ));
    }
    match extension.parsed()? {
        ParsedExtension::ExtendedKeyUsage(usage)
            if usage
                .purposes
                .iter()
                .any(|purpose| purpose.matches(oid::OID_KP_TIME_STAMPING)) =>
        {
            Ok(())
        }
        _ => Err(CryptoError::StrError(
            "ts: TSA certificate lacks the timeStamping extended key usage",
        )),
    }
}

/// Verify one signer against an explicitly supplied certificate.
///
/// The token must be attached (RFC 3161 timestamps are never detached) and
/// the `messageDigest`/`contentType` signed attributes are checked when
/// present.
fn verify_signer_with_certificate(
    signed_data: &SignedData,
    signer: &SignerInfo,
    certificate: &Certificate,
) -> CryptoResult<()> {
    let content = signed_data
        .encap_content_info
        .content
        .as_deref()
        .ok_or(CryptoError::StrError("ts: timestamp token is detached"))?;
    let hash = Hash::from_oid(&signer.digest_algorithm.oid).ok_or_else(|| {
        CryptoError::UnsupportedOperation(alloc::format!(
            "ts: unsupported token digest algorithm {}",
            signer.digest_algorithm.oid
        ))
    })?;
    let algorithm = SignatureAlgorithm::from_identifier_with_digest(
        &signer.signature_algorithm,
        Some(&signer.digest_algorithm),
    )?;
    match (&signer.signed_attrs, &signer.signed_attrs_der) {
        (Some(attributes), Some(attrs_der)) => {
            let digest_attribute = attributes
                .iter()
                .find(|attribute| attribute.oid.matches(oid::OID_PKCS9_MESSAGE_DIGEST))
                .ok_or(CryptoError::StrError(
                    "ts: messageDigest attribute missing from token",
                ))?;
            let expected = hash.digest(content)?;
            if !constant_time_eq(&expected, octet_string_value(digest_attribute)?) {
                return Err(CryptoError::AuthenticationFailed);
            }
            if let Some(attribute) = attributes
                .iter()
                .find(|attribute| attribute.oid.matches(oid::OID_PKCS9_CONTENT_TYPE))
            {
                let value = attribute
                    .values
                    .first()
                    .ok_or(CryptoError::StrError("ts: empty contentType attribute"))?;
                let mut reader = Reader::new(value);
                if reader.read_oid()? != signed_data.encap_content_info.content_type {
                    return Err(CryptoError::AuthenticationFailed);
                }
            }
            if !algorithm.verify_with_sm2_id(
                certificate.public_key(),
                attrs_der,
                &signer.signature,
                crate::sm2::DEFAULT_ID,
            )? {
                return Err(CryptoError::AuthenticationFailed);
            }
        }
        (None, None) => {
            if !algorithm.verify_with_sm2_id(
                certificate.public_key(),
                content,
                &signer.signature,
                crate::sm2::DEFAULT_ID,
            )? {
                return Err(CryptoError::AuthenticationFailed);
            }
        }
        _ => {
            return Err(CryptoError::StrError(
                "ts: inconsistent signed attributes in token",
            ));
        }
    }
    Ok(())
}

/// Require a `signingCertificateV2` (or v1) signed attribute that matches the
/// signer certificate.
fn verify_signing_certificate(signer: &SignerInfo, certificate: &Certificate) -> CryptoResult<()> {
    let attributes = signer.signed_attrs.as_deref().unwrap_or(&[]);
    if let Some(attribute) = attributes
        .iter()
        .find(|attribute| attribute.oid.matches(OID_ID_AA_SIGNING_CERTIFICATE_V2))
    {
        if SigningCertificateV2::from_attribute(attribute)?.matches_certificate(certificate)? {
            return Ok(());
        }
        return Err(CryptoError::AuthenticationFailed);
    }
    if let Some(attribute) = attributes
        .iter()
        .find(|attribute| attribute.oid.matches(OID_ID_AA_SIGNING_CERTIFICATE))
    {
        if SigningCertificate::from_attribute(attribute)?.matches_certificate(certificate)? {
            return Ok(());
        }
        return Err(CryptoError::AuthenticationFailed);
    }
    Err(CryptoError::StrError(
        "ts: token has no signingCertificate attribute",
    ))
}

/// The OID of the `id-ct-TSTInfo` content type, as an [`ObjectIdentifier`].
pub(crate) fn tst_info_oid() -> ObjectIdentifier {
    oid_of(OID_ID_CT_TST_INFO)
}
