//! RFC 3161 timestamping: TimeStampReq/Resp, TSTInfo, ESS signing attributes.
//!
//! This module implements the Time-Stamp Protocol (TSP) of RFC 3161 together
//! with the ESS signing-certificate attributes of RFC 2634 / RFC 5035 that a
//! timestamp token must carry:
//!
//! - [`TimeStampReq`] / [`MessageImprint`]: the client request;
//! - [`TstInfo`] / [`Accuracy`]: the timestamped information inside the token;
//! - [`TimeStampResp`] / [`PkiStatusInfo`]: the TSA response wrapping a CMS
//!   `SignedData` token;
//! - [`SigningCertificateV2`] / [`EsCertIdV2`]: the `id-aa-signingCertificateV2`
//!   signed attribute binding the token signature to the TSA certificate;
//! - [`TimeStampSigner`]: a TSA that signs requests, interoperable with the
//!   OpenSSL `ts` command.
//!
//! ```
//! use crown::ts::{TimeStampReq, TimeStampResp};
//! use crown::x509::algorithm::Hash;
//! use crown::x509::cert::Certificate;
//!
//! # let query = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/ts_query_sha256.der"));
//! # let response = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/ts_response_sha256.der"));
//! # let tsa_pem = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/ts_tsa.pem"));
//! let request = TimeStampReq::parse(query)?;
//! assert!(request.verify_message_imprint(b"crown timestamp test payload\n")?);
//! let response = TimeStampResp::parse(response)?;
//! let tsa = Certificate::from_pem(tsa_pem)?;
//! let info = response.verify_request(&tsa, &request)?;
//! assert_eq!(info.policy.to_dotted_string(), "1.2.3.4.1");
//! # Ok::<(), crown::error::CryptoError>(())
//! ```

use alloc::vec::Vec;

use crate::asn1::oid::ObjectIdentifier;

mod ess;
mod request;
mod response;
mod signer;
mod tst_info;

pub use ess::{EsCertId, EsCertIdV2, IssuerSerial, SigningCertificate, SigningCertificateV2};
pub use request::{MessageImprint, TimeStampReq};
pub use response::{
    PkiStatusInfo, TimeStampResp, PKI_STATUS_GRANTED, PKI_STATUS_GRANTED_WITH_MODS,
    PKI_STATUS_REJECTION, PKI_STATUS_REVOCATION_NOTIFICATION, PKI_STATUS_REVOCATION_WARNING,
    PKI_STATUS_WAITING,
};
pub use signer::TimeStampSigner;
pub use tst_info::{Accuracy, TstInfo};

/// A `GeneralNames ::= SEQUENCE OF GeneralName` sequence (RFC 5280).
pub type GeneralNames = Vec<crate::x509::extensions::GeneralName>;

/// `id-aa-signingCertificate` (1.2.840.113549.1.9.16.2.12).
pub const OID_ID_AA_SIGNING_CERTIFICATE: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 2, 12];
/// `id-aa-signingCertificateV2` (1.2.840.113549.1.9.16.2.47).
pub const OID_ID_AA_SIGNING_CERTIFICATE_V2: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 2, 47];
/// `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4).
pub const OID_ID_CT_TST_INFO: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];

/// The CMS `signingTime` attribute OID (1.2.840.113549.1.9.5).
pub(crate) const OID_PKCS9_SIGNING_TIME: &[u64] = &[1, 2, 840, 113549, 1, 9, 5];

/// Build a static [`ObjectIdentifier`].
pub(crate) fn oid_of(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("static oid")
}

#[cfg(test)]
mod tests;
