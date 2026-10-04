//! PKCS#12 personal information exchange (`PFX`).
//!
//! Parsing, MAC verification, bag decoding and creation of the key/certificate
//! containers used by browsers and TLS tooling. Both modern PBES2
//! (PBKDF2 + AES-CBC) and the legacy PKCS#12 PBE schemes (RC4, RC2, 3DES) are
//! supported, as are HMAC-SHA1 and HMAC-SHA256 MACs.
//!
//! ```text
//! PFX ::= SEQUENCE { version, authSafe ContentInfo, macData MacData OPTIONAL }
//! AuthenticatedSafe ::= SEQUENCE OF ContentInfo
//! SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT, bagAttributes SET OF Attribute OPTIONAL }
//! ```

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash};
use crate::x509::attribute::Attribute;
use crate::x509::cert::Certificate;
use crate::x509::crl::CertificateList;
use crate::x509::keys::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use crate::x509::pbe::{self, Pbes2Cipher};

/// `MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING,
/// iterations INTEGER DEFAULT 1 }`.
#[derive(Debug, Clone)]
pub struct MacData {
    /// MAC digest algorithm.
    pub digest_algorithm: AlgorithmIdentifier,
    /// The MAC value.
    pub digest: Vec<u8>,
    /// MAC salt.
    pub salt: Vec<u8>,
    /// Iteration count.
    pub iterations: u32,
}

impl MacData {
    /// Parse `MacData`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let mut digest_info = seq.read_sequence()?;
        let digest_algorithm = AlgorithmIdentifier::parse(&mut digest_info)?;
        let digest = digest_info.read_octet_string()?.to_vec();
        digest_info.expect_end()?;
        let salt = seq.read_octet_string()?.to_vec();
        let iterations = if !seq.is_empty() {
            u32::try_from(seq.read_integer_i64()?)
                .map_err(|_| CryptoError::StrError("pkcs12: invalid MAC iterations"))?
        } else {
            1
        };
        seq.expect_end()?;
        Ok(MacData {
            digest_algorithm,
            digest,
            salt,
            iterations,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut digest_info = self.digest_algorithm.encode();
        digest_info.extend_from_slice(&der::octet_string(&self.digest));
        let mut content = der::sequence(&digest_info);
        content.extend_from_slice(&der::octet_string(&self.salt));
        content.extend_from_slice(&der::integer(&(self.iterations as u64).to_be_bytes()));
        der::sequence(&content)
    }
}

/// A decoded safe bag.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Bag {
    /// `keyBag`: an unencrypted PKCS#8 key.
    Key(PrivateKeyInfo),
    /// `pkcs8ShroudedKeyBag`: an encrypted PKCS#8 key.
    ShroudedKey(EncryptedPrivateKeyInfo),
    /// `certBag` holding an X.509 certificate.
    Cert(Certificate),
    /// `crlBag`.
    Crl(CertificateList),
    /// `secretBag` (raw).
    Secret {
        /// The secret type OID.
        oid: ObjectIdentifier,
        /// The raw value.
        value: Vec<u8>,
    },
    /// `safeContentsBag`: a nested bag list.
    SafeContents(Vec<SafeBag>),
    /// Any other bag type.
    Other {
        /// The bag id OID.
        oid: ObjectIdentifier,
        /// The raw value.
        value: Vec<u8>,
    },
}

/// `SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY, bagAttributes
/// SET OF Attribute OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct SafeBag {
    /// The bag value.
    pub bag: Bag,
    /// Bag attributes (`friendlyName`, `localKeyId`, ...).
    pub attributes: Vec<Attribute>,
}

impl SafeBag {
    /// Parse a `SafeBag`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let oid = seq.read_oid()?;
        let mut value = seq.read_explicit(0)?;
        let mut attributes = Vec::new();
        if !seq.is_empty() {
            let mut attrs = seq.read_set()?;
            while !attrs.is_empty() {
                attributes.push(Attribute::parse(&mut attrs)?);
            }
        }
        seq.expect_end()?;

        let bag = if oid.matches(oid::OID_PKCS12_KEY_BAG) {
            Bag::Key(PrivateKeyInfo::parse(value.read_raw_tlv()?)?)
        } else if oid.matches(oid::OID_PKCS12_SHROUDED_KEY_BAG) {
            Bag::ShroudedKey(EncryptedPrivateKeyInfo::parse(value.read_raw_tlv()?)?)
        } else if oid.matches(oid::OID_PKCS12_CERT_BAG) {
            // CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
            let mut cert_bag = value.read_sequence()?;
            let cert_id = cert_bag.read_oid()?;
            let mut cert_value = cert_bag.read_explicit(0)?;
            let data = cert_value.read_octet_string()?;
            if cert_id.matches(oid::OID_X509_CERTIFICATE) {
                Bag::Cert(Certificate::parse(data)?)
            } else {
                Bag::Other {
                    oid: cert_id,
                    value: data.to_vec(),
                }
            }
        } else if oid.matches(oid::OID_PKCS12_CRL_BAG) {
            let mut crl_bag = value.read_sequence()?;
            let crl_id = crl_bag.read_oid()?;
            let mut crl_value = crl_bag.read_explicit(0)?;
            let data = crl_value.read_octet_string()?;
            if crl_id.matches(oid::OID_X509_CRL) {
                Bag::Crl(CertificateList::parse(data)?)
            } else {
                Bag::Other {
                    oid: crl_id,
                    value: data.to_vec(),
                }
            }
        } else if oid.matches(oid::OID_PKCS12_SECRET_BAG) {
            let mut secret_bag = value.read_sequence()?;
            let secret_id = secret_bag.read_oid()?;
            let secret_value = secret_bag.read_raw_tlv()?;
            Bag::Secret {
                oid: secret_id,
                value: secret_value.to_vec(),
            }
        } else if oid.matches(oid::OID_PKCS12_SAFE_CONTENTS_BAG) {
            let mut contents = value.read_sequence()?;
            let mut bags = Vec::new();
            while !contents.is_empty() {
                bags.push(SafeBag::parse(&mut contents)?);
            }
            Bag::SafeContents(bags)
        } else {
            Bag::Other {
                oid,
                value: value.read_raw_tlv()?.to_vec(),
            }
        };
        Ok(SafeBag { bag, attributes })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let (oid, value) = match &self.bag {
            Bag::Key(info) => (
                ObjectIdentifier::new(oid::OID_PKCS12_KEY_BAG).expect("static oid"),
                info.encode(),
            ),
            Bag::ShroudedKey(info) => (
                ObjectIdentifier::new(oid::OID_PKCS12_SHROUDED_KEY_BAG).expect("static oid"),
                info.encode(),
            ),
            Bag::Cert(certificate) => (
                ObjectIdentifier::new(oid::OID_PKCS12_CERT_BAG).expect("static oid"),
                der::sequence(
                    &[
                        der::oid(
                            &ObjectIdentifier::new(oid::OID_X509_CERTIFICATE).expect("static oid"),
                        ),
                        der::explicit(0, &der::octet_string(&certificate.encode())),
                    ]
                    .concat(),
                ),
            ),
            Bag::Crl(crl) => (
                ObjectIdentifier::new(oid::OID_PKCS12_CRL_BAG).expect("static oid"),
                der::sequence(
                    &[
                        der::oid(&ObjectIdentifier::new(oid::OID_X509_CRL).expect("static oid")),
                        der::explicit(0, &der::octet_string(&crl.encode())),
                    ]
                    .concat(),
                ),
            ),
            Bag::Secret { oid, value } => (
                ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).expect("static oid"),
                der::sequence(&[der::oid(oid), value.clone()].concat()),
            ),
            Bag::SafeContents(bags) => (
                ObjectIdentifier::new(oid::OID_PKCS12_SAFE_CONTENTS_BAG).expect("static oid"),
                encode_safe_contents(bags),
            ),
            Bag::Other { oid, value } => (oid.clone(), value.clone()),
        };
        let mut content = der::oid(&oid);
        content.extend_from_slice(&der::explicit(0, &value));
        if !self.attributes.is_empty() {
            let mut attrs = Vec::new();
            for attribute in &self.attributes {
                attrs.extend_from_slice(&attribute.encode());
            }
            content.extend_from_slice(&der::set(&attrs));
        }
        der::sequence(&content)
    }

    /// The `friendlyName` attribute text, when present.
    pub fn friendly_name(&self) -> Option<String> {
        self.attributes
            .iter()
            .find(|attr| attr.oid.matches(oid::OID_PKCS9_FRIENDLY_NAME))?
            .first_text()
    }

    /// The `localKeyId` attribute value, when present.
    pub fn local_key_id(&self) -> Option<Vec<u8>> {
        let attribute = self
            .attributes
            .iter()
            .find(|attr| attr.oid.matches(oid::OID_PKCS9_LOCAL_KEY_ID))?;
        crate::x509::attribute::octet_string_value(attribute)
            .ok()
            .map(<[u8]>::to_vec)
    }
}

/// Encode `SafeContents ::= SEQUENCE OF SafeBag`.
pub fn encode_safe_contents(bags: &[SafeBag]) -> Vec<u8> {
    let mut content = Vec::new();
    for bag in bags {
        content.extend_from_slice(&bag.encode());
    }
    der::sequence(&content)
}

/// Parse `SafeContents`.
pub fn parse_safe_contents(content: &[u8]) -> CryptoResult<Vec<SafeBag>> {
    let mut reader = Reader::new(content);
    let mut seq = reader.read_sequence()?;
    let mut bags = Vec::new();
    while !seq.is_empty() {
        bags.push(SafeBag::parse(&mut seq)?);
    }
    Ok(bags)
}

/// A PKCS#12 `PFX`.
#[derive(Debug, Clone)]
pub struct Pfx {
    /// PFX version (3).
    pub version: u8,
    /// The outer `id-data` content info wrapper.
    pub auth_safe: crate::pkcs7::ContentInfo,
    /// The optional MAC.
    pub mac: Option<MacData>,
}

impl Pfx {
    /// Parse a DER `PFX`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("pkcs12: invalid version"))?;
        let auth_safe = crate::pkcs7::ContentInfo::parse_reader(&mut seq)?;
        let mac = if !seq.is_empty() {
            Some(MacData::parse(&mut seq)?)
        } else {
            None
        };
        seq.expect_end()?;
        reader.expect_end()?;
        if !auth_safe.content_type.matches(oid::OID_PKCS7_DATA) {
            return Err(CryptoError::StrError("pkcs12: authSafe is not id-data"));
        }
        Ok(Pfx {
            version,
            auth_safe,
            mac,
        })
    }

    /// Parse a PEM `PFX`.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "PKCS12" {
            return Err(CryptoError::StrError("pkcs12: not a PKCS#12 PEM block"));
        }
        Self::parse(&block.data)
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&self.auth_safe.encode());
        if let Some(mac) = &self.mac {
            content.extend_from_slice(&mac.encode());
        }
        der::sequence(&content)
    }

    /// Encode as PEM.
    pub fn to_pem(&self) -> String {
        pem::encode("PKCS12", &self.encode())
    }

    /// The `AuthenticatedSafe` DER: the contents of the outer OCTET STRING.
    pub fn authenticated_safe(&self) -> CryptoResult<Vec<u8>> {
        let mut reader = Reader::new(&self.auth_safe.content);
        reader.read_octet_string_owned()
    }

    /// Verify the MAC, when present.
    ///
    /// A PFX without a MAC returns `Ok(())`.
    pub fn verify_mac(&self, password: &[u8]) -> CryptoResult<()> {
        let Some(mac) = &self.mac else {
            return Ok(());
        };
        let hash = Hash::from_oid(&mac.digest_algorithm.oid).ok_or_else(|| {
            CryptoError::UnsupportedOperation("pkcs12: unsupported MAC digest".into())
        })?;
        let key = mac_key(hash, password, &mac.salt, mac.iterations, mac.digest.len())?;
        let message = self.authenticated_safe()?;
        let computed = hash.hmac(&key, &message)?;
        if crate::utils::subtle::constant_time_eq(&computed, &mac.digest) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }

    /// Decode every `SafeBag` in the `AuthenticatedSafe`.
    pub fn decoded_bags(&self, password: &[u8]) -> CryptoResult<Vec<SafeBag>> {
        let auth_safe = self.authenticated_safe()?;
        let mut reader = Reader::new(&auth_safe);
        let mut seq = reader.read_sequence()?;
        let mut bags = Vec::new();
        while !seq.is_empty() {
            let info = crate::pkcs7::ContentInfo::parse_reader(&mut seq)?;
            if info.content_type.matches(oid::OID_PKCS7_DATA) {
                let mut inner = Reader::new(&info.content);
                let contents = inner.read_octet_string()?;
                bags.extend(parse_safe_contents(contents)?);
            } else if info.content_type.matches(oid::OID_PKCS7_ENCRYPTED_DATA) {
                let plaintext = decrypt_encrypted_data(&info.content, password)?;
                bags.extend(parse_safe_contents(&plaintext)?);
            } else {
                return Err(CryptoError::UnsupportedOperation(
                    "pkcs12: unsupported AuthenticatedSafe content type".into(),
                ));
            }
        }
        Ok(bags)
    }

    /// Build a PFX from bags.
    ///
    /// The bags are placed in one unencrypted `data` ContentInfo inside the
    /// `AuthenticatedSafe`; shrouded key bags carry their own encryption.
    /// The MAC is HMAC-SHA256 over the `AuthenticatedSafe` using the PKCS#12
    /// KDF.
    pub fn build(
        bags: Vec<SafeBag>,
        password: &[u8],
        mac_iterations: u32,
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        // SafeContents -> ContentInfo -> AuthenticatedSafe -> authSafe.
        let safe_contents = encode_safe_contents(&bags);
        let inner = crate::pkcs7::ContentInfo {
            content_type: ObjectIdentifier::new(oid::OID_PKCS7_DATA).expect("static oid"),
            content: der::octet_string(&safe_contents),
        };
        let authenticated_safe = der::sequence(&inner.encode());
        let auth_safe = crate::pkcs7::ContentInfo {
            content_type: ObjectIdentifier::new(oid::OID_PKCS7_DATA).expect("static oid"),
            content: der::octet_string(&authenticated_safe),
        };
        let hash = Hash::Sha256;
        let mut salt = vec![0u8; 16];
        rng.fill_bytes(&mut salt);
        let key = mac_key(hash, password, &salt, mac_iterations, 32)?;
        let digest = hash.hmac(&key, &authenticated_safe)?;
        let mac = MacData {
            digest_algorithm: AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(Hash::Sha256.oid()).expect("static oid"),
            ),
            digest,
            salt,
            iterations: mac_iterations,
        };
        Ok(Pfx {
            version: 3,
            auth_safe,
            mac: Some(mac),
        })
    }

    /// Build a shrouded key bag for `key` with a friendly name and key id,
    /// encrypted with PBES2 (AES-256-CBC + PBKDF2-HMAC-SHA256).
    pub fn shrouded_key_bag(
        key: &PrivateKeyInfo,
        password: &[u8],
        friendly_name: Option<&str>,
        local_key_id: &[u8],
        iterations: u32,
        rng: &mut impl Rng,
    ) -> CryptoResult<SafeBag> {
        let encrypted = pbe::encrypt_private_key(
            &key.encode(),
            password,
            Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
            iterations,
            rng,
        )?;
        let mut attributes = Vec::new();
        if let Some(name) = friendly_name {
            attributes.push(crate::x509::attribute::friendly_name(name));
        }
        attributes.push(crate::x509::attribute::local_key_id(local_key_id));
        Ok(SafeBag {
            bag: Bag::ShroudedKey(encrypted),
            attributes,
        })
    }

    /// Build a certificate bag.
    pub fn certificate_bag(
        certificate: &Certificate,
        friendly_name: Option<&str>,
        local_key_id: &[u8],
    ) -> SafeBag {
        let mut attributes = Vec::new();
        if let Some(name) = friendly_name {
            attributes.push(crate::x509::attribute::friendly_name(name));
        }
        if !local_key_id.is_empty() {
            attributes.push(crate::x509::attribute::local_key_id(local_key_id));
        }
        SafeBag {
            bag: Bag::Cert(certificate.clone()),
            attributes,
        }
    }
}

/// Derive a PKCS#12 MAC key (id 3).
fn mac_key(
    hash: Hash,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    len: usize,
) -> CryptoResult<Vec<u8>> {
    let bmp = pbe::pkcs12_password(password);
    crate::kdf::pkcs12kdf::derive(hash.factory(), &bmp, salt, 3, iterations as u64, len)
}

/// Decrypt an `id-encryptedData` content info body.
fn decrypt_encrypted_data(content: &[u8], password: &[u8]) -> CryptoResult<Vec<u8>> {
    // EncryptedData ::= SEQUENCE { version, EncryptedContentInfo, ... }
    let mut reader = Reader::new(content);
    let mut seq = reader.read_sequence()?;
    let _version = seq.read_integer()?;
    let mut info = seq.read_sequence()?;
    let _content_type = info.read_oid()?;
    let algorithm = AlgorithmIdentifier::parse(&mut info)?;
    let encrypted = info.read_implicit(0, false)?;
    if algorithm.oid.matches(oid::OID_PBES2) {
        pbe::Pbes2::parse(&algorithm)?.decrypt(encrypted, password)
    } else {
        pbe::LegacyPbe::parse(&algorithm)?.decrypt(encrypted, password)
    }
}

#[cfg(test)]
mod tests;
