//! X.509 / PKCS bindings: certificate, CSR, CRL, CMS, PKCS#12 and PKCS#8
//! inspection and verification, returning JSON reports for the playground.

use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

use crown::asn1::pem;
use crown::asn1::time::Asn1Time;
use crown::pkcs12::{Bag, SafeBag};
use crown::pkcs7::{Pkcs7, SignerIdentifier};
use crown::x509::{
    AlgorithmIdentifier, AuthorityKeyIdentifier, Certificate, CertificateList,
    CertificationRequest, EncryptedPrivateKeyInfo, ExtendedKeyUsage, GeneralName, Hash, KeyUsage,
    ParsedExtension, PrivateKey, PrivateKeyInfo, PublicKey, SignatureAlgorithm,
};

fn js_error(error: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

fn is_pem(data: &[u8]) -> Option<&str> {
    core::str::from_utf8(data)
        .ok()
        .filter(|text| text.contains("-----BEGIN"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hash_name(hash: Hash) -> &'static str {
    match hash {
        Hash::Md2 => "md2",
        Hash::Md4 => "md4",
        Hash::Md5 => "md5",
        Hash::Sha1 => "sha1",
        Hash::Sha224 => "sha224",
        Hash::Sha256 => "sha256",
        Hash::Sha384 => "sha384",
        Hash::Sha512 => "sha512",
        Hash::Sha512_224 => "sha512-224",
        Hash::Sha512_256 => "sha512-256",
        Hash::Sha3_224 => "sha3-224",
        Hash::Sha3_256 => "sha3-256",
        Hash::Sha3_384 => "sha3-384",
        Hash::Sha3_512 => "sha3-512",
        Hash::Sm3 => "sm3",
        Hash::Ripemd160 => "ripemd160",
    }
}

fn time_text(time: Asn1Time) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        time.year, time.month, time.day, time.hour, time.minute, time.second
    )
}

fn serial_hex(serial: &[u8]) -> String {
    let skip = serial.iter().take_while(|&&byte| byte == 0).count();
    if skip == serial.len() {
        "0".to_string()
    } else {
        hex(&serial[skip..])
    }
}

fn signature_algorithm_name(alg: &AlgorithmIdentifier) -> String {
    match SignatureAlgorithm::from_identifier(alg) {
        Ok(algorithm) => signature_algorithm_text(algorithm),
        Err(_) => alg.oid.to_string(),
    }
}

fn signature_algorithm_text(algorithm: SignatureAlgorithm) -> String {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(hash) => {
            format!("{}WithRSAEncryption", hash_name(hash))
        }
        SignatureAlgorithm::RsaPss { hash, salt_len } => {
            format!("RSASSA-PSS ({} salt {salt_len})", hash_name(hash))
        }
        SignatureAlgorithm::Ecdsa(hash) => format!("ecdsa-with-{}", hash_name(hash)),
        SignatureAlgorithm::Ed25519 => "Ed25519".to_string(),
        SignatureAlgorithm::Ed448 => "Ed448".to_string(),
        SignatureAlgorithm::Sm2 => "SM2".to_string(),
        SignatureAlgorithm::Dsa(hash) => format!("dsa-with-{}", hash_name(hash)),
        SignatureAlgorithm::MlDsa(variant) => ml_dsa_name(variant).to_string(),
        SignatureAlgorithm::SlhDsa(variant) => variant.name().to_string(),
    }
}

fn ml_dsa_name(variant: crown::ml_dsa::MlDsaVariant) -> &'static str {
    use crown::ml_dsa::MlDsaVariant;
    match variant {
        MlDsaVariant::MlDsa44 => "ML-DSA-44",
        MlDsaVariant::MlDsa65 => "ML-DSA-65",
        MlDsaVariant::MlDsa87 => "ML-DSA-87",
    }
}

fn public_key_algorithm(key: &PublicKey) -> String {
    match key {
        PublicKey::Rsa(_) => "rsaEncryption".to_string(),
        PublicKey::Ec { curve, .. } => match curve {
            crown::ec::CurveId::P256 => "id-ecPublicKey (prime256v1)",
            crown::ec::CurveId::P384 => "id-ecPublicKey (secp384r1)",
            crown::ec::CurveId::P521 => "id-ecPublicKey (secp521r1)",
        }
        .to_string(),
        PublicKey::Ed25519(_) => "Ed25519".to_string(),
        PublicKey::Ed448(_) => "Ed448".to_string(),
        PublicKey::X25519(_) => "X25519".to_string(),
        PublicKey::X448(_) => "X448".to_string(),
        PublicKey::Sm2(_) => "SM2 (sm2p256v1)".to_string(),
        PublicKey::Dsa { .. } => "dsaEncryption".to_string(),
        PublicKey::MlDsa(key) => ml_dsa_name(key.variant()).to_string(),
        PublicKey::SlhDsa(key) => key.variant().name().to_string(),
        PublicKey::Unknown { algorithm, .. } => algorithm.oid.to_string(),
    }
}

fn public_key_bits(key: &PublicKey) -> Option<usize> {
    Some(match key {
        PublicKey::Rsa(key) => key.size() * 8,
        PublicKey::Ec { curve, .. } => match curve {
            crown::ec::CurveId::P256 => 256,
            crown::ec::CurveId::P384 => 384,
            crown::ec::CurveId::P521 => 521,
        },
        PublicKey::Sm2(_) | PublicKey::Ed25519(_) | PublicKey::X25519(_) => 256,
        PublicKey::Ed448(_) => 456,
        PublicKey::X448(_) => 448,
        PublicKey::Dsa { params, .. } => params.p.bit_len(),
        PublicKey::MlDsa(_) | PublicKey::SlhDsa(_) | PublicKey::Unknown { .. } => return None,
    })
}

fn key_usage_names(usage: &KeyUsage) -> Vec<&'static str> {
    let mut names = Vec::new();
    let all = [
        (usage.digital_signature, "digitalSignature"),
        (usage.content_commitment, "nonRepudiation"),
        (usage.key_encipherment, "keyEncipherment"),
        (usage.data_encipherment, "dataEncipherment"),
        (usage.key_agreement, "keyAgreement"),
        (usage.key_cert_sign, "keyCertSign"),
        (usage.crl_sign, "cRLSign"),
        (usage.encipher_only, "encipherOnly"),
        (usage.decipher_only, "decipherOnly"),
    ];
    for (present, name) in all {
        if present {
            names.push(name);
        }
    }
    names
}

fn extended_key_usage_names(usage: &ExtendedKeyUsage) -> Vec<String> {
    use crown::asn1::{oid, ObjectIdentifier};
    let known: &[(&[u64], &str)] = &[
        (oid::OID_KP_SERVER_AUTH, "serverAuth"),
        (oid::OID_KP_CLIENT_AUTH, "clientAuth"),
        (oid::OID_KP_CODE_SIGNING, "codeSigning"),
        (oid::OID_KP_EMAIL_PROTECTION, "emailProtection"),
        (oid::OID_KP_TIME_STAMPING, "timeStamping"),
        (oid::OID_KP_OCSP_SIGNING, "ocspSigning"),
    ];
    usage
        .purposes
        .iter()
        .map(|purpose: &ObjectIdentifier| {
            known
                .iter()
                .find(|(arcs, _)| purpose.matches(arcs))
                .map(|(_, name)| (*name).to_string())
                .unwrap_or_else(|| purpose.to_string())
        })
        .collect()
}

fn general_name_text(name: &GeneralName) -> String {
    match name {
        GeneralName::DnsName(text) => format!("DNS:{text}"),
        GeneralName::Rfc822Name(text) => format!("email:{text}"),
        GeneralName::Uri(text) => format!("URI:{text}"),
        GeneralName::IpAddress(bytes) => match bytes.len() {
            4 => format!(
                "IP Address:{}.{}.{}.{}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            ),
            16 => {
                let groups: Vec<String> = bytes
                    .chunks(2)
                    .map(|chunk| format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])))
                    .collect();
                format!("IP Address:{}", groups.join(":"))
            }
            _ => format!("IP Address:{}", colon_hex(bytes)),
        },
        GeneralName::DirectoryName(name) => format!("DirName:{name}"),
        GeneralName::RegisteredId(oid) => format!("RegisteredID:{oid}"),
        GeneralName::OtherName { oid, .. } => format!("otherName:{oid}"),
        other => format!("{other:?}"),
    }
}

fn authority_key_identifier(aki: &AuthorityKeyIdentifier) -> Value {
    json!({
        "key_identifier": aki.key_identifier.as_deref().map(colon_hex),
        "serial": aki.authority_cert_serial.as_deref().map(serial_hex),
    })
}

fn extension_json(extension: &crown::x509::Extension) -> Value {
    let parsed = extension.parsed();
    let mut value = json!({
        "oid": extension.oid.to_string(),
        "critical": extension.critical,
    });
    let object = value.as_object_mut().expect("object");
    match parsed {
        Ok(ParsedExtension::BasicConstraints(bc)) => {
            object.insert("name".into(), json!("basicConstraints"));
            object.insert("ca".into(), json!(bc.ca));
            object.insert("path_len".into(), json!(bc.path_len));
        }
        Ok(ParsedExtension::KeyUsage(usage)) => {
            object.insert("name".into(), json!("keyUsage"));
            object.insert("usages".into(), json!(key_usage_names(&usage)));
        }
        Ok(ParsedExtension::ExtendedKeyUsage(usage)) => {
            object.insert("name".into(), json!("extKeyUsage"));
            object.insert("purposes".into(), json!(extended_key_usage_names(&usage)));
        }
        Ok(ParsedExtension::SubjectAltName(names)) => {
            object.insert("name".into(), json!("subjectAltName"));
            let names: Vec<String> = names.iter().map(general_name_text).collect();
            object.insert("names".into(), json!(names));
        }
        Ok(ParsedExtension::IssuerAltName(names)) => {
            object.insert("name".into(), json!("issuerAltName"));
            let names: Vec<String> = names.iter().map(general_name_text).collect();
            object.insert("names".into(), json!(names));
        }
        Ok(ParsedExtension::SubjectKeyIdentifier(key)) => {
            object.insert("name".into(), json!("subjectKeyIdentifier"));
            object.insert("key_identifier".into(), json!(colon_hex(&key)));
        }
        Ok(ParsedExtension::AuthorityKeyIdentifier(aki)) => {
            object.insert("name".into(), json!("authorityKeyIdentifier"));
            object.insert(
                "authority_key_identifier".into(),
                authority_key_identifier(&aki),
            );
        }
        Ok(ParsedExtension::CrlDistributionPoints(points)) => {
            object.insert("name".into(), json!("crlDistributionPoints"));
            object.insert("uris".into(), json!(points.uris));
        }
        Ok(ParsedExtension::AuthorityInfoAccess(access)) => {
            object.insert("name".into(), json!("authorityInfoAccess"));
            object.insert("ocsp".into(), json!(access.ocsp));
            object.insert("ca_issuers".into(), json!(access.ca_issuers));
        }
        Ok(ParsedExtension::CertificatePolicies(policies)) => {
            object.insert("name".into(), json!("certificatePolicies"));
            let policies: Vec<String> = policies
                .policies
                .iter()
                .map(|oid| oid.to_string())
                .collect();
            object.insert("policies".into(), json!(policies));
        }
        _ => {}
    }
    value
}

fn certificate_json(certificate: &Certificate) -> Value {
    let tbs = certificate.tbs();
    let validity = certificate.validity();
    let extensions: Vec<Value> = tbs.extensions.iter().map(extension_json).collect();
    let fingerprint = certificate
        .fingerprint(Hash::Sha256)
        .map(|digest| colon_hex(&digest))
        .ok();
    let self_signed = certificate.is_self_signed();
    json!({
        "kind": "certificate",
        "version": tbs.version + 1,
        "serial": serial_hex(certificate.serial_number()),
        "subject": certificate.subject().to_string(),
        "issuer": certificate.issuer().to_string(),
        "not_before": validity.not_before.to_unix(),
        "not_after": validity.not_after.to_unix(),
        "not_before_text": time_text(validity.not_before),
        "not_after_text": time_text(validity.not_after),
        "signature_algorithm": signature_algorithm_name(certificate.signature_algorithm()),
        "public_key_algorithm": public_key_algorithm(certificate.public_key()),
        "public_key_bits": public_key_bits(certificate.public_key()),
        "public_key": colon_hex(&certificate.subject_public_key_info().key),
        "is_ca": tbs.is_ca(),
        "self_signed": self_signed,
        "self_signature_valid": if self_signed {
            Some(certificate.verify_signature(certificate.public_key()).unwrap_or(false))
        } else {
            None
        },
        "fingerprint_sha256": fingerprint,
        "extensions": extensions,
    })
}

fn csr_json(csr: &CertificationRequest) -> Value {
    let info = csr.info();
    json!({
        "kind": "csr",
        "version": info.version,
        "subject": info.subject.to_string(),
        "public_key_algorithm": public_key_algorithm(&info.subject_public_key_info.public_key),
        "public_key_bits": public_key_bits(&info.subject_public_key_info.public_key),
        "public_key": colon_hex(&info.subject_public_key_info.key),
        "signature_algorithm": signature_algorithm_name(csr.signature_algorithm()),
        "signature_valid": csr.verify_signature().unwrap_or(false),
    })
}

fn crl_json(crl: &CertificateList) -> Value {
    let tbs = crl.tbs();
    let revoked: Vec<Value> = tbs
        .revoked_certificates
        .iter()
        .map(|entry| {
            json!({
                "serial": serial_hex(&entry.serial_number),
                "date": entry.revocation_date.to_unix(),
                "date_text": time_text(entry.revocation_date),
            })
        })
        .collect();
    json!({
        "kind": "crl",
        "version": tbs.version.map(|version| version + 1).unwrap_or(1),
        "issuer": tbs.issuer.to_string(),
        "this_update": tbs.this_update.to_unix(),
        "this_update_text": time_text(tbs.this_update),
        "next_update": tbs.next_update.map(Asn1Time::to_unix),
        "next_update_text": tbs.next_update.map(time_text),
        "signature_algorithm": signature_algorithm_name(&tbs.signature),
        "revoked": revoked,
    })
}

fn parse_x509(data: &[u8]) -> Result<Value, JsValue> {
    if let Some(text) = is_pem(data) {
        let block = pem::parse_first(text).map_err(js_error)?;
        if block.label.contains("CERTIFICATE REQUEST") {
            let csr = CertificationRequest::parse(&block.data).map_err(js_error)?;
            return Ok(csr_json(&csr));
        }
        if block.label == "X509 CRL" || block.label == "CRL" {
            let crl = CertificateList::parse(&block.data).map_err(js_error)?;
            return Ok(crl_json(&crl));
        }
        if block.label == "ATTRIBUTE CERTIFICATE" {
            let certificate =
                crown::x509::AttributeCertificate::parse(&block.data).map_err(js_error)?;
            return Ok(attribute_certificate_json(&certificate));
        }
        let certificate = Certificate::parse(&block.data).map_err(js_error)?;
        return Ok(certificate_json(&certificate));
    }
    if let Ok(certificate) = Certificate::parse(data) {
        return Ok(certificate_json(&certificate));
    }
    if let Ok(csr) = CertificationRequest::parse(data) {
        return Ok(csr_json(&csr));
    }
    if let Ok(crl) = CertificateList::parse(data) {
        return Ok(crl_json(&crl));
    }
    let certificate = crown::x509::AttributeCertificate::parse(data).map_err(js_error)?;
    Ok(attribute_certificate_json(&certificate))
}

/// Parse a certificate, CSR or CRL (PEM or DER) and return a JSON report.
#[wasm_bindgen]
pub fn x509_parse(data: &[u8]) -> Result<String, JsValue> {
    let value = parse_x509(data)?;
    serde_json::to_string(&value).map_err(|error| js_error(error.to_string()))
}

fn pkcs7_content_type(content_type: &crown::asn1::ObjectIdentifier) -> &'static str {
    use crown::asn1::oid;
    if content_type.matches(oid::OID_PKCS7_SIGNED_DATA) {
        "signedData"
    } else if content_type.matches(oid::OID_PKCS7_DATA) {
        "data"
    } else {
        "other"
    }
}

fn pkcs7_json(pkcs7: &Pkcs7) -> Value {
    match pkcs7 {
        Pkcs7::SignedData(data) => {
            let signers: Vec<Value> = data
                .signer_infos
                .iter()
                .map(|signer| {
                    let (issuer, serial) = match &signer.sid {
                        SignerIdentifier::IssuerAndSerialNumber {
                            issuer,
                            serial_number,
                        } => (Some(issuer.to_string()), Some(serial_hex(serial_number))),
                        SignerIdentifier::SubjectKeyIdentifier(key) => (None, Some(colon_hex(key))),
                    };
                    json!({
                        "digest_algorithm": Hash::from_oid(&signer.digest_algorithm.oid)
                            .map(hash_name)
                            .unwrap_or("unknown"),
                        "signature_algorithm": signature_algorithm_name_with_digest(
                            &signer.signature_algorithm,
                            &signer.digest_algorithm
                        ),
                        "issuer": issuer,
                        "serial": serial,
                        "signed_attributes": signer.signed_attrs.as_ref().map(Vec::len),
                    })
                })
                .collect();
            let certificates: Vec<Value> = data
                .certificates
                .iter()
                .map(|certificate| {
                    json!({
                        "subject": certificate.subject().to_string(),
                        "issuer": certificate.issuer().to_string(),
                    })
                })
                .collect();
            json!({
                "kind": "pkcs7",
                "content_type": "signedData",
                "version": data.version,
                "detached": data.encap_content_info.content.is_none(),
                "content_length": data.encap_content_info.content.as_ref().map(Vec::len),
                "digest_algorithms": data.digest_algorithms.iter().map(|algorithm| {
                    Hash::from_oid(&algorithm.oid)
                        .map(|hash| hash_name(hash).to_string())
                        .unwrap_or_else(|| algorithm.oid.to_string())
                }).collect::<Vec<_>>(),
                "signers": signers,
                "certificates": certificates,
            })
        }
        Pkcs7::Data(content) => json!({
            "kind": "pkcs7",
            "content_type": "data",
            "content_length": content.len(),
        }),
        Pkcs7::Other(info) => json!({
            "kind": "pkcs7",
            "content_type": pkcs7_content_type(&info.content_type),
            "oid": info.content_type.to_string(),
        }),
    }
}

fn signature_algorithm_name_with_digest(
    alg: &AlgorithmIdentifier,
    digest: &AlgorithmIdentifier,
) -> String {
    match SignatureAlgorithm::from_identifier_with_digest(alg, Some(digest)) {
        Ok(parsed) => signature_algorithm_text(parsed),
        Err(_) => alg.oid.to_string(),
    }
}

fn load_pkcs7(data: &[u8]) -> Result<Pkcs7, JsValue> {
    if let Some(text) = is_pem(data) {
        let block = pem::parse_first(text).map_err(js_error)?;
        return Pkcs7::parse(&block.data).map_err(js_error);
    }
    Pkcs7::parse(data).map_err(js_error)
}

/// Parse a CMS / PKCS#7 object (PEM or DER) and return a JSON report.
#[wasm_bindgen]
pub fn pkcs7_parse(data: &[u8]) -> Result<String, JsValue> {
    let pkcs7 = load_pkcs7(data)?;
    serde_json::to_string(&pkcs7_json(&pkcs7)).map_err(|error| js_error(error.to_string()))
}

/// Verify a CMS SignedData object. `detached` carries the content for
/// detached signatures and may be omitted for attached ones. `sm2_id`
/// overrides the GM/T default SM2 identity.
#[wasm_bindgen]
pub fn pkcs7_verify(
    data: &[u8],
    detached: Option<Vec<u8>>,
    sm2_id: Option<String>,
) -> Result<bool, JsValue> {
    let pkcs7 = load_pkcs7(data)?;
    let Pkcs7::SignedData(signed_data) = &pkcs7 else {
        return Err(JsValue::from_str("not a CMS SignedData object"));
    };
    let detached = detached.as_deref().filter(|content| !content.is_empty());
    let result = match sm2_id.as_deref() {
        Some(id) if !id.is_empty() => signed_data.verify_with_sm2_id(detached, id.as_bytes()),
        _ => signed_data.verify(detached),
    };
    match result {
        Ok(()) => Ok(true),
        Err(crown::error::CryptoError::AuthenticationFailed) => Ok(false),
        Err(error) => Err(js_error(error)),
    }
}

fn load_pkcs12(
    data: &[u8],
    password: &[u8],
) -> Result<(crown::pkcs12::Pfx, Vec<SafeBag>), JsValue> {
    let pfx = if let Some(text) = is_pem(data) {
        crown::pkcs12::Pfx::from_pem(text).map_err(js_error)?
    } else {
        crown::pkcs12::Pfx::parse(data).map_err(js_error)?
    };
    let bags = pfx.decoded_bags(password).map_err(js_error)?;
    let mut decoded = Vec::with_capacity(bags.len());
    for bag in bags {
        match bag.bag {
            Bag::ShroudedKey(ref info) => {
                let key =
                    crown::x509::pbe::decrypt_private_key(info, password).map_err(js_error)?;
                decoded.push(SafeBag {
                    bag: Bag::Key(key),
                    attributes: bag.attributes.clone(),
                });
            }
            _ => decoded.push(bag),
        }
    }
    Ok((pfx, decoded))
}

/// Parse a PKCS#12 PFX (DER or PEM) with its password and return a JSON
/// report. Shrouded key bags are decrypted with the password.
#[wasm_bindgen]
pub fn pkcs12_parse(data: &[u8], password: &str) -> Result<String, JsValue> {
    let password = password.as_bytes();
    let (pfx, bags) = load_pkcs12(data, password)?;
    let mac = pfx.mac.as_ref().map(|_| pfx.verify_mac(password).is_ok());
    let bags: Vec<Value> = bags
        .iter()
        .map(|bag| {
            let (kind, subject, key_algorithm) = match &bag.bag {
                Bag::Cert(certificate) => (0, Some(certificate.subject().to_string()), None),
                Bag::Key(info) => (1, None, Some(info.algorithm.oid.to_string())),
                Bag::ShroudedKey(info) => (1, None, Some(info.algorithm.oid.to_string())),
                Bag::Crl(crl) => (2, Some(crl.tbs().issuer.to_string()), None),
                Bag::Secret { .. } => (3, None, None),
                Bag::SafeContents(_) => (4, None, None),
                Bag::Other { .. } => (5, None, None),
            };
            json!({
                "kind": kind,
                "friendly_name": bag.friendly_name(),
                "local_key_id": bag.local_key_id().as_deref().map(colon_hex),
                "subject": subject,
                "key_algorithm": key_algorithm,
            })
        })
        .collect();
    let value = json!({
        "kind": "pkcs12",
        "version": pfx.version,
        "mac_present": pfx.mac.is_some(),
        "mac_verified": mac,
        "bags": bags,
    });
    serde_json::to_string(&value).map_err(|error| js_error(error.to_string()))
}

fn private_key_json(private_key: &PrivateKey) -> Value {
    let public_key = private_key.public_key().ok();
    json!({
        "key_type": format!("{private_key:?}"),
        "public_key_algorithm": public_key.as_ref().map(public_key_algorithm),
        "public_key_bits": public_key.as_ref().and_then(public_key_bits),
        "public_key": public_key
            .as_ref()
            .and_then(|key| crown::x509::SubjectPublicKeyInfo::from_public_key(key).ok())
            .map(|spki| colon_hex(&spki.key)),
    })
}

/// Decrypt a PKCS#8 `EncryptedPrivateKeyInfo` (PEM or DER) and return a JSON
/// key report.
#[wasm_bindgen]
pub fn pkcs8_decrypt(data: &[u8], password: &str) -> Result<String, JsValue> {
    let encrypted = if let Some(text) = is_pem(data) {
        let block = pem::parse_first(text).map_err(js_error)?;
        EncryptedPrivateKeyInfo::parse(&block.data).map_err(js_error)?
    } else {
        EncryptedPrivateKeyInfo::parse(data).map_err(js_error)?
    };
    let info: PrivateKeyInfo =
        crown::x509::pbe::decrypt_private_key(&encrypted, password.as_bytes()).map_err(js_error)?;
    let mut value = json!({
        "kind": "pkcs8",
        "algorithm": info.algorithm.oid.to_string(),
    });
    if let Ok(private_key) = info.decode() {
        let object = value.as_object_mut().expect("object");
        object.insert("key".into(), private_key_json(&private_key));
    }
    serde_json::to_string(&value).map_err(|error| js_error(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA_PEM: &[u8] = include_bytes!("../../crown/tests/data/pki/ca.pem");
    const LEAF_PEM: &[u8] = include_bytes!("../../crown/tests/data/pki/leaf.pem");
    const CSR: &[u8] = include_bytes!("../../crown/tests/data/pki/leaf.csr");
    const CRL: &[u8] = include_bytes!("../../crown/tests/data/pki/crl.pem");
    const CMS: &[u8] = include_bytes!("../../crown/tests/data/pki/cms_attached.der");
    const CMS_DETACHED: &[u8] = include_bytes!("../../crown/tests/data/pki/cms_detached.der");
    const PAYLOAD: &[u8] = include_bytes!("../../crown/tests/data/pki/payload.txt");
    const PFX: &[u8] = include_bytes!("../../crown/tests/data/pki/pfx_modern.p12");
    const ENCRYPTED_KEY: &[u8] = include_bytes!("../../crown/tests/data/pki/rsa_pkcs8_pbes2.pem");

    #[test]
    fn x509_reports() {
        let value = parse_x509(CA_PEM).unwrap();
        assert_eq!(value["kind"], "certificate");
        assert_eq!(value["is_ca"], true);
        assert_eq!(value["self_signed"], true);
        assert_eq!(value["self_signature_valid"], true);
        assert!(value["subject"]
            .as_str()
            .unwrap()
            .contains("Crown Test Root CA"));
        assert!(value["extensions"].as_array().unwrap().len() >= 3);

        let value = parse_x509(LEAF_PEM).unwrap();
        assert_eq!(value["self_signed"], false);
        assert_eq!(value["self_signature_valid"], Value::Null);

        let value = parse_x509(CSR).unwrap();
        assert_eq!(value["kind"], "csr");
        assert_eq!(value["signature_valid"], true);

        let value = parse_x509(CRL).unwrap();
        assert_eq!(value["kind"], "crl");
        assert!(value["issuer"]
            .as_str()
            .unwrap()
            .contains("Crown Test Root CA"));
    }

    #[test]
    fn pkcs7_reports() {
        let pkcs7 = load_pkcs7(CMS).unwrap();
        let value = pkcs7_json(&pkcs7);
        assert_eq!(value["content_type"], "signedData");
        assert_eq!(value["detached"], false);
        assert_eq!(value["signers"].as_array().unwrap().len(), 1);
        assert_eq!(value["certificates"].as_array().unwrap().len(), 2);
        assert!(pkcs7_verify(CMS, None, None).unwrap());

        let pkcs7 = load_pkcs7(CMS_DETACHED).unwrap();
        let value = pkcs7_json(&pkcs7);
        assert_eq!(value["detached"], true);
        assert!(pkcs7_verify(CMS_DETACHED, Some(PAYLOAD.to_vec()), None).unwrap());
    }

    #[test]
    fn pkcs12_and_pkcs8_reports() {
        let (_pfx, bags) = load_pkcs12(PFX, b"crown-test").unwrap();
        assert!(bags.iter().any(|bag| matches!(bag.bag, Bag::Cert(_))));
        assert!(bags.iter().any(|bag| matches!(bag.bag, Bag::Key(_))));
        let report: Value =
            serde_json::from_str(&pkcs12_parse(PFX, "crown-test").unwrap()).unwrap();
        assert_eq!(report["mac_verified"], true);
        assert_eq!(report["bags"].as_array().unwrap().len(), bags.len());

        let report: Value =
            serde_json::from_str(&pkcs8_decrypt(ENCRYPTED_KEY, "crown-test").unwrap()).unwrap();
        assert_eq!(report["kind"], "pkcs8");
        assert_eq!(report["key"]["public_key_bits"], 2048);
    }
}

/// Verify a certificate chain (RFC 5280). `trust` and `untrusted` are PEM
/// bundles (or single DER objects); `crl` is an optional PEM/DER CRL.
/// Returns a JSON report.
#[wasm_bindgen]
pub fn x509_verify(
    leaf: &[u8],
    trust: &[u8],
    untrusted: &[u8],
    crl: Option<Vec<u8>>,
    purpose: Option<String>,
    time: Option<i64>,
) -> Result<String, JsValue> {
    use crown::x509::{verify_certificate, Purpose, Store, VerifyFlags, VerifyOptions};
    let leaf = parse_certificate_bytes(leaf)?;
    let mut store = Store::new();
    for candidate in parse_certificate_bundle(trust)? {
        store.add_trusted_certificate(candidate);
    }
    let untrusted = parse_certificate_bundle(untrusted)?;
    if let Some(crl) = &crl {
        let parsed = match is_pem(crl) {
            Some(text) => crown::x509::CertificateList::from_pem(text).map_err(js_error)?,
            None => crown::x509::CertificateList::parse(crl).map_err(js_error)?,
        };
        store.add_crl(parsed);
    }
    let purpose = match purpose.as_deref().unwrap_or("any") {
        "any" => Purpose::Any,
        "ssl-server" | "sslServer" => Purpose::SslServer,
        "ssl-client" | "sslClient" => Purpose::SslClient,
        "smime-sign" => Purpose::SmimeSign,
        "smime-encrypt" => Purpose::SmimeEncrypt,
        "code-signing" => Purpose::CodeSigning,
        "ocsp-helper" => Purpose::OcspHelper,
        "time-stamping" => Purpose::TimeStamping,
        "crl-sign" => Purpose::CrlSign,
        other => return Err(JsValue::from_str(&format!("unknown purpose {other}"))),
    };
    let flags = VerifyFlags {
        crl_check: crl.is_some(),
        ..Default::default()
    };
    let options = VerifyOptions {
        time,
        purpose,
        flags,
        untrusted,
        ..Default::default()
    };
    let value = match verify_certificate(&store, &leaf, &options) {
        Ok(result) => json!({
            "ok": true,
            "chain": result.chain.iter().map(|certificate| json!({
                "subject": certificate.subject().to_string(),
                "issuer": certificate.issuer().to_string(),
            })).collect::<Vec<_>>(),
        }),
        Err(error) => json!({
            "ok": false,
            "error": error.to_string(),
            "code": error.code(),
        }),
    };
    serde_json::to_string(&value).map_err(|error| js_error(error.to_string()))
}

fn parse_certificate_bytes(data: &[u8]) -> Result<Certificate, JsValue> {
    match is_pem(data) {
        Some(text) => Certificate::from_pem(text).map_err(js_error),
        None => Certificate::parse(data).map_err(js_error),
    }
}

fn parse_certificate_bundle(data: &[u8]) -> Result<Vec<Certificate>, JsValue> {
    if let Some(text) = is_pem(data) {
        let mut certificates = Vec::new();
        for block in pem::parse(text).map_err(js_error)? {
            if block.label == "CERTIFICATE" || block.label == "X509 CERTIFICATE" {
                certificates.push(Certificate::parse(&block.data).map_err(js_error)?);
            }
        }
        if certificates.is_empty() {
            return Err(JsValue::from_str("no CERTIFICATE block found"));
        }
        return Ok(certificates);
    }
    Ok(vec![Certificate::parse(data).map_err(js_error)?])
}

/// Encrypt `content` to a recipient certificate (AES-256-CBC + RSA key
/// transport). `password` adds a password recipient when non-empty.
#[wasm_bindgen]
pub fn cms_encrypt(
    content: &[u8],
    certificate: &[u8],
    password: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    use crown::cms::{Cipher, EnvelopedDataBuilder};
    let certificate = parse_certificate_bytes(certificate)?;
    let mut builder = EnvelopedDataBuilder::new(content.to_vec()).add_rsa_recipient(
        &certificate,
        Cipher::Aes256Cbc,
        &mut crate::evp_pki::WasmRng,
    );
    if let Some(password) = password.as_deref().filter(|password| !password.is_empty()) {
        builder = builder.add_password_recipient(password.as_bytes(), Cipher::Aes256Cbc, 2048);
    }
    let enveloped = builder.build(&mut WasmRng).map_err(js_error)?;
    Ok(enveloped.to_content_info().encode())
}

/// Decrypt a CMS EnvelopedData (DER) with an RSA PKCS#8 key and its
/// certificate, or with `password` for a password recipient.
#[wasm_bindgen]
pub fn cms_decrypt(
    data: &[u8],
    key: Option<Vec<u8>>,
    certificate: Option<Vec<u8>>,
    password: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    let content_info = crown::pkcs7::ContentInfo::parse(data).map_err(js_error)?;
    let enveloped =
        crown::cms::EnvelopedData::from_content_info(&content_info).map_err(js_error)?;
    if let Some(password) = password.as_deref().filter(|password| !password.is_empty()) {
        return enveloped
            .decrypt_with_password(password.as_bytes())
            .map_err(js_error);
    }
    let (Some(key), Some(certificate)) = (key, certificate) else {
        return Err(JsValue::from_str(
            "key and certificate, or password, required",
        ));
    };
    let info = parse_private_key_info(&key)?;
    let private_key = info.decode().map_err(js_error)?;
    let certificate = parse_certificate_bytes(&certificate)?;
    enveloped
        .decrypt_with_key(&private_key, &certificate)
        .map_err(js_error)
}

fn parse_private_key_info(data: &[u8]) -> Result<PrivateKeyInfo, JsValue> {
    if let Some(text) = is_pem(data) {
        let block = pem::parse_first(text).map_err(js_error)?;
        return PrivateKeyInfo::parse(&block.data).map_err(js_error);
    }
    PrivateKeyInfo::parse(data).map_err(js_error)
}

/// Verify an OCSP response (PEM or DER) against its issuer certificate and
/// return a JSON report.
#[wasm_bindgen]
pub fn ocsp_verify(response: &[u8], issuer: &[u8]) -> Result<String, JsValue> {
    let issuer = parse_certificate_bytes(issuer)?;
    let response = match is_pem(response) {
        Some(text) => crown::ocsp::OcspResponse::from_pem(text).map_err(js_error)?,
        None => crown::ocsp::OcspResponse::parse(response).map_err(js_error)?,
    };
    let verified = response.verify(&issuer).is_ok();
    let mut value = json!({
        "ok": verified,
        "status": format!("{:?}", response.status),
    });
    if let Ok(basic) = response.basic() {
        let responses: Vec<Value> = basic
            .tbs_response_data
            .responses
            .iter()
            .map(|single| {
                json!({
                    "serial": hex(&single.cert_id.serial_number),
                    "status": format!("{:?}", single.cert_status),
                    "this_update": single.this_update.to_unix(),
                    "next_update": single.next_update.map(|time| time.to_unix()),
                })
            })
            .collect();
        let object = value.as_object_mut().expect("object");
        object.insert(
            "responder".into(),
            json!(format!("{:?}", basic.tbs_response_data.responder_id)),
        );
        object.insert("responses".into(), json!(responses));
    }
    serde_json::to_string(&value).map_err(|error| js_error(error.to_string()))
}

/// An RNG backed by the wasm `getrandom` implementation.
struct WasmRng;

impl crown::rng::Rng for WasmRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        let _ = getrandom::fill(out);
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    const V_ROOT: &[u8] = include_bytes!("../../crown/tests/data/pki/verify/root.pem");
    const V_INTER: &[u8] = include_bytes!("../../crown/tests/data/pki/verify/inter.pem");
    const V_LEAF: &[u8] = include_bytes!("../../crown/tests/data/pki/verify/leaf_good.pem");
    const V_BAD: &[u8] = include_bytes!("../../crown/tests/data/pki/verify/leaf_bad_dns.pem");
    const V_REVOKED: &[u8] = include_bytes!("../../crown/tests/data/pki/verify/leaf_revoked.pem");
    const V_CRL: &[u8] = include_bytes!("../../crown/tests/data/pki/verify/inter.crl");
    const LEAF: &[u8] = include_bytes!("../../crown/tests/data/pki/leaf.pem");
    const RSA_KEY: &[u8] = include_bytes!("../../crown/tests/data/pki/rsa_pkcs8.pem");
    const EC_CERT: &[u8] = include_bytes!("../../crown/tests/data/pki/ec.pem");
    const OCSP_GOOD: &[u8] = include_bytes!("../../crown/tests/data/pki/ocsp_response_good.der");
    const PAYLOAD: &[u8] = include_bytes!("../../crown/tests/data/pki/payload.txt");

    #[test]
    fn verify_chain_reports() {
        let report: Value =
            serde_json::from_str(&x509_verify(V_LEAF, V_ROOT, V_INTER, None, None, None).unwrap())
                .unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["chain"].as_array().unwrap().len(), 3);

        let report: Value =
            serde_json::from_str(&x509_verify(V_BAD, V_ROOT, V_INTER, None, None, None).unwrap())
                .unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["code"], 47);

        let report: Value = serde_json::from_str(
            &x509_verify(V_REVOKED, V_ROOT, V_INTER, Some(V_CRL.to_vec()), None, None).unwrap(),
        )
        .unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["code"], 23);
    }

    #[test]
    fn attribute_certificate_and_timestamp_bindings() {
        use crown::cms::AuthenticatedDataBuilder;

        const TS_QUERY: &[u8] = include_bytes!("../../crown/tests/data/pki/ts_query_sha256.der");
        const TS_RESPONSE: &[u8] =
            include_bytes!("../../crown/tests/data/pki/ts_response_sha256.der");
        const TS_TSA: &[u8] = include_bytes!("../../crown/tests/data/pki/ts_tsa.pem");
        const TS_DATA: &[u8] = b"crown timestamp test payload\n";
        const AC: &[u8] = include_bytes!("../../crown/tests/data/pki/ac_acert_ietf.pem");

        let report: Value = serde_json::from_str(&ac_parse(AC).unwrap()).unwrap();
        assert_eq!(report["kind"], "attribute-certificate");
        assert_eq!(report["version"], 2);
        assert!(report["attributes"].as_array().unwrap().len() >= 1);
        // x509_parse auto-detects the PEM label.
        let report: Value = serde_json::from_str(&x509_parse(AC).unwrap()).unwrap();
        assert_eq!(report["kind"], "attribute-certificate");

        let report: Value = serde_json::from_str(
            &ts_verify(
                TS_RESPONSE,
                TS_TSA,
                Some(TS_QUERY.to_vec()),
                Some(TS_DATA.to_vec()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["message_imprint_matches"], true);

        struct WasmTestRng(u64);
        impl crown::rng::Rng for WasmTestRng {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                WasmRng.fill_bytes(out);
                let _ = &mut self.0;
            }
        }
        let authenticated = AuthenticatedDataBuilder::new(PAYLOAD.to_vec())
            .add_rsa_recipient(&parse_certificate_bytes(LEAF).unwrap())
            .build(&mut WasmTestRng(1))
            .unwrap();
        let der = authenticated.to_content_info().encode();
        let plaintext =
            cms_auth_verify(&der, Some(RSA_KEY.to_vec()), Some(LEAF.to_vec()), None).unwrap();
        assert_eq!(plaintext, PAYLOAD);
    }

    #[test]
    fn cmp_bindings() {
        const CMP_IR: &[u8] = include_bytes!("../../crown/tests/data/pki/cmp_ir_secret.der");
        let report: Value = serde_json::from_str(&cmp_parse(CMP_IR).unwrap()).unwrap();
        assert_eq!(report["kind"], "cmp");
        assert_eq!(report["pvno"], 2);
        assert_eq!(report["body"], "ir");
        assert_eq!(report["requests"].as_array().unwrap().len(), 1);
        assert_eq!(report["requests"][0]["popo"], "signature");
        assert!(cmp_verify(CMP_IR, Some("test".to_string())).unwrap());
        assert!(!cmp_verify(CMP_IR, Some("wrong".to_string())).unwrap());
    }

    #[test]
    fn cms_round_trip_and_ocsp() {
        let enveloped = cms_encrypt(PAYLOAD, LEAF, None).unwrap();
        let plaintext = cms_decrypt(
            &enveloped,
            Some(RSA_KEY.to_vec()),
            Some(LEAF.to_vec()),
            None,
        )
        .unwrap();
        assert_eq!(plaintext, PAYLOAD);

        let enveloped = cms_encrypt(PAYLOAD, LEAF, Some("crown-test".to_string())).unwrap();
        let plaintext =
            cms_decrypt(&enveloped, None, None, Some("crown-test".to_string())).unwrap();
        assert_eq!(plaintext, PAYLOAD);

        let report: Value =
            serde_json::from_str(&ocsp_verify(OCSP_GOOD, EC_CERT).unwrap()).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["responses"].as_array().unwrap().len(), 1);
    }
}

fn attribute_certificate_json(certificate: &crown::x509::AttributeCertificate) -> Value {
    let info = certificate.info();
    let holder = &info.holder;
    let mut holder_json = json!({});
    if let Some(id) = &holder.base_certificate_id {
        holder_json = json!({
            "base_certificate_id": hex(&id.serial),
            "issuer": id.issuer.iter().map(general_name_text).collect::<Vec<_>>(),
        });
    }
    if let Some(names) = &holder.entity_name {
        holder_json = json!({
            "entity_name": names.iter().map(general_name_text).collect::<Vec<_>>(),
        });
    }
    let attributes: Vec<Value> = info
        .attributes
        .iter()
        .map(|attribute| {
            json!({
                "oid": attribute.oid.to_string(),
                "value": attribute.first_text(),
            })
        })
        .collect();
    json!({
        "kind": "attribute-certificate",
        "version": info.version + 1,
        "serial": serial_hex(&info.serial_number),
        "issuer": info.issuer.directory_names().iter().map(|name| name.to_string()).collect::<Vec<_>>(),
        "not_before": info.validity.not_before.to_unix(),
        "not_after": info.validity.not_after.to_unix(),
        "not_before_text": time_text(info.validity.not_before),
        "not_after_text": time_text(info.validity.not_after),
        "holder": holder_json,
        "attributes": attributes,
        "signature_algorithm": signature_algorithm_name(certificate.signature_algorithm()),
        "extensions": info.extensions.iter().map(extension_json).collect::<Vec<_>>(),
    })
}

fn parse_attribute_certificate(data: &[u8]) -> Result<crown::x509::AttributeCertificate, JsValue> {
    use crown::x509::AttributeCertificate;
    match is_pem(data) {
        Some(text) => AttributeCertificate::from_pem(text).map_err(js_error),
        None => AttributeCertificate::parse(data).map_err(js_error),
    }
}

/// Parse an attribute certificate (RFC 5755) and return a JSON report.
#[wasm_bindgen]
pub fn ac_parse(data: &[u8]) -> Result<String, JsValue> {
    let certificate = parse_attribute_certificate(data)?;
    serde_json::to_string(&attribute_certificate_json(&certificate))
        .map_err(|error| js_error(error.to_string()))
}

/// Verify an attribute certificate against its issuer certificate.
#[wasm_bindgen]
pub fn ac_verify(data: &[u8], issuer: &[u8]) -> Result<String, JsValue> {
    let certificate = parse_attribute_certificate(data)?;
    let issuer = parse_certificate_bytes(issuer)?;
    let mut value = attribute_certificate_json(&certificate);
    let object = value.as_object_mut().expect("object");
    object.insert(
        "signature_valid".into(),
        json!(certificate.verify(&issuer, None).is_ok()),
    );
    object.insert(
        "holder_matches_issuer".into(),
        json!(certificate.holder_matches(&issuer)),
    );
    serde_json::to_string(&value).map_err(|error| js_error(error.to_string()))
}

/// Verify an RFC 3161 timestamp response. `query` (optional) checks the
/// message imprint and nonce; `data` (optional) checks the imprint against
/// the original content. Returns a JSON report.
#[wasm_bindgen]
pub fn ts_verify(
    response: &[u8],
    tsa: &[u8],
    query: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
) -> Result<String, JsValue> {
    let tsa = parse_certificate_bytes(tsa)?;
    let response = match is_pem(response) {
        Some(text) => crown::ts::TimeStampResp::from_pem(text).map_err(js_error)?,
        None => crown::ts::TimeStampResp::parse(response).map_err(js_error)?,
    };
    let info = match &query {
        Some(query) => {
            let request = crown::ts::TimeStampReq::parse(query).map_err(js_error)?;
            response.verify_request(&tsa, &request)
        }
        None => response.verify(&tsa),
    };
    let mut value = json!({ "ok": info.is_ok() });
    if let Ok(info) = info {
        let object = value.as_object_mut().expect("object");
        object.insert("policy".into(), json!(info.policy.to_string()));
        object.insert("serial".into(), json!(serial_hex(&info.serial_number)));
        object.insert("gen_time".into(), json!(info.gen_time.to_unix()));
        if let Some(nonce) = &info.nonce {
            object.insert("nonce".into(), json!(hex(nonce)));
        }
        if let Some(data) = &data {
            let matches = info.message_imprint.matches(data).unwrap_or(false);
            object.insert("message_imprint_matches".into(), json!(matches));
            if !matches {
                object.insert("ok".into(), json!(false));
                object.insert(
                    "error".into(),
                    json!("message imprint does not match the data"),
                );
            }
        }
    } else if let Err(error) = info {
        let object = value.as_object_mut().expect("object");
        object.insert("error".into(), json!(error.to_string()));
    }
    serde_json::to_string(&value).map_err(|error| js_error(error.to_string()))
}

/// Verify a CMS AuthenticatedData object (RSA/ECDH key, or password) and
/// return the authenticated content.
#[wasm_bindgen]
pub fn cms_auth_verify(
    data: &[u8],
    key: Option<Vec<u8>>,
    certificate: Option<Vec<u8>>,
    password: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    let content_info = crown::pkcs7::ContentInfo::parse(data).map_err(js_error)?;
    let authenticated =
        crown::cms::AuthenticatedData::from_content_info(&content_info).map_err(js_error)?;
    if let Some(password) = password.as_deref().filter(|password| !password.is_empty()) {
        return authenticated
            .verify_with_password(password.as_bytes())
            .map_err(js_error);
    }
    let (Some(key), Some(certificate)) = (key, certificate) else {
        return Err(JsValue::from_str(
            "key and certificate, or password, required",
        ));
    };
    let info = parse_private_key_info(&key)?;
    let private_key = info.decode().map_err(js_error)?;
    let certificate = parse_certificate_bytes(&certificate)?;
    authenticated
        .verify_with_key(&private_key, &certificate)
        .map_err(js_error)
}

fn cmp_body_kind(body: &crown::cmp::PkiBody) -> &'static str {
    use crown::cmp::PkiBody;
    match body {
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

fn cmp_message_json(message: &crown::cmp::PkiMessage) -> Value {
    let header = &message.header;
    let requests = match &message.body {
        crown::cmp::PkiBody::Ir(requests)
        | crown::cmp::PkiBody::Cr(requests)
        | crown::cmp::PkiBody::Kur(requests)
        | crown::cmp::PkiBody::Ccr(requests) => requests
            .messages
            .iter()
            .map(|request| {
                json!({
                    "cert_req_id": hex(&request.cert_req.cert_req_id),
                    "subject": request
                        .cert_req
                        .cert_template
                        .subject
                        .as_ref()
                        .map(|subject| subject.to_string()),
                    "public_key_algorithm": request
                        .cert_req
                        .cert_template
                        .public_key
                        .as_ref()
                        .map(|key| public_key_algorithm(&key.public_key)),
                    "popo": request.popo.as_ref().map(|popo| match popo {
                        crown::crmf::ProofOfPossession::RaVerified => "raVerified",
                        crown::crmf::ProofOfPossession::Signature(_) => "signature",
                        crown::crmf::ProofOfPossession::KeyEncipherment(_) => "keyEncipherment",
                        crown::crmf::ProofOfPossession::KeyAgreement(_) => "keyAgreement",
                    }),
                })
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    json!({
        "kind": "cmp",
        "pvno": header.pvno,
        "sender": format!("{:?}", header.sender),
        "recipient": format!("{:?}", header.recipient),
        "message_time": header.message_time.map(|time| time.to_unix()),
        "protection_algorithm": message
            .protection
            .as_ref()
            .map(|protection| protection.alg_id.oid.to_string()),
        "transaction_id": header.transaction_id.as_deref().map(hex),
        "sender_nonce": header.sender_nonce.as_deref().map(hex),
        "free_text": header.free_text,
        "body": cmp_body_kind(&message.body),
        "requests": requests,
        "certificates": message
            .extra_certs
            .iter()
            .map(|certificate| certificate.subject().to_string())
            .collect::<Vec<_>>(),
    })
}

/// Parse a CMP message (DER or PEM) and return a JSON report.
#[wasm_bindgen]
pub fn cmp_parse(data: &[u8]) -> Result<String, JsValue> {
    let message = crown::cmp::PkiMessage::parse(data).map_err(js_error)?;
    serde_json::to_string(&cmp_message_json(&message)).map_err(|error| js_error(error.to_string()))
}

/// Verify a CMP message's protection: the PBM password when given, otherwise
/// the signature against the signer in `extraCerts`.
#[wasm_bindgen]
pub fn cmp_verify(data: &[u8], password: Option<String>) -> Result<bool, JsValue> {
    let message = crown::cmp::PkiMessage::parse(data).map_err(js_error)?;
    let result = match password.as_deref() {
        Some(password) if !password.is_empty() => message.verify_password(password.as_bytes()),
        _ => message.verify_signature(),
    };
    result.map_err(js_error)
}
