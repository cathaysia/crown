//! Shared PKI helpers: file loading, key/hash mapping and text reports for
//! the `x509`, `pkcs7`, `pkcs12` and `pkey` commands.

use std::fmt::Write as _;

use anyhow::{anyhow, bail, Context};
use crown::asn1::pem;
use crown::asn1::time::Asn1Time;
use crown::rng::Rng;
use crown::x509::{
    AlgorithmIdentifier, AuthorityKeyIdentifier, Certificate, CertificateList,
    CertificationRequest, EncryptedPrivateKeyInfo, ExtendedKeyUsage, GeneralName, Hash, KeyUsage,
    ParsedExtension, PrivateKey, PrivateKeyInfo, PublicKey, SignatureAlgorithm,
};

use crate::args::{HashAlgorithm, PbeCipher};

/// `/dev/urandom`-backed RNG for the random parameters of PBE and CMS.
pub struct FileRng;

impl Rng for FileRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(out))
            .expect("failed to read /dev/urandom");
    }
}

fn read_bytes(path: &str) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("failed to read {path}"))
}

fn pem_text(bytes: &[u8]) -> Option<String> {
    if bytes.windows(11).any(|window| window == b"-----BEGIN ") {
        Some(String::from_utf8_lossy(bytes).into_owned())
    } else {
        None
    }
}

/// Load the DER payload of a PEM file, or the file's raw bytes.
pub fn load_der_payload(path: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = read_bytes(path)?;
    match pem_text(&bytes) {
        Some(text) => Ok(pem::parse_first(&text)?.data),
        None => Ok(bytes),
    }
}

/// Write `data` to `path`, or to stdout when no path is given.
pub fn write_output(path: Option<&str>, data: &[u8]) -> anyhow::Result<()> {
    match path {
        Some(path) => {
            std::fs::write(path, data).with_context(|| format!("failed to write {path}"))?;
            println!("wrote {path} ({} bytes)", data.len());
        }
        None => {
            use std::io::Write;
            std::io::stdout().write_all(data)?;
        }
    }
    Ok(())
}

/// Load every certificate in a PEM bundle, or the single DER certificate.
pub fn load_certificates(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let bytes = read_bytes(path)?;
    match pem_text(&bytes) {
        Some(text) => {
            let mut certificates = Vec::new();
            for block in pem::parse(&text)? {
                if block.label == "CERTIFICATE" || block.label == "X509 CERTIFICATE" {
                    certificates.push(Certificate::parse(&block.data)?);
                }
            }
            if certificates.is_empty() {
                bail!("{path}: no CERTIFICATE block found");
            }
            Ok(certificates)
        }
        None => Ok(vec![Certificate::parse(&bytes)?]),
    }
}

/// Load the first certificate of a PEM bundle or a DER certificate.
pub fn load_certificate(path: &str) -> anyhow::Result<Certificate> {
    load_certificates(path).map(|certificates| certificates.into_iter().next().expect("non-empty"))
}

/// Load an attribute certificate (PEM or DER).
pub fn load_attribute_certificate(path: &str) -> anyhow::Result<crown::x509::AttributeCertificate> {
    use crown::x509::AttributeCertificate;
    let bytes = read_bytes(path)?;
    match pem_text(&bytes) {
        Some(text) => Ok(AttributeCertificate::from_pem(&text)?),
        None => Ok(AttributeCertificate::parse(&bytes)?),
    }
}

/// Text report for an attribute certificate.
pub fn attribute_certificate_report(certificate: &crown::x509::AttributeCertificate) -> String {
    let info = certificate.info();
    let mut out = String::new();
    let _ = writeln!(out, "Attribute Certificate:");
    let _ = writeln!(out, "    Version: {}", info.version + 1);
    let _ = writeln!(
        out,
        "    Serial Number: {}",
        serial_hex(&info.serial_number)
    );
    let _ = writeln!(
        out,
        "    Signature Algorithm: {}",
        signature_algorithm_name(certificate.signature_algorithm())
    );
    let _ = writeln!(out, "    Issuer:");
    for name in info.issuer.directory_names() {
        let _ = writeln!(out, "        {name}");
    }
    let _ = writeln!(out, "    Validity:");
    let _ = writeln!(
        out,
        "        Not Before: {}",
        format_time(info.validity.not_before)
    );
    let _ = writeln!(
        out,
        "        Not After : {}",
        format_time(info.validity.not_after)
    );
    let _ = writeln!(out, "    Holder:");
    if let Some(id) = &info.holder.base_certificate_id {
        let _ = writeln!(
            out,
            "        Base Certificate ID: serial {}",
            serial_hex(&id.serial)
        );
        for name in &id.issuer {
            let _ = writeln!(out, "        Issuer: {}", general_name_text(name));
        }
    }
    if let Some(names) = &info.holder.entity_name {
        for name in names {
            let _ = writeln!(out, "        Entity: {}", general_name_text(name));
        }
    }
    if let Some(digest) = &info.holder.object_digest_info {
        let _ = writeln!(
            out,
            "        Object Digest: type {} ({} bytes)",
            digest.digested_object_type,
            digest.object_digest.len()
        );
    }
    let _ = writeln!(out, "    Attributes: {}", info.attributes.len());
    for attribute in &info.attributes {
        match attribute.first_text() {
            Some(text) => {
                let _ = writeln!(out, "        {}: {text}", attribute.oid);
            }
            None => {
                let _ = writeln!(out, "        {}: (raw)", attribute.oid);
            }
        }
    }
    if !info.extensions.is_empty() {
        let _ = writeln!(out, "    X509v3 Extensions:");
        for extension in &info.extensions {
            write_extension(&mut out, extension);
        }
    }
    out
}

/// Load a PKCS#10 CSR (PEM or DER).
pub fn load_csr(path: &str) -> anyhow::Result<CertificationRequest> {
    let bytes = read_bytes(path)?;
    match pem_text(&bytes) {
        Some(text) => Ok(CertificationRequest::from_pem(&text)?),
        None => Ok(CertificationRequest::parse(&bytes)?),
    }
}

/// Load a CRL (PEM or DER).
pub fn load_crl(path: &str) -> anyhow::Result<CertificateList> {
    let bytes = read_bytes(path)?;
    match pem_text(&bytes) {
        Some(text) => Ok(CertificateList::from_pem(&text)?),
        None => Ok(CertificateList::parse(&bytes)?),
    }
}

/// Load a PKCS#8 `PrivateKeyInfo`, decrypting an encrypted key when needed.
pub fn load_private_key_info(path: &str, password: Option<&str>) -> anyhow::Result<PrivateKeyInfo> {
    let bytes = read_bytes(path)?;
    let password = password.filter(|password| !password.is_empty());
    if let Some(text) = pem_text(&bytes) {
        let block = pem::parse_first(&text)?;
        return match block.label.as_str() {
            "PRIVATE KEY" => Ok(PrivateKeyInfo::parse(&block.data)?),
            "EC PRIVATE KEY" => wrap_ec_private_key(&block.data),
            "RSA PRIVATE KEY" => wrap_rsa_private_key(&block.data),
            "ENCRYPTED PRIVATE KEY" => {
                let password = password.ok_or_else(|| anyhow!("--password required"))?;
                let encrypted = EncryptedPrivateKeyInfo::parse(&block.data)?;
                Ok(crown::x509::pbe::decrypt_private_key(
                    &encrypted,
                    password.as_bytes(),
                )?)
            }
            other => bail!("{path}: unsupported PEM label {other:?} (PKCS#8 expected)"),
        };
    }
    if let Ok(info) = PrivateKeyInfo::parse(&bytes) {
        return Ok(info);
    }
    if let Ok(info) = wrap_ec_private_key(&bytes) {
        return Ok(info);
    }
    if let Ok(info) = wrap_rsa_private_key(&bytes) {
        return Ok(info);
    }
    let password = password.ok_or_else(|| anyhow!("--password required"))?;
    let encrypted = EncryptedPrivateKeyInfo::parse(&bytes)?;
    Ok(crown::x509::pbe::decrypt_private_key(
        &encrypted,
        password.as_bytes(),
    )?)
}

/// Wrap an RFC 5915 `ECPrivateKey` (SEC1, "EC PRIVATE KEY") into PKCS#8.
fn wrap_ec_private_key(der: &[u8]) -> anyhow::Result<PrivateKeyInfo> {
    use crown::asn1::der::{Class, Reader};
    use crown::x509::AlgorithmIdentifier;
    let mut reader = Reader::new(der);
    let mut sequence = reader.read_sequence()?;
    let _version = sequence.read_integer()?;
    let _private_key = sequence.read_octet_string()?;
    let curve = if !sequence.is_empty()
        && sequence.peek_tag()?.class == Class::ContextSpecific
        && sequence.peek_tag()?.number == 0
    {
        let mut inner = sequence.read_explicit(0)?;
        Some(inner.read_oid()?)
    } else {
        None
    };
    let public_key = if !sequence.is_empty()
        && sequence.peek_tag()?.class == Class::ContextSpecific
        && sequence.peek_tag()?.number == 1
    {
        let mut inner = sequence.read_explicit(1)?;
        let (unused, data) = inner.read_bit_string()?;
        if unused == 0 {
            Some(data.to_vec())
        } else {
            None
        }
    } else {
        None
    };
    let curve = curve.ok_or_else(|| anyhow!("EC key without named-curve parameters"))?;
    let algorithm = AlgorithmIdentifier::new(
        crown::asn1::oid::ObjectIdentifier::new(crown::asn1::oid::OID_EC_PUBLIC_KEY)
            .expect("static oid"),
        Some(crown::asn1::der::oid(&curve)),
    );
    Ok(PrivateKeyInfo {
        algorithm,
        private_key: der.to_vec(),
        attributes: None,
        public_key,
    })
}

/// Wrap a PKCS#1 `RSAPrivateKey` ("RSA PRIVATE KEY") into PKCS#8.
fn wrap_rsa_private_key(der: &[u8]) -> anyhow::Result<PrivateKeyInfo> {
    use crown::asn1::der::Reader;
    use crown::x509::AlgorithmIdentifier;
    let mut reader = Reader::new(der);
    let mut sequence = reader.read_sequence()?;
    for _ in 0..9 {
        sequence.read_integer()?;
    }
    sequence.expect_end()?;
    reader.expect_end()?;
    Ok(PrivateKeyInfo {
        algorithm: AlgorithmIdentifier::with_null(
            crown::asn1::oid::ObjectIdentifier::new(crown::asn1::oid::OID_RSA_ENCRYPTION)
                .expect("static oid"),
        ),
        private_key: der.to_vec(),
        attributes: None,
        public_key: None,
    })
}

/// Map the CLI hash enum onto the X.509 digest enum.
pub fn hash_from_cli(hash: HashAlgorithm) -> anyhow::Result<Hash> {
    use HashAlgorithm as H;
    Ok(match hash {
        H::Md2 => Hash::Md2,
        H::Md4 => Hash::Md4,
        H::Md5 => Hash::Md5,
        H::Sha1 => Hash::Sha1,
        H::Sha224 => Hash::Sha224,
        H::Sha256 => Hash::Sha256,
        H::Sha384 => Hash::Sha384,
        H::Sha512 => Hash::Sha512,
        H::Sha512224 => Hash::Sha512_224,
        H::Sha512256 => Hash::Sha512_256,
        H::Sha3224 => Hash::Sha3_224,
        H::Sha3256 => Hash::Sha3_256,
        H::Sha3384 => Hash::Sha3_384,
        H::Sha3512 => Hash::Sha3_512,
        H::Sm3 => Hash::Sm3,
        H::Ripemd160 => Hash::Ripemd160,
        _ => bail!("digest {hash} is not usable in X.509/PKCS structures"),
    })
}

/// Name of a digest.
pub fn hash_name(hash: Hash) -> &'static str {
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

/// Map the CLI PBES2 cipher enum onto the library enum (IV filled in later).
pub fn pbes2_cipher(cipher: PbeCipher) -> crown::x509::pbe::Pbes2Cipher {
    use crown::x509::pbe::Pbes2Cipher;
    match cipher {
        PbeCipher::Aes128Cbc => Pbes2Cipher::Aes128Cbc { iv: Vec::new() },
        PbeCipher::Aes192Cbc => Pbes2Cipher::Aes192Cbc { iv: Vec::new() },
        PbeCipher::Aes256Cbc => Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
        PbeCipher::DesEde3Cbc => Pbes2Cipher::DesEde3Cbc { iv: Vec::new() },
    }
}

/// The signature algorithm matching a private key and digest.
pub fn default_signature_algorithm(
    key: &PrivateKey,
    hash: Hash,
) -> anyhow::Result<SignatureAlgorithm> {
    Ok(match key {
        PrivateKey::Rsa(_) => SignatureAlgorithm::RsaPkcs1v15(hash),
        PrivateKey::Ec { .. } => SignatureAlgorithm::Ecdsa(hash),
        PrivateKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
        PrivateKey::Ed448(_) => SignatureAlgorithm::Ed448,
        PrivateKey::Sm2(_) => SignatureAlgorithm::Sm2,
        PrivateKey::Dsa(_) => SignatureAlgorithm::Dsa(hash),
        PrivateKey::MlDsa(key) => SignatureAlgorithm::MlDsa(key.variant()),
        PrivateKey::SlhDsa(key) => SignatureAlgorithm::SlhDsa(key.variant()),
        PrivateKey::X25519(_) | PrivateKey::X448(_) => {
            bail!("key agreement keys cannot sign")
        }
    })
}

/// Colon-separated uppercase hex.
pub fn colon_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        let _ = write!(out, "{byte:02X}");
    }
    out
}

/// Text form of an ASN.1 time (`YYYY-MM-DD HH:MM:SS UTC`).
pub fn format_time(time: Asn1Time) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        time.year, time.month, time.day, time.hour, time.minute, time.second
    )
}

/// Hex serial without leading zero octets.
pub fn serial_hex(serial: &[u8]) -> String {
    let trimmed: &[u8] = {
        let skip = serial.iter().take_while(|&&byte| byte == 0).count();
        &serial[skip..]
    };
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        hex::encode(trimmed)
    }
}

/// Human-readable name of a signature algorithm.
pub fn signature_algorithm_name(alg: &AlgorithmIdentifier) -> String {
    match SignatureAlgorithm::from_identifier(alg) {
        Ok(algorithm) => signature_algorithm_text(algorithm),
        Err(_) => alg.oid.to_string(),
    }
}

/// [`signature_algorithm_name`] for CMS, where the digest is carried
/// separately and RSA PKCS#1 v1.5 uses `rsaEncryption` as the signature OID.
pub fn signature_algorithm_name_with_digest(
    alg: &AlgorithmIdentifier,
    digest: Option<&AlgorithmIdentifier>,
) -> String {
    match SignatureAlgorithm::from_identifier_with_digest(alg, digest) {
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

/// Human-readable public key description.
pub fn public_key_text(key: &PublicKey) -> String {
    match key {
        PublicKey::Rsa(key) => format!("rsaEncryption ({} bit)", key.size() * 8),
        PublicKey::Ec { curve, .. } => format!("id-ecPublicKey ({})", curve_name(*curve)),
        PublicKey::Ed25519(_) => "ED25519".to_string(),
        PublicKey::Ed448(_) => "ED448".to_string(),
        PublicKey::X25519(_) => "X25519".to_string(),
        PublicKey::X448(_) => "X448".to_string(),
        PublicKey::Sm2(_) => "SM2 (sm2p256v1)".to_string(),
        PublicKey::Dsa { params, .. } => {
            format!("dsaEncryption ({} bit)", params.p.bit_len())
        }
        PublicKey::MlDsa(key) => ml_dsa_name(key.variant()).to_string(),
        PublicKey::SlhDsa(key) => key.variant().name().to_string(),
        PublicKey::Unknown { algorithm, .. } => algorithm.oid.to_string(),
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

fn curve_name(curve: crown::ec::CurveId) -> &'static str {
    match curve {
        crown::ec::CurveId::P256 => "prime256v1",
        crown::ec::CurveId::P384 => "secp384r1",
        crown::ec::CurveId::P521 => "secp521r1",
    }
}

fn key_usage_text(usage: &KeyUsage) -> String {
    let mut names = Vec::new();
    let all = [
        (usage.digital_signature, "Digital Signature"),
        (usage.content_commitment, "Non Repudiation"),
        (usage.key_encipherment, "Key Encipherment"),
        (usage.data_encipherment, "Data Encipherment"),
        (usage.key_agreement, "Key Agreement"),
        (usage.key_cert_sign, "Certificate Sign"),
        (usage.crl_sign, "CRL Sign"),
        (usage.encipher_only, "Encipher Only"),
        (usage.decipher_only, "Decipher Only"),
    ];
    for (present, name) in all {
        if present {
            names.push(name);
        }
    }
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names.join(", ")
    }
}

fn purpose_name(oid: &crown::asn1::ObjectIdentifier) -> String {
    use crown::asn1::oid;
    let known: &[(&[u64], &str)] = &[
        (oid::OID_KP_SERVER_AUTH, "TLS Web Server Authentication"),
        (oid::OID_KP_CLIENT_AUTH, "TLS Web Client Authentication"),
        (oid::OID_KP_CODE_SIGNING, "Code Signing"),
        (oid::OID_KP_EMAIL_PROTECTION, "E-mail Protection"),
        (oid::OID_KP_TIME_STAMPING, "Time Stamping"),
        (oid::OID_KP_OCSP_SIGNING, "OCSP Signing"),
    ];
    for (arcs, name) in known {
        if oid.matches(arcs) {
            return (*name).to_string();
        }
    }
    oid.to_string()
}

fn extended_key_usage_text(usage: &ExtendedKeyUsage) -> String {
    if usage.purposes.is_empty() {
        return "(none)".to_string();
    }
    usage
        .purposes
        .iter()
        .map(purpose_name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Text form of a general name.
pub fn general_name_text(name: &GeneralName) -> String {
    match name {
        GeneralName::OtherName { oid, .. } => format!("othername:{oid}"),
        GeneralName::Rfc822Name(text) => format!("email:{text}"),
        GeneralName::DnsName(text) => format!("DNS:{text}"),
        GeneralName::X400Address(_) => "X400Address".to_string(),
        GeneralName::DirectoryName(name) => format!("DirName:{name}"),
        GeneralName::EdiPartyName(_) => "EdiPartyName".to_string(),
        GeneralName::Uri(text) => format!("URI:{text}"),
        GeneralName::IpAddress(bytes) => match bytes.len() {
            4 => format!(
                "IP Address:{}.{}.{}.{}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            ),
            16 => {
                let mut groups = Vec::new();
                for chunk in bytes.chunks(2) {
                    groups.push(format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])));
                }
                format!("IP Address:{}", groups.join(":"))
            }
            _ => format!("IP Address:{}", colon_hex(bytes)),
        },
        GeneralName::RegisteredId(oid) => format!("Registered ID:{oid}"),
        GeneralName::Unknown { tag, .. } => format!("Unknown([{tag}])"),
    }
}

fn general_names_text(names: &[GeneralName]) -> String {
    names
        .iter()
        .map(general_name_text)
        .collect::<Vec<_>>()
        .join(", ")
}

fn authority_key_identifier_text(aki: &AuthorityKeyIdentifier) -> String {
    let mut parts = Vec::new();
    if let Some(key) = &aki.key_identifier {
        parts.push(format!("keyid:{}", colon_hex(key)));
    }
    if let Some(serial) = &aki.authority_cert_serial {
        parts.push(format!("serial:{}", serial_hex(serial)));
    }
    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(", ")
    }
}

fn extension_name(oid: &crown::asn1::ObjectIdentifier) -> String {
    use crown::asn1::oid;
    let known: &[(&[u64], &str)] = &[
        (oid::OID_BASIC_CONSTRAINTS, "X509v3 Basic Constraints"),
        (oid::OID_KEY_USAGE, "X509v3 Key Usage"),
        (oid::OID_EXTENDED_KEY_USAGE, "X509v3 Extended Key Usage"),
        (oid::OID_SUBJECT_ALT_NAME, "X509v3 Subject Alternative Name"),
        (oid::OID_ISSUER_ALT_NAME, "X509v3 Issuer Alternative Name"),
        (
            oid::OID_SUBJECT_KEY_IDENTIFIER,
            "X509v3 Subject Key Identifier",
        ),
        (
            oid::OID_AUTHORITY_KEY_IDENTIFIER,
            "X509v3 Authority Key Identifier",
        ),
        (
            oid::OID_CRL_DISTRIBUTION_POINTS,
            "X509v3 CRL Distribution Points",
        ),
        (
            oid::OID_AUTHORITY_INFO_ACCESS,
            "X509v3 Authority Information Access",
        ),
        (oid::OID_CERTIFICATE_POLICIES, "X509v3 Certificate Policies"),
        (oid::OID_FRESHEST_CRL, "X509v3 Freshest CRL"),
        (&[2, 5, 29, 20], "X509v3 CRL Number"),
        (&[2, 5, 29, 21], "X509v3 CRL Reason Code"),
        (&[2, 5, 29, 24], "X509v3 Invalidity Date"),
        (&[2, 5, 29, 27], "X509v3 Delta CRL Indicator"),
        (&[2, 5, 29, 28], "X509v3 Issuing Distribution Point"),
    ];
    for (arcs, name) in known {
        if oid.matches(arcs) {
            return (*name).to_string();
        }
    }
    format!("X509v3 {oid}")
}

fn write_extension(out: &mut String, extension: &crown::x509::Extension) {
    let critical = if extension.critical { " critical" } else { "" };
    let _ = writeln!(out, "        {}{critical}", extension_name(&extension.oid));
    match extension.parsed() {
        Ok(ParsedExtension::BasicConstraints(bc)) => {
            let _ = write!(
                out,
                "            CA:{}",
                if bc.ca { "TRUE" } else { "FALSE" }
            );
            if let Some(path_len) = bc.path_len {
                let _ = write!(out, ", pathlen:{path_len}");
            }
            let _ = writeln!(out);
        }
        Ok(ParsedExtension::KeyUsage(usage)) => {
            let _ = writeln!(out, "            {}", key_usage_text(&usage));
        }
        Ok(ParsedExtension::ExtendedKeyUsage(usage)) => {
            let _ = writeln!(out, "            {}", extended_key_usage_text(&usage));
        }
        Ok(ParsedExtension::SubjectAltName(names)) | Ok(ParsedExtension::IssuerAltName(names)) => {
            let _ = writeln!(out, "            {}", general_names_text(&names));
        }
        Ok(ParsedExtension::SubjectKeyIdentifier(key)) => {
            let _ = writeln!(out, "            {}", colon_hex(&key));
        }
        Ok(ParsedExtension::AuthorityKeyIdentifier(aki)) => {
            let _ = writeln!(out, "            {}", authority_key_identifier_text(&aki));
        }
        Ok(ParsedExtension::CrlDistributionPoints(points)) => {
            for uri in &points.uris {
                let _ = writeln!(out, "            URI:{uri}");
            }
        }
        Ok(ParsedExtension::AuthorityInfoAccess(access)) => {
            for uri in &access.ocsp {
                let _ = writeln!(out, "            OCSP - URI:{uri}");
            }
            for uri in &access.ca_issuers {
                let _ = writeln!(out, "            CA Issuers - URI:{uri}");
            }
        }
        Ok(ParsedExtension::CertificatePolicies(policies)) => {
            let policies: Vec<String> = policies
                .policies
                .iter()
                .map(|oid| oid.to_string())
                .collect();
            let _ = writeln!(out, "            {}", policies.join(", "));
        }
        _ => {
            let _ = writeln!(out, "            (unparsed)");
        }
    }
}

/// Text report for a certificate.
pub fn certificate_report(certificate: &Certificate) -> String {
    let tbs = certificate.tbs();
    let mut out = String::new();
    let _ = writeln!(out, "Certificate:");
    let _ = writeln!(
        out,
        "    Version: {} (0x{:x})",
        tbs.version + 1,
        tbs.version
    );
    let _ = writeln!(out, "    Serial Number: {}", serial_hex(&tbs.serial_number));
    let _ = writeln!(
        out,
        "    Signature Algorithm: {}",
        signature_algorithm_name(&tbs.signature)
    );
    let _ = writeln!(out, "    Issuer: {}", tbs.issuer);
    let _ = writeln!(out, "    Validity:");
    let _ = writeln!(
        out,
        "        Not Before: {}",
        format_time(tbs.validity.not_before)
    );
    let _ = writeln!(
        out,
        "        Not After : {}",
        format_time(tbs.validity.not_after)
    );
    let _ = writeln!(out, "    Subject: {}", tbs.subject);
    let _ = writeln!(out, "    Subject Public Key Info:");
    let _ = writeln!(
        out,
        "        Public Key Algorithm: {}",
        public_key_text(certificate.public_key())
    );
    let _ = writeln!(
        out,
        "        Public Key: {}",
        colon_hex(&certificate.subject_public_key_info().key)
    );
    if !tbs.extensions.is_empty() {
        let _ = writeln!(out, "    X509v3 Extensions:");
        for extension in &tbs.extensions {
            write_extension(&mut out, extension);
        }
    }
    let _ = writeln!(
        out,
        "    Signature Algorithm: {}",
        signature_algorithm_name(certificate.signature_algorithm())
    );
    let _ = writeln!(out, "    Signature: {}", colon_hex(certificate.signature()));
    let self_signed = certificate.is_self_signed();
    let _ = writeln!(
        out,
        "    Self-Signed: {}",
        if self_signed { "yes" } else { "no" }
    );
    if self_signed {
        let valid = certificate
            .verify_signature(certificate.public_key())
            .unwrap_or(false);
        let _ = writeln!(
            out,
            "    Self-Signature: {}",
            if valid { "valid" } else { "INVALID" }
        );
    }
    out
}

/// Text report for a certification request.
pub fn csr_report(csr: &CertificationRequest) -> String {
    let info = csr.info();
    let mut out = String::new();
    let _ = writeln!(out, "Certificate Request:");
    let _ = writeln!(out, "    Version: {} (0x{:x})", info.version, info.version);
    let _ = writeln!(out, "    Subject: {}", info.subject);
    let _ = writeln!(out, "    Subject Public Key Info:");
    let _ = writeln!(
        out,
        "        Public Key Algorithm: {}",
        public_key_text(&info.subject_public_key_info.public_key)
    );
    let _ = writeln!(
        out,
        "        Public Key: {}",
        colon_hex(&info.subject_public_key_info.key)
    );
    if info.attributes.is_empty() {
        let _ = writeln!(out, "    Attributes: (none)");
    } else {
        let _ = writeln!(out, "    Attributes:");
        for attribute in &info.attributes {
            match attribute.first_text() {
                Some(text) => {
                    let _ = writeln!(out, "        {}: {text}", attribute.oid);
                }
                None => {
                    let _ = writeln!(out, "        {}: (raw)", attribute.oid);
                }
            }
        }
    }
    let _ = writeln!(
        out,
        "    Signature Algorithm: {}",
        signature_algorithm_name(csr.signature_algorithm())
    );
    let valid = csr.verify_signature().unwrap_or(false);
    let _ = writeln!(
        out,
        "    Self-Signature: {}",
        if valid { "valid" } else { "INVALID" }
    );
    out
}

/// Text report for a CRL.
pub fn crl_report(crl: &CertificateList) -> String {
    let tbs = crl.tbs();
    let mut out = String::new();
    let _ = writeln!(out, "Certificate Revocation List:");
    let _ = writeln!(
        out,
        "    Version: {}",
        tbs.version.map(|version| version + 1).unwrap_or(1)
    );
    let _ = writeln!(
        out,
        "    Signature Algorithm: {}",
        signature_algorithm_name(&tbs.signature)
    );
    let _ = writeln!(out, "    Issuer: {}", tbs.issuer);
    let _ = writeln!(out, "    This Update: {}", format_time(tbs.this_update));
    if let Some(next_update) = tbs.next_update {
        let _ = writeln!(out, "    Next Update: {}", format_time(next_update));
    }
    let _ = writeln!(
        out,
        "    Revoked Certificates: {}",
        tbs.revoked_certificates.len()
    );
    for revoked in &tbs.revoked_certificates {
        let _ = writeln!(
            out,
            "        Serial Number: {} ({})",
            serial_hex(&revoked.serial_number),
            format_time(revoked.revocation_date)
        );
    }
    if !tbs.extensions.is_empty() {
        let _ = writeln!(out, "    X509v3 Extensions:");
        for extension in &tbs.extensions {
            write_extension(&mut out, extension);
        }
    }
    let _ = writeln!(
        out,
        "    Signature Algorithm: {}",
        signature_algorithm_name(&tbs.signature)
    );
    out
}

/// Parse a CLI name of the form `C=CN,O=Org,CN=example.com` into an X.500
/// name (RDNs root first).
pub fn parse_name(text: &str) -> anyhow::Result<crown::x509::Name> {
    use crown::asn1::oid::{self, ObjectIdentifier};
    use crown::x509::{AttributeTypeAndValue, Name, Rdn};
    let mut rdns = Vec::new();
    for part in text.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid name component {part:?} (expected KEY=VALUE)"))?;
        let (oid, printable) = match key.trim().to_ascii_lowercase().as_str() {
            "c" | "country" => (oid::OID_AT_COUNTRY, true),
            "o" | "organization" => (oid::OID_AT_ORGANIZATION, false),
            "ou" | "organizationalunit" => (oid::OID_AT_ORGANIZATIONAL_UNIT, false),
            "cn" | "commonname" => (oid::OID_AT_COMMON_NAME, false),
            other => bail!("unsupported name attribute {other:?} (C/O/OU/CN)"),
        };
        let oid = ObjectIdentifier::new(oid).expect("static oid");
        let attribute = if printable {
            AttributeTypeAndValue::from_printable(oid, value.trim())
        } else {
            AttributeTypeAndValue::from_utf8(oid, value.trim())
        };
        rdns.push(Rdn {
            attributes: vec![attribute],
        });
    }
    if rdns.is_empty() {
        bail!("empty subject");
    }
    Ok(Name { rdns })
}

/// Map the CLI purpose onto the verification purpose.
pub fn purpose_from_cli(purpose: crate::args::CertPurpose) -> crown::x509::Purpose {
    use crate::args::CertPurpose as From;
    use crown::x509::Purpose as To;
    match purpose {
        From::Any => To::Any,
        From::SslServer => To::SslServer,
        From::SslClient => To::SslClient,
        From::SmimeSign => To::SmimeSign,
        From::SmimeEncrypt => To::SmimeEncrypt,
        From::CodeSigning => To::CodeSigning,
        From::OcspHelper => To::OcspHelper,
        From::TimeStamping => To::TimeStamping,
        From::CrlSign => To::CrlSign,
    }
}

/// Map the CLI CMS cipher onto the library cipher.
pub fn cms_cipher_from_cli(cipher: crate::args::CmsCipher) -> crown::cms::Cipher {
    use crate::args::CmsCipher as From;
    use crown::cms::Cipher as To;
    match cipher {
        From::Aes128Cbc => To::Aes128Cbc,
        From::Aes192Cbc => To::Aes192Cbc,
        From::Aes256Cbc => To::Aes256Cbc,
        From::Aes128Gcm => To::Aes128Gcm,
        From::Aes192Gcm => To::Aes192Gcm,
        From::Aes256Gcm => To::Aes256Gcm,
        From::DesEde3Cbc => To::DesEde3Cbc,
    }
}

/// A random positive serial number (8 bytes, top bit clear).
pub fn random_serial() -> Vec<u8> {
    let mut serial = vec![0u8; 8];
    FileRng.fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    if serial.iter().all(|&byte| byte == 0) {
        serial[7] = 1;
    }
    serial
}

/// Resolve a `--serial` option (hex) or generate one.
pub fn resolve_serial(serial: Option<&str>) -> anyhow::Result<Vec<u8>> {
    match serial {
        Some(serial) => {
            let decoded = hex::decode(serial)?;
            if decoded.is_empty() {
                bail!("empty serial");
            }
            Ok(decoded)
        }
        None => Ok(random_serial()),
    }
}

/// Build the leaf/CA extensions shared by `self-sign` and `issue`.
pub fn issuance_extensions(
    subject: &crown::x509::Name,
    public_key: &crown::x509::PublicKey,
    sans: &[String],
    ca: bool,
) -> anyhow::Result<Vec<crown::x509::Extension>> {
    use crown::x509::extensions::{
        authority_key_identifier as aki, basic_constraints, key_usage, subject_alt_name,
        subject_key_identifier as ski,
    };
    use crown::x509::{KeyUsage, SubjectPublicKeyInfo};
    let spki = SubjectPublicKeyInfo::from_public_key(public_key)?;
    let key_id = spki.key_identifier()?;
    let mut extensions = vec![
        basic_constraints(ca, None),
        key_usage(KeyUsage {
            digital_signature: !ca,
            key_cert_sign: ca,
            crl_sign: ca,
            key_encipherment: !ca,
            ..Default::default()
        }),
        ski(&key_id),
        aki(&key_id),
    ];
    if !sans.is_empty() {
        extensions.push(subject_alt_name(sans, &[]));
    }
    let _ = subject;
    Ok(extensions)
}

/// The default signature algorithm for a private key at the given digest.
pub fn signature_algorithm_for_key(
    key: &crown::x509::PrivateKey,
    hash: crown::x509::Hash,
) -> anyhow::Result<crown::x509::SignatureAlgorithm> {
    default_signature_algorithm(key, hash)
}
