//! Golden-vector gate for the PKI modules (`x509`, `pkcs7`, `pkcs12`).
//!
//! The vectors come from the pyca/cryptography tree
//! (`crown/tests/cryptography`), which contains real-world certificates,
//! CSRs, CRLs, PKCS#7 and PKCS#12 files. Every family asserts a minimum
//! number of verified items so a broken harness cannot silently degrade into
//! skipping everything.

use crown::pkcs12::{Bag, Pfx};
use crown::pkcs7::{Pkcs7, SignedData};
use crown::x509::cert::Certificate;
use crown::x509::crl::CertificateList;
use crown::x509::csr::CertificationRequest;

const BASE: &str = "tests/cryptography/vectors/cryptography_vectors/";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!("{BASE}{path}")).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

fn read_text(path: &str) -> String {
    String::from_utf8(read(path)).unwrap_or_else(|err| panic!("utf8 {path}: {err}"))
}

#[test]
fn pyca_x509_roots_verify() {
    // Self-signed roots covering RSA (with MD2/SHA-1/SHA-256), ECDSA,
    // Ed25519 and Ed448 signatures.
    let roots = [
        "x509/accvraiz1.pem",
        "x509/custom/ca/ca.pem",
        "x509/custom/ca/rsa_ca.pem",
        "x509/ecdsa_root.pem",
        "x509/verisign_md2_root.pem",
        "x509/ed25519/root-ed25519.pem",
        "x509/ed448/root-ed448.pem",
    ];
    let mut checked = 0;
    for path in roots {
        let text = read_text(path);
        let certificate =
            Certificate::from_pem(&text).unwrap_or_else(|err| panic!("parse {path}: {err:?}"));
        assert!(certificate.is_self_signed(), "{path}: not self-signed");
        assert!(
            certificate
                .verify_signature(certificate.public_key())
                .unwrap_or_else(|err| panic!("verify {path}: {err:?}")),
            "{path}: self-signature failed"
        );
        // Re-encoding is byte-exact.
        let der = crown::asn1::pem::parse_first(&text).unwrap().data;
        assert_eq!(certificate.encode(), der, "{path}: re-encode");
        checked += 1;
    }
    assert!(checked >= 7, "only {checked} root certificates verified");
}

#[test]
fn pyca_x509_chain_verifies() {
    let text = read_text("x509/cryptography.io.chain.pem");
    let certificates: Vec<Certificate> = crown::asn1::pem::parse(&text)
        .unwrap()
        .iter()
        .map(|block| Certificate::parse(&block.data).unwrap())
        .collect();
    assert!(certificates.len() >= 2);
    let mut checked = 0;
    for pair in certificates.windows(2) {
        let (leaf, issuer) = (&pair[0], &pair[1]);
        leaf.verify(issuer, None)
            .unwrap_or_else(|err| panic!("chain verify: {err:?}"));
        checked += 1;
    }
    assert!(checked >= 1, "only {checked} chain links verified");
}

#[test]
fn pyca_x509_certificates_parse_broadly() {
    // Parse a wider sample of real certificates (including some with
    // unsupported signature algorithms) and require that the vast majority
    // decode.
    let mut parsed = 0;
    let mut attempted = 0;
    for entry in std::fs::read_dir(format!("{BASE}x509")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        attempted += 1;
        if Certificate::from_pem(&text).is_ok() {
            parsed += 1;
        }
    }
    assert!(attempted >= 20, "only {attempted} certificates attempted");
    assert!(
        parsed * 10 >= attempted * 8,
        "only {parsed}/{attempted} top-level certificates parsed"
    );
}

#[test]
fn pyca_csrs_verify() {
    let csrs = [
        "x509/requests/ec_sha256.pem",
        "x509/requests/ec_sha256.der",
        "x509/requests/rsa_sha256.pem",
        "x509/requests/rsa_sha1.der",
        "x509/requests/rsa_md4.der",
        "x509/requests/dsa_sha1.pem",
        "x509/requests/challenge.pem",
        "x509/requests/san_rsa_sha1.pem",
    ];
    let mut checked = 0;
    for path in csrs {
        let data = read(path);
        let request = if path.ends_with(".pem") {
            CertificationRequest::from_pem(&String::from_utf8(data).unwrap())
        } else {
            CertificationRequest::parse(&data)
        }
        .unwrap_or_else(|err| panic!("parse {path}: {err:?}"));
        assert!(
            request
                .verify_signature()
                .unwrap_or_else(|err| panic!("verify {path}: {err:?}")),
            "{path}: self-signature failed"
        );
        // The DER encoding roundtrips exactly.
        assert_eq!(
            CertificationRequest::parse(&request.encode())
                .unwrap()
                .encode(),
            request.encode(),
            "{path}: re-encode"
        );
        checked += 1;
    }
    assert!(checked >= 8, "only {checked} CSRs verified");

    // A CSR with a broken signature must be rejected.
    let invalid = read("x509/requests/invalid_signature.pem");
    let request = CertificationRequest::from_pem(&String::from_utf8(invalid).unwrap()).unwrap();
    assert!(!request.verify_signature().unwrap());
}

#[test]
fn pyca_crls_parse_and_verify() {
    // Matching CRLs to issuers: scan the PKITS certificate corpus for a
    // subject equal to the CRL issuer.
    let mut issuers: Vec<Certificate> = Vec::new();
    for entry in std::fs::read_dir(format!("{BASE}x509/PKITS_data/certs")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("crt") {
            continue;
        }
        if let Ok(data) = std::fs::read(&path) {
            if let Ok(certificate) = Certificate::parse(&data) {
                issuers.push(certificate);
            }
        }
    }
    assert!(
        issuers.len() >= 100,
        "only {} issuer candidates",
        issuers.len()
    );

    let mut parsed = 0;
    let mut verified = 0;
    for entry in std::fs::read_dir(format!("{BASE}x509/PKITS_data/crls")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("crl") {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Ok(crl) = CertificateList::parse(&data) else {
            continue;
        };
        parsed += 1;
        if let Some(issuer) = issuers
            .iter()
            .find(|cert| *cert.subject() == crl.tbs().issuer)
        {
            if crl.verify_signature(issuer.public_key()).unwrap_or(false) {
                verified += 1;
            }
        }
    }
    assert!(parsed >= 100, "only {parsed} CRLs parsed");
    assert!(
        verified >= 5,
        "only {verified} CRLs verified against an issuer"
    );
}

#[test]
fn pyca_pkcs7_parses() {
    let mut certificate_total = 0;
    let mut checked = 0;
    for path in [
        "pkcs7/amazon-roots.p7b",
        "pkcs7/amazon-roots.der",
        "pkcs7/isrg.pem",
    ] {
        let data = read(path);
        let pkcs7 = if path.ends_with(".pem") {
            let text = String::from_utf8(data).unwrap();
            let block = crown::asn1::pem::parse_first(&text).unwrap();
            Pkcs7::parse(&block.data)
        } else {
            Pkcs7::parse(&data)
        }
        .unwrap_or_else(|err| panic!("parse {path}: {err:?}"));
        let Pkcs7::SignedData(SignedData { certificates, .. }) = &pkcs7 else {
            panic!("{path}: not signed data");
        };
        assert!(!certificates.is_empty(), "{path}: no certificates");
        for certificate in certificates.iter().take(3) {
            certificate
                .verify_signature(certificate.public_key())
                .unwrap_or_else(|err| panic!("{path}: {err:?}"));
        }
        certificate_total += certificates.len();
        checked += 1;
    }
    assert!(checked >= 3, "only {checked} PKCS#7 files parsed");
    assert!(
        certificate_total >= 5,
        "only {certificate_total} PKCS#7 certificates"
    );
}

#[test]
fn pyca_pkcs12_parses_and_decodes() {
    // (path, password)
    let cases: [(&str, &[u8]); 5] = [
        ("pkcs12/cert-key-aes256cbc.p12", b"cryptography"),
        ("pkcs12/cert-aes256cbc-no-key.p12", b"cryptography"),
        ("pkcs12/cert-rc2-key-3des.p12", b"cryptography"),
        ("pkcs12/no-cert-key-aes256cbc.p12", b"cryptography"),
        ("pkcs12/no-password.p12", b""),
    ];
    let mut checked = 0;
    let mut keys = 0;
    let mut certificates_total = 0;
    for (path, password) in cases {
        let data = read(path);
        let pfx = Pfx::parse(&data).unwrap_or_else(|err| panic!("parse {path}: {err:?}"));
        pfx.verify_mac(password)
            .unwrap_or_else(|err| panic!("mac {path}: {err:?}"));
        let bags = pfx
            .decoded_bags(password)
            .unwrap_or_else(|err| panic!("bags {path}: {err:?}"));
        for bag in &bags {
            match &bag.bag {
                Bag::Cert(_) => certificates_total += 1,
                Bag::ShroudedKey(info) => {
                    let key = crown::x509::pbe::decrypt_private_key(info, password)
                        .unwrap_or_else(|err| panic!("key {path}: {err:?}"));
                    key.decode()
                        .unwrap_or_else(|err| panic!("key decode {path}: {err:?}"));
                    keys += 1;
                }
                Bag::Key(info) => {
                    info.decode()
                        .unwrap_or_else(|err| panic!("key decode {path}: {err:?}"));
                    keys += 1;
                }
                _ => {}
            }
        }
        // Wrong password must not verify.
        if pfx.mac.is_some() && !password.is_empty() {
            assert!(pfx.verify_mac(b"definitely-wrong").is_err(), "{path}");
        }
        checked += 1;
    }
    assert!(checked >= 5, "only {checked} PKCS#12 files checked");
    assert!(keys >= 3, "only {keys} PKCS#12 keys decoded");
    assert!(
        certificates_total >= 3,
        "only {certificates_total} PKCS#12 certificates"
    );
}
