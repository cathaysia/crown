//! Name-matching gate for `Certificate::check_host` / `check_email` /
//! `check_ip`.
//!
//! Every expectation below is pinned to the OpenSSL CLI on the same fixtures
//! (`openssl verify -verify_hostname/-verify_email/-verify_ip`, OpenSSL
//! 3.0.13); see `tests/data/pki/pki_match_SOURCE.txt` for the generation
//! commands. `-verify_hostname` also serves as the CN-fallback reference.

use crown::asn1::pem;
use crown::asn1::time::Asn1Time;
use crown::x509::extensions::subject_alt_name;
use crown::x509::keys::{PrivateKeyInfo, SubjectPublicKeyInfo};
use crown::x509::name::Name;
use crown::x509::{Certificate, CertificateBuilder, Hash, SignatureAlgorithm};

const BASE: &str = "tests/data/pki/";

fn cert(name: &str) -> Certificate {
    let pem_text = std::fs::read_to_string(format!("{BASE}{name}.pem"))
        .unwrap_or_else(|err| panic!("read {name}: {err}"));
    Certificate::from_pem(&pem_text).unwrap_or_else(|err| panic!("parse {name}: {err}"))
}

/// A deterministic RNG for the in-code certificates.
struct TestRng(u64);

impl crown::rng::Rng for TestRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (self.0 >> 33) as u8;
        }
    }
}

/// Sign a self-issued certificate for `common_name` with the committed RSA
/// fixture key and the given `subjectAltName` entries.
fn issued(common_name: &str, dns_names: &[String], ip_addresses: &[[u8; 4]]) -> Certificate {
    let key_pem = std::fs::read_to_string(format!("{BASE}rsa_pkcs8.pem")).unwrap();
    let block = pem::parse_first(&key_pem).unwrap();
    let key = PrivateKeyInfo::parse(&block.data)
        .unwrap()
        .decode()
        .unwrap();
    let spki = SubjectPublicKeyInfo::from_public_key(&key.public_key().unwrap()).unwrap();
    let mut rng = TestRng(7);
    CertificateBuilder::new(
        Name::from_common_name(common_name),
        spki,
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
    )
    .validity(
        Asn1Time::from_unix(1_700_000_000, true),
        Asn1Time::from_unix(2_200_000_000, true),
    )
    .extension(subject_alt_name(dns_names, ip_addresses))
    .sign(&key, &mut rng)
    .unwrap()
}

#[test]
fn dns_names_match_openssl() {
    let san = cert("matching_san");
    // DNS:www.crown.example, DNS:*.wild.crown.example
    assert!(san.check_host("www.crown.example"));
    assert!(san.check_host("WWW.CROWN.EXAMPLE"));
    assert!(san.check_host("www.crown.example."));
    assert!(!san.check_host("crown.example"));
    assert!(!san.check_host("x.www.crown.example"));
    assert!(!san.check_host(""));

    // A wildcard matches exactly one label.
    assert!(san.check_host("x.wild.crown.example"));
    assert!(!san.check_host("wild.crown.example"));
    assert!(!san.check_host("a.b.wild.crown.example"));

    // A wildcard-only certificate.
    let wild = cert("matching_wild");
    assert!(wild.check_host("www.crown.example"));
    assert!(!wild.check_host("crown.example"));
    assert!(!wild.check_host("a.b.crown.example"));

    // Partial wildcards are allowed in the leftmost label; the star may
    // match empty (`www*.crown.example` matches `www.crown.example`).
    let partial = cert("matching_partial");
    assert!(partial.check_host("www1.crown.example"));
    assert!(partial.check_host("www.crown.example"));
    assert!(partial.check_host("wwwxyz.crown.example"));
    assert!(!partial.check_host("ww.crown.example"));
    assert!(!partial.check_host("x.www1.crown.example"));

    // A wildcard outside the leftmost label never matches.
    let weird = issued(
        "weird.crown.example",
        &[String::from("a.*.crown.example")],
        &[],
    );
    assert!(!weird.check_host("a.b.crown.example"));
    assert!(!weird.check_host("a.*.crown.example"));
}

#[test]
fn cn_fallback_only_without_san_dns() {
    // No SAN at all: the subject CN is the reference
    // (`openssl verify -verify_hostname matching_cn_only.crown.example`
    // succeeds on this fixture).
    let cn_only = cert("matching_cn_only");
    assert!(cn_only.check_host("matching_cn_only.crown.example"));
    assert!(cn_only.check_host("MATCHING_CN_ONLY.CROWN.EXAMPLE"));
    assert!(!cn_only.check_host("other.crown.example"));

    // With SAN dNSName entries present, the CN is not consulted, even when it
    // would match.
    let san = cert("matching_san");
    assert!(!san.check_host("matching_san.crown.example"));

    // SAN entries of other types do not disable the fallback: OpenSSL checks
    // for the absence of dNSName entries, not of the SAN extension
    // (verified with `openssl verify -verify_hostname` on an equivalent
    // certificate).
    let ip_only = issued("iponly.crown.example", &[], &[[10, 9, 9, 9]]);
    assert!(ip_only.check_host("iponly.crown.example"));
    assert!(!ip_only.check_host("other.crown.example"));
    assert!(ip_only.check_ip(&[10, 9, 9, 9]));
}

#[test]
fn ip_addresses_match_openssl() {
    let san = cert("matching_san");
    // IP:127.0.0.1 and IP:::1
    assert!(san.check_ip(&[127, 0, 0, 1]));
    assert!(san.check_ip_asc("127.0.0.1"));
    assert!(san.check_ip_asc("::1"));
    assert!(san.check_ip_asc("[::1]"));
    assert!(san.check_ip_asc("0:0:0:0:0:0:0:1"));
    assert!(san.check_ip(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    // IPv4-mapped IPv6 forms compare equal to the plain IPv4 address.
    assert!(san.check_ip(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]));
    assert!(san.check_ip_asc("::ffff:127.0.0.1"));
    assert!(!san.check_ip(&[127, 0, 0, 2]));
    assert!(!san.check_ip_asc("10.0.0.1"));
    assert!(!san.check_ip_asc("::2"));
    // Malformed references never match.
    assert!(!san.check_ip_asc("not-an-ip"));
    assert!(!san.check_ip_asc("1.2.3"));
    assert!(!san.check_ip_asc("1.2.3.4.5"));
    assert!(!san.check_ip_asc("1.2.3.256"));
    assert!(!san.check_ip_asc("::1::2"));
    assert!(!san.check_ip_asc("1:2:3:4:5:6:7:8:9"));
    assert!(!san.check_ip_asc("1:2:3:4:5:6:7:8::"));
    // A valid IPv6 address that is simply not in the SAN.
    assert!(!san.check_ip_asc("2001:db8:1:2:3:4:5:6"));
    // An IP reference must not match through a DNS name and vice versa.
    assert!(!san.check_host("127.0.0.1"));
}

#[test]
fn emails_follow_openssl_case_rules() {
    let san = cert("matching_san");
    // email:user@crown.example. OpenSSL compares the local part
    // case-sensitively and the domain case-insensitively
    // (`openssl verify -verify_email`).
    assert!(san.check_email("user@crown.example"));
    assert!(san.check_email("user@CROWN.EXAMPLE"));
    assert!(!san.check_email("USER@crown.example"));
    assert!(!san.check_email("User@Crown.Example"));
    assert!(!san.check_email("other@crown.example"));
    assert!(!san.check_email("user@other.example"));

    // No SAN rfc822Name at all: the subject emailAddress is the fallback.
    let cn_only = cert("matching_cn_only");
    assert!(!cn_only.check_email("user@crown.example"));
}

#[test]
fn certificates_expose_fetch_urls() {
    let crldp = cert("crldp");
    assert_eq!(
        crldp.crl_urls(),
        vec![String::from("http://crl.crown.example/root.crl")]
    );
    assert!(crldp.freshest_crl_urls().is_empty());
    assert_eq!(
        crldp.ocsp_urls(),
        vec![String::from("http://ocsp.crown.example")]
    );
    assert_eq!(
        crldp.ca_issuer_urls(),
        vec![String::from("http://certs.crown.example/ca.crt")]
    );

    // Certificates without the extensions report no URLs.
    let san = cert("matching_san");
    assert!(san.crl_urls().is_empty());
    assert!(san.ocsp_urls().is_empty());
    assert!(san.ca_issuer_urls().is_empty());
}
