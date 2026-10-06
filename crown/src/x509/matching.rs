//! Certificate name matching: the `X509_check_host`, `X509_check_email` and
//! `X509_check_ip` equivalents.
//!
//! The checks follow OpenSSL's default behavior:
//!
//! - `check_host` matches `subjectAltName` `dNSName` entries (case
//!   insensitive, trailing dots ignored, wildcards only in the leftmost
//!   label). When the certificate has no `dNSName` entries at all, the
//!   subject common names are checked instead.
//! - `check_email` matches `subjectAltName` `rfc822Name` entries, falling
//!   back to the subject `emailAddress` attributes.
//! - `check_ip` matches `subjectAltName` `iPAddress` entries, treating
//!   IPv4-mapped IPv6 addresses as equal to the plain IPv4 form. There is no
//!   subject fallback for IP addresses.
//!
//! ```
//! use crown::x509::Certificate;
//!
//! # let pem = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/matching_san.pem"));
//! let certificate = Certificate::from_pem(pem)?;
//! assert!(certificate.check_host("www.crown.example"));
//! assert!(!certificate.check_host("crown.example"));
//! # Ok::<(), crown::error::CryptoError>(())
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use super::cert::Certificate;
use super::extensions::GeneralName;

impl Certificate {
    /// Whether this certificate is valid for `host`
    /// (OpenSSL's `X509_check_host`).
    pub fn check_host(&self, host: &str) -> bool {
        let host = normalize_dns(host);
        if host.is_empty() {
            return false;
        }
        let mut san_names = 0;
        if let Some(names) = self.tbs().subject_alt_names() {
            for name in &names {
                if let GeneralName::DnsName(pattern) = name {
                    san_names += 1;
                    if dns_matches(pattern, &host) {
                        return true;
                    }
                }
            }
        }
        if san_names > 0 {
            return false;
        }
        // Fall back to the subject common names when no dNSName exists.
        self.common_names()
            .iter()
            .any(|name| dns_matches(name, &host))
    }

    /// Whether this certificate is valid for `email`
    /// (OpenSSL's `X509_check_email`).
    ///
    /// The local part of the address is compared case-sensitively, the
    /// domain case-insensitively (matching OpenSSL).
    pub fn check_email(&self, email: &str) -> bool {
        let email = email.trim_end_matches('.');
        if email.is_empty() {
            return false;
        }
        let mut san_emails = 0;
        if let Some(names) = self.tbs().subject_alt_names() {
            for name in &names {
                if let GeneralName::Rfc822Name(pattern) = name {
                    san_emails += 1;
                    if email_matches(pattern, email) {
                        return true;
                    }
                }
            }
        }
        if san_emails > 0 {
            return false;
        }
        self.email_addresses()
            .iter()
            .any(|pattern| email_matches(pattern, email))
    }

    /// Whether this certificate is valid for the raw IP address `ip` (4 or 16
    /// bytes; OpenSSL's `X509_check_ip`).
    pub fn check_ip(&self, ip: &[u8]) -> bool {
        let Some(names) = self.tbs().subject_alt_names() else {
            return false;
        };
        names.iter().any(|name| match name {
            GeneralName::IpAddress(address) => address_equal(address, ip),
            _ => false,
        })
    }

    /// [`Self::check_ip`] for a textual IPv4 or IPv6 address
    /// (OpenSSL's `X509_check_ip_asc`).
    pub fn check_ip_asc(&self, ip: &str) -> bool {
        match parse_ip(ip) {
            Some(bytes) => self.check_ip(&bytes),
            None => false,
        }
    }

    /// Every subject common name, decoded as text.
    fn common_names(&self) -> Vec<String> {
        self.tbs()
            .subject
            .get_all(crate::asn1::oid::OID_AT_COMMON_NAME)
            .iter()
            .filter_map(|attribute| attribute.text().ok())
            .collect()
    }

    /// Every subject `emailAddress`, decoded as text.
    fn email_addresses(&self) -> Vec<String> {
        self.tbs()
            .subject
            .get_all(crate::asn1::oid::OID_AT_EMAIL_ADDRESS)
            .iter()
            .filter_map(|attribute| attribute.text().ok())
            .collect()
    }
}

/// Lowercase and strip the trailing dot of a DNS name.
fn normalize_dns(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Email address equality: the local part is case-sensitive, the domain is
/// not. Patterns without an `@` fall back to a case-insensitive comparison.
fn email_matches(pattern: &str, email: &str) -> bool {
    match (pattern.rsplit_once('@'), email.rsplit_once('@')) {
        (Some((pattern_local, pattern_domain)), Some((email_local, email_domain))) => {
            pattern_local == email_local && pattern_domain.eq_ignore_ascii_case(email_domain)
        }
        _ => pattern.eq_ignore_ascii_case(email),
    }
}

/// RFC 6125 / OpenSSL-style matching of a dNSName `pattern` against the
/// reference `host` (both already normalized).
fn dns_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalize_dns(pattern);
    if pattern.is_empty() {
        return false;
    }
    let Some((pattern_label, pattern_rest)) = pattern.split_once('.') else {
        // A single-label pattern covers names of the same label only.
        return wildcard_matches(&pattern, host);
    };
    if !pattern_label.contains('*') {
        if pattern.contains('*') {
            // Wildcards outside the leftmost label never match
            // (OpenSSL rejects them outright).
            return false;
        }
        return pattern == host;
    }
    // The pattern has subdomains; the reference must too, with an exact
    // remainder and a wildcard leftmost label.
    let Some((host_label, host_rest)) = host.split_once('.') else {
        return false;
    };
    pattern_rest == host_rest && wildcard_matches(pattern_label, host_label)
}

/// Glob matching with `*` matching any (possibly empty) run of characters
/// within a single label.
fn wildcard_matches(pattern: &str, label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    let Some(star) = pattern.find('*') else {
        return pattern == label;
    };
    if pattern[star + 1..].contains('*') {
        // Multiple stars are degenerate; reject instead of approximating.
        return false;
    }
    let (prefix, suffix) = (&pattern[..star], &pattern[star + 1..]);
    label.len() >= prefix.len() + suffix.len()
        && label.starts_with(prefix)
        && label.ends_with(suffix)
}

/// IP equality with IPv4-mapped IPv6 handling (OpenSSL's `equal_address`).
fn address_equal(left: &[u8], right: &[u8]) -> bool {
    if left == right {
        return true;
    }
    if left.len() == 16 && right.len() == 4 {
        return is_ipv4_mapped(left) && &left[12..] == right;
    }
    if left.len() == 4 && right.len() == 16 {
        return is_ipv4_mapped(right) && &right[12..] == left;
    }
    false
}

fn is_ipv4_mapped(address: &[u8]) -> bool {
    address.len() == 16
        && address[..10].iter().all(|&byte| byte == 0)
        && address[10] == 0xff
        && address[11] == 0xff
}

/// Parse a textual IPv4 or IPv6 address into its 4- or 16-byte form.
pub fn parse_ip(text: &str) -> Option<Vec<u8>> {
    if text.contains(':') {
        parse_ipv6(text).map(Vec::from)
    } else {
        parse_ipv4(text).map(Vec::from)
    }
}

fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = text.split('.');
    for byte in &mut out {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        *byte = part.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn parse_ipv6(text: &str) -> Option<[u8; 16]> {
    let text = text.trim_start_matches('[').trim_end_matches(']');
    let compressed = text.contains("::");
    if text.matches("::").count() > 1 {
        return None;
    }
    let (head, tail) = match text.split_once("::") {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    };
    let head = parse_ipv6_groups(head)?;
    let tail = match tail {
        Some(tail) => parse_ipv6_groups(tail)?,
        None => Vec::new(),
    };
    let zeros = 8usize.checked_sub(head.len() + tail.len())?;
    // `::` must stand for at least one group; an uncompressed address must
    // spell out all eight.
    if compressed && zeros == 0 {
        return None;
    }
    if !compressed && zeros != 0 {
        return None;
    }
    let mut groups = Vec::with_capacity(8);
    groups.extend(head);
    groups.extend(core::iter::repeat_n(0u16, zeros));
    groups.extend(tail);
    let mut out = [0u8; 16];
    for (index, group) in groups.iter().enumerate() {
        out[index * 2] = (group >> 8) as u8;
        out[index * 2 + 1] = (group & 0xff) as u8;
    }
    Some(out)
}

/// One side of a `::` split: colon-separated hex groups with an optional
/// trailing IPv4 address.
fn parse_ipv6_groups(side: &str) -> Option<Vec<u16>> {
    if side.is_empty() {
        return Some(Vec::new());
    }
    let mut parts: Vec<&str> = side.split(':').collect();
    let mut ipv4_tail = None;
    if let Some(last) = parts.last() {
        if last.contains('.') {
            let address = parse_ipv4(last)?;
            ipv4_tail = Some([
                (u16::from(address[0]) << 8) | u16::from(address[1]),
                (u16::from(address[2]) << 8) | u16::from(address[3]),
            ]);
            parts.pop();
        }
    }
    let mut groups = Vec::new();
    for part in parts {
        if part.is_empty() || part.len() > 4 {
            return None;
        }
        groups.push(u16::from_str_radix(part, 16).ok()?);
    }
    if let Some(tail) = ipv4_tail {
        groups.extend_from_slice(&tail);
    }
    Some(groups)
}
