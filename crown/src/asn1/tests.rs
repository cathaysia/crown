//! Unit tests for the ASN.1 toolkit.

use alloc::vec;
use alloc::vec::Vec;

use super::der::{self, Reader};
use super::oid::{self, ObjectIdentifier};
use super::pem;
use super::time::Asn1Time;
use crate::error::CryptoError;

#[test]
fn integer_encoding_is_canonical() {
    assert_eq!(der::integer(&[]), vec![0x02, 0x01, 0x00]);
    assert_eq!(der::integer(&[0x00]), vec![0x02, 0x01, 0x00]);
    assert_eq!(der::integer(&[0x00, 0x00, 0x2a]), vec![0x02, 0x01, 0x2a]);
    assert_eq!(der::integer(&[0x7f]), vec![0x02, 0x01, 0x7f]);
    assert_eq!(der::integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
    assert_eq!(
        der::integer(&[0xff, 0xff]),
        vec![0x02, 0x03, 0x00, 0xff, 0xff]
    );
    assert_eq!(der::integer_i64(-1), vec![0x02, 0x01, 0xff]);
    assert_eq!(der::integer_i64(-129), vec![0x02, 0x02, 0xff, 0x7f]);
}

#[test]
fn integer_roundtrip() {
    for magnitude in [
        &[][..],
        &[0x2a],
        &[0x80],
        &[0xff, 0x00, 0x01],
        &[0x01, 0x00, 0x00, 0x00, 0x00],
    ] {
        let encoded = der::integer(magnitude);
        let mut r = Reader::new(&encoded);
        assert_eq!(r.read_integer().unwrap(), magnitude);
        r.expect_end().unwrap();
    }
}

#[test]
fn boolean_and_null() {
    let true_der = der::boolean(true);
    let mut r = Reader::new(&true_der);
    assert!(r.read_boolean().unwrap());
    let false_der = der::boolean(false);
    let mut r = Reader::new(&false_der);
    assert!(!r.read_boolean().unwrap());
    let null_der = der::null();
    let mut r = Reader::new(&null_der);
    r.read_null().unwrap();
    // Non-canonical booleans are accepted, as OpenSSL does.
    let mut r = Reader::new(&[0x01, 0x01, 0x01]);
    assert!(r.read_boolean().unwrap());
    let mut r = Reader::new(&[0x01, 0x02, 0x00, 0x00]);
    assert!(r.read_boolean().is_err());
}

#[test]
fn bit_string_roundtrip() {
    let encoded = der::bit_string(3, &[0b1010_0000]);
    let mut r = Reader::new(&encoded);
    let (unused, data) = r.read_bit_string().unwrap();
    assert_eq!((unused, data), (3, &[0b1010_0000][..]));
    let bad = [0x03, 0x01, 0x08];
    let mut r = Reader::new(&bad);
    assert!(r.read_bit_string().is_err());
}

#[test]
fn nested_structures() {
    let inner = der::sequence(&der::oid(&crate::oid!(1, 2, 840, 10045, 2, 1)));
    let outer = der::sequence(&inner);
    let mut r = Reader::new(&outer);
    let mut seq = r.read_sequence().unwrap();
    let mut inner = seq.read_sequence().unwrap();
    assert_eq!(
        inner.read_oid().unwrap().to_dotted_string(),
        "1.2.840.10045.2.1"
    );
    r.expect_end().unwrap();
}

#[test]
fn long_lengths_encode_and_parse() {
    let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let encoded = der::octet_string(&data);
    // 1000 needs two length octets (0x82 0x03 0xe8).
    assert_eq!(&encoded[..4], &[0x04, 0x82, 0x03, 0xe8]);
    let mut r = Reader::new(&encoded);
    assert_eq!(r.read_octet_string().unwrap(), &data[..]);
    // 128 is the first long form.
    let encoded = der::octet_string(&vec![7u8; 128]);
    assert_eq!(&encoded[..3], &[0x04, 0x81, 0x80]);
}

#[test]
fn rejects_malformed_input() {
    // Truncated content.
    let mut r = Reader::new(&[0x04, 0x05, 0x01]);
    assert!(r.read_octet_string().is_err());
    // Indefinite length on a primitive encoding is invalid.
    let mut r = Reader::new(&[0x04, 0x80, 0x00, 0x00]);
    assert!(r.read_octet_string().is_err());
    // Unterminated indefinite construction.
    let mut r = Reader::new(&[0x30, 0x80, 0x02, 0x01, 0x01]);
    assert!(r.read_sequence().is_err());
    // Wrong tag.
    let mut r = Reader::new(&[0x02, 0x01, 0x00]);
    assert!(r.read_octet_string().is_err());
    // Negative integer.
    let encoded = [0x02, 0x01, 0x80];
    let mut r = Reader::new(&encoded);
    assert!(r.read_integer().is_err());
    // Empty integer.
    let encoded = [0x02, 0x00];
    let mut r = Reader::new(&encoded);
    assert!(r.read_integer().is_err());
    // Trailing data.
    let mut encoded = der::null();
    encoded.extend_from_slice(&der::null());
    let mut r = Reader::new(&encoded);
    r.read_null().unwrap();
    assert!(r.expect_end().is_err());
}

#[test]
fn ber_indefinite_lengths() {
    // SEQUENCE { INTEGER 1 } in BER indefinite form, with a nested
    // indefinite OCTET STRING.
    let encoded = [
        0x30, 0x80, // SEQUENCE, indefinite
        0x02, 0x01, 0x2a, // INTEGER 42
        0x24, 0x80, 0x04, 0x02, 0xde, 0xad, 0x00, 0x00, // constructed OCTET STRING
        0x00, 0x00, // end of contents
    ];
    let mut r = Reader::new(&encoded);
    let mut seq = r.read_sequence().unwrap();
    assert_eq!(seq.read_integer().unwrap(), &[0x2a]);
    assert_eq!(seq.read_octet_string_owned().unwrap(), [0xde, 0xad]);
    seq.expect_end().unwrap();
    r.expect_end().unwrap();

    // Constructed OCTET STRING segments split across several primitives.
    let encoded = [0x24, 0x80, 0x04, 0x01, 0x01, 0x04, 0x01, 0x02, 0x00, 0x00];
    let mut r = Reader::new(&encoded);
    assert_eq!(r.read_octet_string_owned().unwrap(), [0x01, 0x02]);
    r.expect_end().unwrap();
}

#[test]
fn high_tag_number_roundtrip() {
    let tag = der::Tag::context_constructed(200);
    let encoded = der::tlv(tag, &[0x01, 0x02]);
    let mut r = Reader::new(&encoded);
    let (parsed, content) = r.read_tlv().unwrap();
    assert_eq!(parsed, tag);
    assert_eq!(content, &[0x01, 0x02]);
    // The identifier octets are 0xbf 0x81 0x48 for [200].
    assert_eq!(&encoded[..3], &[0xbf, 0x81, 0x48]);
}

#[test]
fn explicit_and_implicit_tags() {
    let inner = der::integer(&[0x2a]);
    let encoded = der::explicit(0, &inner);
    assert_eq!(&encoded[..2], &[0xa0, 0x03]);
    let mut r = Reader::new(&encoded);
    let mut inner_reader = r.read_explicit(0).unwrap();
    assert_eq!(inner_reader.read_integer().unwrap(), &[0x2a]);
    r.expect_end().unwrap();

    let encoded = der::implicit(2, false, &[0xde, 0xad]);
    assert_eq!(encoded, vec![0x82, 0x02, 0xde, 0xad]);
    let mut r = Reader::new(&encoded);
    assert_eq!(r.read_implicit(2, false).unwrap(), &[0xde, 0xad]);
}

#[test]
fn oid_roundtrip() {
    // Known encoding of 1.2.840.113549.1.1.11.
    let der = der::oid(&crate::oid!(1, 2, 840, 113549, 1, 1, 11));
    assert_eq!(
        der,
        vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
    );
    let mut r = Reader::new(&der);
    let parsed = r.read_oid().unwrap();
    assert_eq!(parsed.arcs(), &[1, 2, 840, 113549, 1, 1, 11]);
    assert_eq!(parsed.to_dotted_string(), "1.2.840.113549.1.1.11");
    assert!(parsed.matches(oid::OID_SHA256_WITH_RSA));

    // First-arc packing: 2.999 and 1.2.
    let oid = ObjectIdentifier::from_der_content(&[0x88, 0x37]).unwrap();
    assert_eq!(oid.arcs(), &[2, 999]);
    let oid = ObjectIdentifier::from_dotted_string("1.2.3.4").unwrap();
    assert_eq!(oid.arcs(), &[1, 2, 3, 4]);

    assert!(ObjectIdentifier::new(&[3, 1]).is_err());
    assert!(ObjectIdentifier::new(&[1, 40]).is_err());
    assert!(ObjectIdentifier::from_der_content(&[0x80]).is_err());
    assert!(ObjectIdentifier::from_dotted_string("1.x.3").is_err());
}

#[test]
fn time_parsing() {
    let utc = Asn1Time::parse_utc(b"200101000000Z").unwrap();
    assert_eq!((utc.year, utc.month, utc.day), (2020, 1, 1));
    assert_eq!(utc.to_unix(), 1_577_836_800);
    assert!(utc.utc);
    let utc = Asn1Time::parse_utc(b"500101000000Z").unwrap();
    assert_eq!(utc.year, 1950);
    let utc = Asn1Time::parse_utc(b"491231235959Z").unwrap();
    assert_eq!(utc.year, 2049);
    // Seconds may be omitted in BER encodings.
    let utc = Asn1Time::parse_utc(b"2001010000Z").unwrap();
    assert_eq!(utc.second, 0);

    let gen = Asn1Time::parse_generalized(b"20260101000000Z").unwrap();
    assert_eq!(gen.year, 2026);
    assert!(!gen.utc);
    let gen = Asn1Time::parse_generalized(b"202601010000Z").unwrap();
    assert_eq!(gen.second, 0);
    let gen = Asn1Time::parse_generalized(b"20260101000000.5Z").unwrap();
    assert_eq!(gen.second, 0);

    assert!(Asn1Time::parse_utc(b"200101000000").is_err());
    assert!(Asn1Time::parse_utc(b"201301000000Z").is_err()); // month 13
    assert!(Asn1Time::parse_generalized(b"20260230000000Z").is_err()); // Feb 30
    assert!(Asn1Time::parse_utc(b"2001010000+0100").is_err());
}

#[test]
fn time_conversion_and_ordering() {
    let t = Asn1Time::from_unix(1_577_836_800, true);
    assert_eq!(
        (t.year, t.month, t.day, t.hour, t.minute, t.second),
        (2020, 1, 1, 0, 0, 0)
    );
    assert_eq!(t.encode_utc(), b"200101000000Z".to_vec());
    assert_eq!(t.encode_generalized(), b"20200101000000Z".to_vec());
    // Leap day.
    let leap = Asn1Time::new(2024, 2, 29, 12, 0, 0, false).unwrap();
    assert_eq!(Asn1Time::from_unix(leap.to_unix(), false).day, 29);
    assert!(Asn1Time::new(2023, 2, 29, 0, 0, 0, false).is_err());
    // Ordering.
    let earlier = Asn1Time::parse_utc(b"200101000000Z").unwrap();
    let later = Asn1Time::parse_utc(b"210101000000Z").unwrap();
    assert!(earlier < later);
    // A year outside 1950..=2049 must not be written as UTCTime.
    let out_of_range = Asn1Time::new(2050, 1, 1, 0, 0, 0, true).unwrap();
    assert_eq!(out_of_range.encode(), b"20500101000000Z".to_vec());
}

#[test]
fn pem_roundtrip() {
    let data: Vec<u8> = (0..=255u8).collect();
    let text = pem::encode("CERTIFICATE", &data);
    assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(text.ends_with("-----END CERTIFICATE-----\n"));
    let block = pem::parse_first(&text).unwrap();
    assert_eq!(block.label, "CERTIFICATE");
    assert_eq!(block.data, data);
}

#[test]
fn pem_known_vector() {
    // "hello" in the PEM body.
    let text = "-----BEGIN TEST-----\naGVsbG8=\n-----END TEST-----\n";
    let block = pem::parse_first(text).unwrap();
    assert_eq!(block.data, b"hello");
    assert_eq!(pem::encode("TEST", b"hello"), text);
}

#[test]
fn pem_multiple_blocks_and_noise() {
    let text = "subject=CN=x\n-----BEGIN A-----\nAA==\n-----END A-----\n\
                \r\n-----BEGIN B-----\nProc-Type: 4,ENCRYPTED\n\nAQID\n-----END B-----\n";
    let blocks = pem::parse(text).unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].label, "A");
    assert_eq!(blocks[0].data, vec![0x00]);
    assert_eq!(blocks[1].label, "B");
    assert_eq!(blocks[1].data, vec![0x01, 0x02, 0x03]);
}

#[test]
fn pem_rejects_malformed() {
    assert!(pem::parse("no pem here").is_err());
    assert!(pem::parse("-----BEGIN A-----\nAA==\n").is_err());
    assert!(pem::parse("-----BEGIN A-----\n!!\n-----END A-----\n").is_err());
    assert!(pem::parse("-----BEGIN A-----\nAA==\n-----END B-----\n").is_err());
    // A single dangling character is not a valid base64 quantum.
    assert!(pem::parse_first("-----BEGIN A-----\nA\n-----END A-----\n").is_err());
}

#[test]
fn base64_known_vectors() {
    assert_eq!(pem::base64_encode(b""), "");
    assert_eq!(pem::base64_encode(b"f"), "Zg==");
    assert_eq!(pem::base64_encode(b"fo"), "Zm8=");
    assert_eq!(pem::base64_encode(b"foo"), "Zm9v");
    assert_eq!(pem::base64_encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(pem::base64_decode("Zg==").unwrap(), b"f");
    assert_eq!(pem::base64_decode("Zm8=").unwrap(), b"fo");
    assert_eq!(pem::base64_decode("Zm9vYmFy").unwrap(), b"foobar");
}

#[test]
fn algorithm_identifier_helper() {
    let encoded = der::algorithm_identifier(&crate::oid!(1, 3, 101, 112), None);
    let mut r = Reader::new(&encoded);
    let mut seq = r.read_sequence().unwrap();
    assert!(seq.read_oid().unwrap().matches(oid::OID_ED25519));
    seq.expect_end().unwrap();
    assert_eq!(encoded, vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);

    let encoded =
        der::algorithm_identifier(&crate::oid!(1, 2, 840, 113549, 1, 1, 1), Some(&der::null()));
    assert_eq!(&encoded[..2], &[0x30, 0x0d]);
}

#[test]
fn raw_tlv_keeps_original_bytes() {
    let encoded = der::sequence(&der::oid(&crate::oid!(1, 2, 3)));
    let mut r = Reader::new(&encoded);
    let raw = r.read_raw_tlv().unwrap();
    assert_eq!(raw, &encoded[..]);
}

#[test]
fn string_decoding() {
    let utf8 = der::utf8_string("héllo");
    let mut r = Reader::new(&utf8);
    assert_eq!(r.read_directory_string().unwrap(), "héllo");
    let printable = der::printable_string("example.com");
    let mut r = Reader::new(&printable);
    assert_eq!(r.read_directory_string().unwrap(), "example.com");
    let ia5 = der::ia5_string("a@b.example");
    let mut r = Reader::new(&ia5);
    assert_eq!(r.read_directory_string().unwrap(), "a@b.example");
    // BMPString "Hi".
    let bmp = [0x1e, 0x04, 0x00, 0x48, 0x00, 0x69];
    let mut r = Reader::new(&bmp);
    assert_eq!(r.read_directory_string().unwrap(), "Hi");
    // A non-ASCII PrintableString is invalid.
    let bad = [0x13, 0x02, 0xc3, 0xa9];
    let mut r = Reader::new(&bad);
    assert!(matches!(
        r.read_directory_string(),
        Err(CryptoError::StrError(_))
    ));
}
