use super::*;
use crate::envelope::EvpHash;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Vectors from OpenSSL evpkdf_x942.txt: RFC 3565 B.2 examples and
// option-combination tests.
#[test]
fn rfc3565_examples() {
    // Output length 16 = 128 bits, so use_keybits encodes suppPubInfo.
    let out = derive(
        EvpHash::new_sha1,
        &hex_to_bytes("000102030405060708090a0b0c0d0e0f10111213"),
        CekAlg::Aes128Wrap,
        &[],
        &[],
        &[],
        &[],
        true,
        16,
    )
    .unwrap();
    assert_eq!(out, hex_to_bytes("d6d6b094c1027a7de6e3117294a35364"));

    // Output length 24 with a 49-byte ukm as partyUInfo.
    let ukm = hex_to_bytes(
        "0123456789abcdeffedcba98765432010123456789abcdeffedcba98765432010123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201",
    );
    let out = derive(
        EvpHash::new_sha1,
        &hex_to_bytes("000102030405060708090a0b0c0d0e0f10111213"),
        CekAlg::Aes256Wrap,
        &ukm,
        &[],
        &[],
        &[],
        true,
        28,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("8890585C4E281A5C1167CAA530BED59B3230D893CBA8F922BD1B56A0")
    );
}

#[test]
fn option_combinations() {
    let secret = hex_to_bytes("000102030405060708090a0b0c0d0e0f10111213");
    let ukm = hex_to_bytes(
        "0123456789abcdeffedcba98765432010123456789abcdeffedcba98765432010123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201",
    );

    // use-keybits = 0: keylen bits are omitted from the OtherInfo.
    let out = derive(
        EvpHash::new_sha1,
        &secret,
        CekAlg::Aes256Wrap,
        &ukm,
        &[],
        &[],
        &[],
        false,
        28,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("54bd5dbc1fa4c42c951f6fa51ec59e202b8c622bdb179fb2dd691ffb")
    );

    // partyVInfo instead of partyUInfo.
    let out = derive(
        EvpHash::new_sha1,
        &secret,
        CekAlg::Aes256Wrap,
        &[],
        &ukm,
        &[],
        &[],
        false,
        28,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("76d566e948ca9ae61bcd4ce076f0bd5fe6789b5b0f288977235ecb12")
    );

    // Explicit suppPubInfo replaces the keybits field.
    let out = derive(
        EvpHash::new_sha1,
        &secret,
        CekAlg::Aes256Wrap,
        &[],
        &[],
        &ukm,
        &[],
        false,
        28,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("ff368c7addb27d7599f8d49bc8d7fbf804540f119491ea419792c82c")
    );
}

#[test]
fn rejects_invalid_parameters() {
    let secret = hex_to_bytes("000102030405060708090a0b0c0d0e0f10111213");
    // supp_pub together with use_keybits encodes the same field twice.
    assert!(derive(
        EvpHash::new_sha1,
        &secret,
        CekAlg::Aes256Wrap,
        &[],
        &[],
        &[1u8],
        &[],
        true,
        16
    )
    .is_err());
    assert!(derive(
        EvpHash::new_sha1,
        &secret,
        CekAlg::Aes256Wrap,
        &[],
        &[],
        &[],
        &[],
        true,
        0
    )
    .is_err());
}
