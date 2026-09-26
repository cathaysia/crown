use super::*;
use crate::block::aes::Aes;
use crate::envelope::EvpHash;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fixed_input<'a>(info: &'a [u8]) -> FixedInput<'a> {
    FixedInput {
        label: &[],
        context: info,
        iv: &[],
        use_l: false,
        use_separator: false,
        r: 8,
    }
}

// Counter-mode vectors from OpenSSL evpkdf_kbkdf_counter.txt.
#[test]
fn counter_mode_cmac() {
    let info = hex_to_bytes("c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5");
    let out = derive_cmac::<Aes, 16>(
        Aes::new(&hex_to_bytes("dff1e50ac0b69dc40f1051d46c2b069c")).unwrap(),
        Mode::Counter,
        &fixed_input(&info),
        16,
    )
    .unwrap();
    assert_eq!(out, hex_to_bytes("8be8f0869b3c0ba97b71863d1b9f7813"));

    let info = hex_to_bytes("e323cdfa7873a0d72cd86ffb4468744f097db60498f7d0e3a43bafd2d1af675e4a88338723b1236199705357c47bf1d89b2f4617a340980e6331625c");
    let out = derive_cmac::<Aes, 16>(
        Aes::new(&hex_to_bytes("682e814d872397eba71170a693514904")).unwrap(),
        Mode::Counter,
        &fixed_input(&info),
        32,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("dac9b6ca405749cfb065a0f1e42c7c4224d3d5db32fdafe9dee6ca193316f2c7")
    );
}

#[test]
fn counter_mode_hmac() {
    let info = hex_to_bytes("98132c1ffaf59ae5cbc0a3133d84c551bb97e0c75ecaddfc30056f6876f59803009bffc7d75c4ed46f40b8f80426750d15bc1ddb14ac5dcb69a68242");
    let out = derive_hmac(
        EvpHash::new_sha1_hmac,
        Mode::Counter,
        &hex_to_bytes("00a39bd547fb88b2d98727cf64c195c61e1cad6c"),
        &fixed_input(&info),
        16,
    )
    .unwrap();
    assert_eq!(out, hex_to_bytes("0611e1903609b47ad7a5fc2c82e47702"));

    let info = hex_to_bytes("4b10500ba5c9391da83d2ef78d01bcdccda32ff6f242960323324474b9d0685d99dc9143ac6d667a5b46dcc89784b3a4af7a7684b01efee41b144f48");
    let out = derive_hmac(
        EvpHash::new_sha1_hmac,
        Mode::Counter,
        &hex_to_bytes("1ee222f5cdd60b0ae956eeeaa838c51bd767672c"),
        &fixed_input(&info),
        32,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("806e342013853083a3f7294c63a9ec9a6dba75b256c62fac1e480ef26276cd4b")
    );
}

// Feedback-mode vector generated with `openssl kdf ... KBKDF`.
#[test]
fn feedback_mode_cmac() {
    let info = hex_to_bytes("c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5");
    let fi = FixedInput {
        label: &[],
        context: &info,
        iv: &hex_to_bytes("00112233445566778899aabbccddeeff"),
        use_l: false,
        use_separator: false,
        r: 8,
    };
    let out = derive_cmac::<Aes, 16>(
        Aes::new(&hex_to_bytes("dff1e50ac0b69dc40f1051d46c2b069c")).unwrap(),
        Mode::Feedback,
        &fi,
        16,
    )
    .unwrap();
    assert_eq!(out, hex_to_bytes("DBF84A924A37D364EECAB5FD0E6EFF5D"));
}

// KMAC128 vector generated with `openssl kdf -kdfopt mac:KMAC128 ... KBKDF`.
#[test]
fn kmac128_derive() {
    let out = derive_kmac128(
        &hex_to_bytes("00112233445566778899aabbccddeeff"),
        &hex_to_bytes("deadbeef"),
        &[],
        32,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("6B380A2B5B2B595470E0F0EB6908CB2C51F41A1E42C7E6724AAF708BC8A95F8D")
    );
}

#[test]
fn rejects_invalid_parameters() {
    let fi = fixed_input(&[]);
    assert!(derive_cmac::<Aes, 16>(Aes::new(&[0u8; 16]).unwrap(), Mode::Counter, &fi, 0).is_err());
    assert!(derive_hmac(EvpHash::new_sha1_hmac, Mode::Counter, b"ki", &fi, 0).is_err());
    // r must be 8, 16 or 32.
    let bad_r = FixedInput {
        label: &[],
        context: &[],
        iv: &[],
        use_l: false,
        use_separator: false,
        r: 12,
    };
    assert!(
        derive_cmac::<Aes, 16>(Aes::new(&[0u8; 16]).unwrap(), Mode::Counter, &bad_r, 16).is_err()
    );
}
