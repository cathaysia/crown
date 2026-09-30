//! RFC 7748 X25519 test vectors.

use super::*;

fn hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_str(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// RFC 7748 §5.2 vector 1: scalar multiplication.
#[test]
fn rfc7748_scalar_mult_1() {
    let scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
    let mut out = [0u8; 32];
    scalar_mult(&mut out, &scalar, &u);
    assert_eq!(hex_str(&out), expected);
}

/// RFC 7748 §5.2 vector 2.
#[test]
fn rfc7748_scalar_mult_2() {
    let scalar = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    let u = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    let expected = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";
    let mut out = [0u8; 32];
    scalar_mult(&mut out, &scalar, &u);
    assert_eq!(hex_str(&out), expected);
}

/// RFC 7748 §6.1 Diffie-Hellman.
#[test]
fn rfc7748_diffie_hellman() {
    let alice_priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_priv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let alice_pub_expected = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    let bob_pub_expected = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    let shared_expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    let alice_pub = public_from_private(&alice_priv);
    let bob_pub = public_from_private(&bob_priv);
    assert_eq!(hex_str(&alice_pub), alice_pub_expected);
    assert_eq!(hex_str(&bob_pub), bob_pub_expected);

    let s1 = x25519(&alice_priv, &bob_pub).unwrap();
    let s2 = x25519(&bob_priv, &alice_pub).unwrap();
    assert_eq!(hex_str(&s1), shared_expected);
    assert_eq!(s1, s2);
}

/// Base-point public derivation is just scalar_mult with u = 9.
#[test]
fn public_from_private_matches_base_scalar() {
    let priv_key = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let expected = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    assert_eq!(hex_str(&public_from_private(&priv_key)), expected);
}

/// Clamping: bits 0..2 clear, bit 254 set, bit 255 clear.
#[test]
fn clamp_shape() {
    let mut s = [0xffu8; 32];
    clamp(&mut s);
    assert_eq!(s[0], 248);
    assert_eq!(s[31], 64 | 127);
    assert_eq!(s[31] & 0x80, 0);
}
