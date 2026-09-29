//! RFC 7748 X448 test vectors.

use super::*;

fn hex(s: &str) -> [u8; 56] {
    let mut out = [0u8; 56];
    for i in 0..56 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_str(bytes: &[u8; 56]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// RFC 7748 §5.2 vector 1: scalar multiplication.
#[test]
fn rfc7748_scalar_mult_1() {
    let scalar = hex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
         700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
    let u = hex("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
         814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
    let expected = "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f";
    let mut out = [0u8; 56];
    scalar_mult(&mut out, &scalar, &u);
    assert_eq!(hex_str(&out), expected.replace('\n', ""));
}

/// RFC 7748 §5.2 vector 2.
#[test]
fn rfc7748_scalar_mult_2() {
    let scalar = hex("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5\
         38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
    let u = hex("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b\
         165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");
    let expected = "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7\
ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d";
    let mut out = [0u8; 56];
    scalar_mult(&mut out, &scalar, &u);
    assert_eq!(hex_str(&out), expected.replace('\n', ""));
}

/// RFC 7748 §6.2 Diffie-Hellman.
#[test]
fn rfc7748_diffie_hellman() {
    let alice_priv = hex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
         d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let bob_priv = hex("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
         6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
    let alice_pub_expected = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
    let bob_pub_expected = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
    let shared_expected = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

    let alice_pub = public_from_private(&alice_priv);
    let bob_pub = public_from_private(&bob_priv);
    assert_eq!(hex_str(&alice_pub), alice_pub_expected.replace('\n', ""));
    assert_eq!(hex_str(&bob_pub), bob_pub_expected.replace('\n', ""));

    let s1 = x448(&alice_priv, &bob_pub).unwrap();
    let s2 = x448(&bob_priv, &alice_pub).unwrap();
    assert_eq!(hex_str(&s1), shared_expected.replace('\n', ""));
    assert_eq!(s1, s2);
}

/// RFC 7748 §5.2 iterative vector, one iteration starting from
/// k = u = 5 (56-byte little-endian).
#[test]
fn rfc7748_iterative_one() {
    let k = {
        let mut v = [0u8; 56];
        v[0] = 5;
        v
    };
    let out = x448(&k, &k).unwrap();
    let expected = "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a\
4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113";
    assert_eq!(hex_str(&out), expected.replace('\n', ""));
}

/// Base-point public derivation is scalar_mult with u = 5.
#[test]
fn public_from_private_matches_base_scalar() {
    let priv_key = hex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
         d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let expected = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
    assert_eq!(
        hex_str(&public_from_private(&priv_key)),
        expected.replace('\n', "")
    );
}

/// Clamping: bits 0..1 clear, bit 447 set.
#[test]
fn clamp_shape() {
    let mut s = [0xffu8; 56];
    clamp(&mut s);
    assert_eq!(s[0], 252);
    assert_eq!(s[55], 0xff | 128);
    assert_eq!(s[55] & 128, 128);
}

/// An all-zero shared secret is reported as None (low-order point).
#[test]
fn zero_output_is_none() {
    // u = 0 is a low-order point on curve448; the ladder output is 0.
    let priv_key = [1u8; 56];
    let zero_pub = [0u8; 56];
    assert!(x448(&priv_key, &zero_pub).is_none());
}
