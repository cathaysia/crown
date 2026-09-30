//! RSA test vectors generated with the system OpenSSL 3.5.8 CLI
//! (`openssl genrsa 1024`, `openssl dgst -sign`, `openssl pkeyutl`).

use super::der;
use super::*;
use crate::envelope::EvpHash;
use crate::kdf::HashFactory;
use alloc::vec::Vec;

/// Deterministic splitmix64-based RNG for reproducible padding and keys.
struct TestRng(u64);

impl TestRng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

impl Rng for TestRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

const PRIV_DER: &str = concat!(
    "30820277020100300d06092a864886f70d0101010500048202613082025d0201",
    "00028181009d7210d4fb192602aaf2466f7e89be08fc9336a7ab64c17727180d",
    "5760732b16ebe13e2339cdea1fc03b77fbf3428a19413a63ab1f58658e9f3a83",
    "88d660a86e837d838713fef586ef57f77336b0f5c140848edaaa3373550f2002",
    "7733832c44bcfe98d6196ccb9d238f860fb12ed0e658ebfc25812040fb92584c",
    "678165057702030100010281804dcb54a1c7c82f4dd6258bc3ff6413efe0cce4",
    "8e88536a7c7366a100f179366b46f5ae7c3d4d8f474cf6955c7a600058663071",
    "9ad60c1972151f166b007216066e80da66a6e812a27a0b25ec65d1f2892ecbb6",
    "e4184c2070675ee1c7bae59ed2f40846e3cefbc0f9e3042f574171e8ccee1ce7",
    "a6a47d686d88e4304de2a42a71024100d199cae106c4795434ea176d505b4b64",
    "6fa7ce19f36751cc5d5c734fc28b2d91a264fd9119487aa52b782a1f6288a11b",
    "65d74bdd09c94f3831058e15beb7467b024100c04c9b22087ec3032dae2e01fb",
    "0761930dc29a85cec803a58106013a383e3b0ffcfddbbf451d2f8be6354979bf",
    "8c514a4940e20762cce7a7011d2a5b69e5ea35024027540d1e460fcd98404980",
    "55d1931fc55bb207d914b3d944586c4572bcd5329ab5f6ef212fb64ad4fd2011",
    "ff4b94c96e03a0ef2a2d70e97d68ad5b28b75d5a4b0241008882d96e2391b966",
    "bc3af63639ba57ae490a691fac57991f18a4e6a229e323928a0abcc0df938479",
    "50076c0d9dc942bbf59cb5d8806eedd4449a2bc3913dc231024100b4608a268c",
    "cf8c6a8bea7bb0833f908085b51df7926a1edb0dcd6652e7115e3732ca9bfd43",
    "5eabbfbd49cd35f95bf11a9d5ddfabfb494c78ac7792fba398d015"
);

const PUB_DER: &str = concat!(
    "308189028181009d7210d4fb192602aaf2466f7e89be08fc9336a7ab64c17727",
    "180d5760732b16ebe13e2339cdea1fc03b77fbf3428a19413a63ab1f58658e9f",
    "3a8388d660a86e837d838713fef586ef57f77336b0f5c140848edaaa3373550f",
    "20027733832c44bcfe98d6196ccb9d238f860fb12ed0e658ebfc25812040fb92",
    "584c67816505770203010001"
);

const MSG: &str = concat!(
    "63726f776e207273612074657374206d65737361676520666f72207061646469",
    "6e6720636865636b730a"
);

const SIG256: &str = concat!(
    "584b4320de920eaad7bcdeafc7650cf929a1c495a1e1d32e9e94b04503e077d3",
    "e7b7c54cf2cd43b25b2688fd08c35ce0493c7466e2d30a38b40bdcbaac553446",
    "fa1ad1da65111f57e39e98254102faf127435b6019a3176f9b040b1c6fedfe1a",
    "8be5e7b532eb576d3dbca6decc1c78b51ff55d6a0e0288116ae1123a173626af"
);

const SIGPSS: &str = concat!(
    "65db6887e7ac94d5e9227de535cc8283dc0d090ea8a66374a166e93294ff1180",
    "5049d7f4e926b8b84bc519dd0b54b5e9558231e050629681b62d415a37173cb8",
    "bd907ac26d0f14b6114b933cc84af77ff5486d2f3add7b3cc1dcc9ad2f69fd7e",
    "6e055a110951411c1b06b05aa2930a1c000b61881ddea57939aaea6558bf4659"
);

const CT_PKCS1: &str = concat!(
    "8d4280ba1cc8a6d76573e18c0b2c2a9e65b23cddfe21e8a3c6f4ff1c459219f6",
    "62cd3071711c47e41da13d59209dd98e51b998ec03cf7e447c35d6fe676c94fb",
    "96002a9778aad11ab3b67621c0a5254c64f05add5476d3370db6deefc0ff421d",
    "7b602e07a5ae1d2bee897dee2210d2bd650bcec0bdf0710e4e10255c2b1696c1"
);

const CT_OAEP: &str = concat!(
    "14deef4c8b80d986beead65e548f46c9dc02a6c20c90ec711ad919f75a1fd18a",
    "57240b0b29c2c454036c771e72bd22ac73af5f46a053ebe7c25a6e670c4968e5",
    "69abb590df227f3e56d93215b239bda2aed9d0986011db360daa7b2bee912782",
    "524119d0d98eaf68383d8183ca4e4b9ef8f7b55a70731071f4df385e5eb68754"
);

fn sha256() -> HashFactory {
    EvpHash::new_sha256
}

fn private_key() -> RsaPrivateKey {
    let (n, e, d, p, q, dp, dq, qinv) =
        der::parse_pkcs8_rsa_private_key(&hex_bytes(PRIV_DER)).unwrap();
    RsaPrivateKey::from_components(
        &n,
        &e,
        &d,
        Some(&p),
        Some(&q),
        Some(&dp),
        Some(&dq),
        Some(&qinv),
    )
    .unwrap()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn pkcs1v15_signature_interop() {
    let key = private_key();
    let msg = hex_bytes(MSG);
    let sig = hex_bytes(SIG256);

    // Sign and compare byte-for-byte with the OpenSSL-produced signature
    // (PKCS#1 v1.5 signatures are deterministic).
    let mine = key.sign_pkcs1v15(sha256(), &msg).unwrap();
    assert_eq!(mine, sig);

    // Verify the OpenSSL signature.
    assert!(key.public().verify_pkcs1v15(sha256(), &msg, &sig).unwrap());

    // Tampering fails.
    let mut bad = sig.clone();
    bad[10] ^= 1;
    assert!(!key.public().verify_pkcs1v15(sha256(), &msg, &bad).unwrap());
    assert!(!key
        .public()
        .verify_pkcs1v15(crate::envelope::EvpHash::new_sha512, &msg, &sig)
        .unwrap());
}

#[test]
fn pss_verify_interop() {
    let key = private_key();
    let msg = hex_bytes(MSG);
    let sig = hex_bytes(SIGPSS);

    // OpenSSL signed with salt length 32.
    assert!(key.public().verify_pss(sha256(), &msg, &sig, 32).unwrap());
    // Wrong salt length fails.
    assert!(!key.public().verify_pss(sha256(), &msg, &sig, 20).unwrap());
}

#[test]
fn pss_sign_roundtrip() {
    let mut rng = TestRng(0x5eed_1234_5678_9abc);
    let key = private_key();
    let msg = hex_bytes(MSG);

    let sig = key.sign_pss(sha256(), &msg, 32, &mut rng).unwrap();
    assert!(key.public().verify_pss(sha256(), &msg, &sig, 32).unwrap());
    assert!(!key.public().verify_pss(sha256(), &msg, &sig, 31).unwrap());

    // Signatures from the same salt length but different randomness differ.
    let sig2 = key.sign_pss(sha256(), &msg, 32, &mut rng).unwrap();
    assert_ne!(sig, sig2);
}

#[test]
fn pkcs1v15_encryption_interop() {
    let key = private_key();
    let msg = hex_bytes(MSG);
    let ct = hex_bytes(CT_PKCS1);

    // Decrypt the OpenSSL-encrypted message.
    assert_eq!(key.decrypt_pkcs1v15(&ct).unwrap(), msg);

    // Round-trip through our own encryption.
    let mut rng = TestRng(42);
    let mine = key.public().encrypt_pkcs1v15(&mut rng, &msg).unwrap();
    assert_eq!(key.decrypt_pkcs1v15(&mine).unwrap(), msg);
    assert_ne!(mine, ct);
}

#[test]
fn oaep_interop() {
    let key = private_key();
    let msg = hex_bytes(MSG);
    let ct = hex_bytes(CT_OAEP);

    assert_eq!(key.decrypt_oaep(sha256(), &ct).unwrap(), msg);

    let mut rng = TestRng(7);
    let mine = key.public().encrypt_oaep(sha256(), &mut rng, &msg).unwrap();
    assert_eq!(key.decrypt_oaep(sha256(), &mine).unwrap(), msg);

    // Wrong digest fails the OAEP decode.
    assert!(key
        .decrypt_oaep(crate::envelope::EvpHash::new_sha512, &ct)
        .is_err());
}

#[test]
fn raw_out_of_range() {
    let key = private_key();
    let long = alloc::vec![0xffu8; key.public().size()];
    assert!(key.public().encrypt_raw(&long).is_err());
    assert!(key.decrypt_raw(&long).is_err());
}

#[test]
fn keygen_roundtrip() {
    let mut rng = TestRng(0xdead_beef_cafe_f00d);
    let key = RsaPrivateKey::generate(512, 65537, &mut rng).unwrap();

    // Components are consistent: e * d == 1 (mod (p-1)(q-1)).
    let p = key.p.as_ref().unwrap();
    let q = key.q.as_ref().unwrap();
    let e = Bn::from_be_bytes(&key.public.e());
    let n = Bn::from_be_bytes(&key.public.n());
    assert_eq!(p.mul(q), n);

    let phi = p.sub(&Bn::one()).unwrap().mul(&q.sub(&Bn::one()).unwrap());
    let d = Bn::from_be_bytes({
        // d is private to the module; recompute it from CRT for the check.
        let _ = &key.d;
        &key.d.to_be_bytes()
    });
    assert_eq!(e.mul(&d).modulus(&phi), Bn::one());

    // The factors are probable primes.
    assert!(prime::is_probable_prime(p, 8, &mut rng).unwrap());
    assert!(prime::is_probable_prime(q, 8, &mut rng).unwrap());

    // Sign/verify and encrypt/decrypt round-trips.
    let msg = b"keygen roundtrip";
    let sig = key.sign_pkcs1v15(sha256(), msg).unwrap();
    assert!(key.public().verify_pkcs1v15(sha256(), msg, &sig).unwrap());

    let mut rng2 = TestRng(3);
    let ct = key
        .public()
        .encrypt_oaep(crate::envelope::EvpHash::new_sha1, &mut rng2, msg)
        .unwrap();
    assert_eq!(
        key.decrypt_oaep(crate::envelope::EvpHash::new_sha1, &ct)
            .unwrap(),
        msg
    );
}

#[test]
fn der_roundtrip() {
    let (n, e, d, p, q, dp, dq, qinv) =
        der::parse_pkcs8_rsa_private_key(&hex_bytes(PRIV_DER)).unwrap();

    // The public key re-encodes byte-for-byte to OpenSSL's PKCS#1 DER.
    let re_pub = der::rsa_public_key_der(&n, &e);
    assert_eq!(re_pub, hex_bytes(PUB_DER));

    // The private key round-trips through our own encoder/parser.
    let re = der::rsa_private_key_der(&n, &e, &d, &p, &q, &dp, &dq, &qinv);
    let again = der::parse_rsa_private_key(&re).unwrap();
    assert_eq!(again, (n, e, d, p, q, dp, dq, qinv));
}
