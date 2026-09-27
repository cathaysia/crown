use super::*;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to32(s: &str) -> [u8; 32] {
    let v = hex_to_bytes(s);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

// RFC 8032 section 7.1 TEST 1: empty message.
#[test]
fn rfc8032_test_1() {
    let secret = to32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = to32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let msg: [u8; 0] = [];
    let expected = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    let derived = public_from_secret(&secret);
    assert_eq!(derived, public);

    let sig = sign(&secret, &msg);
    assert_eq!(sig[..], hex_to_bytes(expected)[..]);
    assert!(verify(&public, &sig, &msg));
}

// RFC 8032 section 7.1 TEST 2: 1-byte message.
#[test]
fn rfc8032_test_2() {
    let secret = to32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let public = to32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let msg = hex_to_bytes("72");

    assert_eq!(public_from_secret(&secret), public);
    let sig = sign(&secret, &msg);
    assert_eq!(
        sig[..],
        hex_to_bytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")[..]
    );
    assert!(verify(&public, &sig, &msg));
}

// RFC 8032 section 7.1 TEST 3: 2-byte message.
#[test]
fn rfc8032_test_3() {
    let secret = to32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let public = to32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let msg = hex_to_bytes("af82");

    assert_eq!(public_from_secret(&secret), public);
    let sig = sign(&secret, &msg);
    assert_eq!(
        sig[..],
        hex_to_bytes("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")[..]
    );
    assert!(verify(&public, &sig, &msg));
}

// RFC 8032 section 7.1 TEST 1024: 1023-byte message (message hex taken
// from the RFC; signature cross-checked with the OpenSSL 3.5.8 CLI).
#[test]
fn rfc8032_test_1024() {
    let secret = to32("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
    let public = to32("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
    let msg = hex_to_bytes(&concat!(
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98",
        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8",
        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d",
        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc",
        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe",
        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e",
        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef",
        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7",
        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1",
        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2",
        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24",
        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270",
        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc",
        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07",
        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba",
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a",
        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e",
        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7",
        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c",
        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8",
        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df",
        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08",
        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649",
        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4",
        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e",
        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f",
        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5",
        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1",
        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d",
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c",
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
    ));

    assert_eq!(public_from_secret(&secret), public);
    let sig = sign(&secret, &msg);
    assert_eq!(
        sig[..],
        hex_to_bytes("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03")[..]
    );
    assert!(verify(&public, &sig, &msg));
}

// RFC 8032 section 7.1 TEST SHA(abc): the message is SHA-512("abc").
#[test]
fn rfc8032_sha_abc() {
    let secret = to32("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    let public = to32("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let msg = hex_to_bytes(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );

    assert_eq!(public_from_secret(&secret), public);
    let sig = sign(&secret, &msg);
    assert_eq!(
        sig[..],
        hex_to_bytes("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")[..]
    );
    assert!(verify(&public, &sig, &msg));
}

#[test]
fn rejects_tampering() {
    let secret = to32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let public = public_from_secret(&secret);
    let msg = hex_to_bytes("72");
    let sig = sign(&secret, &msg);

    // Flipping any message byte breaks verification.
    let mut bad_msg = msg.clone();
    bad_msg[0] ^= 1;
    assert!(!verify(&public, &sig, &bad_msg));

    // A tampered signature fails.
    let mut bad_sig = sig;
    bad_sig[63] ^= 1;
    assert!(!verify(&public, &bad_sig, &msg));
    let mut bad_sig_r = sig;
    bad_sig_r[0] ^= 1;
    assert!(!verify(&public, &bad_sig_r, &msg));

    // Wrong public key fails.
    let other_secret = to32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let other_public = public_from_secret(&other_secret);
    assert!(!verify(&other_public, &sig, &msg));
}

// Non-canonical S (>= L) is rejected outright, matching OpenSSL.
#[test]
fn rejects_non_canonical_s() {
    let secret = to32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let public = public_from_secret(&secret);
    let msg = hex_to_bytes("72");
    let sig = sign(&secret, &msg);

    let mut bad = sig;
    bad[63] = 0xff; // s[31] = 0xff > 0x10
    assert!(!verify(&public, &bad, &msg));

    // s == L exactly is also rejected.
    let mut bad = sig;
    bad[32..].copy_from_slice(&crate::ed25519::sc::L);
    assert!(!verify(&public, &bad, &msg));
}

// An invalid (undecodable) public key fails verification.
#[test]
fn rejects_invalid_public_key() {
    // y = 1: dy^2 + 1 has no square root for x, so decoding fails.
    let mut bad_public = [0u8; 32];
    bad_public[0] = 1;
    let secret = to32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let msg = hex_to_bytes("72");
    let sig = sign(&secret, &msg);
    assert!(!verify(&bad_public, &sig, &msg));
}

// x25519-x86_64.pl fe51 helpers vs the portable radix-2^51 arithmetic.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod asm_tests {
    use super::asm;
    use super::fe;
    use super::*;

    fn sample(n: u64) -> fe::Fe {
        // deterministic pseudo-random canonical field element
        let mut s = [0u8; 32];
        let mut x = n.wrapping_mul(0x9e3779b97f4a7c15);
        for b in s.iter_mut() {
            x = x.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(0x51);
            *b = (x >> 24) as u8;
        }
        s[31] &= 0x7f;
        fe::from_bytes(&s)
    }

    #[test]
    fn fe51_mul_matches_portable() {
        for n in 1..8 {
            let a = sample(n);
            let b = sample(n * 7 + 1);
            let got = asm::fe51_mul(&a, &b);
            let want = fe::mul(&a, &b);
            assert_eq!(got, want, "n={n}");
        }
    }

    #[test]
    fn fe51_sqr_matches_portable() {
        for n in 1..8 {
            let a = sample(n * 3 + 2);
            let got = asm::fe51_sqr(&a);
            let want = fe::sq(&a);
            assert_eq!(got, want, "n={n}");
        }
    }

    #[test]
    fn fe51_mul121666_matches_portable() {
        for n in 1..8 {
            let a = sample(n * 5 + 3);
            let got = asm::fe51_mul121666(&a);
            let want = fe::mul(&a, &[121666, 0, 0, 0, 0]);
            assert_eq!(got, want, "n={n}");
        }
    }

    // fe64 helpers: operands live in [0, 2^256) with partial reduction; the
    // tobytes output must equal the fully reduced product mod 2^255-19.
    #[test]
    fn fe64_small_known_values() {
        let two = [2u64, 0, 0, 0];
        let five = [5u64, 0, 0, 0];
        let seven = [7u64, 0, 0, 0];

        let prod = asm::fe64_mul(&five, &seven);
        assert_eq!(asm::fe64_tobytes(&prod)[0], 35, "5*7");

        let sum = asm::fe64_add(&five, &seven);
        assert_eq!(asm::fe64_tobytes(&sum)[0], 12, "5+7");

        let diff = asm::fe64_sub(&seven, &five);
        assert_eq!(asm::fe64_tobytes(&diff)[0], 2, "7-5");

        let sq = asm::fe64_sqr(&two);
        assert_eq!(asm::fe64_tobytes(&sq)[0], 4, "2^2");

        // 5 * 121666 stays far below 2^255-19, so tobytes passes it through.
        let m = asm::fe64_mul121666(&five);
        assert_eq!(
            u64::from_le_bytes(asm::fe64_tobytes(&m)[..8].try_into().unwrap()),
            5 * 121666
        );
    }

    #[test]
    fn fe64_ops_match_bigint_reference() {
        let modulus = {
            // 2^255 - 19 as big-endian bytes for Bn: 0x7fff..ffed.
            let mut m = [0xffu8; 32];
            m[0] = 0x7f;
            m[31] = 0xed;
            m
        };
        let p = crate::bn::Bn::from_be_bytes(&modulus);
        let fe64_bytes = |x: u64| {
            let mut v = [0u8; 32];
            v[..8].copy_from_slice(&x.to_le_bytes());
            v
        };

        for n in 1..6u64 {
            let mut a_raw = [0u64; 4];
            let mut b_raw = [0u64; 4];
            let mut x = n.wrapping_mul(0x9e3779b97f4a7c15) | 1;
            for limb in a_raw.iter_mut().chain(b_raw.iter_mut()) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *limb = x;
            }
            // keep operands below 2^255 so the sub expectation stays
            // representable without an extra reduction
            a_raw[3] &= 0x7fff_ffff_ffff_ffff;
            b_raw[3] &= 0x7fff_ffff_ffff_ffff;

            // fe64 limbs are little-endian; reverse into a big-endian
            // byte string for Bn.
            let fe64_be = |limbs: &[u64; 4]| {
                let mut v = [0u8; 32];
                for i in 0..4 {
                    v[i * 8..i * 8 + 8].copy_from_slice(&limbs[i].to_le_bytes());
                }
                v.reverse();
                v
            };
            let a = crate::bn::Bn::from_be_bytes(&fe64_be(&a_raw));
            let b = crate::bn::Bn::from_be_bytes(&fe64_be(&b_raw));

            // fe64_tobytes emits little-endian bytes; Bn serializes big-endian.
            let be_bytes = |v: &crate::bn::Bn| {
                let mut b = v.to_be_bytes_padded(32).unwrap();
                b.reverse();
                b
            };

            let prod = asm::fe64_mul(&a_raw, &b_raw);
            let encoded = asm::fe64_tobytes(&prod);
            let want = a.mul(&b).modulus(&p);
            assert_eq!(encoded.to_vec(), be_bytes(&want), "mul n={n}");

            let sum = asm::fe64_add(&a_raw, &b_raw);
            let encoded = asm::fe64_tobytes(&sum);
            let want = a.add(&b).modulus(&p);
            assert_eq!(encoded.to_vec(), be_bytes(&want), "add n={n}");

            let diff = asm::fe64_sub(&a_raw, &b_raw);
            let encoded = asm::fe64_tobytes(&diff);
            let want = if a.lt(&b) {
                a.add(&p).sub(&b).unwrap()
            } else {
                a.sub(&b).unwrap()
            };
            assert_eq!(encoded.to_vec(), be_bytes(&want), "sub n={n}");
        }
        let _ = fe64_bytes;
    }

    #[test]
    fn fe64_eligible_runs() {
        // Just exercises the CPUID probe; either answer is valid.
        let _ = asm::fe64_eligible();
    }
}
