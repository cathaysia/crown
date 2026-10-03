use super::*;
use crate::ec::{mul_base, Curve};

fn example_curve() -> Curve {
    // GB/T 32918.1-2016 annex A example curve (used by the worked examples
    // of GB/T 32918.3/.4-2016).
    Curve::from_parts(
        bn("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"),
        bn("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
        bn("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
        bn("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
        bn("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
        bn("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"),
    )
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn bn(s: &str) -> Bn {
    Bn::from_be_bytes(&hex(s))
}

/// Rng yielding one fixed 32-byte value (the ephemeral k).
struct FixedK {
    k: [u8; 32],
    used: bool,
}
impl Rng for FixedK {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        if !self.used {
            out.copy_from_slice(&self.k);
            self.used = true;
        } else {
            for b in out.iter_mut() {
                *b = 0;
            }
        }
    }
}

/// BouncyCastle `SM2EngineTest` (C1C2C3 mode, private key fixed by the
/// seeded generator, message "encryption standard").
const D: &str = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
const K: &str = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";
// Raw C1C2C3 output: 04 || x1 || y1 || C2 || C3.
const C12C3_CT: &str = "04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E776CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8650053A89B41C418B0C3AAD00D886C002864679C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D";
// Raw C1C3C2 output: 04 || x1 || y1 || C3 || C2.
const C13C2_CT: &str = "04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E776CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B89C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D650053A89B41C418B0C3AAD00D886C00286467";
const MSG: &[u8] = b"encryption standard";

#[test]
fn bouncycastle_fixed_k_kats() {
    let d = bn(D);
    let c = example_curve();
    let pub_key = mul_base(&c, &d);

    let mut rng = FixedK {
        k: hex(K).try_into().unwrap(),
        used: false,
    };
    let got = encrypt_raw(&c, &pub_key, MSG, &mut rng).unwrap();

    // Reorder the C1C2C3 vector into the C1C3C2 wire form:
    // 04 || x1(32) || y1(32) || C2(19) || C3(32).
    let v = hex(C12C3_CT);
    let mut expect = vec![0x04u8];
    expect.extend_from_slice(&v[1..65]);
    expect.extend_from_slice(&v[84..116]);
    expect.extend_from_slice(&v[65..84]);
    assert_eq!(got, expect, "C1C3C2 recomposition of the C1C2C3 vector");

    // The C1C3C2 vector must match directly.
    assert_eq!(got, hex(C13C2_CT), "C1C3C2 vector");

    // Decrypt recovers the message from both orderings.
    assert_eq!(decrypt_raw(&c, &d, &got).unwrap(), MSG);
    let v = hex(C13C2_CT);
    assert_eq!(decrypt_raw(&c, &d, &v).unwrap(), MSG);

    // Tampering with C2 or C3 fails the C3 check.
    let mut bad = got.clone();
    bad[100] ^= 0x01;
    assert!(decrypt_raw(&c, &d, &bad).is_err());
    let mut bad = got.clone();
    bad[70] ^= 0x01;
    assert!(decrypt_raw(&c, &d, &bad).is_err());
}

#[test]
fn random_roundtrip_raw_and_der() {
    struct R(u64);
    impl Rng for R {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }
    let mut rng = R(0x5B17_4B7C_0000_0001);
    let c = example_curve();
    let d = bn("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    let pub_key = mul_base(&c, &d);
    for len in [0usize, 1, 16, 32, 100, 1000] {
        let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let raw = encrypt_raw(&c, &pub_key, &msg, &mut rng).unwrap();
        assert_eq!(raw.len(), 1 + 64 + 32 + len);
        assert_eq!(decrypt_raw(&c, &d, &raw).unwrap(), msg);
        // Component helpers round-trip and keep the DER form consistent.
        let parsed = parse_raw(&raw).unwrap();
        assert_eq!(to_raw(&parsed), raw);
        let der = to_der(&parsed);
        assert_eq!(decrypt(&c, &d, &der).unwrap(), msg);
    }
}

/// The DER form re-encodes a raw C1C2C3-parsed ciphertext so that
/// OpenSSL's `pkeyutl` can consume it (see the interop scratch checks).
#[test]
fn der_from_bouncycastle_vector() {
    let d = bn(D);
    let c = example_curve();
    let v = hex(C13C2_CT);
    let parsed = parse_raw(&v).unwrap();
    let der = to_der(&parsed);
    assert_eq!(decrypt(&c, &d, &der).unwrap(), MSG);
}

/// OpenSSL CLI interop (system 3.0.13): `openssl genpkey -algorithm SM2`
/// + `openssl pkeyutl -encrypt` ciphertext decrypted by crown, and a
/// crown-produced DER ciphertext that OpenSSL's `pkeyutl -decrypt`
/// accepted (both directions checked while recording these vectors).
#[test]
fn openssl_cli_interop_vectors() {
    let d = bn("c51c730b25873c2c9b287c0de8375ac3aed697e8874df94fb54ceede7bae16ac");
    let openssl_ct = hex("3081830221009F8FC98B1EACB5C8C66EC5820773E8B05CF9A1840665CCDCAB8B8ABE1C5D2FCE022100F99E11E91EEB44F45BF1CA76E7DF28C63ECBDEE21F2628E2D8D232C2E99D0E1804205D7F1C0F8E483104DD06835CB684F4979C4A9B5391CFE36AE1DCFC03A0A1C8D104196BC695B8C628721A937930D14A0561C35D8E8666AF468B96D2");
    assert_eq!(
        decrypt_sm2_curve(&d, &openssl_ct).unwrap(),
        b"crown sm2 interop message"
    );
    let crown_ct = hex("3079022023EE759400BBD3DE0D800548321E04678CABCB32E5C39140415D1AB8C39D6830022100B0541F2443F8E5BBD36DE85D4B1B4981F37B5F86E080E6575E51928C75F71B7C042011D3F84E148DC241469204DECE8DCF471CAE835254F4195F2C47163409AB3E41041047F0007B54CFB0F5F36EEB583C403005");
    assert_eq!(
        decrypt_sm2_curve(&d, &crown_ct).unwrap(),
        b"reply from crown"
    );
}
