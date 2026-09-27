//! Golden vectors for the modes that have no `Evp*` envelope surface: XTS,
//! AES-SIV, ECB and the RC4 stream cipher, from the pyca/cryptography tree.

mod utils;

use crown::block::aes::Aes;
use crown::modes::xts::Xts;
use crown::stream::StreamCipher;
use utils::{parse_vectors, read_pyca};

/// XTS: `Key`, `i` (either a 128-bit tweak or a decimal data unit sequence
/// number) and `PT`/`CT` pairs.
#[test]
fn test_pyca_xts() {
    let mut checked = 0usize;

    for file in [
        "ciphers/AES/XTS/tweak-128hexstr/XTSGenAES128.rsp",
        "ciphers/AES/XTS/tweak-128hexstr/XTSGenAES256.rsp",
        "ciphers/AES/XTS/tweak-dataunitseqno/XTSGenAES128.rsp",
        "ciphers/AES/XTS/tweak-dataunitseqno/XTSGenAES256.rsp",
    ] {
        let seqno_tweaks = file.contains("dataunitseqno");
        for v in parse_vectors(&read_pyca(file)) {
            let (Some(key), Some(pt), Some(ct)) =
                (v.field(&["key"]), v.field(&["pt"]), v.field(&["ct"]))
            else {
                continue;
            };
            let tweak = if seqno_tweaks {
                // IEEE 1619 stores the data unit sequence number little-endian.
                let Some(n) = v.int_field(&["i"]) else {
                    continue;
                };
                let mut t = [0u8; 16];
                t[..8].copy_from_slice(&n.to_le_bytes());
                t.to_vec()
            } else {
                match v.field(&["i"]) {
                    Some(t) if t.len() == 16 => t.to_vec(),
                    _ => continue,
                }
            };
            // The CAVS generator reports data unit lengths in bits, some of
            // which are not byte aligned (130, 250); crown's XTS is
            // byte-oriented, so only whole-byte units can be checked.
            let Some(unit_bits) = v.int_field(&["dataunitlen"]) else {
                continue;
            };
            if unit_bits % 8 != 0 || unit_bits as usize / 8 != pt.len() {
                continue;
            }

            let cipher = Xts::<Aes>::new(key).unwrap();

            let mut buf = pt.to_vec();
            cipher.encrypt(&tweak, &mut buf).unwrap();
            assert_eq!(
                hex::encode(&buf),
                hex::encode(ct),
                "{file}: XTS encrypt with key {}",
                hex::encode(key)
            );

            let mut buf = ct.to_vec();
            cipher.decrypt(&tweak, &mut buf).unwrap();
            assert_eq!(hex::encode(&buf), hex::encode(pt), "{file}: XTS decrypt");
            checked += 1;
        }
    }

    assert!(checked > 100, "only {checked} XTS vectors were verified");
}

/// AES-SIV: the tag is a separate field and up to three AADs are chained.
#[test]
fn test_pyca_siv() {
    use crown::aead::siv::AesSiv;

    let mut checked = 0usize;
    for v in parse_vectors(&read_pyca("ciphers/AES/SIV/openssl.txt")) {
        let (Some(key), Some(pt), Some(ct), Some(tag)) = (
            v.field(&["key"]),
            v.field(&["plaintext"]),
            v.field(&["ciphertext"]),
            v.field(&["tag"]),
        ) else {
            continue;
        };
        let aads: Vec<&[u8]> = ["aad", "aad2", "aad3"]
            .iter()
            .filter_map(|n| v.field(&[*n]))
            .collect();

        let mut siv = AesSiv::new(key).unwrap();

        let mut buf = pt.to_vec();
        let computed = siv.seal_in_place(&mut buf, &aads).unwrap();
        assert_eq!(
            hex::encode(computed),
            hex::encode(tag),
            "{file}",
            file = "SIV tag"
        );
        assert_eq!(hex::encode(&buf), hex::encode(ct), "SIV ciphertext");

        let mut buf = ct.to_vec();
        siv.open_in_place(&mut buf, tag, &aads).unwrap();
        assert_eq!(hex::encode(&buf), hex::encode(pt), "SIV open");
        checked += 1;
    }

    assert!(checked >= 4, "only {checked} SIV vectors were verified");
}

/// Raw ECB vectors, driven one block at a time (`Aes` deliberately has no
/// `BlockCipherMarker`, so there is no AES `to_ecb`).
#[test]
fn test_pyca_ecb() {
    use crown::block::des::TripleDes;
    use crown::block::sm4::Sm4;
    use crown::block::BlockCipher;
    use crown::modes::ecb::Ecb;
    use crown::modes::BlockMode;

    fn aes_ecb(key: &[u8], pt: &[u8]) -> Vec<u8> {
        let cipher = Aes::new(key).unwrap();
        let mut out = pt.to_vec();
        for block in out.chunks_mut(16) {
            cipher.encrypt_block(block);
        }
        out
    }

    let mut checked = 0usize;

    for (file, tripledes) in [
        ("ciphers/AES/ECB/ECBGFSbox128.rsp", false),
        ("ciphers/AES/ECB/ECBGFSbox192.rsp", false),
        ("ciphers/AES/ECB/ECBGFSbox256.rsp", false),
        ("ciphers/AES/ECB/ECBKeySbox128.rsp", false),
        ("ciphers/AES/ECB/ECBKeySbox192.rsp", false),
        ("ciphers/AES/ECB/ECBKeySbox256.rsp", false),
        ("ciphers/AES/ECB/ECBVarTxt128.rsp", false),
        ("ciphers/AES/ECB/ECBVarTxt192.rsp", false),
        ("ciphers/AES/ECB/ECBVarTxt256.rsp", false),
        ("ciphers/AES/ECB/ECBVarKey128.rsp", false),
        ("ciphers/AES/ECB/ECBVarKey192.rsp", false),
        ("ciphers/AES/ECB/ECBVarKey256.rsp", false),
        ("ciphers/AES/ECB/ECBMMT128.rsp", false),
        ("ciphers/AES/ECB/ECBMMT192.rsp", false),
        ("ciphers/AES/ECB/ECBMMT256.rsp", false),
        ("ciphers/3DES/ECB/TECBinvperm.rsp", true),
        ("ciphers/3DES/ECB/TECBpermop.rsp", true),
        ("ciphers/3DES/ECB/TECBsubtab.rsp", true),
        ("ciphers/3DES/ECB/TECBvarkey.rsp", true),
        ("ciphers/3DES/ECB/TECBvartext.rsp", true),
        ("ciphers/3DES/ECB/TECBMMT1.rsp", true),
        ("ciphers/3DES/ECB/TECBMMT2.rsp", true),
        ("ciphers/3DES/ECB/TECBMMT3.rsp", true),
        ("ciphers/SM4/draft-ribose-cfrg-sm4-10-ecb.txt", false),
    ] {
        for v in parse_vectors(&read_pyca(file)) {
            let Some(key) = v.concat(&["key", "keys"]) else {
                continue;
            };
            let (Some(pt), Some(ct)) = (v.field(&["plaintext"]), v.field(&["ciphertext"])) else {
                continue;
            };

            let computed = if tripledes {
                let key = match key.len() {
                    16 => [&key[..8], &key[8..], &key[..8]].concat(),
                    8 => [&key[..], &key[..], &key[..]].concat(),
                    _ => key.clone(),
                };
                let cipher = TripleDes::new(&key).unwrap();
                let mut mode = cipher.to_ecb().unwrap();
                let mut buf = pt.to_vec();
                mode.encrypt(&mut buf);
                buf
            } else if pt.len() % 16 == 0 && file.contains("SM4") {
                let cipher = Sm4::new(&key).unwrap();
                let mut mode = cipher.to_ecb().unwrap();
                let mut buf = pt.to_vec();
                mode.encrypt(&mut buf);
                buf
            } else {
                aes_ecb(&key, pt)
            };

            assert_eq!(
                hex::encode(&computed),
                hex::encode(ct),
                "{file}: ECB with key {}",
                hex::encode(&key)
            );
            checked += 1;
        }
    }

    assert!(checked > 1500, "only {checked} ECB vectors were verified");
}

/// RC4: the vectors carry the keystream offset to discard first.
#[test]
fn test_pyca_arc4() {
    use crown::stream::rc4::Rc4;

    let mut checked = 0usize;
    for file in [
        "ciphers/ARC4/arc4.txt",
        "ciphers/ARC4/rfc-6229-128.txt",
        "ciphers/ARC4/rfc-6229-192.txt",
        "ciphers/ARC4/rfc-6229-256.txt",
    ] {
        for v in parse_vectors(&read_pyca(file)) {
            let (Some(key), Some(pt), Some(ct), Some(offset)) = (
                v.field(&["key"]),
                v.field(&["plaintext"]),
                v.field(&["ciphertext"]),
                v.int_field(&["offset"]),
            ) else {
                continue;
            };

            let mut cipher = Rc4::new(key).unwrap();
            let mut skip = vec![0u8; offset as usize];
            cipher.xor_key_stream(&mut skip).unwrap();

            let mut buf = pt.to_vec();
            cipher.xor_key_stream(&mut buf).unwrap();
            assert_eq!(
                hex::encode(&buf),
                hex::encode(ct),
                "{file}: RC4 with offset {offset}"
            );
            checked += 1;
        }
    }

    assert!(checked > 30, "only {checked} RC4 vectors were verified");
}
