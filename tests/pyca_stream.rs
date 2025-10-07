mod utils;

use kittycrypto::{envelope::EvpStreamCipher, error::CryptoResult};

use crate::utils::parse_response_line;

#[test]
fn test_pyca_stream_vectors() {
    const BASE_DIR: &str = "tests/cryptography/vectors/cryptography_vectors/";
    #[rustfmt::skip]
    const FILES: [(fn (key:&[u8], iv:&[u8])->CryptoResult<EvpStreamCipher>, &str); 128] = [
        (EvpStreamCipher::new_chacha20, "ciphers/ChaCha20/counter-overflow.txt"),
        (EvpStreamCipher::new_chacha20, "ciphers/ChaCha20/rfc7539.txt"),
        (EvpStreamCipher::new_aes_ctr, "ciphers/AES/CTR/aes-128-ctr.txt"),
        (EvpStreamCipher::new_aes_ctr, "ciphers/AES/CTR/aes-192-ctr.txt"),
        (EvpStreamCipher::new_aes_ctr, "ciphers/AES/CTR/aes-256-ctr.txt"),
        (EvpStreamCipher::new_cast5_ctr, "ciphers/CAST5/cast5-ctr.txt"),
        // CFB
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB1invperm.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB1MMT1.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB1MMT2.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB1MMT3.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB1permop.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB1subtab.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB1varkey.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB1vartext.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64invperm.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64MMT1.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64MMT2.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64MMT3.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64permop.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64subtab.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64varkey.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64vartext.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB8invperm.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB8MMT1.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB8MMT2.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB8MMT3.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB8permop.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB8subtab.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB8varkey.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB8vartext.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP1invperm.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP1MMT1.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP1MMT2.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP1MMT3.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP1permop.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP1subtab.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP1varkey.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP1vartext.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64invperm.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64MMT1.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64MMT2.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64MMT3.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64permop.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64subtab.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64varkey.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64vartext.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP8invperm.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP8MMT1.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP8MMT2.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP8MMT3.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP8permop.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP8subtab.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP8varkey.rsp"),
        (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP8vartext.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128GFSbox128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128GFSbox192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128GFSbox256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128KeySbox128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128KeySbox192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128KeySbox256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128MMT128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128MMT192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128MMT256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128VarKey128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128VarKey192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128VarKey256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128VarTxt128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128VarTxt192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB128VarTxt256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1GFSbox128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1GFSbox192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1GFSbox256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1KeySbox128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1KeySbox192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1KeySbox256.rsp"),
        // (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1MMT128.rsp"),
        // (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1MMT192.rsp"),
        // (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1MMT256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1VarKey128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1VarKey192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1VarKey256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1VarTxt128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1VarTxt192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB1VarTxt256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8GFSbox128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8GFSbox192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8GFSbox256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8KeySbox128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8KeySbox192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8KeySbox256.rsp"),
        // (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8MMT128.rsp"),
        // (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8MMT192.rsp"),
        // (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8MMT256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8VarKey128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8VarKey192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8VarKey256.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8VarTxt128.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8VarTxt192.rsp"),
        (EvpStreamCipher::new_aes_cfb,"ciphers/AES/CFB/CFB8VarTxt256.rsp"),
        (EvpStreamCipher::new_blowfish_cfb, "ciphers/Blowfish/bf-cfb.txt"),
        // (|key: &[u8], iv: &[u8]| ->CryptoResult<EvpStreamCipher> { EvpStreamCipher::new_camellia_cfb (key, iv, None)} , "ciphers/Camellia/camellia-cfb.txt"),
        (EvpStreamCipher::new_cast5_cfb, "ciphers/CAST5/cast5-cfb.txt"),
        // (EvpStreamCipher::new_idea_cfb, "ciphers/IDEA/idea-cfb.txt"),
        // (EvpStreamCipher::new_seed_cfb, "ciphers/SEED/seed-cfb.txt"),
        // (EvpStreamCipher::new_blowfish_cfb, "ciphers/SM4/draft-ribose-cfrg-sm4-10-cfb.txt"),
        // OFB
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIinvperm.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIMMT1.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIMMT2.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIMMT3.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBinvperm.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIpermop.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIsubtab.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIvarkey.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIvartext.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBMMT1.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBMMT2.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBMMT3.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBpermop.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBsubtab.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBvarkey.rsp"),
        (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBvartext.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBGFSbox128.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBGFSbox192.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBGFSbox256.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBKeySbox128.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBKeySbox192.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBKeySbox256.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBMMT128.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBMMT192.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBMMT256.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarKey128.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarKey192.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarKey256.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarTxt128.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarTxt192.rsp"),
        (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarTxt256.rsp"),
        (EvpStreamCipher::new_blowfish_ofb, "ciphers/Blowfish/bf-ofb.txt"),
        // (EvpStreamCipher::new_camellia_ofb, "ciphers/Camellia/camellia-ofb.txt"),
        (EvpStreamCipher::new_cast5_ofb, "ciphers/CAST5/cast5-ofb.txt"),
        // (EvpStreamCipher::new_idea_ofb, "ciphers/IDEA/idea-ofb.txt"),
        // (EvpStreamCipher::new_seed_ofb, "ciphers/SEED/seed-ofb.txt"),
        // (EvpStreamCipher::new_sm4_ofb, "ciphers/SM4/draft-ribose-cfrg-sm4-10-ofb.txt"),
    ];

    for (newer, filename) in FILES {
        let content = std::fs::read_to_string(format!("{BASE_DIR}/{filename}")).unwrap();
        let mut lines = content.lines();

        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("COUNT = ") {
                let mut key = None;
                let mut plaintext = None;
                let mut expected_ciphertext = None;
                let mut iv = None;

                for line in lines.by_ref() {
                    let line = line.trim();
                    if line.is_empty() {
                        break;
                    }
                    if line.starts_with('#') {
                        continue;
                    }
                    let Ok((rkey, value)) = parse_response_line(line) else {
                        eprintln!("parse response line failed: {line}");
                        continue;
                    };

                    match rkey.as_str() {
                        "key" => {
                            key = Some(value);
                        }
                        "plaintext" => {
                            plaintext = Some(value);
                        }
                        "ciphertext" => {
                            expected_ciphertext = Some(value);
                        }
                        "iv" => {
                            iv = Some(value);
                        }
                        _ => {
                            eprintln!("unexpected key: {rkey}");
                        }
                    }
                }

                if let (Some(key), Some(mut plaintext), Some(expected_ciphertext), Some(iv)) =
                    (key, plaintext, expected_ciphertext, iv)
                {
                    let mut cipher = newer(&key, &iv).unwrap();

                    cipher.encrypt(&mut plaintext).unwrap();
                    let result_ciphertext = plaintext;

                    assert_eq!(
                        result_ciphertext,
                        expected_ciphertext,
                        "ctr test failed for {}: expected {}, got {}",
                        filename,
                        hex::encode(&expected_ciphertext),
                        hex::encode(&result_ciphertext)
                    );

                    // println!("test {filename} success!");
                }
            }
        }
    }
}
