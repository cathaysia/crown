use super::*;
use crate::block::aes::Aes;
use crate::block::sm4::Sm4;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// AES XTS test vectors from IEEE Std 1619-2007 (OpenSSL evpciph_aes_common.txt).
// The all-zero-key IEEE vector is excluded: K1 == K2 is rejected by
// construction (see rejects_invalid_inputs).
#[test]
fn aes_xts_ieee1619() {
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "1111111111111111111111111111111122222222222222222222222222222222",
            "33333333330000000000000000000000",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
        ),
        (
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
            "33333333330000000000000000000000",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
        ),
        (
            "2718281828459045235360287471352631415926535897932384626433832795",
            "00000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412",
        ),
    ];

    for (key, iv, pt, ct) in cases {
        let key = hex_to_bytes(key);
        let iv = hex_to_bytes(iv);
        let pt = hex_to_bytes(pt);
        let ct = hex_to_bytes(ct);

        let xts = Xts::<Aes>::new(&key).unwrap();
        let mut buf = pt.clone();
        xts.encrypt(&iv, &mut buf).unwrap();
        assert_eq!(buf, ct, "encrypt failed for key {key:02x?}");

        xts.decrypt(&iv, &mut buf).unwrap();
        assert_eq!(buf, pt, "decrypt failed for key {key:02x?}");
    }
}

// Non-standard AES-128-XTS vectors exercising ciphertext stealing for data
// units of 33, 49, 65 and 81 bytes.
#[test]
fn aes_xts_ciphertext_stealing() {
    let key = hex_to_bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0");
    let iv = hex_to_bytes("9a785634120000000000000000000000");
    let cases: &[(&str, &str)] = &[
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
            "edbf9dace45d6f6a7306e64be5dd824b9dc31efeb418c373ce073b66755529982538",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
            "edbf9dace45d6f6a7306e64be5dd824b2538f5724fcf24249ac111ab45ad39237a709959673bd8747d58690f8c762a353ad6",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
            "edbf9dace45d6f6a7306e64be5dd824b2538f5724fcf24249ac111ab45ad39233ad6183c66fa548a3cdf3e36d2b21ccde9ffb48286ec211619e02decc7ca0883c6",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051",
            "edbf9dace45d6f6a7306e64be5dd824b2538f5724fcf24249ac111ab45ad39233ad6183c66fa548a3cdf3e36d2b21ccdc6bc657cb3aeb87ba2c5f58ffafacd765ecc4c85c0a01bf317b823fbd6111956d0a0",
        ),
    ];

    for (pt, ct) in cases {
        let pt = hex_to_bytes(pt);
        let ct = hex_to_bytes(ct);
        let xts = Xts::<Aes>::new(&key).unwrap();

        let mut buf = pt.clone();
        xts.encrypt(&iv, &mut buf).unwrap();
        assert_eq!(buf, ct);

        xts.decrypt(&iv, &mut buf).unwrap();
        assert_eq!(buf, pt);
    }
}

// SM4-XTS vectors from GB/T 17964-2021 and the IEEE Std 1619-2007 variant
// (OpenSSL evpciph_sm4.txt).
#[test]
fn sm4_xts() {
    let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f");
    let iv = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let pt = hex_to_bytes(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17",
    );

    let xts = Xts::<Sm4>::new(&key).unwrap();

    let mut buf = pt.clone();
    xts.encrypt(&iv, &mut buf).unwrap();
    assert_eq!(
        buf,
        hex_to_bytes(
            "e9538251c71d7b80bbe4483fef497bd1b3db1a3e60408c575d63ff7db39f83260869f9e2585fec9f0b863bf8fd784b8627d16c0db6d2cfc7"
        )
    );

    xts.decrypt(&iv, &mut buf).unwrap();
    assert_eq!(buf, pt);

    let mut buf = pt;
    xts.encrypt_gb(&iv, &mut buf).unwrap();
    assert_eq!(
        buf,
        hex_to_bytes(
            "e9538251c71d7b80bbe4483fef497bd12c5c581bd6242fc51e08964fb4f60fdb0ba42f63499279213d318d2c11f6886e903be7f93a1b3479"
        )
    );
}

// SM4-XTS with a 17-byte data unit (16 + 1 stolen byte). The recipe does not
// set XTSStandard, so it exercises the default GB path.
#[test]
fn sm4_xts_stealing() {
    let key = hex_to_bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0");
    let iv = hex_to_bytes("9a785634120000000000000000000000");
    let pt = hex_to_bytes("000102030405060708090a0b0c0d0e0f10");
    let ct = hex_to_bytes("9e52443a35410ca0ba5637b94c0766f469");

    let xts = Xts::<Sm4>::new(&key).unwrap();
    let mut buf = pt.clone();
    xts.encrypt_gb(&iv, &mut buf).unwrap();
    assert_eq!(buf, ct);

    xts.decrypt_gb(&iv, &mut buf).unwrap();
    assert_eq!(buf, pt);
}

#[test]
fn rejects_invalid_inputs() {
    // AES-192-XTS does not exist upstream: 48-byte keys are rejected.
    assert!(Xts::<Aes>::new(&[0u8; 48]).is_err());
    // The two key halves must differ.
    assert!(Xts::<Aes>::new(&[0u8; 32]).is_err());
    assert!(Xts::<Sm4>::new(&[7u8; 32]).is_err());
    assert!(Xts::<Sm4>::new(&[0u8; 48]).is_err());
    assert!(Xts::<Sm4>::new(&[0u8; 31]).is_err());

    let xts = Xts::<Aes>::new(&hex_to_bytes(
        "0101010101010101010101010101010102020202020202020202020202020202",
    ))
    .unwrap();

    // Data units shorter than one block and wrong tweak sizes are rejected.
    let mut short = [0u8; 15];
    assert!(xts.encrypt(&[0u8; 16], &mut short).is_err());
    let mut block = [0u8; 16];
    assert!(xts.encrypt(&[0u8; 15], &mut block).is_err());
}

#[test]
fn rejects_oversized_data_unit() {
    let key = hex_to_bytes("0101010101010101010101010101010102020202020202020202020202020202");
    let xts = Xts::<Aes>::new(&key).unwrap();
    let iv = [0u8; 16];
    let mut buf = alloc::vec::Vec::new();

    // 2^20 blocks exactly is allowed.
    buf.resize((1 << 20) * 16, 0);
    assert!(xts.encrypt(&iv, &mut buf).is_ok());

    buf.resize((1 << 20) * 16 + 1, 0);
    assert!(xts.encrypt(&iv, &mut buf).is_err());
}
