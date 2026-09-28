use super::*;

// ISO/IEC 10118-3 Whirlpool test vector set (the final Whirlpool version),
// as used by OpenSSL test/recipes/30-test_evp_data/evpmd_whirlpool.txt.
const VECTORS: [(&str, &str); 7] = [
    (
        "",
        "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73\
         E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3",
    ),
    (
        "a",
        "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D\
         11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A",
    ),
    (
        "abc",
        "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7\
         181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5",
    ),
    (
        "message digest",
        "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B8\
         421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E",
    ),
    (
        "abcdefghijklmnopqrstuvwxyz",
        "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B0\
         8BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B",
    ),
    (
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "526B2394D85683E24B29ACD0FD37F7D5027F61366A1407262DC2A6A345D9E240\
         C017C1833DB1E6DB6A46BD444B0C69520C856E7C6E9C366D150A7DA3AEB160D1",
    ),
    (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E0\
         8EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467",
    ),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn iso_10118_3_vectors() {
    for (input, expected) in VECTORS {
        assert_eq!(
            &hex(&sum_whirlpool(input.as_bytes())).to_uppercase(),
            &expected.replace('\n', ""),
            "input={input:?}"
        );
    }
}

#[test]
fn eight_block_message() {
    // 80-byte message "1234567890" * 8.
    let input = "1234567890".repeat(8);
    let tag = sum_whirlpool(input.as_bytes());
    assert_eq!(
        &hex(&tag).to_uppercase(),
        "466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB6014294\
         D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B"
    );
}

#[test]
fn million_a() {
    let tag = {
        let mut h = new_whirlpool();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.write_all(&chunk).unwrap();
        }
        h.sum()
    };
    assert_eq!(
        &hex(&tag).to_uppercase(),
        "0C99005BEB57EFF50A7CF005560DDF5D29057FD86B20BFD62DECA0F1CCEA4AF51\
         FC15490EDDC47AF32BB2B66C34FF9AD8C6008AD677F77126953B226E4ED8B01"
    );
}

#[test]
fn streaming_matches_oneshot() {
    let data: alloc::vec::Vec<u8> = (0..250u32).map(|i| (i * 37 + 11) as u8).collect();
    let expected = sum_whirlpool(&data);

    let mut h = new_whirlpool();
    h.write_all(&data[..13]).unwrap();
    h.write_all(&data[13..127]).unwrap();
    h.write_all(&data[127..]).unwrap();
    assert_eq!(h.sum(), expected);
}

#[test]
fn reset_reuses_state() {
    let mut h = new_whirlpool();
    h.write_all(b"abc").unwrap();
    assert_eq!(h.sum(), sum_whirlpool(b"abc"));

    h.reset();
    h.write_all(b"a").unwrap();
    assert_eq!(h.sum(), sum_whirlpool(b"a"));
}

#[test]
fn block_matches_software() {
    // Compare the dispatching `block` against the portable implementation
    // on the same single-block inputs (exercises the asm path when
    // feature="asm" on x86_64).
    let mut inputs: [[u8; 64]; 11] = [[0u8; 64]; 11];
    inputs[1] = [0xffu8; 64];
    inputs[2][0] = 0x80;
    let mut prng = 0x1234_5678_9abc_def0u64;
    for (case, b) in inputs[3..].iter_mut().enumerate() {
        for slot in b.iter_mut() {
            prng = prng.wrapping_mul(6364136223846793005).wrapping_add(1);
            *slot = (prng >> 33) as u8;
        }
        b[63] ^= case as u8;
    }

    for data in &inputs {
        let mut h_asm = [0u64; 8];
        let mut h_soft = [0u64; 8];
        super::block(&mut h_asm, data);
        super::block_soft(&mut h_soft, data);
        assert_eq!(h_asm, h_soft, "data[..8]={:02x?}", &data[..8]);
    }
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
#[test]
fn asm_multiblock_matches_single() {
    // The asm entry point accepts a block count; feeding N blocks in one
    // call must equal N single-block software compressions chained.
    let mut prng = 0xfeed_face_cafe_beefu64;
    let mut data = [0u8; 64 * 5];
    for slot in data.iter_mut() {
        prng = prng.wrapping_mul(6364136223846793005).wrapping_add(1);
        *slot = (prng >> 33) as u8;
    }

    let mut h_multi = [0u64; 8];
    super::asm::block(&mut h_multi, &data);

    let mut h_single = [0u64; 8];
    for chunk in data.chunks_exact(64) {
        super::block_soft(&mut h_single, chunk);
    }
    assert_eq!(h_multi, h_single);
}
