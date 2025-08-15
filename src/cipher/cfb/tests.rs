use crate::cipher::{cfb::CfbAble, StreamCipher};

const TEST_CASES: [[&str; 4]; 4] = [
    [
        "2b7e151628aed2a6abf7158809cf4f3c",
        "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172a",
        "3b3fd92eb72dad20333449f8e83cfb4a",
    ],
    [
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3B3FD92EB72DAD20333449F8E83CFB4A",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "c8a64537a0b3a93fcde3cdad9f1ce58b",
    ],
    [
        "2b7e151628aed2a6abf7158809cf4f3c",
        "C8A64537A0B3A93FCDE3CDAD9F1CE58B",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "26751f67a3cbb140b1808cf187a4f4df",
    ],
    [
        "2b7e151628aed2a6abf7158809cf4f3c",
        "26751F67A3CBB140B1808CF187A4F4DF",
        "f69f2445df4f9b17ad2b417be66c3710",
        "c04b05357c5d1c0eeac4c66f9ff7f2e6",
    ],
];

#[test]
fn test_cfb_vectors() {
    use crate::aes;

    for test in TEST_CASES {
        let [key, iv, pt, ct] = test;
        let key = hex::decode(key).unwrap();
        let iv = hex::decode(iv).unwrap();
        let pt = hex::decode(pt).unwrap();
        let ct = hex::decode(ct).unwrap();

        let mut block = aes::Aes::new(&key).unwrap().to_cfb_encrypter(&iv).unwrap();
        let mut dst = pt.to_vec();
        block.xor_key_stream(&mut dst).unwrap();

        assert_eq!(dst, ct);

        let mut block = aes::Aes::new(&key).unwrap().to_cfb_decrypter(&iv).unwrap();
        let mut dst = dst.clone();
        block.xor_key_stream(&mut dst).unwrap();
        assert_eq!(dst, pt);
    }
}
