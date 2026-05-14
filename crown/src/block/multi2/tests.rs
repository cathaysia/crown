use super::*;
use crate::block::BlockCipher;

#[test]
fn test_multi2_vector1() {
    // Vector 1 (128 rounds)
    let key_hex =
        "00000000000000000000000000000000000000000000000000000000000000000123456789ABCDEF";
    let pt_hex = "0000000000000001";
    let ct_expected_hex = "F89440845E11CF89";

    let key = hex::decode(key_hex).unwrap();
    let pt = hex::decode(pt_hex).unwrap();

    let cipher = Multi2::new(&key, None).unwrap();
    let mut block = pt.clone();

    cipher.encrypt_block(&mut block);
    assert_eq!(hex::encode(&block).to_uppercase(), ct_expected_hex);

    cipher.decrypt_block(&mut block);
    assert_eq!(block, pt);
}

#[test]
fn test_multi2_vector2() {
    // Vector 2 (216 rounds)
    let key_hex =
        "35919D960702E2CE8D0B583CC9C89D59A2AE964E878245ED3F2E62D63635D067B127B906E7562238";
    let pt_hex = "1FB46060D0B34FA5";
    let ct_expected_hex = "CA84A93475C860E5";

    let key = hex::decode(key_hex).unwrap();
    let pt = hex::decode(pt_hex).unwrap();

    let cipher = Multi2::new(&key, Some(216)).unwrap();
    let mut block = pt.clone();

    cipher.encrypt_block(&mut block);
    assert_eq!(hex::encode(&block).to_uppercase(), ct_expected_hex);

    cipher.decrypt_block(&mut block);
    assert_eq!(block, pt);
}
