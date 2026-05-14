use super::*;

#[test]
fn test_khazad_nessie_set1_0() {
    let key = hex::decode("80000000000000000000000000000000").unwrap();
    let pt = hex::decode("0000000000000000").unwrap();
    let expected_ct = hex::decode("49A4CE32AC190E3F").unwrap();

    let cipher = Khazad::new(&key).unwrap();
    let mut block = pt.clone();
    cipher.encrypt_block(&mut block);
    assert_eq!(block, expected_ct, "Encryption failed");

    cipher.decrypt_block(&mut block);
    assert_eq!(block, pt, "Decryption failed");
}

#[test]
fn test_khazad_nessie_set1_7() {
    let key = hex::decode("01000000000000000000000000000000").unwrap();
    let pt = hex::decode("0000000000000000").unwrap();
    let expected_ct = hex::decode("37F1F5997C673921").unwrap();

    let cipher = Khazad::new(&key).unwrap();
    let mut block = pt.clone();
    cipher.encrypt_block(&mut block);
    assert_eq!(block, expected_ct, "Encryption failed");

    cipher.decrypt_block(&mut block);
    assert_eq!(block, pt, "Decryption failed");
}

#[test]
fn test_khazad_nessie_set2_0() {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let pt = hex::decode("8000000000000000").unwrap();
    let expected_ct = hex::decode("9E399864F78ECA02").unwrap();

    let cipher = Khazad::new(&key).unwrap();
    let mut block = pt.clone();
    cipher.encrypt_block(&mut block);
    assert_eq!(block, expected_ct, "Encryption failed");

    cipher.decrypt_block(&mut block);
    assert_eq!(block, pt, "Decryption failed");
}

#[test]
fn test_khazad_nessie_set2_1() {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let pt = hex::decode("4000000000000000").unwrap();
    let expected_ct = hex::decode("3EABB25778098FF7").unwrap();

    let cipher = Khazad::new(&key).unwrap();
    let mut block = pt.clone();
    cipher.encrypt_block(&mut block);
    assert_eq!(block, expected_ct, "Encryption failed");

    cipher.decrypt_block(&mut block);
    assert_eq!(block, pt, "Decryption failed");
}

#[test]
fn test_khazad_nessie_set3_1() {
    let key = hex::decode("01010101010101010101010101010101").unwrap();
    let pt = hex::decode("0101010101010101").unwrap();
    let expected_ct = hex::decode("3D666F991262FD70").unwrap();

    let cipher = Khazad::new(&key).unwrap();
    let mut block = pt.clone();
    cipher.encrypt_block(&mut block);
    assert_eq!(block, expected_ct, "Encryption failed");

    cipher.decrypt_block(&mut block);
    assert_eq!(block, pt, "Decryption failed");
}
