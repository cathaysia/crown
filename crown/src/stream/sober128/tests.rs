use super::*;

#[test]
fn test_sober128_libtomcrypt_vector() {
    let key = hex::decode("74657374206b65792031323862697473").unwrap();
    let iv = hex::decode("00000000").unwrap();
    let expected_keystream = hex::decode("43500ccf89919f1daa377495f4b458c240378bbb").unwrap();

    let mut cipher = Sober128::new(&key).unwrap();
    cipher.set_iv(&iv).unwrap();

    let mut keystream = vec![0u8; expected_keystream.len()];
    cipher.xor_key_stream(&mut keystream).unwrap();

    assert_eq!(keystream, expected_keystream);
}

#[test]
fn test_sober128_incremental() {
    let key = hex::decode("74657374206b65792031323862697473").unwrap();
    let iv = hex::decode("00000000").unwrap();
    let expected_keystream = hex::decode("43500ccf89919f1daa377495f4b458c240378bbb").unwrap();

    let mut cipher = Sober128::new(&key).unwrap();
    cipher.set_iv(&iv).unwrap();

    let mut keystream = vec![0u8; expected_keystream.len()];
    // Process 1 byte at a time
    for i in 0..keystream.len() {
        cipher.xor_key_stream(&mut keystream[i..i + 1]).unwrap();
    }

    assert_eq!(keystream, expected_keystream);
}
