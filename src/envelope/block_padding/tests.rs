use super::*;

#[test]
fn test_aes_cbc() {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let mut iv = [0u8; 16];
    rand::fill(&mut iv);
    let mut cipher = EvpBlockCipher::new_aes_cbc(&key, &iv).unwrap();

    for _ in 0..1000 {
        let len = rand::random_range(1..1000);
        let mut plaintext = vec![0u8; len];
        rand::fill(plaintext.as_mut_slice());

        let mut ciphertext = plaintext.clone();
        cipher.encrypt_alloc(&mut ciphertext).unwrap();
        cipher.decrypt_alloc(&mut ciphertext).unwrap();
        assert_eq!(plaintext, ciphertext);
    }
}
