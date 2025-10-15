use boring::symm::Cipher;
use crown::{envelope::EvpStreamCipher, error::CryptoResult};

fn test_interop<T, F>(new_crown: T, new_boring: F, key_len: usize, iv_len: usize)
where
    T: Fn(&[u8], &[u8]) -> CryptoResult<EvpStreamCipher>,
    F: Fn() -> boring::symm::Cipher,
{
    let mut key = vec![0u8; key_len];
    rand::fill(key.as_mut_slice());
    let key = key.as_slice();
    let mut iv = vec![0u8; iv_len];
    rand::fill(iv.as_mut_slice());
    let iv = iv.as_slice();

    for _ in 0..1000 {
        let len = rand::random_range(12..2048);
        let mut src = vec![0u8; len];
        rand::fill(src.as_mut_slice());

        let this = {
            let mut dst = src.clone();
            let mut cipher = new_crown(key, iv).unwrap();

            cipher.encrypt(&mut dst).unwrap();
            dst
        };

        let rustcrypto = {
            let dst = src;
            let cipher = new_boring();
            boring::symm::encrypt(cipher, key, Some(iv), &dst).unwrap()
        };

        assert_eq!(this, rustcrypto);
    }
}

macro_rules! impl_test_interop {
    (
        $name:ident,
        $crown_fn:path,
        $boring_fn:expr,
        $key_len:expr,
        $iv_len:expr
    ) => {
        paste::paste! {
            #[test]
            fn [<test_ $name>]() {
                test_interop(
                    $crown_fn,
                    $boring_fn,
                    $key_len,
                    $iv_len,
                );
            }
        }
    };
}

impl_test_interop!(
    aes_128_ctr,
    EvpStreamCipher::new_aes_ctr,
    Cipher::aes_128_ctr,
    16,
    16
);

impl_test_interop!(
    aes_192_ctr,
    EvpStreamCipher::new_aes_ctr,
    Cipher::aes_192_ctr,
    24,
    16
);

impl_test_interop!(
    aes_256_ctr,
    EvpStreamCipher::new_aes_ctr,
    Cipher::aes_256_ctr,
    32,
    16
);

fn new_rc4(key: &[u8], _iv: &[u8]) -> CryptoResult<EvpStreamCipher> {
    EvpStreamCipher::new_rc4(key)
}
impl_test_interop!(rc4, new_rc4, Cipher::rc4, 32, 16);
