#![no_main]

use arbitrary::Arbitrary;
use crown::core::CoreWrite;
use crown::envelope::{EvpAeadCipher, EvpBlockCipher, EvpHash, EvpStreamCipher};
use libfuzzer_sys::fuzz_target;

macro_rules! define_fuzz_actions {
    (
        hashes: [$($hash:ident),*],
        hashes_var: [$($hash_var:ident),*],
        aead_gcm: [$($aead_gcm:ident),*],
        aead_ccm: [$($aead_ccm:ident),*],
        aead_special: [$($aead_special:ident),*],
        block_cbc: [$($block_cbc:ident),*],
        block_cbc_rounds: [$($block_cbc_rounds:ident),*],
        stream_cfb: [$($stream_cfb:ident),*],
        stream_ctr: [$($stream_ctr:ident),*],
        stream_ofb: [$($stream_ofb:ident),*],
        stream_special_rc4: [$($stream_special_rc4:ident),*],
        stream_special_iv: [$($stream_special_iv:ident),*]
    ) => {
        paste::paste! {
            #[derive(Arbitrary, Debug)]
            #[allow(non_camel_case_types)]
            enum FuzzAction {
                $(
                    [<Hash $hash>] { data: Vec<u8> },
                )*
                $(
                    [<Hash $hash_var>] {
                        data: Vec<u8>,
                        key: Option<Vec<u8>>,
                        key_len: u8,
                    },
                )*
                $(
                    [<$aead_gcm Gcm>] {
                        key: Vec<u8>,
                        nonce: Vec<u8>,
                        data: Vec<u8>,
                        aad: Vec<u8>,
                    },
                )*
                $(
                    [<$aead_ccm Ccm>] {
                        key: Vec<u8>,
                        nonce: [u8; 12],
                        data: Vec<u8>,
                        aad: Vec<u8>,
                    },
                )*
                $(
                    [<$aead_special>] {
                        key: Vec<u8>,
                        nonce: Vec<u8>,
                        data: Vec<u8>,
                        aad: Vec<u8>,
                    },
                )*
                $(
                    [<$block_cbc Cbc>] {
                        key: Vec<u8>,
                        iv: Vec<u8>,
                        data: Vec<u8>,
                    },
                )*
                $(
                    [<$block_cbc_rounds Cbc>] {
                        key: Vec<u8>,
                        iv: Vec<u8>,
                        data: Vec<u8>,
                        rounds: Option<usize>,
                    },
                )*
                $(
                    [<$stream_cfb Cfb>] {
                        key: Vec<u8>,
                        iv: Vec<u8>,
                        data: Vec<u8>,
                    },
                )*
                $(
                    [<$stream_ctr Ctr>] {
                        key: Vec<u8>,
                        iv: Vec<u8>,
                        data: Vec<u8>,
                    },
                )*
                $(
                    [<$stream_ofb Ofb>] {
                        key: Vec<u8>,
                        iv: Vec<u8>,
                        data: Vec<u8>,
                    },
                )*
                $(
                    [<$stream_special_rc4>] {
                        key: Vec<u8>,
                        data: Vec<u8>,
                    },
                )*
                $(
                    [<$stream_special_iv>] {
                        key: Vec<u8>,
                        iv: Vec<u8>,
                        data: Vec<u8>,
                    },
                )*
            }

            fuzz_target!(|action: FuzzAction| {
                match action {
                    $(
                        FuzzAction::[<Hash $hash>] { data } => {
                            if let Ok(mut hasher) = EvpHash::[<new_ $hash:lower>]() {
                                let _ = hasher.write(&data);
                                let _ = hasher.sum();
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<Hash $hash_var>] { data, key, key_len } => {
                            let k = key.as_deref();
                            if let Ok(mut hasher) = EvpHash::[<new_ $hash_var:lower>](k, key_len as usize) {
                                let _ = hasher.write(&data);
                                let _ = hasher.sum();
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$aead_gcm Gcm>] { key, nonce, data, aad } => {
                            if let Ok(cipher) = EvpAeadCipher::[<new_ $aead_gcm:lower _gcm>](&key) {
                                let mut data_clone = data.clone();
                                if let Ok(tag) = cipher.seal_in_place_separate_tag(&mut data_clone, &nonce, &aad) {
                                    let mut decrypted = data_clone.clone();
                                    let res = cipher.open_in_place_separate_tag(&mut decrypted, &tag, &nonce, &aad);
                                    if res.is_ok() {
                                        assert_eq!(data, decrypted);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$aead_ccm Ccm>] { key, nonce, data, aad } => {
                            if let Ok(cipher) = EvpAeadCipher::[<new_ $aead_ccm:lower _ccm>]::<16, 12>(&key) {
                                let mut data_clone = data.clone();
                                if let Ok(tag) = cipher.seal_in_place_separate_tag(&mut data_clone, &nonce, &aad) {
                                    let mut decrypted = data_clone.clone();
                                    let res = cipher.open_in_place_separate_tag(&mut decrypted, &tag, &nonce, &aad);
                                    if res.is_ok() {
                                        assert_eq!(data, decrypted);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$aead_special>] { key, nonce, data, aad } => {
                            if let Ok(cipher) = EvpAeadCipher::[<new_ $aead_special:lower>](&key) {
                                let mut data_clone = data.clone();
                                if let Ok(tag) = cipher.seal_in_place_separate_tag(&mut data_clone, &nonce, &aad) {
                                    let mut decrypted = data_clone.clone();
                                    let res = cipher.open_in_place_separate_tag(&mut decrypted, &tag, &nonce, &aad);
                                    if res.is_ok() {
                                        assert_eq!(data, decrypted);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$block_cbc Cbc>] { key, iv, data } => {
                            if let Ok(mut cipher) = EvpBlockCipher::[<new_ $block_cbc:lower _cbc>](&key, &iv) {
                                let mut inout = data.clone();
                                if cipher.encrypt_alloc(&mut inout).is_ok() {
                                    if let Ok(mut dec_cipher) = EvpBlockCipher::[<new_ $block_cbc:lower _cbc>](&key, &iv) {
                                        let _ = dec_cipher.decrypt_alloc(&mut inout);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$block_cbc_rounds Cbc>] { key, iv, data, rounds } => {
                            if let Ok(mut cipher) = EvpBlockCipher::[<new_ $block_cbc_rounds:lower _cbc>](&key, &iv, rounds) {
                                let mut inout = data.clone();
                                if cipher.encrypt_alloc(&mut inout).is_ok() {
                                    if let Ok(mut dec_cipher) = EvpBlockCipher::[<new_ $block_cbc_rounds:lower _cbc>](&key, &iv, rounds) {
                                        let _ = dec_cipher.decrypt_alloc(&mut inout);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$stream_cfb Cfb>] { key, iv, data } => {
                            if let Ok(mut cipher) = EvpStreamCipher::[<new_ $stream_cfb:lower _cfb>](&key, &iv) {
                                let mut inout = data.clone();
                                if cipher.encrypt(&mut inout).is_ok() {
                                    if let Ok(mut dec_cipher) = EvpStreamCipher::[<new_ $stream_cfb:lower _cfb>](&key, &iv) {
                                        let _ = dec_cipher.decrypt(&mut inout);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$stream_ctr Ctr>] { key, iv, data } => {
                            if let Ok(mut cipher) = EvpStreamCipher::[<new_ $stream_ctr:lower _ctr>](&key, &iv) {
                                let mut inout = data.clone();
                                if cipher.encrypt(&mut inout).is_ok() {
                                    if let Ok(mut dec_cipher) = EvpStreamCipher::[<new_ $stream_ctr:lower _ctr>](&key, &iv) {
                                        let _ = dec_cipher.decrypt(&mut inout);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$stream_ofb Ofb>] { key, iv, data } => {
                            if let Ok(mut cipher) = EvpStreamCipher::[<new_ $stream_ofb:lower _ofb>](&key, &iv) {
                                let mut inout = data.clone();
                                if cipher.encrypt(&mut inout).is_ok() {
                                    if let Ok(mut dec_cipher) = EvpStreamCipher::[<new_ $stream_ofb:lower _ofb>](&key, &iv) {
                                        let _ = dec_cipher.decrypt(&mut inout);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$stream_special_rc4>] { key, data } => {
                            if let Ok(mut cipher) = EvpStreamCipher::[<new_ $stream_special_rc4:lower>](&key) {
                                let mut inout = data.clone();
                                if cipher.encrypt(&mut inout).is_ok() {
                                    if let Ok(mut dec_cipher) = EvpStreamCipher::[<new_ $stream_special_rc4:lower>](&key) {
                                        let _ = dec_cipher.decrypt(&mut inout);
                                    }
                                }
                            }
                        }
                    )*
                    $(
                        FuzzAction::[<$stream_special_iv>] { key, iv, data } => {
                            if let Ok(mut cipher) = EvpStreamCipher::[<new_ $stream_special_iv:lower>](&key, &iv) {
                                let mut inout = data.clone();
                                if cipher.encrypt(&mut inout).is_ok() {
                                    if let Ok(mut dec_cipher) = EvpStreamCipher::[<new_ $stream_special_iv:lower>](&key, &iv) {
                                        let _ = dec_cipher.decrypt(&mut inout);
                                    }
                                }
                            }
                        }
                    )*
                }
            });
        }
    };
}

define_fuzz_actions!(
    hashes: [
        Md2, Md4, Md5, Sha1, Sha224, Sha256, Sha384, Sha512,
        Sha512_224, Sha512_256, Sha3_224, Sha3_256, Sha3_384, Sha3_512,
        Shake128, Shake256, Sm3
    ],
    hashes_var: [
        Blake2s, Blake2b
    ],
    aead_gcm: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack, Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent
    ],
    aead_ccm: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack, Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent
    ],
    aead_special: [
        ChaCha20_Poly1305, XChaCha20_Poly1305
    ],
    block_cbc: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack, Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent
    ],
    block_cbc_rounds: [
        Rc2, Rc5, Camellia, Multi2
    ],
    stream_cfb: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack, Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent
    ],
    stream_ctr: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack, Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent
    ],
    stream_ofb: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack, Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent
    ],
    stream_special_rc4: [
        Rc4
    ],
    stream_special_iv: [
        Salsa20, Chacha20, Rabbit, Sosemanuk, Sober128
    ]
);
