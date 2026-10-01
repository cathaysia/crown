#![no_main]

//! MAC, XTS, key wrap, FF1, CTS and OTP fuzzing: round trips plus
//! envelope-vs-direct differential checks.

use arbitrary::Arbitrary;
use crown::block::aes::Aes;
use crown::block::sm4::Sm4;
use crown::block::twofish::Twofish;
use crown::core::CoreWrite;
use crown::envelope::{
    aes_key_unwrap, aes_key_unwrap_padded, aes_key_wrap, aes_key_wrap_padded, ff1_decrypt,
    ff1_encrypt, EvpHash, EvpMac, EvpXts,
};
use crown::mac::{cmac, gmac, kmac, poly1305, siphash};
use crown::modes::cts::Cts;
use crown::otp;
use libfuzzer_sys::fuzz_target;

#[path = "common/det_rng.rs"]
mod common;

#[derive(Arbitrary, Debug)]
enum Action {
    Siphash {
        key: Vec<u8>,
        out_len: u8,
        data: Vec<u8>,
    },
    Kmac128 {
        key: Vec<u8>,
        custom: Vec<u8>,
        out_len: u8,
        data: Vec<u8>,
    },
    Kmac256 {
        key: Vec<u8>,
        custom: Vec<u8>,
        out_len: u8,
        data: Vec<u8>,
    },
    CmacAes {
        key: Vec<u8>,
        data: Vec<u8>,
    },
    GmacAes {
        key: Vec<u8>,
        iv: [u8; 12],
        data: Vec<u8>,
    },
    Poly1305 {
        key: Vec<u8>,
        data: Vec<u8>,
        split: u16,
    },
    HmacChunked {
        hash: u8,
        key: Vec<u8>,
        data: Vec<u8>,
        split: u16,
    },
    AesXts {
        variant: u8,
        key: Vec<u8>,
        tweak: [u8; 16],
        data: Vec<u8>,
    },
    Sm4Xts {
        gb: bool,
        key: Vec<u8>,
        tweak: [u8; 16],
        data: Vec<u8>,
    },
    KeyWrap {
        key_len: u8,
        padded: bool,
        plaintext: Vec<u8>,
    },
    KeyUnwrapFuzzed {
        key: Vec<u8>,
        padded: bool,
        ciphertext: Vec<u8>,
    },
    Ff1 {
        key: Vec<u8>,
        tweak: Vec<u8>,
        radix: u16,
        digits: Vec<u8>,
    },
    Cts {
        cipher: u8,
        key: Vec<u8>,
        iv: [u8; 16],
        data: Vec<u8>,
    },
    Otp {
        key: Vec<u8>,
        counter: u64,
        step: u64,
        digits: u8,
    },
}

fn cts_round_trip<B: crown::block::BlockCipher>(b: B, iv: &[u8], data: &[u8], what: &'static str) {
    if let Ok(cts) = Cts::new(b, iv) {
        if let Ok(ct) = cts.encrypt(data) {
            let back = cts.decrypt(&ct).unwrap();
            assert_eq!(back, data, "{what} round trip mismatch");
        }
    }
}

fuzz_target!(|action: Action| {
    match action {
        Action::Siphash { key, out_len, data } => {
            let k: [u8; 16] = common::fixed(&key);
            let out_len = if out_len & 1 == 0 { 8 } else { 16 };
            if let Ok(mut mac) = EvpMac::new_siphash(&k, out_len) {
                mac.write(&data);
                let tag = mac.sum();
                // Differential: the envelope tag must equal the direct API tag.
                let direct = if out_len == 8 {
                    siphash::sum(&data, &k).to_vec()
                } else {
                    siphash::sum128(&data, &k).to_vec()
                };
                assert_eq!(tag, direct, "siphash envelope/direct mismatch");
            }
        }
        Action::Kmac128 {
            key,
            custom,
            out_len,
            data,
        } => {
            let out_len = (out_len as usize % 64) + 1;
            if let Ok(mut mac) = EvpMac::new_kmac128(&key, &custom, out_len) {
                mac.write(&data);
                let tag = mac.sum();
                let mut direct = vec![0u8; out_len];
                let mut k = kmac::Kmac128::new(&key, &custom).unwrap();
                k.write(&data);
                k.sum(&mut direct);
                assert_eq!(tag, direct, "kmac128 envelope/direct mismatch");
            }
        }
        Action::Kmac256 {
            key,
            custom,
            out_len,
            data,
        } => {
            let out_len = (out_len as usize % 64) + 1;
            if let Ok(mut mac) = EvpMac::new_kmac256(&key, &custom, out_len) {
                mac.write(&data);
                let tag = mac.sum();
                let mut direct = vec![0u8; out_len];
                let mut k = kmac::Kmac256::new(&key, &custom).unwrap();
                k.write(&data);
                k.sum(&mut direct);
                assert_eq!(tag, direct, "kmac256 envelope/direct mismatch");
            }
        }
        Action::CmacAes { key, data } => {
            if let Ok(cipher) = Aes::new(&key) {
                if let Ok(mut mac) = EvpMac::new_cmac_aes(&key) {
                    mac.write(&data);
                    let tag = mac.sum();
                    let direct = cmac::sum::<Aes, 16>(cipher, &data).unwrap();
                    assert_eq!(tag, direct, "cmac envelope/direct mismatch");
                }
            }
        }
        Action::GmacAes { key, iv, data } => {
            if let Ok(cipher) = Aes::new(&key) {
                if let Ok(mut mac) = EvpMac::new_gmac_aes(&key, &iv) {
                    mac.write(&data);
                    let tag = mac.sum();
                    let direct = gmac::sum(cipher, &iv, &data).unwrap();
                    assert_eq!(tag, direct, "gmac envelope/direct mismatch");
                }
            }
        }
        Action::Poly1305 { key, data, split } => {
            let k: [u8; 32] = common::fixed(&key);
            let one_shot = poly1305::sum(&data, &k);
            let at = (split as usize) % (data.len() + 1);
            let mut streaming = poly1305::Poly1305::new(&k);
            streaming.write(&data[..at]);
            streaming.write(&data[at..]);
            assert_eq!(one_shot, streaming.sum(), "poly1305 chunked mismatch");
        }
        Action::HmacChunked {
            hash,
            key,
            data,
            split,
        } => {
            type HmacFactory = fn(&[u8]) -> crown::error::CryptoResult<EvpHash>;
            let factory: HmacFactory = match hash % 3 {
                0 => EvpHash::new_sha256_hmac,
                1 => EvpHash::new_sha384_hmac,
                _ => EvpHash::new_sha512_hmac,
            };
            if let (Ok(mut whole), Ok(mut part)) = (factory(&key), factory(&key)) {
                let _ = whole.write(&data);
                let at = (split as usize) % (data.len() + 1);
                let _ = part.write(&data[..at]);
                let _ = part.write(&data[at..]);
                assert_eq!(whole.sum(), part.sum(), "hmac chunked mismatch");
            }
        }
        Action::AesXts {
            variant,
            key,
            tweak,
            data,
        } => {
            let mut key_full = vec![0u8; if variant & 1 == 0 { 32 } else { 64 }];
            let n = key.len().min(key_full.len());
            key_full[..n].copy_from_slice(&key[..n]);
            if let Ok(xts) = EvpXts::new_aes_xts(&key_full) {
                let mut buf = data.clone();
                if xts.encrypt(&tweak, &mut buf).is_ok() && xts.decrypt(&tweak, &mut buf).is_ok() {
                    assert_eq!(buf, data, "aes-xts round trip mismatch");
                }
            }
        }
        Action::Sm4Xts {
            gb,
            key,
            tweak,
            data,
        } => {
            let key_full: [u8; 32] = common::fixed(&key);
            let built = if gb {
                EvpXts::new_sm4_xts_gb(&key_full)
            } else {
                EvpXts::new_sm4_xts(&key_full)
            };
            if let Ok(xts) = built {
                let mut buf = data.clone();
                if xts.encrypt(&tweak, &mut buf).is_ok() && xts.decrypt(&tweak, &mut buf).is_ok() {
                    assert_eq!(buf, data, "sm4-xts round trip mismatch");
                }
            }
        }
        Action::KeyWrap {
            key_len,
            padded,
            plaintext,
        } => {
            let key: Vec<u8> = match key_len % 3 {
                0 => common::fixed::<16>(&plaintext).to_vec(),
                1 => common::fixed::<24>(&plaintext).to_vec(),
                _ => common::fixed::<32>(&plaintext).to_vec(),
            };
            if padded {
                if let Ok(ct) = aes_key_wrap_padded(&key, &plaintext) {
                    let back = aes_key_unwrap_padded(&key, &ct).unwrap();
                    assert_eq!(back, plaintext, "kwp round trip mismatch");
                }
            } else if let Ok(ct) = aes_key_wrap(&key, &plaintext) {
                let back = aes_key_unwrap(&key, &ct).unwrap();
                assert_eq!(back, plaintext, "kw round trip mismatch");
            }
        }
        Action::KeyUnwrapFuzzed {
            key,
            padded,
            ciphertext,
        } => {
            let k: [u8; 16] = common::fixed(&key);
            if padded {
                let _ = aes_key_unwrap_padded(&k, &ciphertext);
            } else {
                let _ = aes_key_unwrap(&k, &ciphertext);
            }
        }
        Action::Ff1 {
            key,
            tweak,
            radix,
            digits,
        } => {
            let radix = (radix % 65535) as u32 + 2;
            let ds: Vec<u32> = digits
                .iter()
                .take(48)
                .map(|&b| (b as u32) % radix)
                .collect();
            if ds.is_empty() {
                return;
            }
            if let Ok(ct) = ff1_encrypt(&key, &tweak, radix, &ds) {
                let back = ff1_decrypt(&key, &tweak, radix, &ct).unwrap();
                assert_eq!(back, ds, "ff1 round trip mismatch");
            }
        }
        Action::Cts {
            cipher,
            key,
            iv,
            data,
        } => match cipher % 3 {
            0 => {
                if let Ok(b) = Aes::new(&key) {
                    cts_round_trip(b, &iv, &data, "cts-aes");
                }
            }
            1 => {
                if let Ok(b) = Sm4::new(&key) {
                    cts_round_trip(b, &iv, &data, "cts-sm4");
                }
            }
            _ => {
                if let Ok(b) = Twofish::new(&key) {
                    cts_round_trip(b, &iv, &data, "cts-twofish");
                }
            }
        },
        Action::Otp {
            key,
            counter,
            step,
            digits,
        } => {
            let digits = 6 + (digits % 3) as usize;
            let bound = 10u32.pow(digits as u32);
            let code = otp::hotp(&key, counter, digits);
            assert!(code < bound, "hotp out of range");
            let code = otp::totp(&key, counter, step % 3600 + 1, digits, 0);
            assert!(code < bound, "totp out of range");
        }
    }
});
