#![no_main]

//! KDF, password-hash and DRBG fuzzing: every derivation is exercised with
//! fuzzed inputs; iteration counts and memory sizes are clamped to keep the
//! per-exec cost bounded.

use arbitrary::Arbitrary;
use crown::block::aes::Aes;
use crown::core::CoreRead;
use crown::envelope::EvpHash;
use crown::kdf::kbkdf::{FixedInput, Mode};
use crown::kdf::sshkdf::SshKdfType;
use crown::kdf::x942kdf::CekAlg;
use crown::password_hash::pbes2::{HashId, Pbes2Cipher, Pbes2Kdf};
use libfuzzer_sys::fuzz_target;

#[path = "common/det_rng.rs"]
mod common;

#[derive(Arbitrary, Debug)]
enum Action {
    Hkdf {
        ikm: Vec<u8>,
        salt: Vec<u8>,
        info: Vec<u8>,
        len: u8,
    },
    Pbkdf2 {
        pass: Vec<u8>,
        salt: Vec<u8>,
        iter: u8,
        len: u8,
    },
    Pbkdf1 {
        hash: u8,
        pass: Vec<u8>,
        salt: Vec<u8>,
        iter: u8,
        len: u8,
    },
    Pkcs12 {
        hash: u8,
        pass: Vec<u8>,
        salt: Vec<u8>,
        id: u8,
        iter: u8,
        len: u8,
    },
    Tls1Prf {
        md5_sha1: bool,
        secret: Vec<u8>,
        seed: Vec<u8>,
        len: u8,
    },
    Sskdf {
        kind: u8,
        salt: Vec<u8>,
        secret: Vec<u8>,
        info: Vec<u8>,
        len: u8,
    },
    Kbkdf {
        cmac: bool,
        feedback: bool,
        ki: Vec<u8>,
        label: Vec<u8>,
        context: Vec<u8>,
        len: u8,
    },
    Krb5 {
        key_len: u8,
        key: Vec<u8>,
        constant: Vec<u8>,
    },
    Ssh {
        ty: u8,
        key: Vec<u8>,
        xcghash: Vec<u8>,
        session_id: Vec<u8>,
        len: u8,
    },
    Srtp {
        label: u8,
        kdr: u8,
        key: Vec<u8>,
        index: Vec<u8>,
    },
    Ikev2 {
        rekey: bool,
        key: Vec<u8>,
        ni: Vec<u8>,
        nr: Vec<u8>,
        spi: Vec<u8>,
        shared: Vec<u8>,
        len: u8,
    },
    X942 {
        alg: u8,
        use_keybits: bool,
        secret: Vec<u8>,
        partyu: Vec<u8>,
        partyv: Vec<u8>,
        supp: Vec<u8>,
        len: u8,
    },
    Scrypt {
        pass: Vec<u8>,
        salt: Vec<u8>,
        n_exp: u8,
        r: u8,
        p: u8,
        len: u8,
    },
    Argon2 {
        pass: Vec<u8>,
        salt: Vec<u8>,
        m: u8,
        t: u8,
        len: u8,
    },
    Bcrypt {
        pass: Vec<u8>,
        cost: u8,
    },
    Pbes2 {
        hkdf: bool,
        pass: Vec<u8>,
        salt: Vec<u8>,
        hash: u8,
        cipher: u8,
        iter: u8,
        pt: Vec<u8>,
    },
    HmacDrbg {
        entropy: Vec<u8>,
        nonce: Vec<u8>,
        pers: Vec<u8>,
        extra: Vec<u8>,
        len: u8,
    },
    HashDrbg {
        entropy: Vec<u8>,
        nonce: Vec<u8>,
        pers: Vec<u8>,
        extra: Vec<u8>,
        len: u8,
    },
}

type HashFactory = fn() -> crown::error::CryptoResult<EvpHash>;

fn hash_factory(id: u8) -> HashFactory {
    match id % 4 {
        0 => EvpHash::new_sha256,
        1 => EvpHash::new_sha384,
        2 => EvpHash::new_sha512,
        _ => EvpHash::new_sha1,
    }
}

fn hash_id(id: u8) -> HashId {
    match id % 4 {
        0 => HashId::Sha1,
        1 => HashId::Sha256,
        2 => HashId::Sha384,
        _ => HashId::Sha512,
    }
}

fuzz_target!(|action: Action| {
    match action {
        Action::Hkdf {
            ikm,
            salt,
            info,
            len,
        } => {
            let mut okm =
                crown::kdf::hkdf::new::<32, _, _>(crown::hash::sha256::new256, &ikm, &salt, &info);
            let mut out = vec![0u8; (len as usize % 64) + 1];
            okm.read(&mut out).unwrap();
        }
        Action::Pbkdf2 {
            pass,
            salt,
            iter,
            len,
        } => {
            let iters = (iter as u32 % 64) + 1;
            let out = crown::password_hash::pbkdf2::key::<32, _, _>(
                &pass,
                &salt,
                iters,
                (len as usize % 64) + 1,
                crown::hash::sha256::new256,
            );
            assert_eq!(out.len(), (len as usize % 64) + 1);
        }
        Action::Pbkdf1 {
            hash,
            pass,
            salt,
            iter,
            len,
        } => {
            let _ = crown::kdf::pbkdf1::derive(
                hash_factory(hash),
                &pass,
                &salt,
                (iter as u64 % 64) + 1,
                (len as usize % 64) + 1,
            );
        }
        Action::Pkcs12 {
            hash,
            pass,
            salt,
            id,
            iter,
            len,
        } => {
            let _ = crown::kdf::pkcs12kdf::derive(
                hash_factory(hash),
                &pass,
                &salt,
                (id % 3) + 1,
                (iter as u64 % 64) + 1,
                (len as usize % 128) + 1,
            );
        }
        Action::Tls1Prf {
            md5_sha1,
            secret,
            seed,
            len,
        } => {
            let n = (len as usize % 256) + 1;
            if md5_sha1 {
                let _ = crown::kdf::tls1_prf::derive_md5_sha1(&secret, &seed, n);
            } else {
                let _ = crown::kdf::tls1_prf::derive(EvpHash::new_sha384_hmac, &secret, &seed, n);
            }
        }
        Action::Sskdf {
            kind,
            salt,
            secret,
            info,
            len,
        } => {
            let n = (len as usize % 256) + 1;
            match kind % 3 {
                0 => {
                    let _ = crown::kdf::sskdf::derive_hash(EvpHash::new_sha256, &secret, &info, n);
                }
                1 => {
                    let _ = crown::kdf::sskdf::derive_hmac(
                        EvpHash::new_sha256_hmac,
                        &salt,
                        &secret,
                        &info,
                        n,
                    );
                }
                _ => {
                    let _ =
                        crown::kdf::sskdf::x963_derive_hash(EvpHash::new_sha512, &secret, &info, n);
                }
            }
        }
        Action::Kbkdf {
            cmac,
            feedback,
            ki,
            label,
            context,
            len,
        } => {
            let n = (len as usize % 256) + 1;
            let fi = FixedInput {
                label: &label,
                context: &context,
                iv: &[],
                use_l: true,
                use_separator: true,
                r: 32,
            };
            let mode = if feedback {
                Mode::Feedback
            } else {
                Mode::Counter
            };
            if cmac {
                if let Ok(cipher) = Aes::new(&ki) {
                    let _ = crown::kdf::kbkdf::derive_cmac::<Aes, 16>(cipher, mode, &fi, n);
                }
            } else {
                let _ = crown::kdf::kbkdf::derive_hmac(EvpHash::new_sha256_hmac, mode, &ki, &fi, n);
            }
        }
        Action::Krb5 {
            key_len,
            key,
            constant,
        } => {
            if let Ok(cipher) = Aes::new(&key) {
                let _ =
                    crown::kdf::krb5kdf::derive(&cipher, (key_len as usize % 64) + 1, &constant);
            }
        }
        Action::Ssh {
            ty,
            key,
            xcghash,
            session_id,
            len,
        } => {
            let kty = match ty % 6 {
                0 => SshKdfType::A,
                1 => SshKdfType::B,
                2 => SshKdfType::C,
                3 => SshKdfType::D,
                4 => SshKdfType::E,
                _ => SshKdfType::F,
            };
            let _ = crown::kdf::sshkdf::derive(
                EvpHash::new_sha256,
                &key,
                &xcghash,
                &session_id,
                kty,
                (len as usize % 256) + 1,
            );
        }
        Action::Srtp {
            label,
            kdr,
            key,
            index,
        } => {
            let salt = common::fixed::<14>(&index);
            let _ = crown::kdf::srtpkdf::derive_aes_cm(&key, &salt, &index, kdr as u32, label % 8);
        }
        Action::Ikev2 {
            rekey,
            key,
            ni,
            nr,
            spi,
            shared,
            len,
        } => {
            if rekey {
                let _ = crown::kdf::ikev2kdf::dkm(
                    EvpHash::new_sha256_hmac,
                    &key,
                    &ni,
                    &nr,
                    if spi.is_empty() { None } else { Some(&spi) },
                    if spi.is_empty() { None } else { Some(&spi) },
                    if shared.is_empty() {
                        None
                    } else {
                        Some(&shared)
                    },
                    (len as usize % 512) + 1,
                );
            } else {
                let _ = crown::kdf::ikev2kdf::seedkey_gen(EvpHash::new_sha256_hmac, &key, &ni, &nr);
            }
        }
        Action::X942 {
            alg,
            use_keybits,
            secret,
            partyu,
            partyv,
            supp,
            len,
        } => {
            let cek = match alg % 4 {
                0 => CekAlg::Aes128Wrap,
                1 => CekAlg::Aes192Wrap,
                2 => CekAlg::Aes256Wrap,
                _ => CekAlg::Des3Wrap,
            };
            let _ = crown::kdf::x942kdf::derive(
                EvpHash::new_sha256,
                &secret,
                cek,
                &partyu,
                &partyv,
                &supp,
                &[],
                use_keybits,
                (len as usize % 256) + 1,
            );
        }
        Action::Scrypt {
            pass,
            salt,
            n_exp,
            r,
            p,
            len,
        } => {
            let n = 1usize << (2 + (n_exp % 7) as usize);
            let rr = 1 + (r % 8) as usize;
            let pp = 1 + (p % 2) as usize;
            let _ =
                crown::password_hash::scrypt::key(&pass, &salt, n, rr, pp, (len as usize % 64) + 1);
        }
        Action::Argon2 {
            pass,
            salt,
            m,
            t,
            len,
        } => {
            let memory = 64 + (m % 16) as u32 * 64;
            let salt = common::fixed::<16>(&salt);
            let _ = crown::password_hash::argon2::id_key(
                &pass,
                &salt,
                (t % 2) as u32 + 1,
                memory,
                1,
                (len as u32 % 64) + 1,
            );
        }
        Action::Bcrypt { pass, cost } => {
            let cost = 4 + (cost % 3) as u32;
            if let Ok(hashed) = crown::password_hash::bcrypt::generate_from_password(&pass, cost) {
                crown::password_hash::bcrypt::compare_hash_and_password(&hashed, &pass)
                    .expect("bcrypt round trip");
                let wrong = [pass.as_slice(), b"x"].concat();
                assert!(
                    crown::password_hash::bcrypt::compare_hash_and_password(&hashed, &wrong)
                        .is_err(),
                    "bcrypt accepted the wrong password"
                );
                assert_eq!(crown::password_hash::bcrypt::cost(&hashed).unwrap(), cost);
            }
        }
        Action::Pbes2 {
            hkdf,
            pass,
            salt,
            hash,
            cipher,
            iter,
            pt,
        } => {
            let kdf = if hkdf {
                Pbes2Kdf::Hkdf {
                    hash: hash_id(hash),
                }
            } else {
                Pbes2Kdf::Pbkdf2 {
                    hash: hash_id(hash),
                    iterations: (iter as u32 % 64) + 1,
                }
            };
            let cipher = match cipher % 3 {
                0 => Pbes2Cipher::Aes128Cbc,
                1 => Pbes2Cipher::Aes256Cbc,
                _ => Pbes2Cipher::DesEde3Cbc,
            };
            if let Ok(ct) =
                crown::password_hash::pbes2::pbes2_encrypt(&pass, &salt, &kdf, cipher, &pt)
            {
                let back =
                    crown::password_hash::pbes2::pbes2_decrypt(&pass, &salt, &kdf, cipher, &ct)
                        .unwrap();
                assert_eq!(back, pt, "pbes2 round trip mismatch");
            }
        }
        Action::HmacDrbg {
            entropy,
            nonce,
            pers,
            extra,
            len,
        } => {
            let mut drbg = crown::drbg::HmacDrbg::new(&entropy, &nonce, &pers);
            let mut out = vec![0u8; (len as usize % 128) + 1];
            drbg.generate(&mut out, &extra).unwrap();
            drbg.reseed(&entropy, &extra);
            drbg.generate(&mut out, &extra).unwrap();
        }
        Action::HashDrbg {
            entropy,
            nonce,
            pers,
            extra,
            len,
        } => {
            let mut drbg = crown::drbg::HashDrbg::new(&entropy, &nonce, &pers);
            let mut out = vec![0u8; (len as usize % 128) + 1];
            drbg.generate(&mut out, &extra).unwrap();
            drbg.reseed(&entropy, &extra);
            drbg.generate(&mut out, &extra).unwrap();
        }
    }
});
