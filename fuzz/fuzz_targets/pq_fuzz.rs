#![no_main]

//! Post-quantum fuzzing: ML-KEM, ML-DSA and SLH-DSA round trips, implicit
//! rejection on corrupted ciphertexts, key parse/serialize round trips and
//! verification on attacker-controlled keys and signatures.

use arbitrary::Arbitrary;
use crown::ml_dsa::{self, MlDsaVariant};
use crown::ml_kem::{self, MlKemVariant};
use crown::slh_dsa::{self, SlhDsaVariant};
use libfuzzer_sys::fuzz_target;

#[path = "common/det_rng.rs"]
mod common;

#[derive(Arbitrary, Debug)]
enum Action {
    MlKem {
        variant: u8,
        seed: Vec<u8>,
        m: Vec<u8>,
        corrupt: bool,
    },
    MlKemDecapsFuzzed {
        variant: u8,
        sk: Vec<u8>,
        ct: Vec<u8>,
    },
    MlDsa {
        variant: u8,
        seed: Vec<u8>,
        msg: Vec<u8>,
        ctx: Vec<u8>,
        hedge: bool,
    },
    MlDsaVerifyFuzzed {
        variant: u8,
        pk: Vec<u8>,
        msg: Vec<u8>,
        ctx: Vec<u8>,
        sig: Vec<u8>,
    },
    MlDsaKeyRoundTrip {
        variant: u8,
        sk: Vec<u8>,
    },
    SlhDsa {
        variant: u8,
        seed: Vec<u8>,
        msg: Vec<u8>,
    },
    SlhDsaVerifyFuzzed {
        variant: u8,
        pk: Vec<u8>,
        msg: Vec<u8>,
        sig: Vec<u8>,
    },
}

fn ml_kem_variant(id: u8) -> MlKemVariant {
    match id % 3 {
        0 => MlKemVariant::MlKem512,
        1 => MlKemVariant::MlKem768,
        _ => MlKemVariant::MlKem1024,
    }
}

fn ml_dsa_variant(id: u8) -> MlDsaVariant {
    match id % 3 {
        0 => MlDsaVariant::MlDsa44,
        1 => MlDsaVariant::MlDsa65,
        _ => MlDsaVariant::MlDsa87,
    }
}

fn slh_variant(id: u8) -> SlhDsaVariant {
    if id & 1 == 0 {
        SlhDsaVariant::Sha2_128s
    } else {
        SlhDsaVariant::Shake_128f
    }
}

fuzz_target!(|action: Action| {
    match action {
        Action::MlKem {
            variant,
            seed,
            m,
            corrupt,
        } => {
            let variant = ml_kem_variant(variant);
            let seed: [u8; 64] = common::fixed(&seed);
            let m: [u8; 32] = common::fixed(&m);
            let (pk, sk) = ml_kem::keygen(variant, &seed).unwrap();
            let (ct, ss) = ml_kem::encapsulate(&pk, &m).unwrap();
            assert_eq!(
                ml_kem::decapsulate(&sk, &ct).unwrap(),
                ss,
                "ml-kem mismatch"
            );
            if corrupt && !ct.is_empty() {
                let mut bad = ct.clone();
                bad[0] ^= 0x40;
                let rejected = ml_kem::decapsulate(&sk, &bad).unwrap();
                assert_ne!(rejected, ss, "corrupted ciphertext accepted");
            }
        }
        Action::MlKemDecapsFuzzed { variant, sk, ct } => {
            let variant = ml_kem_variant(variant);
            if let Ok(sk) = ml_kem::MlKemPrivateKey::from_bytes(variant, &sk) {
                let mut ct = ct;
                ct.resize(variant.ciphertext_len(), 0);
                let _ = ml_kem::decapsulate(&sk, &ct);
            }
        }
        Action::MlDsa {
            variant,
            seed,
            msg,
            ctx,
            hedge,
        } => {
            let variant = ml_dsa_variant(variant);
            let seed: [u8; 32] = common::fixed(&seed);
            let ctx = &ctx[..ctx.len().min(255)];
            let (pk, sk) = ml_dsa::keygen(variant, &seed).unwrap();
            if let Ok(sig) = ml_dsa::sign(&sk, &msg, ctx, None) {
                assert_eq!(sig.len(), ml_dsa::signature_size(variant));
                assert!(
                    ml_dsa::verify(&pk, &msg, ctx, &sig).unwrap(),
                    "ml-dsa verify rejected its own signature"
                );
            }
            if hedge {
                let rnd: [u8; 32] = common::fixed(b"hedge");
                if let Ok(sig) = ml_dsa::sign(&sk, &msg, ctx, Some(&rnd)) {
                    assert!(
                        ml_dsa::verify(&pk, &msg, ctx, &sig).unwrap(),
                        "ml-dsa hedged verify rejected its own signature"
                    );
                }
            }
        }
        Action::MlDsaVerifyFuzzed {
            variant,
            pk,
            msg,
            ctx,
            sig,
        } => {
            let variant = ml_dsa_variant(variant);
            if let Ok(pk) = ml_dsa::MlDsaPublicKey::from_bytes(variant, &pk) {
                let ctx = &ctx[..ctx.len().min(255)];
                let _ = ml_dsa::verify(&pk, &msg, ctx, &sig);
            }
        }
        Action::MlDsaKeyRoundTrip { variant, sk } => {
            let variant = ml_dsa_variant(variant);
            let mut bytes = sk;
            bytes.resize(ml_dsa::private_key_size(variant), 0);
            if let Ok(sk) = ml_dsa::MlDsaPrivateKey::from_bytes(variant, &bytes) {
                assert_eq!(sk.to_bytes(), bytes, "ml-dsa sk round trip mismatch");
                let _ = sk.public_key();
            }
        }
        Action::SlhDsa { variant, seed, msg } => {
            let variant = slh_variant(variant);
            let seed = common::fixed::<48>(&seed);
            let (pk, sk) = slh_dsa::keygen(variant, &seed).unwrap();
            let sig = slh_dsa::sign(&sk, &msg, &[], false).unwrap();
            assert!(
                slh_dsa::verify(&pk, &msg, &[], &sig, false).unwrap(),
                "slh-dsa verify rejected its own signature"
            );
            let mut bad = sig.clone();
            let at = msg.first().copied().unwrap_or(0) as usize % bad.len();
            bad[at] ^= 1;
            assert!(
                !slh_dsa::verify(&pk, &msg, &[], &bad, false).unwrap(),
                "slh-dsa verify accepted a mutated signature"
            );
            assert_eq!(
                sk.public_key().to_bytes(),
                pk.to_bytes(),
                "slh-dsa pk mismatch"
            );
        }
        Action::SlhDsaVerifyFuzzed {
            variant,
            pk,
            msg,
            sig,
        } => {
            let variant = slh_variant(variant);
            if let Ok(pk) = slh_dsa::SlhDsaPublicKey::from_bytes(variant, &pk) {
                let _ = slh_dsa::verify(&pk, &msg, &[], &sig, false);
            }
        }
    }
});
