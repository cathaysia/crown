use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::ml_dsa::{self, MlDsaVariant};
use crown::ml_kem::{self, MlKemVariant};
use crown::slh_dsa::{self, SlhDsaVariant};

fn bench_ml_kem_all(c: &mut Criterion) {
    let seed = [0x42u8; 64];
    let m = [0x24u8; 32];

    for (name, variant) in [
        ("ml_kem_512", MlKemVariant::MlKem512),
        ("ml_kem_1024", MlKemVariant::MlKem1024),
    ] {
        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Elements(1));

        let (pk, sk) = ml_kem::keygen(variant, &seed).unwrap();
        let (ct, ss) = ml_kem::encapsulate(&pk, &m).unwrap();

        group.bench_function("keygen", |b| {
            b.iter(|| black_box(ml_kem::keygen(black_box(variant), black_box(&seed)).unwrap()))
        });
        group.bench_function("encapsulate", |b| {
            b.iter(|| black_box(ml_kem::encapsulate(black_box(&pk), black_box(&m)).unwrap()))
        });
        group.bench_function("decapsulate", |b| {
            b.iter(|| black_box(ml_kem::decapsulate(black_box(&sk), black_box(&ct)).unwrap()))
        });
        assert_eq!(ss, ml_kem::decapsulate(&sk, &ct).unwrap());
        group.finish();
    }
}

fn bench_ml_kem768_rustcrypto(c: &mut Criterion) {
    use kem::Decapsulate;
    // `::` to dodge the `crown::ml_kem` module binding above.
    use ml_kem::{EncapsulateDeterministic, KemCore, MlKem768, B32};

    let d = B32::from([0x42u8; 32]);
    let z = B32::from([0x7eu8; 32]);
    let m = B32::from([0x24u8; 32]);

    let mut group = c.benchmark_group("ml_kem_768");
    group.throughput(Throughput::Elements(1));

    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    let (ct, ss) = ek.encapsulate_deterministic(&m).unwrap();
    assert_eq!(ss.as_slice(), dk.decapsulate(&ct).unwrap().as_slice());

    group.bench_function("rustcrypto_keygen", |b| {
        b.iter(|| {
            black_box(MlKem768::generate_deterministic(
                black_box(&d),
                black_box(&z),
            ))
        })
    });
    group.bench_function("rustcrypto_encapsulate", |b| {
        b.iter(|| black_box(ek.encapsulate_deterministic(black_box(&m)).unwrap()))
    });
    group.bench_function("rustcrypto_decapsulate", |b| {
        b.iter(|| black_box(dk.decapsulate(black_box(&ct)).unwrap()))
    });

    group.finish();
}

fn bench_ml_dsa_all(c: &mut Criterion) {
    let seed = [0x42u8; 32];
    let msg: [u8; 64] = core::array::from_fn(|i| i as u8);

    for (name, variant) in [
        ("ml_dsa_44", MlDsaVariant::MlDsa44),
        ("ml_dsa_87", MlDsaVariant::MlDsa87),
    ] {
        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Elements(1));

        let (pk, sk) = ml_dsa::keygen(variant, &seed).unwrap();
        let sig = ml_dsa::sign(&sk, &msg, &[], None).unwrap();

        group.bench_function("keygen", |b| {
            b.iter(|| black_box(ml_dsa::keygen(black_box(variant), black_box(&seed)).unwrap()))
        });
        group.bench_function("sign", |b| {
            b.iter(|| black_box(ml_dsa::sign(black_box(&sk), &msg, &[], None).unwrap()))
        });
        group.bench_function("verify", |b| {
            b.iter(|| {
                black_box(ml_dsa::verify(black_box(&pk), &msg, &[], black_box(&sig)).unwrap())
            })
        });
        assert!(ml_dsa::verify(&pk, &msg, &[], &sig).unwrap());
        group.finish();
    }
}

fn bench_slh_dsa_more(c: &mut Criterion) {
    let seed = vec![0x42u8; 48]; // 3 * n for n = 16
    let msg: [u8; 64] = core::array::from_fn(|i| i as u8);

    for (name, variant) in [
        ("slh_dsa_sha2_128f", SlhDsaVariant::Sha2_128f),
        ("slh_dsa_shake_128s", SlhDsaVariant::Shake_128s),
    ] {
        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Elements(1));

        let (pk, sk) = slh_dsa::keygen(variant, &seed).unwrap();
        let sig = slh_dsa::sign(&sk, &msg, &[], false).unwrap();

        group.bench_function("keygen", |b| {
            b.iter(|| black_box(slh_dsa::keygen(black_box(variant), black_box(&seed)).unwrap()))
        });
        group.bench_function("sign", |b| {
            b.iter(|| black_box(slh_dsa::sign(black_box(&sk), &msg, &[], false).unwrap()))
        });
        group.bench_function("verify", |b| {
            b.iter(|| {
                black_box(
                    slh_dsa::verify(black_box(&pk), &msg, &[], black_box(&sig), false).unwrap(),
                )
            })
        });
        assert!(slh_dsa::verify(&pk, &msg, &[], &sig, false).unwrap());
        group.finish();
    }
}

criterion_group!(
    benches,
    bench_ml_kem_all,
    bench_ml_kem768_rustcrypto,
    bench_ml_dsa_all,
    bench_slh_dsa_more
);
criterion_main!(benches);
