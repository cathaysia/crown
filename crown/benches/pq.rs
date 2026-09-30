use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::ml_dsa::{self, MlDsaVariant};
use crown::ml_kem::{self, MlKemVariant};
use crown::slh_dsa::{self, SlhDsaVariant};

fn bench_ml_kem(c: &mut Criterion) {
    let seed = [0x42u8; 64];
    let m = [0x24u8; 32];

    let mut group = c.benchmark_group("ml_kem_768");
    group.throughput(Throughput::Elements(1));

    let (pk, sk) = ml_kem::keygen(MlKemVariant::MlKem768, &seed).unwrap();
    let (ct, ss) = ml_kem::encapsulate(&pk, &m).unwrap();

    group.bench_function("keygen", |b| {
        b.iter(|| black_box(ml_kem::keygen(MlKemVariant::MlKem768, black_box(&seed)).unwrap()))
    });
    group.bench_function("encapsulate", |b| {
        b.iter(|| black_box(ml_kem::encapsulate(black_box(&pk), black_box(&m)).unwrap()))
    });
    group.bench_function("decapsulate", |b| {
        b.iter(|| black_box(ml_kem::decapsulate(black_box(&sk), black_box(&ct)).unwrap()))
    });
    let ss2 = ml_kem::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss, ss2);
    group.finish();
}

fn bench_ml_dsa(c: &mut Criterion) {
    let seed = [0x42u8; 32];
    let msg: [u8; 64] = core::array::from_fn(|i| i as u8);

    let mut group = c.benchmark_group("ml_dsa_65");
    group.throughput(Throughput::Elements(1));

    let (pk, sk) = ml_dsa::keygen(MlDsaVariant::MlDsa65, &seed).unwrap();
    let sig = ml_dsa::sign(&sk, &msg, &[], None).unwrap();

    group.bench_function("keygen", |b| {
        b.iter(|| black_box(ml_dsa::keygen(MlDsaVariant::MlDsa65, black_box(&seed)).unwrap()))
    });
    group.bench_function("sign", |b| {
        b.iter(|| black_box(ml_dsa::sign(black_box(&sk), &msg, &[], None).unwrap()))
    });
    group.bench_function("verify", |b| {
        b.iter(|| black_box(ml_dsa::verify(black_box(&pk), &msg, &[], black_box(&sig)).unwrap()))
    });
    assert!(ml_dsa::verify(&pk, &msg, &[], &sig).unwrap());
    group.finish();
}

fn bench_slh_dsa(c: &mut Criterion) {
    let seed = vec![0x42u8; 48]; // 3 * n for n = 16
    let msg: [u8; 64] = core::array::from_fn(|i| i as u8);

    let mut group = c.benchmark_group("slh_dsa_sha2_128s");
    group.throughput(Throughput::Elements(1));

    let (pk, sk) = slh_dsa::keygen(SlhDsaVariant::Sha2_128s, &seed).unwrap();
    let sig = slh_dsa::sign(&sk, &msg, &[], false).unwrap();

    group.bench_function("keygen", |b| {
        b.iter(|| black_box(slh_dsa::keygen(SlhDsaVariant::Sha2_128s, black_box(&seed)).unwrap()))
    });
    group.bench_function("sign", |b| {
        b.iter(|| black_box(slh_dsa::sign(black_box(&sk), &msg, &[], false).unwrap()))
    });
    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(slh_dsa::verify(black_box(&pk), &msg, &[], black_box(&sig), false).unwrap())
        })
    });
    assert!(slh_dsa::verify(&pk, &msg, &[], &sig, false).unwrap());
    group.finish();
}

criterion_group!(benches, bench_ml_kem, bench_ml_dsa, bench_slh_dsa);
criterion_main!(benches);
