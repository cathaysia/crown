use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

const ENTROPY: &[u8] = &[0x42u8; 32];
const NONCE: &[u8] = &[0x24u8; 16];
const PERSONALIZATION: &[u8] = b"crown-drbg-benchmark";
const ADDITIONAL: &[u8] = &[0x11u8; 8];

fn bench_hmac_drbg(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_drbg_sha256");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("generate_1024", |b| {
        let mut drbg = crown::drbg::HmacDrbg::new(ENTROPY, NONCE, PERSONALIZATION);
        let mut out = [0u8; 1024];
        b.iter(|| {
            drbg.generate(&mut out, &[]).unwrap();
            black_box(out[0])
        })
    });
    group.bench_function("generate_1024_additional", |b| {
        let mut drbg = crown::drbg::HmacDrbg::new(ENTROPY, NONCE, PERSONALIZATION);
        let mut out = [0u8; 1024];
        b.iter(|| {
            drbg.generate(&mut out, ADDITIONAL).unwrap();
            black_box(out[0])
        })
    });

    group.finish();
}

fn bench_hash_drbg(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_drbg_sha256");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("generate_1024", |b| {
        let mut drbg = crown::drbg::HashDrbg::new(ENTROPY, NONCE, PERSONALIZATION);
        let mut out = [0u8; 1024];
        b.iter(|| {
            drbg.generate(&mut out, &[]).unwrap();
            black_box(out[0])
        })
    });
    group.bench_function("generate_1024_additional", |b| {
        let mut drbg = crown::drbg::HashDrbg::new(ENTROPY, NONCE, PERSONALIZATION);
        let mut out = [0u8; 1024];
        b.iter(|| {
            drbg.generate(&mut out, ADDITIONAL).unwrap();
            black_box(out[0])
        })
    });

    group.finish();
}

criterion_group!(benches, bench_hmac_drbg, bench_hash_drbg);
criterion_main!(benches);
