use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::bn::{Bn, Montgomery};

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::fill(buf.as_mut_slice());
    buf
}

/// Random big-endian integer with the top bit set.
fn rand_bn(bits: usize) -> Bn {
    let bytes = bits / 8;
    let mut b = rand_bytes(bytes);
    b[0] |= 0x80;
    Bn::from_be_bytes(&b)
}

/// Random odd big-endian integer with the top bit set (usable as a
/// Montgomery modulus).
fn rand_odd_bn(bits: usize) -> Bn {
    let bytes = bits / 8;
    let mut b = rand_bytes(bytes);
    b[0] |= 0x80;
    b[bytes - 1] |= 1;
    Bn::from_be_bytes(&b)
}

fn bench_bn_mul(c: &mut Criterion) {
    for bits in [256, 512, 1024, 2048, 4096] {
        let a = rand_bn(bits);
        let b = rand_bn(bits);
        let mut group = c.benchmark_group("bn_mul");
        group.throughput(Throughput::Elements(1));
        group.bench_function(bits.to_string(), |bench| {
            bench.iter(|| black_box(a.mul(black_box(&b))))
        });
        group.finish();
    }
}

fn bench_bn_mont_mul(c: &mut Criterion) {
    for bits in [256, 512, 1024, 2048, 4096] {
        let n = rand_odd_bn(bits);
        let mont = Montgomery::new(&n).unwrap();
        // Operands strictly below the modulus.
        let mut ab = rand_bytes(bits / 8);
        ab[0] &= 0x3f;
        let a_mont = mont.to_mont(&Bn::from_be_bytes(&ab));
        let mut bb = rand_bytes(bits / 8);
        bb[0] &= 0x3f;
        let b_mont = mont.to_mont(&Bn::from_be_bytes(&bb));
        let mut group = c.benchmark_group("bn_mont_mul");
        group.throughput(Throughput::Elements(1));
        group.bench_function(bits.to_string(), |bench| {
            bench.iter(|| black_box(mont.mul(black_box(&a_mont), black_box(&b_mont))))
        });
        group.finish();
    }
}

fn bench_bn_mont_pow(c: &mut Criterion) {
    // Public-exponent-style: e = 65537 over a 2048-bit modulus.
    let n2048 = rand_odd_bn(2048);
    let mont2048 = Montgomery::new(&n2048).unwrap();
    let mut base = rand_bytes(256);
    base[0] &= 0x3f;
    let base_mont = mont2048.to_mont(&Bn::from_be_bytes(&base));
    let e65537 = Bn::from_u64(65537);

    let mut group = c.benchmark_group("bn_mont_pow_e65537");
    group.throughput(Throughput::Elements(1));
    group.bench_function("2048", |bench| {
        bench.iter(|| black_box(mont2048.pow(black_box(&base_mont), black_box(&e65537))))
    });
    group.finish();

    // Private-exponent-style: full-width random exponent.
    for bits in [1024, 2048, 4096] {
        let n = rand_odd_bn(bits);
        let mont = Montgomery::new(&n).unwrap();
        let mut base = rand_bytes(bits / 8);
        base[0] &= 0x3f;
        let base_mont = mont.to_mont(&Bn::from_be_bytes(&base));
        let e = rand_bn(bits);
        let mut group = c.benchmark_group("bn_mont_pow_full");
        group.throughput(Throughput::Elements(1));
        group.bench_function(bits.to_string(), |bench| {
            bench.iter(|| black_box(mont.pow(black_box(&base_mont), black_box(&e))))
        });
        group.finish();
    }
}

fn bench_bn_mod_pow(c: &mut Criterion) {
    // End-to-end Bn entry point (includes Montgomery setup and conversions,
    // i.e. the shape of an RSA public-key operation).
    for bits in [1024, 2048, 4096] {
        let n = rand_odd_bn(bits);
        let base = rand_bn(bits - 8);
        let e65537 = Bn::from_u64(65537);
        let mut group = c.benchmark_group("bn_mod_pow_e65537");
        group.throughput(Throughput::Elements(1));
        group.bench_function(bits.to_string(), |bench| {
            bench.iter(|| black_box(base.mod_pow(black_box(&e65537), black_box(&n)).unwrap()))
        });
        group.finish();
    }
}

fn bench_bn_modmul(c: &mut Criterion) {
    for bits in [256, 1024] {
        let a = rand_bn(bits);
        let b = rand_bn(bits);
        let n = rand_odd_bn(bits);
        let mut group = c.benchmark_group("bn_modmul");
        group.throughput(Throughput::Elements(1));
        group.bench_function(bits.to_string(), |bench| {
            bench.iter(|| black_box(a.modmul(black_box(&b), black_box(&n))))
        });
        group.finish();
    }
}

criterion_group!(
    benches,
    bench_bn_mul,
    bench_bn_mont_mul,
    bench_bn_mont_pow,
    bench_bn_mod_pow,
    bench_bn_modmul
);
criterion_main!(benches);
