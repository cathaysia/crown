use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

fn bench_blake2b(c: &mut Criterion) {
    for size in [128, 1024, 65536] {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());
        let mut group = c.benchmark_group("blake2b512");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            b.iter(|| black_box(crown::hash::blake2b::sum512(black_box(&data))))
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use blake2::Digest;
            b.iter(|| {
                let mut h = blake2::Blake2b512::new();
                h.update(black_box(&data));
                black_box(h.finalize())
            })
        });

        group.finish();
    }
}

fn bench_sm3(c: &mut Criterion) {
    for size in [128, 1024, 65536] {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());
        let mut group = c.benchmark_group("sm3");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            b.iter(|| black_box(crown::hash::sm3::sum_sm3(black_box(&data))))
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use sm3::Digest;
            b.iter(|| {
                let mut h = sm3::Sm3::new();
                h.update(black_box(&data));
                black_box(h.finalize())
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_blake2b, bench_sm3);
criterion_main!(benches);
