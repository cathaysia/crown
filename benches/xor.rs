use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kittytls::subtle::xor::xor_bytes;
use std::hint::black_box;

fn bench_xor(c: &mut Criterion) {
    let case = [
        8,
        64,
        128,
        256,
        512,
        1024,
        8192,
        1024 * 1024,
        8 * 1024 * 1024,
    ];
    for size in case {
        let mut group = c.benchmark_group("xor");
        group.throughput(Throughput::Bytes(size as u64));

        let mut dst = vec![0u8; size];
        let mut x = vec![0u8; size];
        let mut y = vec![0u8; size];

        rand::fill(x.as_mut_slice());
        rand::fill(y.as_mut_slice());

        group.bench_function(format!("kittytls_xor_{size}"), |b| {
            b.iter(|| {
                xor_bytes(black_box(&mut dst), black_box(&x), black_box(&y));
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_xor);

criterion_main!(benches);
