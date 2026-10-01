use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

fn bench_hash(c: &mut Criterion) {
    for size in [64, 1024, 65536] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

        let mut group = c.benchmark_group(format!("hash_misc_{size}"));
        group.throughput(Throughput::Bytes(size as u64));

        macro_rules! one {
            ($name:literal, $f:expr) => {
                group.bench_function(concat!($name, "_crown"), |b| {
                    b.iter(|| black_box(($f)(black_box(&data))))
                });
            };
        }

        one!("whirlpool", crown::hash::whirlpool::sum_whirlpool);
        one!("ripemd160", crown::hash::ripemd160::sum_ripemd160);
        one!("mdc2", crown::hash::mdc2::sum_mdc2);
        one!("md5_sha1", crown::hash::md5_sha1::sum_md5_sha1);
        one!("md2", crown::hash::md2::sum_md2);
        one!("md4", crown::hash::md4::sum_md4);
        one!("blake2s", crown::hash::blake2s::sum256);
        one!("sha1", crown::hash::sha1::sum);

        if size <= 1024 {
            group.bench_function("whirlpool_rustcrypto", |b| {
                use whirlpool::Digest;
                b.iter(|| {
                    let mut h = whirlpool::Whirlpool::new();
                    Digest::update(&mut h, black_box(&data));
                    black_box(Digest::finalize(h))
                })
            });
            group.bench_function("ripemd160_rustcrypto", |b| {
                use ripemd::Digest;
                b.iter(|| {
                    let mut h = ripemd::Ripemd160::new();
                    Digest::update(&mut h, black_box(&data));
                    black_box(Digest::finalize(h))
                })
            });
            group.bench_function("md4_rustcrypto", |b| {
                use md4::Digest;
                b.iter(|| {
                    let mut h = md4::Md4::new();
                    Digest::update(&mut h, black_box(&data));
                    black_box(Digest::finalize(h))
                })
            });
            group.bench_function("blake2s_rustcrypto", |b| {
                use blake2::Digest;
                b.iter(|| {
                    let mut h = blake2::Blake2s256::new();
                    Digest::update(&mut h, black_box(&data));
                    black_box(Digest::finalize(h))
                })
            });
            group.bench_function("sha1_rustcrypto", |b| {
                use sha1::Digest;
                b.iter(|| {
                    let mut h = sha1::Sha1::new();
                    Digest::update(&mut h, black_box(&data));
                    black_box(Digest::finalize(h))
                })
            });
        }

        group.finish();
    }
}

criterion_group!(benches, bench_hash);
criterion_main!(benches);
