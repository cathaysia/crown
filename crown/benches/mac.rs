use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::block::aes::Aes;
use crown::core::CoreWrite;
use crown::hash::{Hash, HashUser};

fn bench_kmac(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let custom = b"crown-bench";

    for size in [64, 1024] {
        let data = vec![0u8; size];
        let mut group = c.benchmark_group("kmac128");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            b.iter(|| {
                let mut mac = crown::mac::kmac::Kmac128::new(&key, custom).unwrap();
                mac.write(black_box(&data));
                let mut out = [0u8; 32];
                mac.sum(&mut out);
                black_box(out)
            })
        });

        group.finish();
    }
}

fn bench_cmac(c: &mut Criterion) {
    let key = [0x42u8; 16];

    for size in [64, 1024] {
        let data = vec![0u8; size];
        let mut group = c.benchmark_group("cmac_aes128");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            b.iter(|| {
                black_box(
                    crown::mac::cmac::sum::<Aes, 16>(Aes::new(&key).unwrap(), black_box(&data))
                        .unwrap(),
                )
            })
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use cmac::{Cmac, Mac};
            b.iter(|| {
                let mut mac = Cmac::<aes::Aes128>::new_from_slice(&key).unwrap();
                Mac::update(&mut mac, black_box(&data));
                black_box(mac.finalize())
            })
        });

        group.finish();
    }
}

fn bench_gmac(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];

    for size in [64, 1024] {
        let data = vec![0u8; size];
        let mut group = c.benchmark_group("gmac_aes128");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            b.iter(|| {
                black_box(
                    crown::mac::gmac::sum(Aes::new(&key).unwrap(), &iv, black_box(&data)).unwrap(),
                )
            })
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use ghash::universal_hash::{KeyInit, UniversalHash};
            // GHASH is the universal hash behind GMAC; the keyed GHASH
            // comparison isolates the GF(2^128) multiply cost.
            b.iter(|| {
                let mut g = ghash::GHash::new_from_slice(&key).unwrap();
                UniversalHash::update_padded(&mut g, black_box(&data));
                black_box(g.finalize())
            })
        });

        group.finish();
    }
}

fn bench_siphash(c: &mut Criterion) {
    let key = [0x42u8; 16];

    for size in [64, 1024] {
        let data = vec![0u8; size];
        let mut group = c.benchmark_group("siphash24_128");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            b.iter(|| black_box(crown::mac::siphash::sum(black_box(&data), &key)))
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use siphasher::sip::SipHasher;
            use std::hash::Hasher;
            let k0 = u64::from_be_bytes(key[..8].try_into().unwrap());
            let k1 = u64::from_be_bytes(key[8..].try_into().unwrap());
            b.iter(|| {
                let mut h = SipHasher::new_with_keys(k0, k1);
                h.write(black_box(&data));
                black_box(h.finish())
            })
        });

        group.finish();
    }
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let key = [0x42u8; 32];

    for size in [64, 1024] {
        let data = vec![0u8; size];
        let mut group = c.benchmark_group("hmac_sha256");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            let mut mac = crown::mac::hmac::new::<32, _, _>(crown::hash::sha256::new256, &key);
            b.iter(|| {
                mac.reset();
                let _ = mac.write(black_box(&data));
                black_box(mac.sum())
            })
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use hmac::Mac;
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
            b.iter(|| {
                mac.update(black_box(&data));
                black_box(mac.finalize_reset())
            })
        });

        group.finish();
    }
}

criterion_group!(
    benches,
    bench_kmac,
    bench_cmac,
    bench_gmac,
    bench_siphash,
    bench_hmac_sha256
);
criterion_main!(benches);
