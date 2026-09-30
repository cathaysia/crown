use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::aead::gcm::Gcm;
use crown::aead::Aead;
use crown::block::aes::Aes;

fn bench_gcm(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];

    for size in [16, 64, 256, 1024, 8192, 65536] {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());
        let mut group = c.benchmark_group("aes256_gcm");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_seal_{size}"), |b| {
            let gcm = Aes::new(&key).unwrap().to_gcm().unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = gcm
                    .seal_in_place_separate_tag(&mut buf, &nonce, &[])
                    .unwrap();
                black_box(tag);
            })
        });
        group.bench_function(format!("rustcrypto_seal_{size}"), |b| {
            use aes_gcm::aead::AeadMutInPlace;
            use cipher::KeyInit;
            let mut gcm = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = gcm
                    .encrypt_in_place(nonce.as_slice().into(), &[], &mut buf)
                    .unwrap();
                black_box(tag);
            })
        });
        group.bench_function(format!("ring_seal_{size}"), |b| {
            let gcm = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key).unwrap(),
            );
            let mut buf = data.clone();
            b.iter(|| {
                let tag = gcm
                    .seal_in_place_separate_tag(
                        ring::aead::Nonce::assume_unique_for_key(nonce),
                        ring::aead::Aad::empty(),
                        &mut buf,
                    )
                    .unwrap();
                black_box(tag);
            })
        });

        group.finish();
    }
}

fn bench_poly1305(c: &mut Criterion) {
    let key = [0x42u8; 32];

    for size in [64, 1024, 16384] {
        let data = vec![0u8; size];
        let mut group = c.benchmark_group("poly1305");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            b.iter(|| black_box(crown::mac::poly1305::sum(black_box(&data), &key)))
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use poly1305::universal_hash::{KeyInit, UniversalHash};
            let key = poly1305::Key::from_slice(&key);
            b.iter(|| {
                let mut mac = poly1305::Poly1305::new(key);
                mac.update_padded(black_box(&data));
                black_box(mac.finalize())
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_gcm, bench_poly1305);
criterion_main!(benches);
