use aes_gcm::aead::AeadMutInPlace;
use cipher::KeyInit;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use crown::aead::gcm::Gcm;
use crown::aead::Aead;
use std::hint::black_box;

fn bench_aes_gcm(c: &mut Criterion) {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;

    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce);
    let nonce = nonce;

    let case = [128, 1024];

    for size in case {
        let mut buf = vec![0u8; size + 1];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        let data = vec![0u8; size];

        let mut group = c.benchmark_group("aes_gcm");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}",), |b| {
            let cipher = crown::block::aes::Aes::new(&key).unwrap().to_gcm().unwrap();
            let mut dst = data.clone();
            b.iter(|| {
                let _ = cipher.seal_in_place_separate_tag(black_box(&mut dst), &nonce, &[]);
            })
        });

        group.bench_function(format!("rustcrypto_{size}",), |b| {
            let mut cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
            b.iter(|| {
                let mut data = data.clone();
                cipher.encrypt_in_place(&nonce.into(), &[], black_box(&mut data))
            })
        });

        group.bench_function(format!("ring_{size}",), |b| {
            let cipher = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key).unwrap(),
            );
            b.iter(|| {
                let mut data = data.clone();
                cipher.seal_in_place_separate_tag(
                    ring::aead::Nonce::assume_unique_for_key(nonce),
                    ring::aead::Aad::empty(),
                    black_box(&mut data),
                )
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_aes_gcm);

criterion_main!(benches);
