use chacha20poly1305::aead::AeadMutInPlace;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kittycrypto::cipher::Aead;
use rc4::KeyInit;

fn bench_chacha20poly1305(c: &mut Criterion) {
    let case = [128, 512, 1024, 2048, 8192];
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;
    let mut nonce = [0u8; 24];
    rand::fill(&mut nonce);
    let nonce = nonce;

    for size in case {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());

        let mut group = c.benchmark_group("crypto");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("kittycrypto_{size}",), |b| {
            let cipher = kittycrypto::chacha20poly1305::XChaCha20Poly1305::new(&key).unwrap();
            b.iter(|| {
                let mut dst = data.clone();
                cipher
                    .seal_in_place_append_tag(&mut dst, &nonce, &[])
                    .unwrap();
            })
        });

        group.bench_function(format!("rustcrypto_{size}",), |b| {
            let mut cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
            b.iter(|| {
                let mut dst = data.clone();
                cipher
                    .encrypt_in_place(&nonce.into(), &[], &mut dst)
                    .unwrap();
            })
        });

        group.finish();
    }

    for size in case {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());
        let cipher = kittycrypto::chacha20poly1305::XChaCha20Poly1305::new(&key).unwrap();
        cipher
            .seal_in_place_append_tag(&mut data, &nonce, &[])
            .unwrap();

        let mut group = c.benchmark_group("decrypt");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("kittycrypto_{size}",), |b| {
            let cipher = kittycrypto::chacha20poly1305::XChaCha20Poly1305::new(&key).unwrap();
            b.iter(|| {
                let mut dst = data.clone();
                cipher.open_in_place(&mut dst, &nonce, &[]).unwrap();
            })
        });

        group.bench_function(format!("rustcrypto_{size}",), |b| {
            let mut cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
            b.iter(|| {
                let mut dst = data.clone();
                cipher
                    .decrypt_in_place(&nonce.into(), &[], &mut dst)
                    .unwrap();
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_chacha20poly1305);

criterion_main!(benches);
