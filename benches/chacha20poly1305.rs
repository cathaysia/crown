use chacha20poly1305::aead::AeadMutInPlace;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rc4::KeyInit;
use ring::aead::UnboundKey;

fn bench_chacha20poly1305(c: &mut Criterion) {
    let case = [128, 512, 1024, 2048, 8192];
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;
    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce);
    let nonce = nonce;

    for size in case {
        let mut buf = vec![0u8; size + 1];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        let data = vec![0u8; size];

        let mut group = c.benchmark_group("chacha20_poly1305");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("kittycrypto_{size}",), |b| {
            let cipher = kittycrypto::chacha20ploy1305::ChaCha20Poly1305::new(&key).unwrap();
            b.iter(|| {
                let mut dst = vec![];
                cipher.seal(&mut dst, &nonce, &data, &[]).unwrap();
            })
        });

        group.bench_function(format!("rustcrypto_{size}",), |b| {
            let mut cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).unwrap();
            b.iter(|| {
                let mut dst = data.clone();
                cipher
                    .encrypt_in_place(&nonce.into(), &[], &mut dst)
                    .unwrap();
            })
        });

        group.bench_function(format!("ring_{size}",), |b| {
            let cipher = ring::aead::LessSafeKey::new(
                UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap(),
            );

            b.iter(|| {
                let mut dst = data.clone();
                cipher
                    .seal_in_place_append_tag(
                        ring::aead::Nonce::assume_unique_for_key(nonce),
                        ring::aead::Aad::from(&[]),
                        &mut dst,
                    )
                    .unwrap();
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_chacha20poly1305);

criterion_main!(benches);
