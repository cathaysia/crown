use cipher::{generic_array::GenericArray, BlockEncrypt, KeyIvInit};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use crown::stream::StreamCipher;
use crown::{block::BlockCipher, modes::ctr::Ctr};
use rc4::KeyInit;
use std::hint::black_box;

fn bench_twofish(c: &mut Criterion) {
    const BLOCK_SIZE: usize = 16;
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;

    let mut pt = [0u8; 4];
    rand::fill(&mut pt);

    let mut group = c.benchmark_group("block");
    group.throughput(Throughput::Bytes(BLOCK_SIZE as u64));

    group.bench_function("crown".to_string(), |b| {
        let cipher = crown::block::twofish::Twofish::new(&key).unwrap();
        b.iter(|| {
            let mut dst = pt;
            for i in (0..pt.len()).step_by(BLOCK_SIZE) {
                let end = (i + BLOCK_SIZE).min(pt.len());
                if end - i == BLOCK_SIZE {
                    cipher.encrypt(black_box(&mut dst[i..end]));
                }
            }
        })
    });

    group.bench_function("rustcrypto".to_string(), |b| {
        let cipher = twofish::Twofish::new(&key.into());

        b.iter(|| {
            let mut dst = pt;
            for chunk in dst.chunks_exact_mut(BLOCK_SIZE) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.encrypt_block(black_box(block));
            }
        })
    });

    group.finish();

    for size in [128usize, 512, 1024, 2048] {
        let mut group = c.benchmark_group(format!("ctr_{size}"));
        group.throughput(Throughput::Bytes(size as _));
        let mut iv = [0u8; BLOCK_SIZE];
        rand::fill(&mut iv);

        let mut pt = vec![0u8; size];
        rand::fill(pt.as_mut_slice());

        group.bench_function("crown".to_string(), |b| {
            let mut cipher = crown::block::twofish::Twofish::new(&key)
                .unwrap()
                .to_ctr(&iv)
                .unwrap();
            b.iter(|| {
                let mut dst = pt.clone();
                cipher.xor_key_stream(black_box(&mut dst)).unwrap();
            })
        });

        group.bench_function("rustcrypto".to_string(), |b| {
            type Aes256Ctr64Be = ctr::Ctr64BE<twofish::Twofish>;
            let mut cipher = Aes256Ctr64Be::new_from_slices(&key, &[0u8; 16]).unwrap();

            b.iter(|| {
                let mut dst = pt.clone();
                cipher::StreamCipher::apply_keystream(&mut cipher, black_box(&mut dst));
            })
        });
        group.finish();
    }
}

criterion_group!(benches, bench_twofish);

criterion_main!(benches);
