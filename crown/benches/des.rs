use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn bench_des(c: &mut Criterion) {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;

    let mut block = [0u8; 4];
    rand::fill(&mut block);

    let mut iv = [0u8; 16];
    rand::fill(&mut iv);

    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce);

    let cases = [128, 512, 1024];

    for i in cases {
        let mut block = vec![0u8; i];
        rand::fill(block.as_mut_slice());

        let mut group = c.benchmark_group(format!("des_cbc_{i}"));
        group.throughput(Throughput::Bytes(i as u64));

        group.bench_function("crown".to_string(), |b| {
            let mut cipher = crown::envelope::EvpBlockCipher::new_des_cbc(&key, &iv).unwrap();
            let mut block = block.to_vec();
            b.iter(|| {
                let _ = cipher.encrypt_alloc(&mut block);
            })
        });

        group.bench_function("boring".to_string(), |b| {
            let cipher = boring::symm::Cipher::des_cbc();

            b.iter(|| {
                let _ = boring::symm::encrypt(cipher, &key, Some(&iv), &block);
            });
        });
        group.finish();
    }

    for i in cases {
        let mut block = vec![0u8; i];
        rand::fill(block.as_mut_slice());

        let mut group = c.benchmark_group(format!("des_ctr_{i}"));
        group.throughput(Throughput::Bytes(i as u64));

        group.bench_function("crown".to_string(), |b| {
            let mut cipher = crown::envelope::EvpStreamCipher::new_des_ctr(&key, &iv).unwrap();
            let block = block.as_mut_slice();
            b.iter(|| {
                let _ = cipher.encrypt(block);
            })
        });

        group.bench_function("boring".to_string(), |b| {
            let cipher = boring::symm::Cipher::des_cbc();

            b.iter(|| {
                let _ = boring::symm::encrypt(cipher, &key, Some(&iv), &block);
            });
        });
        group.finish();
    }

    for i in cases {
        let mut block = vec![0u8; i];
        rand::fill(block.as_mut_slice());

        let mut group = c.benchmark_group(format!("des_gcm_{i}"));
        group.throughput(Throughput::Bytes(i as u64));

        group.bench_function("crown".to_string(), |b| {
            let cipher = crown::envelope::EvpAeadCipher::new_des_gcm(&key).unwrap();
            let block = &mut block;
            b.iter(|| {
                let _ = cipher.seal_in_place_separate_tag(block, &nonce, &[]);
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_des);

criterion_main!(benches);
