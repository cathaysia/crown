use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::block::aes::Aes;
use crown::modes::cbc::{CbcDecryptor, CbcEncryptor};
use crown::modes::cfb::Cfb;
use crown::modes::ctr::Ctr;
use crown::modes::ofb::Ofb;
use crown::modes::xts::Xts;
use crown::modes::BlockMode;
use crown::stream::StreamCipher;

fn bench_cbc(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 16];

    for size in [512, 4096] {
        let data = vec![0u8; size];
        let mut group = c.benchmark_group("aes128_cbc");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_encrypt_{size}"), |b| {
            let mut mode = Aes::new(&key).unwrap().to_cbc_enc(&iv);
            let mut buf = data.clone();
            b.iter(|| {
                mode.encrypt(&mut buf);
                black_box(&buf);
            })
        });
        group.bench_function(format!("rustcrypto_encrypt_{size}"), |b| {
            use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
            let mode = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv).unwrap();
            let mut buf = vec![0u8; size + 16];
            b.iter(|| {
                let out = mode
                    .clone()
                    .encrypt_padded_b2b_mut::<Pkcs7>(&data, &mut buf)
                    .unwrap();
                black_box(out);
            })
        });
        group.bench_function(format!("crown_decrypt_{size}"), |b| {
            let mut mode = Aes::new(&key).unwrap().to_cbc_enc(&iv);
            let mut buf = data.clone();
            mode.encrypt(&mut buf);
            let ct = buf.clone();
            // The crate's BlockMode follows Go's CryptBlocks semantics: the
            // decrypter performs CBC decryption through `encrypt`.
            let mut dec = Aes::new(&key).unwrap().to_cbc_dec(&iv);
            b.iter(|| {
                let mut buf = ct.clone();
                dec.encrypt(&mut buf);
                black_box(&buf);
            })
        });
        group.bench_function(format!("rustcrypto_decrypt_{size}"), |b| {
            use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
            let mode = cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv).unwrap();
            let enc = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv).unwrap();
            let mut ct_buf = vec![0u8; size + 16];
            let ct = enc
                .encrypt_padded_b2b_mut::<Pkcs7>(&data, &mut ct_buf)
                .unwrap()
                .to_vec();
            b.iter(|| {
                let mut out = vec![0u8; size + 16];
                let out = mode
                    .clone()
                    .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut out)
                    .unwrap();
                black_box(out);
            })
        });

        group.finish();
    }
}

fn bench_ctr(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 16];

    for size in [512, 4096] {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());
        let mut group = c.benchmark_group("aes128_ctr");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            let mut cipher = Aes::new(&key).unwrap().to_ctr(&iv).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                cipher.xor_key_stream(&mut buf).unwrap();
                black_box(&buf);
            })
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use cipher::{KeyIvInit, StreamCipher};
            let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&key, &iv).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                cipher.apply_keystream(&mut buf);
                black_box(&buf);
            })
        });

        group.finish();
    }
}

fn bench_xts(c: &mut Criterion) {
    let mut key = [0x42u8; 32];
    key[16..].fill(0x24);
    let tweak = [0x24u8; 16];

    for size in [512, 4096] {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());
        let mut group = c.benchmark_group("aes256_xts");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_encrypt_{size}"), |b| {
            let xts = Xts::<Aes>::new(&key).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                xts.encrypt(&tweak, &mut buf).unwrap();
                black_box(&buf);
            })
        });
        group.bench_function(format!("rustcrypto_encrypt_{size}"), |b| {
            use cipher::KeyInit;
            // XTS-AES-256: two AES-128 halves over the 32-byte combined key.
            let c1 = aes::Aes128::new_from_slice(&key[..16]).unwrap();
            let c2 = aes::Aes128::new_from_slice(&key[16..]).unwrap();
            let xts = xts_mode::Xts128::<aes::Aes128>::new(c1, c2);
            let mut buf = data.clone();
            b.iter(|| {
                xts.encrypt_area(&mut buf, size, 0, |_| tweak);
                black_box(&buf);
            })
        });

        group.finish();
    }
}

fn bench_key_wrap(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let aes = Aes::new(&key).unwrap();

    for size in [32, 256] {
        let pt = vec![0u8; size];
        let ct = crown::modes::kw::key_wrap(&aes, &pt).unwrap();
        assert_eq!(crown::modes::kw::key_unwrap(&aes, &ct).unwrap(), pt);

        let mut group = c.benchmark_group(format!("aes128_kw_{size}"));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("crown_wrap_{size}"), |b| {
            b.iter(|| black_box(crown::modes::kw::key_wrap(&aes, black_box(&pt)).unwrap()))
        });
        group.bench_function(format!("crown_unwrap_{size}"), |b| {
            b.iter(|| black_box(crown::modes::kw::key_unwrap(&aes, black_box(&ct)).unwrap()))
        });
        group.finish();
    }

    // RFC 5649 padded wrap with a non-multiple-of-8 payload.
    let pt = vec![0u8; 100];
    let mut group = c.benchmark_group("aes128_kwp");
    group.throughput(Throughput::Bytes(100));
    group.bench_function("crown_wrap_padded", |b| {
        b.iter(|| black_box(crown::modes::kw::key_wrap_padded(&aes, black_box(&pt)).unwrap()))
    });
    group.finish();
}

fn bench_ff1(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let tweak = [0x24u8; 7];
    let numeral = "1234567890123456789";

    let ct = crown::modes::ff1::ff1_encrypt_decimal(&key, &tweak, numeral).unwrap();
    assert_eq!(
        crown::modes::ff1::ff1_decrypt_decimal(&key, &tweak, &ct).unwrap(),
        numeral
    );

    let mut group = c.benchmark_group("ff1_aes128_decimal19");
    group.throughput(Throughput::Elements(1));
    group.bench_function("crown_encrypt", |b| {
        b.iter(|| {
            black_box(
                crown::modes::ff1::ff1_encrypt_decimal(black_box(&key), &tweak, numeral).unwrap(),
            )
        })
    });
    group.bench_function("crown_decrypt", |b| {
        b.iter(|| {
            black_box(crown::modes::ff1::ff1_decrypt_decimal(black_box(&key), &tweak, &ct).unwrap())
        })
    });
    group.finish();
}

fn bench_cts(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 16];
    let cts = crown::modes::cts::Cts::new(Aes::new(&key).unwrap(), &iv).unwrap();

    for size in [512, 4096] {
        let pt = vec![0u8; size];
        let ct = cts.encrypt(&pt).unwrap();
        assert_eq!(cts.decrypt(&ct).unwrap(), pt);

        let mut group = c.benchmark_group(format!("aes128_cts_cs3_{size}"));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("crown_encrypt_{size}"), |b| {
            b.iter(|| black_box(cts.encrypt(black_box(&pt)).unwrap()))
        });
        group.bench_function(format!("crown_decrypt_{size}"), |b| {
            b.iter(|| black_box(cts.decrypt(black_box(&ct)).unwrap()))
        });
        group.finish();
    }
}

fn bench_cfb_ofb(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 16];

    for size in [512, 4096] {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());

        let mut group = c.benchmark_group(format!("aes128_stream_{size}"));
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_cfb_encrypt_{size}"), |b| {
            let mut cipher = Aes::new(&key).unwrap().to_cfb_encryptor(&iv).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                cipher.xor_key_stream(&mut buf).unwrap();
                black_box(&buf);
            })
        });
        group.bench_function(format!("crown_ofb_{size}"), |b| {
            let mut cipher = Aes::new(&key).unwrap().to_ofb(&iv).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                cipher.xor_key_stream(&mut buf).unwrap();
                black_box(&buf);
            })
        });

        group.finish();
    }
}

criterion_group!(
    benches,
    bench_cbc,
    bench_ctr,
    bench_xts,
    bench_key_wrap,
    bench_ff1,
    bench_cts,
    bench_cfb_ofb
);
criterion_main!(benches);
