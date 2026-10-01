use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::bn::Bn;
use crown::ec::{field_bytes, CurveId};
use crown::ecdsa::DigestId;

struct BenchRng;

impl crown::rng::Rng for BenchRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        rand::fill(out);
    }
}

/// Random scalar below 2^(bits-1) so it comfortably fits the group order.
fn rand_scalar(bytes: usize, top_mask: u8) -> Bn {
    let mut b = vec![0u8; bytes];
    rand::fill(b.as_mut_slice());
    b[0] &= top_mask;
    b[bytes - 1] |= 1;
    Bn::from_be_bytes(&b)
}

/// r||s big-endian, each padded to the curve field size.
fn sig_bytes(r: &Bn, s: &Bn, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; 2 * n];
    out[..n].copy_from_slice(&r.to_be_bytes_padded(n).unwrap());
    out[n..].copy_from_slice(&s.to_be_bytes_padded(n).unwrap());
    out
}

fn bench_p384(c: &mut Criterion) {
    let curve = crown::ec::curve(CurveId::P384);
    let fb = field_bytes(&curve);
    let d = rand_scalar(fb, 0x7f);
    let msg: [u8; 48] = core::array::from_fn(|i| i as u8);
    let peer = crown::ec::mul_base(&curve, &rand_scalar(fb, 0x7f));

    let mut group = c.benchmark_group("p384");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_mul_base", |b| {
        b.iter(|| black_box(crown::ec::mul_base(black_box(&curve), black_box(&d))))
    });
    group.bench_function("rustcrypto_public_from_secret", |b| {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        use p384::SecretKey;
        let secret = SecretKey::from_slice(&d.to_be_bytes_padded(fb).unwrap()).unwrap();
        b.iter(|| black_box(secret.public_key().to_encoded_point(false)))
    });

    let priv_key = rand_scalar(fb, 0x7f);
    group.bench_function("crown_ecdh", |b| {
        b.iter(|| {
            black_box(crown::ecdh::agree(CurveId::P384, black_box(&priv_key), &peer).unwrap())
        })
    });
    group.bench_function("rustcrypto_ecdh", |b| {
        use p384::ecdh::EphemeralSecret;
        use p384::elliptic_curve::rand_core::OsRng;
        use p384::PublicKey;
        let peer = PublicKey::from_sec1_bytes(&peer.to_bytes_with(&curve)).unwrap();
        let secret = EphemeralSecret::random(&mut OsRng);
        b.iter(|| black_box(secret.diffie_hellman(&peer)))
    });

    let (r, s) =
        crown::ecdsa::sign(CurveId::P384, DigestId::Sha384, &d, &msg, &mut BenchRng).unwrap();
    let sig = sig_bytes(&r, &s, fb);
    group.bench_function("crown_sign", |b| {
        b.iter(|| {
            black_box(
                crown::ecdsa::sign(
                    CurveId::P384,
                    DigestId::Sha384,
                    black_box(&d),
                    &msg,
                    &mut BenchRng,
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("crown_verify", |b| {
        b.iter(|| {
            black_box(
                crown::ecdsa::verify(
                    CurveId::P384,
                    DigestId::Sha384,
                    black_box(&peer),
                    &msg,
                    black_box(&r),
                    &s,
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("rustcrypto_sign", |b| {
        use p384::ecdsa::signature::Signer;
        use p384::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(&d.to_be_bytes_padded(fb).unwrap()).unwrap();
        b.iter(|| {
            let sig: p384::ecdsa::Signature = sk.sign(black_box(&msg));
            black_box(sig)
        })
    });
    group.bench_function("rustcrypto_verify", |b| {
        use p384::ecdsa::signature::Verifier;
        use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
        let sk = SigningKey::from_slice(&d.to_be_bytes_padded(fb).unwrap()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let sig = Signature::from_slice(&sig).unwrap();
        b.iter(|| black_box(vk.verify(black_box(&msg), &sig).is_ok()))
    });

    group.finish();
}

fn bench_p521(c: &mut Criterion) {
    let curve = crown::ec::curve(CurveId::P521);
    let fb = field_bytes(&curve);
    // 66 bytes = 528 bits; keep the scalar below 2^521.
    let d = rand_scalar(fb, 0x01);
    let msg: [u8; 64] = core::array::from_fn(|i| i as u8);
    let peer = crown::ec::mul_base(&curve, &rand_scalar(fb, 0x01));

    let mut group = c.benchmark_group("p521");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_mul_base", |b| {
        b.iter(|| black_box(crown::ec::mul_base(black_box(&curve), black_box(&d))))
    });
    group.bench_function("rustcrypto_public_from_secret", |b| {
        use p521::elliptic_curve::sec1::ToEncodedPoint;
        use p521::SecretKey;
        let secret = SecretKey::from_slice(&d.to_be_bytes_padded(fb).unwrap()).unwrap();
        b.iter(|| black_box(secret.public_key().to_encoded_point(false)))
    });

    let priv_key = rand_scalar(fb, 0x01);
    group.bench_function("crown_ecdh", |b| {
        b.iter(|| {
            black_box(crown::ecdh::agree(CurveId::P521, black_box(&priv_key), &peer).unwrap())
        })
    });
    group.bench_function("rustcrypto_ecdh", |b| {
        use p521::ecdh::EphemeralSecret;
        use p521::elliptic_curve::rand_core::OsRng;
        use p521::PublicKey;
        let peer = PublicKey::from_sec1_bytes(&peer.to_bytes_with(&curve)).unwrap();
        let secret = EphemeralSecret::random(&mut OsRng);
        b.iter(|| black_box(secret.diffie_hellman(&peer)))
    });

    let (r, s) =
        crown::ecdsa::sign(CurveId::P521, DigestId::Sha512, &d, &msg, &mut BenchRng).unwrap();
    let sig = sig_bytes(&r, &s, fb);
    group.bench_function("crown_sign", |b| {
        b.iter(|| {
            black_box(
                crown::ecdsa::sign(
                    CurveId::P521,
                    DigestId::Sha512,
                    black_box(&d),
                    &msg,
                    &mut BenchRng,
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("crown_verify", |b| {
        b.iter(|| {
            black_box(
                crown::ecdsa::verify(
                    CurveId::P521,
                    DigestId::Sha512,
                    black_box(&peer),
                    &msg,
                    black_box(&r),
                    &s,
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("rustcrypto_sign", |b| {
        use p521::ecdsa::signature::Signer;
        use p521::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(&d.to_be_bytes_padded(fb).unwrap()).unwrap();
        b.iter(|| {
            let sig: p521::ecdsa::Signature = sk.sign(black_box(&msg));
            black_box(sig)
        })
    });
    group.bench_function("rustcrypto_verify", |b| {
        use p521::ecdsa::signature::Verifier;
        use p521::ecdsa::{Signature, SigningKey, VerifyingKey};
        let sk = SigningKey::from_slice(&d.to_be_bytes_padded(fb).unwrap()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let sig = Signature::from_slice(&sig).unwrap();
        b.iter(|| black_box(vk.verify(black_box(&msg), &sig).is_ok()))
    });

    group.finish();
}

criterion_group!(benches, bench_p384, bench_p521);
criterion_main!(benches);
