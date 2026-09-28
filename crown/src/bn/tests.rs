use super::*;

fn hex_to_bn(s: &str) -> Bn {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect::<alloc::vec::Vec<u8>>();
    Bn::from_be_bytes(&bytes)
}

#[test]
fn add_sub_mul_roundtrip() {
    let a = hex_to_bn("ffffffffffffffff0000000000000001");
    let b = hex_to_bn("123456789abcdef0123456789abcdef0");
    let sum = a.add(&b);
    assert_eq!(sum.sub(&b).unwrap(), a);
    assert_eq!(sum.sub(&a).unwrap(), b);

    let prod = a.mul(&b);
    let (q, r) = prod.divrem(&b).unwrap();
    assert_eq!(q, a);
    assert_eq!(r, Bn::zero());
}

#[test]
fn divrem_basic() {
    let a = hex_to_bn("deadbeefcafebabe0123456789abcdefdeadbeef");
    let b = hex_to_bn("abcdef0123456789");
    let (q, r) = a.divrem(&b).unwrap();
    assert_eq!(a, q.mul(&b).add(&r));
    assert!(r.lt(&b));

    // remainder by small divisor matches the generic path
    let r_small = a.rem_small(97);
    assert_eq!(
        r_small as u64,
        a.modulus(&Bn::from_u64(97))
            .limbs
            .first()
            .copied()
            .unwrap_or(0)
    );
}

#[test]
fn bit_helpers() {
    let v = hex_to_bn("ff00ff00ff00ff00ff00ff00ff00ff00");
    assert_eq!(v.bit_len(), 128);
    assert!(v.bit(120));
    assert!(!v.is_odd());
    let mut odd = v.clone();
    odd.set_bit(0);
    assert!(odd.is_odd());
}

// A 512-bit odd modulus (primality is irrelevant for the Montgomery
// roundtrip).
const ODD_N: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01";

// Montgomery: (a * R) * (b * R) -> a * b (mod n) after converting back.
#[test]
fn montgomery_roundtrip() {
    let n = hex_to_bn(ODD_N);
    let a = hex_to_bn("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0");
    let b = hex_to_bn("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

    let mont = Montgomery::new(&n).unwrap();
    let am = mont.to_mont(&a);
    let bm = mont.to_mont(&b);
    let ab = mont.from_mont(&mont.mul(&am, &bm));
    assert_eq!(ab, a.modmul(&b, &n));

    // Exponentiation agrees with the plain square-and-multiply path.
    let e = hex_to_bn("010001");
    let expect = a.mod_pow(&e, &n).unwrap();
    let got = a.mod_pow_odd(&e, &n).unwrap();
    assert_eq!(expect, got);
}

#[test]
fn modular_inverse() {
    // 3^-1 mod 11 == 4
    let inv = Bn::from_u64(3).mod_inverse(&Bn::from_u64(11)).unwrap();
    assert_eq!(inv, Bn::from_u64(4));

    // e = 65537 inverse mod (p-1)(q-1) for two small primes.
    let p = hex_to_bn("e7e2eeaf94a2ec4f78d070c14c4cee76");
    let q = hex_to_bn("d1c90a4444ba8e0af7f98c26d6cba869");
    let phi = p.sub(&Bn::one()).unwrap().mul(&q.sub(&Bn::one()).unwrap());
    let e = Bn::from_u64(65537);
    let d = e.mod_inverse(&phi).unwrap();
    // e * d == 1 (mod phi)
    let check = e.mul(&d).modulus(&phi);
    assert_eq!(check, Bn::one());

    // No inverse when gcd != 1.
    assert!(Bn::from_u64(4).mod_inverse(&Bn::from_u64(8)).is_err());
}

// Large division cross-checked against Python.
#[test]
fn divrem_large() {
    let a = hex_to_bn("073618bfc574218f09103b3205c35057d7477837e19cfde69e145cdbebf344fbe893b410ac4ed5c0713851ea9db6c97711a277fdbfb40500d15f54d39f869cc740480a1d640b42adb7a9aad95331e61658fc9e97e0e21b823afdc01adc6c889c73a42c647c44de32ea2e59092f77911b9757ecba09e47a021efbaac162aa56cd");
    let b = hex_to_bn("b6f675cc81e74ef5e8e25d940ed904759531985d5d9dc9f81818e811892f902bd23f0824128b2f330c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b439");
    let (q, r) = a.divrem(&b).unwrap();
    assert_eq!(q, hex_to_bn("0a170b3339263059f28c105d1fb17c2390c192cfd3ac94af0f21ddb66cad4a268d116ece1738f7d93d9c172411e20b8f6b0d549b6f03675a1600a35a099950d8"));
    assert_eq!(r, hex_to_bn("06b4cb4a23d5962217beaddbc496cb8e81973e0becd7b03898d190f9ebdacc0cb1e29c658cda1495e60af593bd04cf0fd630f1f29d0da9953f48f1a09f76b5"));
    assert_eq!(a, q.mul(&b).add(&r));
}

// The quotient estimate must be corrected against `b*rhat + u[j+n-2]`; with
// the wrong low half the estimate stays one too large for some operands and
// the division silently returns `q*v > u` (this case was found through
// wycheproof's RSA keys, where it panicked in debug builds).
#[test]
fn divrem_qhat_correction() {
    let a = hex_to_bn("ba28a6794d4ca9c767c98fb9736506ecae7c8f097ddfcbc9f3308ce500eb4e11");
    let b = hex_to_bn("60487e15580dc5ab6a8ad9cb24056361");
    let (q, r) = a.divrem(&b).unwrap();
    assert_eq!(q, hex_to_bn("01eef6a38c623da1b9fb8a9a2fca8ad47f"));
    assert_eq!(r, hex_to_bn("36e11e59b1091369e1f503288fa8acf2"));
    assert_eq!(a, q.mul(&b).add(&r));
    assert!(r.lt(&b));
}

// Randomised division: `q*v + r == u` with `r < v` pins q and r uniquely.
#[test]
fn divrem_random_roundtrip() {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);

    for _ in 0..200 {
        let v_bits = rng.random_range(65..1024usize);
        let u_bits = rng.random_range(v_bits..2048usize);

        let mut u = alloc::vec![0u8; u_bits.div_ceil(8)];
        let mut v = alloc::vec![0u8; v_bits.div_ceil(8)];
        rng.fill(&mut u[..]);
        rng.fill(&mut v[..]);
        // Odd leading bytes keep the operands at their intended size.
        u[0] |= 1;
        v[0] |= 1;

        let u = Bn::from_be_bytes(&u);
        let v = Bn::from_be_bytes(&v);
        if u.lt(&v) {
            continue;
        }

        let (q, r) = u.divrem(&v).unwrap();
        assert!(r.lt(&v));
        assert_eq!(u, q.mul(&v).add(&r));
    }
}

// x86_64-mont.pl bn_mul_mont vs the portable Montgomery implementation.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod asm_tests {
    use super::*;

    fn to_limbs(bytes: &[u8], limbs: usize) -> Vec<u64> {
        let mut v = vec![0u64; limbs];
        let be = Bn::from_be_bytes(bytes)
            .to_be_bytes_padded(limbs * 8)
            .unwrap();
        for i in 0..limbs {
            v[i] = u64::from_be_bytes(
                be[be.len() - (i + 1) * 8..be.len() - i * 8]
                    .try_into()
                    .unwrap(),
            );
        }
        v
    }

    #[test]
    fn mul_mont_matches_portable() {
        // Odd 512-bit modulus (primality irrelevant for Montgomery mul).
        let n_be = hex_to_bn("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01").to_be_bytes_padded(64).unwrap();
        let n = Bn::from_be_bytes(&n_be);
        let num = 8;

        // n0 = -n^-1 mod 2^64 (n is odd).
        let n_lo = u64::from_be_bytes(n_be[56..64].try_into().unwrap());
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n_lo.wrapping_mul(inv)));
        }
        let n0 = inv.wrapping_neg();

        let mont = Montgomery::new(&n).unwrap();
        let n_limbs = to_limbs(&n_be, num);

        let mut rng = 0x5eedu64;
        for case in 0..4 {
            let a_be: Vec<u8> = (0..64)
                .map(|_| {
                    rng = rng.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(case);
                    (rng >> 24) as u8
                })
                .collect();
            let b_be: Vec<u8> = (0..64)
                .map(|_| {
                    rng = rng.wrapping_mul(0xbf58476d1ce4e5b9).wrapping_add(case + 9);
                    (rng >> 24) as u8
                })
                .collect();
            let a = Bn::from_be_bytes(&a_be).modulus(&n);
            let b = Bn::from_be_bytes(&b_be).modulus(&n);

            // Feed Montgomery forms: the routine returns a*b*R mod n, which
            // converts back to (a*b) mod n.
            let a_limbs = to_limbs(&mont.to_mont(&a).to_be_bytes(), num);
            let b_limbs = to_limbs(&mont.to_mont(&b).to_be_bytes(), num);

            let mut got = super::asm::mul_mont(&a_limbs, &b_limbs, &n_limbs, n0)
                .expect("bn_mul_mont supports 8 limbs");
            while got.last() == Some(&0) {
                got.pop();
            }
            let got_bn = Bn { limbs: got };
            let expect = a.mul(&b).modulus(&n);
            assert_eq!(mont.from_mont(&got_bn), expect, "case {case}");
        }
    }

    #[test]
    fn mul_mont_variable_path_small() {
        // The variable-length path accepts small odd limb counts (num=2)
        // and still matches the portable Montgomery multiplication.
        let n = [3u64, 1]; // 2^64 + 3
        let a = [5u64, 1];
        let b = [7u64, 2];
        let n_lo = n[0];
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n_lo.wrapping_mul(inv)));
        }
        let got = super::asm::mul_mont(&a, &b, &n, inv.wrapping_neg()).unwrap();
        let bn_a = Bn { limbs: a.to_vec() };
        let bn_b = Bn { limbs: b.to_vec() };
        let bn_n = Bn { limbs: n.to_vec() };
        let mont = Montgomery::new(&bn_n).unwrap();
        let mut want = mont.mul(&bn_a, &bn_b).limbs;
        while want.last() == Some(&0) {
            want.pop();
        }
        assert_eq!(got, want);
    }
}

/// pow_consttime must agree with the 4-bit windowed pow.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
#[test]
fn pow_consttime_matches_windowed() {
    // 512-bit odd modulus
    let n_be = hex_to_bn("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01")
        .to_be_bytes_padded(64)
        .unwrap();
    let n = Bn::from_be_bytes(&n_be);
    let mont = Montgomery::new(&n).unwrap();

    let mut rng = 0xc0ffeeu64;
    for case in 0..6 {
        let mut a_be = [0u8; 64];
        let mut e_be = [0u8; 64];
        for b in a_be.iter_mut().chain(e_be.iter_mut()) {
            rng = rng.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(case);
            *b = (rng >> 24) as u8;
        }
        a_be[0] |= 1;
        e_be[0] |= 1;

        let a = Bn::from_be_bytes(&a_be).modulus(&n);
        let e = Bn::from_be_bytes(&e_be);
        let a_mont = mont.to_mont(&a);

        let got = mont.pow_consttime(&a_mont, &e);
        let want = mont.pow(&a_mont, &e);
        assert_eq!(got, want, "case {case}");
    }
}
