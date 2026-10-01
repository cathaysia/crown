#![no_main]

//! Big-number arithmetic fuzzing: algebraic identities and cross-checks
//! between the generic, odd-modulus and constant-time exponentiation paths.

use arbitrary::Arbitrary;
use crown::bn::{Bn, Montgomery};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Action {
    Add {
        a: Vec<u8>,
        b: Vec<u8>,
    },
    MulDiv {
        a: Vec<u8>,
        b: Vec<u8>,
    },
    ModArith {
        a: Vec<u8>,
        b: Vec<u8>,
        m: Vec<u8>,
    },
    ModPow {
        base: Vec<u8>,
        exp: Vec<u8>,
        m: Vec<u8>,
    },
    ModInverse {
        a: Vec<u8>,
        m: Vec<u8>,
    },
    Gcd {
        a: Vec<u8>,
        b: Vec<u8>,
    },
    Montgomery {
        a: Vec<u8>,
        b: Vec<u8>,
        e: Vec<u8>,
        m: Vec<u8>,
    },
    Shifts {
        a: Vec<u8>,
        bit: u16,
    },
    Bytes {
        a: Vec<u8>,
        pad: u8,
    },
}

/// Operand bounded to 48 bytes to keep exponentiation costs small.
fn op(v: &[u8]) -> Bn {
    let n = v.len().min(48);
    Bn::from_be_bytes(&v[..n])
}

fn odd_modulus(v: &[u8]) -> Option<Bn> {
    let n = v.len().min(48);
    let mut bytes = v[..n].to_vec();
    if bytes.is_empty() {
        return None;
    }
    let last = bytes.len() - 1;
    bytes[last] |= 1; // force odd
    bytes[0] |= 0x80; // keep the modulus at full width
    let m = Bn::from_be_bytes(&bytes);
    if m.lt(&Bn::from_u64(3)) {
        None
    } else {
        Some(m)
    }
}

fuzz_target!(|action: Action| {
    match action {
        Action::Add { a, b } => {
            let (a, b) = (op(&a), op(&b));
            let sum = a.add(&b);
            assert_eq!(sum, b.add(&a), "addition not commutative");
            assert_eq!(sum.sub(&b).unwrap(), a, "(a+b)-b != a");
        }
        Action::MulDiv { a, b } => {
            let (a, b) = (op(&a), op(&b));
            if b.is_zero() {
                return;
            }
            let prod = a.mul(&b);
            let (q, r) = prod.divrem(&b).unwrap();
            assert_eq!(q, a, "(a*b)/b != a");
            assert!(r.is_zero(), "(a*b) % b != 0");
            let (q, r) = a.divrem(&b).unwrap();
            assert_eq!(q.mul(&b).add(&r), a, "q*b+r != a");
            assert!(r.lt(&b), "remainder >= divisor");
            // The small-remainder helper must agree with divrem.
            let d = b.rem_small(u64::MAX) | 1;
            if d != 0 {
                let (q, r) = a.divrem(&Bn::from_u64(d)).unwrap();
                let small = a.rem_small(d);
                if r.byte_len() <= 8 {
                    assert_eq!(u64::from_be_bytes(pad8(r.to_be_bytes())), small);
                    let _ = q;
                }
            }
        }
        Action::ModArith { a, b, m } => {
            let (a, b, m) = (op(&a), op(&b), op(&m));
            if m.is_zero() {
                return;
            }
            let x = a.modulus(&m);
            assert!(x.lt(&m), "a mod m >= m");
            assert_eq!(a.modmul(&b, &m), a.mul(&b).modulus(&m), "modmul mismatch");
        }
        Action::ModPow { base, exp, m } => {
            let (base, exp) = (op(&base), op(&exp));
            let Some(m) = odd_modulus(&m) else {
                return;
            };
            let p1 = base.mod_pow(&exp, &m).unwrap();
            let p2 = base.mod_pow_odd(&exp, &m).unwrap();
            let p3 = base.mod_pow_odd_consttime(&exp, &m).unwrap();
            assert_eq!(p1, p2, "mod_pow vs mod_pow_odd mismatch");
            assert_eq!(p1, p3, "mod_pow vs consttime mismatch");
            assert!(p1.lt(&m), "power >= modulus");
        }
        Action::ModInverse { a, m } => {
            let (a, m) = (op(&a), op(&m));
            if m.lt(&Bn::from_u64(2)) {
                return;
            }
            if let Ok(inv) = a.mod_inverse(&m) {
                assert_eq!(a.modmul(&inv, &m), Bn::one(), "a*inv != 1 mod m");
            }
        }
        Action::Gcd { a, b } => {
            let (a, b) = (op(&a), op(&b));
            let g = a.gcd(&b);
            if g.is_zero() {
                return;
            }
            assert!(a.divrem(&g).unwrap().1.is_zero(), "gcd does not divide a");
            assert!(b.divrem(&g).unwrap().1.is_zero(), "gcd does not divide b");
        }
        Action::Montgomery { a, b, e, m } => {
            let (a, b, e) = (op(&a), op(&b), op(&e));
            let Some(m) = odd_modulus(&m) else {
                return;
            };
            let ctx = Montgomery::new(&m).unwrap();
            let am = ctx.to_mont(&a);
            let bm = ctx.to_mont(&b);
            assert_eq!(
                ctx.from_mont(&ctx.mul(&am, &bm)),
                a.modmul(&b, &m),
                "montgomery mul mismatch"
            );
            let pe = ctx.from_mont(&ctx.pow(&am, &e));
            let expected = a.mod_pow(&e, &m).unwrap();
            assert_eq!(pe, expected, "montgomery pow mismatch");
        }
        Action::Shifts { a, bit } => {
            let a = op(&a);
            let (q, _) = a.divrem(&Bn::from_u64(2)).unwrap();
            let mut shr = a.clone();
            shr.shr1();
            assert_eq!(shr, q, "shr1 != division by two");
            assert_ne!(a.is_odd(), a.is_even());
            assert_eq!(a.is_odd(), a.bit(0));
            let i = (bit as usize) % (a.bit_len() + 1);
            let mut v = a.clone();
            v.set_bit(i);
            assert!(v.bit(i), "set_bit did not take effect");
            assert!(!v.lt(&a), "set_bit decreased the value");
        }
        Action::Bytes { a, pad } => {
            let a = op(&a);
            let rt = Bn::from_be_bytes(&a.to_be_bytes());
            assert_eq!(rt, a, "be-bytes round trip mismatch");
            let pad = pad as usize % 80;
            if pad >= a.byte_len() {
                let padded = a.to_be_bytes_padded(pad).unwrap();
                assert_eq!(padded.len(), pad);
                assert_eq!(Bn::from_be_bytes(&padded), a);
            } else {
                assert!(a.to_be_bytes_padded(pad).is_err());
            }
        }
    }
});

fn pad8(mut v: Vec<u8>) -> [u8; 8] {
    let mut out = [0u8; 8];
    if v.len() > 8 {
        // Strip leading zeros; the caller guards on byte_len() <= 8.
        while v.len() > 8 && v[0] == 0 {
            v.remove(0);
        }
    }
    out[8 - v.len()..].copy_from_slice(&v);
    out
}
