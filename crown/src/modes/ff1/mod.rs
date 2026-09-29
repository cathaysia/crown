//! FF1 format-preserving encryption (NIST SP 800-38G §3.3).
//!
//! AES-CBC-MAC based Feistel network, 10 rounds, radix in `2..=65536`.
//! Strings are represented as `Vec<u32>` digits. AES-128/192/256 is
//! selected by key length.

use crate::block::aes::Aes;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};

use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;
const ROUNDS: usize = 10;

/// Encrypt a numeral string (digits in `radix`) under FF1.
pub fn ff1_encrypt(
    key: &[u8],
    tweak: &[u8],
    radix: u32,
    digits: &[u32],
) -> CryptoResult<Vec<u32>> {
    ff1_crypt(key, tweak, radix, digits, true)
}

/// Decrypt a numeral string (digits in `radix`) under FF1.
pub fn ff1_decrypt(
    key: &[u8],
    tweak: &[u8],
    radix: u32,
    digits: &[u32],
) -> CryptoResult<Vec<u32>> {
    ff1_crypt(key, tweak, radix, digits, false)
}

/// FF1-encrypt a decimal digit string (ASCII `'0'..='9'`).
pub fn ff1_encrypt_decimal(key: &[u8], tweak: &[u8], s: &str) -> CryptoResult<String> {
    let digits = parse_decimal(s)?;
    let out = ff1_encrypt(key, tweak, 10, &digits)?;
    Ok(out.iter().map(|&d| (b'0' + d as u8) as char).collect())
}

/// FF1-decrypt a decimal digit string (ASCII `'0'..='9'`).
pub fn ff1_decrypt_decimal(key: &[u8], tweak: &[u8], s: &str) -> CryptoResult<String> {
    let digits = parse_decimal(s)?;
    let out = ff1_decrypt(key, tweak, 10, &digits)?;
    Ok(out.iter().map(|&d| (b'0' + d as u8) as char).collect())
}

fn parse_decimal(s: &str) -> CryptoResult<Vec<u32>> {
    s.bytes()
        .map(|b| {
            if b.is_ascii_digit() {
                Ok((b - b'0') as u32)
            } else {
                Err(CryptoError::InvalidParameterStr(
                    "ff1: non-decimal character",
                ))
            }
        })
        .collect()
}

fn check_params(key: &[u8], radix: u32, digits: &[u32]) -> CryptoResult<()> {
    match key.len() {
        16 | 24 | 32 => {}
        actual => {
            return Err(CryptoError::InvalidKeySize {
                expected: "16 | 24 | 32",
                actual,
            })
        }
    }
    if !(2..=65536).contains(&radix) {
        return Err(CryptoError::InvalidParameterStr(
            "ff1: radix must be in 2..=65536",
        ));
    }
    let n = digits.len();
    if n < 2 {
        return Err(CryptoError::InvalidLength);
    }
    if digits.iter().any(|&d| d >= radix) {
        return Err(CryptoError::InvalidParameterStr(
            "ff1: digit out of range for radix",
        ));
    }
    // SP 800-38G requires radix^n >= 100.
    let log = (n as f64) * (radix as f64).log2();
    if log < (100f64).log2() - 1e-9 {
        return Err(CryptoError::InvalidParameterStr(
            "ff1: radix^n must be >= 100",
        ));
    }
    Ok(())
}

/// `b = ceil(ceil(v * log2(radix)) / 8)`.
fn num_bytes(radix: u32, num_digits: usize) -> usize {
    if num_digits == 0 {
        return 0;
    }
    let bits = (num_digits as f64) * (radix as f64).log2();
    // Subtract a hair so an exactly-integral product is not rounded up
    // by floating-point noise.
    let bits_ceil = (bits - 1e-9).ceil().max(0.0) as usize;
    bits_ceil.div_ceil(8)
}

/// AES-CBC-MAC over `data` (a multiple of 16 bytes), IV = 0.
fn cbc_mac(aes: &Aes, data: &[u8]) -> [u8; 16] {
    debug_assert!(data.len().is_multiple_of(16) && !data.is_empty());
    let mut state = [0u8; 16];
    for chunk in data.as_chunks::<16>().0 {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = state[i] ^ chunk[i];
        }
        aes.encrypt_block(&mut block);
        state = block;
    }
    state
}

/// `S = R || AES_K(R ⊕ 1) || AES_K(R ⊕ 2) || …` truncated to `d` bytes.
fn prf_expand(aes: &Aes, r: &[u8; 16], d: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(d + 16);
    s.extend_from_slice(r);
    let mut counter: u128 = 1;
    while s.len() < d {
        let mut x = *r;
        let c = counter.to_be_bytes();
        for i in 0..16 {
            x[i] ^= c[i];
        }
        aes.encrypt_block(&mut x);
        s.extend_from_slice(&x);
        counter += 1;
    }
    s.truncate(d);
    s
}

/// Big-endian bytes → little-endian digits in `radix`, truncated to `m`
/// (i.e. reduced modulo `radix^m`).
fn bytes_to_digits_mod(bytes: &[u8], radix: u32, m: usize) -> Vec<u32> {
    let mut digits: Vec<u32> = Vec::new();
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = *d * 256 + carry;
            *d = v % radix;
            carry = v / radix;
        }
        while carry > 0 {
            digits.push(carry % radix);
            carry /= radix;
        }
    }
    digits.resize(m, 0);
    digits
}

/// Big-endian digits → exactly `b` big-endian bytes.
fn digits_to_bytes_be(digits_be: &[u32], radix: u32, b: usize) -> Vec<u8> {
    // Horner: value = ((msd * radix + next) * radix + …). Digits are
    // consumed most-significant first, so the running total lives in
    // little-endian base 256.
    let mut le: Vec<u32> = vec![0];
    for &d in digits_be {
        let mut carry = d;
        for x in le.iter_mut() {
            let v = *x * radix + carry;
            *x = v & 0xff;
            carry = v >> 8;
        }
        while carry > 0 {
            le.push(carry & 0xff);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; b];
    let n = le.len().min(b);
    for i in 0..n {
        out[b - 1 - i] = le[i] as u8;
    }
    out
}

/// `(a + y) mod radix^m`, both little-endian digits of length `m`.
fn mod_add(a: &[u32], y: &[u32], radix: u32) -> Vec<u32> {
    debug_assert_eq!(a.len(), y.len());
    let mut out = vec![0u32; a.len()];
    let mut carry = 0u32;
    for i in 0..a.len() {
        let s = a[i] + y[i] + carry;
        out[i] = s % radix;
        carry = s / radix;
    }
    // Discarding the final carry subtracts radix^m.
    out
}

/// `(a - y) mod radix^m`, both little-endian digits of length `m`.
fn mod_sub(a: &[u32], y: &[u32], radix: u32) -> Vec<u32> {
    debug_assert_eq!(a.len(), y.len());
    let mut out = vec![0u32; a.len()];
    let mut borrow = 0i32;
    for i in 0..a.len() {
        let mut diff = a[i] as i32 - y[i] as i32 - borrow;
        if diff < 0 {
            diff += radix as i32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = diff as u32;
    }
    // Ignoring the final borrow adds radix^m.
    out
}

/// Round PRF: y = NUM(PR F(B)) mod radix^m, as little-endian digits.
#[allow(clippy::too_many_arguments)]
fn round_y(
    aes: &Aes,
    p: &[u8; 16],
    tweak: &[u8],
    b_le: &[u32],
    i: usize,
    radix: u32,
    b_bytes: usize,
    pad: usize,
    m: usize,
) -> Vec<u32> {
    // Q = T || 0^pad || [i] || [B] as b_bytes
    let mut q = Vec::with_capacity(tweak.len() + pad + 1 + b_bytes);
    q.extend_from_slice(tweak);
    q.extend(core::iter::repeat_n(0u8, pad));
    q.push(i as u8);
    let b_be: Vec<u32> = b_le.iter().rev().copied().collect();
    q.extend_from_slice(&digits_to_bytes_be(&b_be, radix, b_bytes));

    let mut pq = Vec::with_capacity(16 + q.len());
    pq.extend_from_slice(p);
    pq.extend_from_slice(&q);
    let r = cbc_mac(aes, &pq);

    // d = 4 * ceil(b/4) + 4, with b fixed from v (SP 800-38G step 4).
    let d = 4 * b_bytes.div_ceil(4) + 4;
    let s = prf_expand(aes, &r, d);
    bytes_to_digits_mod(&s, radix, m)
}

fn ff1_crypt(
    key: &[u8],
    tweak: &[u8],
    radix: u32,
    digits: &[u32],
    encrypt: bool,
) -> CryptoResult<Vec<u32>> {
    check_params(key, radix, digits)?;
    let aes = Aes::new(key)?;
    let n = digits.len();
    let u = n / 2;
    let v = n - u;
    let t = tweak.len();

    // P = [1,2,1] || radix(3) || [10] || [u] || n(4) || t(4)
    let mut p = [0u8; 16];
    p[0] = 1;
    p[1] = 2;
    p[2] = 1;
    p[3] = ((radix >> 16) & 0xff) as u8;
    p[4] = ((radix >> 8) & 0xff) as u8;
    p[5] = (radix & 0xff) as u8;
    p[6] = 10;
    p[7] = u as u8;
    p[8..12].copy_from_slice(&(n as u32).to_be_bytes());
    p[12..16].copy_from_slice(&(t as u32).to_be_bytes());

    // b (Q octet width) is always derived from the original right-half length v.
    let b = num_bytes(radix, v);
    let pad = (-(t as i64) - (b as i64) - 1).rem_euclid(16) as usize;

    let mut a: Vec<u32> = digits[..u].iter().rev().copied().collect(); // LE
    let mut bb: Vec<u32> = digits[u..].iter().rev().copied().collect(); // LE

    for round in 0..ROUNDS {
        let i = if encrypt {
            round
        } else {
            ROUNDS - 1 - round
        };
        // m = |A_in| = |C| for this round.
        let m = if i % 2 == 0 { u } else { v };

        if encrypt {
            // a = A_in (m), bb = B_in (n-m); PRF input is B_in.
            let y = round_y(&aes, &p, tweak, &bb, i, radix, b, pad, m);
            let c = mod_add(&a, &y, radix);
            a = bb;
            bb = c;
        } else {
            // a = A_out (n-m), bb = B_out (m); B_in = a, A_in = (B_out - y).
            let y = round_y(&aes, &p, tweak, &a, i, radix, b, pad, m);
            let c = mod_sub(&bb, &y, radix);
            let b_in = a;
            a = c;
            bb = b_in;
        }
    }

    let mut out = Vec::with_capacity(n);
    out.extend(a.iter().rev().copied());
    out.extend(bb.iter().rev().copied());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn str_digits(s: &str, radix: u32) -> Vec<u32> {
        s.chars()
            .map(|c| c.to_digit(radix).expect("digit"))
            .collect()
    }

    fn digits_to_string(digits: &[u32]) -> String {
        digits
            .iter()
            .map(|&d| std::char::from_digit(d, 36).unwrap())
            .collect()
    }

    // NIST SP 800-38G sample vectors (FF1samples.pdf).
    #[test]
    fn ff1_sample_vector_1() {
        // Sample #1: AES-128, radix 10, empty tweak.
        let key = hex_to_vec("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = b"";
        let pt = str_digits("0123456789", 10);
        let ct = ff1_encrypt(&key, tweak, 10, &pt).unwrap();
        assert_eq!(digits_to_string(&ct), "2433477484");
        let back = ff1_decrypt(&key, tweak, 10, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn ff1_sample_vector_2() {
        // Sample #2: AES-128, radix 10, tweak 39 38 37 36 35 34 33 32 31 30.
        let key = hex_to_vec("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_to_vec("39383736353433323130");
        let pt = str_digits("0123456789", 10);
        let ct = ff1_encrypt(&key, &tweak, 10, &pt).unwrap();
        assert_eq!(digits_to_string(&ct), "6124200773");
        let back = ff1_decrypt(&key, &tweak, 10, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn ff1_sample_vector_3_radix36() {
        // Sample #3: AES-128, radix 36, tweak "7777pqrs777".
        let key = hex_to_vec("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_to_vec("3737373770717273373737");
        let pt = str_digits("0123456789abcdefghi", 36);
        let ct = ff1_encrypt(&key, &tweak, 36, &pt).unwrap();
        assert_eq!(digits_to_string(&ct), "a9tv40mll9kdu509eum");
        let back = ff1_decrypt(&key, &tweak, 36, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn ff1_decimal_helper_roundtrip() {
        let key = hex_to_vec("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = b"";
        let ct = ff1_encrypt_decimal(&key, tweak, "0123456789").unwrap();
        assert_eq!(ct, "2433477484");
        let pt = ff1_decrypt_decimal(&key, tweak, &ct).unwrap();
        assert_eq!(pt, "0123456789");
    }

    #[test]
    fn ff1_roundtrip_various() {
        let key = hex_to_vec("2B7E151628AED2A6ABF7158809CF4F3C");
        for radix in [2u32, 10, 16, 36, 256] {
            let n = 20;
            let pt: Vec<u32> = (0..n).map(|i| (i as u32 * 7 + 3) % radix).collect();
            let ct = ff1_encrypt(&key, b"tweak", radix, &pt).unwrap();
            assert_eq!(ct.len(), n);
            assert_ne!(ct, pt);
            let back = ff1_decrypt(&key, b"tweak", radix, &ct).unwrap();
            assert_eq!(back, pt);
        }
    }

    #[test]
    fn ff1_odd_length_roundtrip() {
        let key = hex_to_vec("2B7E151628AED2A6ABF7158809CF4F3C");
        for n in [2usize, 3, 5, 7, 11, 21] {
            let pt: Vec<u32> = (0..n as u32).map(|i| i % 10).collect();
            let ct = ff1_encrypt(&key, b"t", 10, &pt).unwrap();
            assert_eq!(ct.len(), n);
            let back = ff1_decrypt(&key, b"t", 10, &ct).unwrap();
            assert_eq!(back, pt);
        }
    }

    #[test]
    fn ff1_aes192_256_roundtrip() {
        let pt = str_digits("1234567890", 10);
        for klen in [24usize, 32] {
            let key = vec![0x42u8; klen];
            let ct = ff1_encrypt(&key, b"", 10, &pt).unwrap();
            let back = ff1_decrypt(&key, b"", 10, &ct).unwrap();
            assert_eq!(back, pt);
        }
    }

    #[test]
    fn ff1_rejects_bad_input() {
        let key = [0u8; 16];
        assert!(ff1_encrypt(&key, b"", 10, &[0]).is_err());
        assert!(ff1_encrypt(&[0u8; 15], b"", 10, &[0, 1]).is_err());
        assert!(ff1_encrypt(&key, b"", 1, &[0, 1]).is_err());
        assert!(ff1_encrypt(&key, b"", 10, &[0, 10]).is_err());
    }
}
