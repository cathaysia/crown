//! Minimal arbitrary-precision unsigned integers ("BigNums") for RSA.
//!
//! Numbers are little-endian vectors of 64-bit limbs; the empty vector
//! represents zero. This mirrors the parts of OpenSSL's `crypto/bn` used by
//! the RSA implementation: magnitudes with add/sub/mul, binary long
//! division, GCD and modular inversion via the extended Euclidean
//! algorithm, and Montgomery modular exponentiation for odd moduli
//! (`bn_exp.c`'s Montgomery path).
//!
//! All operations are constant-time only with respect to the Montgomery
//! exponentiation data path; key generation performs variable-time work on
//! public data, like OpenSSL's default RSA key generation.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) mod asm;
#[cfg(test)]
mod tests;

use crate::error::{CryptoError, CryptoResult};
use alloc::vec::Vec;

/// An unsigned arbitrary-precision integer, little-endian 64-bit limbs
/// with no trailing zero limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bn {
    limbs: Vec<u64>,
}

/// Ordering by numeric magnitude: normalized numbers compare by limb
/// count first, then from the most significant limb.
impl Ord for Bn {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for i in (0..self.limbs.len()).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Bn {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Bn {
    pub const fn zero() -> Self {
        Bn { limbs: Vec::new() }
    }

    pub fn one() -> Self {
        Bn {
            limbs: alloc::vec![1],
        }
    }

    pub fn from_u64(v: u64) -> Self {
        if v == 0 {
            return Self::zero();
        }
        Bn {
            limbs: alloc::vec![v],
        }
    }

    pub fn from_u32(v: u32) -> Self {
        Self::from_u64(v as u64)
    }

    /// Parse a big-endian byte string.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        let mut acc = 0u64;
        let mut shift = 0;
        // limbs accumulate little-endian; walk bytes from the end.
        for &b in bytes.iter().rev() {
            acc |= (b as u64) << shift;
            shift += 8;
            if shift == 64 {
                limbs.push(acc);
                acc = 0;
                shift = 0;
            }
        }
        if shift > 0 {
            limbs.push(acc);
        }
        let mut bn = Bn { limbs };
        bn.normalize();
        bn
    }

    /// Serialize into exactly `len` big-endian bytes (left-padded with
    /// zeros); errors if the value does not fit.
    pub fn to_be_bytes_padded(&self, len: usize) -> CryptoResult<Vec<u8>> {
        let need = self.byte_len();
        if need > len {
            return Err(CryptoError::StrError("bn: value does not fit"));
        }
        let mut out = alloc::vec![0u8; len];
        out[len - need..].copy_from_slice(&self.to_be_bytes());
        Ok(out)
    }

    /// Serialize into the minimal big-endian byte string (empty for zero).
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.limbs.len() * 8);
        for (i, limb) in self.limbs.iter().enumerate().rev() {
            let bytes = limb.to_be_bytes();
            if i == self.limbs.len() - 1 {
                // most significant limb: strip leading zero bytes
                let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
                out.extend_from_slice(&bytes[first..]);
            } else {
                out.extend_from_slice(&bytes);
            }
        }
        if self.limbs.is_empty() {
            // zero serializes to an empty string; callers wanting a byte
            // use to_be_bytes_padded
        }
        out
    }

    pub fn byte_len(&self) -> usize {
        if self.limbs.is_empty() {
            return 0;
        }
        (self.limbs.len() - 1) * 8
            + ((64 - self.limbs.last().unwrap().leading_zeros()) as usize).div_ceil(8)
    }

    /// Bit length (0 for zero).
    pub fn bit_len(&self) -> usize {
        if self.limbs.is_empty() {
            return 0;
        }
        (self.limbs.len() * 64) - self.limbs.last().unwrap().leading_zeros() as usize
    }

    pub fn bit(&self, i: usize) -> bool {
        let limb = i / 64;
        if limb >= self.limbs.len() {
            return false;
        }
        (self.limbs[limb] >> (i % 64)) & 1 == 1
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    pub fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|l| l & 1 == 1)
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// Set bit `i` (grows the number).
    pub fn set_bit(&mut self, i: usize) {
        let limb = i / 64;
        if limb >= self.limbs.len() {
            self.limbs.resize(limb + 1, 0);
        }
        self.limbs[limb] |= 1 << (i % 64);
    }

    pub fn lt(&self, other: &Bn) -> bool {
        self < other
    }

    pub fn add(&self, other: &Bn) -> Bn {
        let n = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u128;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u128;
            let s = a + b + carry as u128;
            out.push(s as u64);
            carry = (s >> 64) as u64;
        }
        if carry != 0 {
            out.push(carry);
        }
        let mut bn = Bn { limbs: out };
        bn.normalize();
        bn
    }

    /// `self - other`; errors on underflow.
    pub fn sub(&self, other: &Bn) -> CryptoResult<Bn> {
        if self.lt(other) {
            return Err(CryptoError::StrError("bn: subtraction underflow"));
        }
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i];
            let b = other.limbs.get(i).copied().unwrap_or(0);
            let (s, b1) = a.overflowing_sub(b);
            let (s, b2) = s.overflowing_sub(borrow as u64);
            borrow = (b1 as i64) | (b2 as i64);
            out.push(s);
        }
        debug_assert_eq!(borrow, 0);
        let mut bn = Bn { limbs: out };
        bn.normalize();
        Ok(bn)
    }

    pub fn mul(&self, other: &Bn) -> Bn {
        if self.is_zero() || other.is_zero() {
            return Bn::zero();
        }
        let mut out = alloc::vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let t = (a as u128) * (b as u128) + (out[i + j] as u128) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            let mut k = i + other.limbs.len();
            while carry != 0 {
                let t = (out[k] as u128) + carry;
                out[k] = t as u64;
                carry = t >> 64;
                k += 1;
            }
        }
        let mut bn = Bn { limbs: out };
        bn.normalize();
        bn
    }

    /// Long division (Knuth algorithm D, Hacker's Delight `divmnu`).
    /// Returns `(quotient, remainder)`.
    pub fn divrem(&self, divisor: &Bn) -> CryptoResult<(Bn, Bn)> {
        use core::cmp::Ordering;

        if divisor.is_zero() {
            return Err(CryptoError::StrError("bn: division by zero"));
        }
        match self.cmp(divisor) {
            Ordering::Less => return Ok((Bn::zero(), self.clone())),
            Ordering::Equal => return Ok((Bn::one(), Bn::zero())),
            _ => {}
        }

        // Small divisor: keep the simple word-at-a-time path.
        if divisor.limbs.len() == 1 {
            let d = divisor.limbs[0];
            let mut q = alloc::vec![0u64; self.limbs.len()];
            let mut rem = 0u128;
            for i in (0..self.limbs.len()).rev() {
                let cur = (rem << 64) | self.limbs[i] as u128;
                q[i] = (cur / d as u128) as u64;
                rem = cur % d as u128;
            }
            let mut quotient = Bn { limbs: q };
            quotient.normalize();
            let remainder = if rem == 0 {
                Bn::zero()
            } else {
                Bn {
                    limbs: alloc::vec![rem as u64],
                }
            };
            return Ok((quotient, remainder));
        }

        // Normalize so the divisor's top limb has its high bit set.
        let shift = divisor.limbs.last().unwrap().leading_zeros();
        let vn = shl_limbs(&divisor.limbs, shift);
        let n = vn.len();
        let mut un = shl_limbs(&self.limbs, shift);
        un.push(0);
        let m = un.len() - n - 1;

        let mut q = alloc::vec![0u64; m + 1];
        let b: u128 = 1 << 64;
        let vn1 = vn[n - 1] as u128;
        let vn2 = vn[n - 2] as u128;

        for j in (0..=m).rev() {
            let num = ((un[j + n] as u128) << 64) | un[j + n - 1] as u128;
            let mut qhat = num / vn1;
            let mut rhat = num % vn1;

            // Knuth 4.3.1 D3: the test is against `b*rhat + u[j+n-2]`, the
            // low part of the numerator left over by the estimate.
            while qhat >= b || qhat * vn2 > ((rhat << 64) + un[j + n - 2] as u128) {
                qhat -= 1;
                rhat += vn1;
                if rhat >= b {
                    break;
                }
            }

            // Multiply and subtract: un[j..j+n+1] -= qhat * vn
            let mut borrow = 0i128;
            let mut carry = 0u128;
            for i in 0..n {
                let p = qhat * vn[i] as u128 + carry;
                carry = p >> 64;
                let sub = (un[i + j] as i128) - ((p & 0xffff_ffff_ffff_ffff) as i128) - borrow;
                un[i + j] = sub as u64;
                borrow = if sub < 0 { 1 } else { 0 };
            }
            let sub = (un[j + n] as i128) - carry as i128 - borrow;
            un[j + n] = sub as u64;
            borrow = if sub < 0 { 1 } else { 0 };

            if borrow != 0 {
                // qhat was one too large: add the divisor back.
                qhat -= 1;
                let mut carry2 = 0u128;
                for i in 0..n {
                    let t = un[i + j] as u128 + vn[i] as u128 + carry2;
                    un[i + j] = t as u64;
                    carry2 = t >> 64;
                }
                let _ = carry2;
                un[j + n] = un[j + n].wrapping_add(1);
            }
            q[j] = qhat as u64;
        }

        let mut quotient = Bn { limbs: q };
        quotient.normalize();
        let rem_limbs = shr_limbs(&un[..n], shift);
        let mut remainder = Bn { limbs: rem_limbs };
        remainder.normalize();
        Ok((quotient, remainder))
    }

    /// `self mod d` where `d` fits in a u64.
    pub fn rem_small(&self, d: u64) -> u64 {
        debug_assert!(d != 0);
        let mut rem = 0u128;
        for &limb in self.limbs.iter().rev() {
            rem = ((rem << 64) | limb as u128) % d as u128;
        }
        rem as u64
    }

    /// `self / 2` in place (rounds down).
    pub fn shr1(&mut self) {
        let mut carry = 0u64;
        for limb in self.limbs.iter_mut().rev() {
            let next = *limb & 1;
            *limb = (*limb >> 1) | (carry << 63);
            carry = next;
        }
        self.normalize();
    }

    pub fn is_even(&self) -> bool {
        !self.is_odd()
    }

    /// Greatest common divisor (Euclid).
    pub fn gcd(&self, other: &Bn) -> Bn {
        let mut a = self.clone();
        let mut b = other.clone();
        while !b.is_zero() {
            let r = a.divrem(&b).map(|(_, r)| r).unwrap_or_else(|_| Bn::zero());
            a = b;
            b = r;
        }
        a
    }

    /// Modular inverse via the extended Euclidean algorithm with
    /// coefficients kept in `[0, modulus)`.
    pub fn mod_inverse(&self, modulus: &Bn) -> CryptoResult<Bn> {
        if modulus.is_zero() || modulus.is_one() {
            return Err(CryptoError::StrError("bn: no inverse"));
        }

        let mut old_r = self.clone();
        let mut r = modulus.clone();
        let mut old_s = Bn::one();
        let mut s = Bn::zero();

        while !r.is_zero() {
            let (q, new_r) = old_r.divrem(&r)?;
            old_r = r;
            r = new_r;

            // (old_s, s) = (s, old_s - q * s) mod modulus
            let qs = q.modmul(&s, modulus);
            let new_s = if old_s.lt(&qs) {
                // old_s - qs + modulus
                let diff = qs.sub(&old_s)?;
                modulus.sub(&diff)?
            } else {
                old_s.sub(&qs)?
            };
            old_s = s;
            s = new_s;
        }

        if !old_r.is_one() {
            return Err(CryptoError::StrError("bn: no modular inverse"));
        }
        Ok(old_s)
    }

    /// `(a * b) mod m` via mul + divrem (no parity restriction on m).
    pub fn modmul(&self, b: &Bn, m: &Bn) -> Bn {
        self.mul(b)
            .divrem(m)
            .map(|(_, r)| r)
            .unwrap_or_else(|_| Bn::zero())
    }

    /// `self mod m`.
    pub fn modulus(&self, m: &Bn) -> Bn {
        self.divrem(m)
            .map(|(_, r)| r)
            .unwrap_or_else(|_| Bn::zero())
    }

    /// Modular exponentiation for odd moduli (Montgomery, 4-bit windows).
    pub fn mod_pow_odd(&self, exp: &Bn, modulus: &Bn) -> CryptoResult<Bn> {
        let mont = Montgomery::new(modulus)?;
        let base = mont.to_mont(&self.modulus(modulus));
        let res = mont.pow(&base, exp);
        Ok(mont.from_mont(&res))
    }

    /// Modular exponentiation for any modulus: square-and-multiply via
    /// Montgomery when the modulus is odd, plain modmul otherwise.
    pub fn mod_pow(&self, exp: &Bn, modulus: &Bn) -> CryptoResult<Bn> {
        if modulus.is_zero() {
            return Err(CryptoError::StrError("bn: modulus is zero"));
        }
        if modulus.is_one() {
            return Ok(Bn::zero());
        }
        if modulus.is_odd() {
            return self.mod_pow_odd(exp, modulus);
        }

        // Generic path for even moduli: sliding square-and-multiply with
        // plain modmul.
        let base = self.modulus(modulus);
        let mut result = Bn::one();
        for i in (0..exp.bit_len()).rev() {
            result = result.modmul(&result, modulus);
            if exp.bit(i) {
                result = result.modmul(&base, modulus);
            }
        }
        Ok(result)
    }
}

/// Shift a little-endian limb vector left by `shift` bits (< 64).
fn shl_limbs(limbs: &[u64], shift: u32) -> Vec<u64> {
    if shift == 0 {
        return limbs.to_vec();
    }
    let mut out = Vec::with_capacity(limbs.len() + 1);
    let mut carry = 0u64;
    for &limb in limbs {
        out.push((limb << shift) | carry);
        carry = limb >> (64 - shift);
    }
    if carry != 0 {
        out.push(carry);
    }
    out
}

/// Shift a little-endian limb vector right by `shift` bits (< 64).
fn shr_limbs(limbs: &[u64], shift: u32) -> Vec<u64> {
    if shift == 0 {
        return limbs.to_vec();
    }
    let mut out = Vec::with_capacity(limbs.len());
    for i in 0..limbs.len() {
        let hi = if i + 1 < limbs.len() {
            limbs[i + 1] << (64 - shift)
        } else {
            0
        };
        out.push((limbs[i] >> shift) | hi);
    }
    out
}

/// Montgomery representation helpers for an odd modulus (CIOS).
pub struct Montgomery {
    n: Bn,
    /// -n^-1 mod 2^64
    n0: u64,
    /// R^2 mod n where R = 2^(64 * limbs)
    r2: Bn,
    limbs: usize,
}

impl Montgomery {
    pub fn new(n: &Bn) -> CryptoResult<Self> {
        if !n.is_odd() {
            return Err(CryptoError::StrError(
                "bn: montgomery requires an odd modulus",
            ));
        }
        let limbs = n.limbs.len().max(1);

        // n0 = -n^-1 mod 2^64 via Newton iteration on x = n (mod 2^64).
        let n0w = n.limbs.first().copied().unwrap_or(0);
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0w.wrapping_mul(inv)));
        }
        let n0 = inv.wrapping_neg();

        // R mod n, then R^2 mod n via repeated doubling and one squaring.
        // R = 2^(64*limbs).
        let mut r = Bn::zero();
        r.set_bit(64 * limbs);
        let r_mod = r.divrem(n).map(|(_, m)| m)?;
        let r2 = {
            // r_mod * r_mod mod n: Montgomery-free since r2 is computed once.
            let prod = r_mod.mul(&r_mod);
            prod.divrem(n).map(|(_, m)| m)?
        };

        Ok(Montgomery {
            n: n.clone(),
            n0,
            r2,
            limbs,
        })
    }

    fn mont_mul(&self, a: &Bn, b: &Bn) -> Bn {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        {
            if let Some(r) = self.mont_mul_asm(a, b) {
                return r;
            }
        }
        self.mont_mul_generic(a, b)
    }

    /// Montgomery mul via the x86_64-mont.pl bn_mul_mont routine.
    /// Returns `None` only when the assembly rejects the limb count.
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn mont_mul_asm(&self, a: &Bn, b: &Bn) -> Option<Bn> {
        let n = self.limbs;
        let mut al = alloc::vec![0u64; n];
        let mut bl = alloc::vec![0u64; n];
        let mut nl = alloc::vec![0u64; n];
        for i in 0..n {
            al[i] = a.limbs.get(i).copied().unwrap_or(0);
            bl[i] = b.limbs.get(i).copied().unwrap_or(0);
            nl[i] = self.n.limbs.get(i).copied().unwrap_or(0);
        }
        let got = asm::mul_mont(&al, &bl, &nl, self.n0)?;
        let mut res = Bn { limbs: got };
        res.normalize();
        if !res.lt(&self.n) {
            res = res.sub(&self.n).unwrap_or_else(|_| Bn::zero());
        }
        Some(res)
    }

    fn mont_mul_generic(&self, a: &Bn, b: &Bn) -> Bn {
        let t_len = self.limbs + 1;
        let mut t = alloc::vec![0u64; t_len + 1];

        for i in 0..self.limbs {
            // t = t + a_i * b
            let ai = a.limbs.get(i).copied().unwrap_or(0) as u128;
            let mut carry = 0u128;
            for j in 0..self.limbs {
                let bj = b.limbs.get(j).copied().unwrap_or(0) as u128;
                let tj = t[j] as u128;
                let s = ai * bj + tj + carry;
                t[j] = s as u64;
                carry = s >> 64;
            }
            let s = (t[self.limbs] as u128) + carry;
            t[self.limbs] = s as u64;
            if self.limbs + 1 < t.len() {
                t[self.limbs + 1] = (s >> 64) as u64;
            }

            // m = t_0 * n0 mod 2^64; t = t + m * n; drop t_0
            let m = t[0].wrapping_mul(self.n0);
            let mut carry2 = 0u128;
            for j in 0..self.limbs {
                let nj = self.n.limbs.get(j).copied().unwrap_or(0) as u128;
                let s = (m as u128) * nj + (t[j] as u128) + carry2;
                t[j] = s as u64;
                carry2 = s >> 64;
            }
            let s = (t[self.limbs] as u128) + carry2;
            t[self.limbs] = s as u64;
            if self.limbs + 1 < t.len() {
                t[self.limbs + 1] += (s >> 64) as u64;
            }

            // shift t right by one limb
            for j in 0..t_len {
                t[j] = t[j + 1];
            }
            t[t_len] = 0;
        }

        let mut res = Bn {
            limbs: t[..t_len].to_vec(),
        };
        res.normalize();

        // res in [0, 2n): subtract n once if needed.
        if !res.lt(&self.n) {
            res = res.sub(&self.n).unwrap_or_else(|_| Bn::zero());
        }
        res
    }

    /// Convert into Montgomery form: `a * R mod n`.
    pub fn to_mont(&self, a: &Bn) -> Bn {
        self.mont_mul(a, &self.r2)
    }

    /// Convert out of Montgomery form: `a / R mod n`.
    pub fn from_mont(&self, a: &Bn) -> Bn {
        let one = Bn::one();
        self.mont_mul(a, &one)
    }

    pub fn mul(&self, a: &Bn, b: &Bn) -> Bn {
        self.mont_mul(a, b)
    }

    /// `a^e mod n` with `a` in Montgomery form (4-bit windowed).
    pub fn pow(&self, a_mont: &Bn, e: &Bn) -> Bn {
        let mut table = alloc::vec![Bn::zero(); 16];
        table[0] = self.to_mont(&Bn::one());
        table[1] = a_mont.clone();
        for i in 2..16 {
            table[i] = self.mul(&table[i - 1], a_mont);
        }

        let mut result = table[0].clone();
        let bits = e.bit_len();
        let mut i = bits;
        while i > 0 {
            // consume a 4-bit window
            let w = 4usize.min(i);
            for _ in 0..w {
                result = self.mul(&result, &result);
            }
            let mut nib = 0u8;
            for k in 0..w {
                // bit i-w+k maps to nibble bit k (k = w-1 is the window's
                // most significant bit).
                if e.bit(i - w + k) {
                    nib |= 1 << k;
                }
            }
            result = self.mul(&result, &table[nib as usize]);
            i -= w;
        }
        result
    }
}
