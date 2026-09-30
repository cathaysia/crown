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
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) mod gf2m;
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) mod rsaz;
#[cfg(test)]
mod tests;

use crate::error::{CryptoError, CryptoResult};
use alloc::vec::Vec;

/// An unsigned arbitrary-precision integer, little-endian 64-bit limbs
/// with no trailing zero limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bn {
    pub(crate) limbs: Vec<u64>,
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
        self.write_be_bytes(&mut out[len - need..]);
        Ok(out)
    }

    /// Serialize into the minimal big-endian byte string (empty for zero).
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut out = alloc::vec![0u8; self.byte_len()];
        self.write_be_bytes(&mut out);
        out
    }

    /// Write the minimal big-endian encoding into `out`, which must be
    /// exactly `byte_len()` bytes long.
    fn write_be_bytes(&self, out: &mut [u8]) {
        let mut off = 0;
        for (i, limb) in self.limbs.iter().enumerate().rev() {
            let bytes = limb.to_be_bytes();
            if i == self.limbs.len() - 1 {
                // most significant limb: strip leading zero bytes
                let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
                out[off..off + (8 - first)].copy_from_slice(&bytes[first..]);
                off += 8 - first;
            } else {
                out[off..off + 8].copy_from_slice(&bytes);
                off += 8;
            }
        }
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

    pub(crate) fn normalize(&mut self) {
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

    /// Modular inverse. Uses the division-free binary extended Euclidean
    /// algorithm for odd moduli (the common case: prime fields and RSA prime
    /// moduli) and falls back to extended Euclid otherwise.
    pub fn mod_inverse(&self, modulus: &Bn) -> CryptoResult<Bn> {
        if modulus.is_zero() || modulus.is_one() {
            return Err(CryptoError::StrError("bn: no inverse"));
        }
        if modulus.is_odd() {
            return self.mod_inverse_odd(modulus);
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

    /// Binary extended Euclidean inverse for an odd modulus (HAC Alg. 14.64).
    /// Maintains `a*x1 = u` and `a*x2 = v (mod m)`; only shifts, adds and
    /// subs, so it avoids the O(n²) division of Euclid.
    fn mod_inverse_odd(&self, modulus: &Bn) -> CryptoResult<Bn> {
        let m = modulus;
        let mut u = self.modulus(m);
        let mut v = m.clone();
        let mut x1 = Bn::one();
        let mut x2 = Bn::zero();

        while !u.is_one() && !v.is_one() {
            if u.is_zero() || v.is_zero() {
                return Err(CryptoError::StrError("bn: no modular inverse"));
            }
            while u.is_even() {
                u.shr1();
                // x1 = x1 / 2 (mod m): odd x1 folds in the modulus first.
                if x1.is_even() {
                    x1.shr1();
                } else {
                    x1 = x1.add(m);
                    x1.shr1();
                }
            }
            while v.is_even() {
                v.shr1();
                if x2.is_even() {
                    x2.shr1();
                } else {
                    x2 = x2.add(m);
                    x2.shr1();
                }
            }
            if u.lt(&v) {
                v = v.sub(&u)?;
                x2 = sub_mod(&x2, &x1, m);
            } else {
                u = u.sub(&v)?;
                x1 = sub_mod(&x1, &x2, m);
            }
        }

        if u.is_one() {
            Ok(x1)
        } else {
            Ok(x2)
        }
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

    /// Constant-time modular exponentiation for odd moduli (private-key
    /// paths). Uses the mont5 5-bit window table when the asm accepts the
    /// limb count.
    pub fn mod_pow_odd_consttime(&self, exp: &Bn, modulus: &Bn) -> CryptoResult<Bn> {
        let mont = Montgomery::new(modulus)?;
        let base = mont.to_mont(&self.modulus(modulus));
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        let res = mont.pow_consttime(&base, exp);
        #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
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

/// `(x - y) mod m` for `x, y` in `[0, m)` (no allocation beyond the result).
fn sub_mod(x: &Bn, y: &Bn, m: &Bn) -> Bn {
    if x.lt(y) {
        x.add(m).sub(y).expect("x + m >= y")
    } else {
        x.sub(y).expect("x >= y")
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

impl Clone for Montgomery {
    fn clone(&self) -> Self {
        Montgomery {
            n: self.n.clone(),
            n0: self.n0,
            r2: self.r2.clone(),
            limbs: self.limbs,
        }
    }
}

impl core::fmt::Debug for Montgomery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Montgomery").field("limbs", &self.limbs).finish()
    }
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
        for i in 0..n {
            al[i] = a.limbs.get(i).copied().unwrap_or(0);
            bl[i] = b.limbs.get(i).copied().unwrap_or(0);
        }
        // `Montgomery::new` derives `limbs` from `n.limbs.len()`, so the
        // stored modulus is already exactly `n` limbs for the asm routine.
        let got = asm::mul_mont(&al, &bl, &self.n.limbs, self.n0)?;
        let mut res = Bn { limbs: got };
        res.normalize();
        if !res.lt(&self.n) {
            res = res.sub(&self.n).unwrap_or_else(|_| Bn::zero());
        }
        Some(res)
    }

    fn mont_mul_generic(&self, a: &Bn, b: &Bn) -> Bn {
        let s = self.limbs;
        // Field-element sized operands (<= 1024 bits) run entirely on the
        // stack: only the result limbs are allocated.
        if s <= 16 {
            let mut ap = [0u64; 16];
            let mut bp = [0u64; 16];
            let mut scratch = [0u64; 33]; // 2 * 16 + 1
            for (i, &x) in a.limbs.iter().take(s).enumerate() {
                ap[i] = x;
            }
            for (i, &x) in b.limbs.iter().take(s).enumerate() {
                bp[i] = x;
            }
            self.mont_mul_core(&ap[..s], &bp[..s], &mut scratch[..2 * s + 1]);
            return self.mont_result(&mut scratch[s..2 * s + 1]);
        }
        let mut scratch = alloc::vec![0u64; 2 * s + 1];
        let mut ap = alloc::vec![0u64; s];
        let mut bp = alloc::vec![0u64; s];
        for (i, &x) in a.limbs.iter().take(s).enumerate() {
            ap[i] = x;
        }
        for (i, &x) in b.limbs.iter().take(s).enumerate() {
            bp[i] = x;
        }
        self.mont_mul_core(&ap, &bp, &mut scratch);
        self.mont_result(&mut scratch[s..2 * s + 1])
    }

    /// Normalize a raw `limbs + 1`-word CIOS result and reduce it below the
    /// modulus.
    fn mont_result(&self, raw: &mut [u64]) -> Bn {
        let mut res = Bn {
            limbs: alloc::vec::Vec::from(raw),
        };
        res.normalize();
        if !res.lt(&self.n) {
            res = res.sub(&self.n).unwrap_or_else(|_| Bn::zero());
        }
        res
    }

    /// CIOS Montgomery multiplication over fixed-width limb slices.
    ///
    /// `a` and `b` must be exactly `self.limbs` limbs (values below `R`); the
    /// `limbs + 1`-word result (< 2 * modulus) is left in
    /// `scratch[limbs..2 * limbs + 1]`. `scratch` needs `2 * limbs + 1` words
    /// and is used as scratch space only. Allocation-free: the classic CIOS
    /// per-iteration whole-buffer shift is folded into a moving window base,
    /// so iteration `i` works in place on `scratch[i..]`.
    pub(crate) fn mont_mul_core(&self, a: &[u64], b: &[u64], scratch: &mut [u64]) {
        let s = self.limbs;
        debug_assert_eq!(a.len(), s);
        debug_assert_eq!(b.len(), s);
        debug_assert!(scratch.len() >= 2 * s + 1);

        scratch[..s + 1].fill(0);
        let n = &self.n.limbs[..s];

        for i in 0..s {
            // t = t + a_i * b (t is the window scratch[i..i+s+2])
            let bi = b[i] as u128;
            let mut carry = 0u128;
            for (tj, &aj) in scratch[i..i + s].iter_mut().zip(a.iter()) {
                let v = (*tj as u128) + (aj as u128) * bi + carry;
                *tj = v as u64;
                carry = v >> 64;
            }
            let v = (scratch[i + s] as u128) + carry;
            scratch[i + s] = v as u64;
            scratch[i + s + 1] = (v >> 64) as u64;

            // m = t_0 * n0 mod 2^64; t = t + m * n
            let m = scratch[i].wrapping_mul(self.n0) as u128;
            let mut carry = 0u128;
            for (tj, &nj) in scratch[i..i + s].iter_mut().zip(n.iter()) {
                let v = (*tj as u128) + m * (nj as u128) + carry;
                *tj = v as u64;
                carry = v >> 64;
            }
            let v = (scratch[i + s] as u128) + carry;
            scratch[i + s] = v as u64;
            scratch[i + s + 1] += (v >> 64) as u64;

            // the "shift t right by one limb" of the textbook CIOS is the
            // window base bump: iteration i + 1 starts at scratch[i + 1].
        }
    }

    /// Reduce a raw `limbs + 1`-word CIOS result in place to below the
    /// modulus (one conditional subtract; the input is < 2n).
    fn mont_finish_s1(&self, raw: &mut [u64]) {
        let s = self.limbs;
        let n = &self.n.limbs[..s];
        // raw >= n? Equality counts (raw == n must reduce to zero).
        let mut ge = raw[s] != 0;
        if !ge {
            ge = true;
            for j in (0..s).rev() {
                if raw[j] != n[j] {
                    ge = raw[j] > n[j];
                    break;
                }
            }
        }
        if ge {
            let mut borrow = 0u64;
            for j in 0..s {
                let (d, b1) = raw[j].overflowing_sub(n[j]);
                let (d, b2) = d.overflowing_sub(borrow);
                borrow = (b1 as u64) | (b2 as u64);
                raw[j] = d;
            }
            raw[s] = 0;
        }
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

    /// `a^e mod n` with `a` in Montgomery form.
    ///
    /// Pure-software path. All intermediates stay in fixed-width limb
    /// buffers (one scratch for every multiplication, one buffer for the
    /// window table), so a full exponentiation performs no per-multiplication
    /// allocation. Exponents up to 64 bits use plain square-and-multiply;
    /// wider exponents use a 4-bit window.
    pub fn pow(&self, a_mont: &Bn, e: &Bn) -> Bn {
        let s = self.limbs;
        debug_assert_eq!(self.n.limbs.len(), s);

        let mut scratch = alloc::vec![0u64; 2 * s + 1];
        let mut base = alloc::vec![0u64; s];
        for (i, &x) in a_mont.limbs.iter().take(s).enumerate() {
            base[i] = x;
        }
        let one_m = self.to_mont(&Bn::one());

        let bits = e.bit_len();
        let mut acc = alloc::vec![0u64; s];
        if bits == 0 {
            acc.copy_from_slice(&one_m.limbs[..s.min(one_m.limbs.len())]);
            return Bn { limbs: acc };
        }

        if bits <= 64 {
            // MSB-first square-and-multiply: bits/2 multiplications on
            // average, and no window-table setup. acc starts at a^1 (the
            // MSB is consumed by the initialization).
            acc.copy_from_slice(&base);
            for i in (0..bits - 1).rev() {
                self.mont_mul_core(&acc, &acc, &mut scratch);
                self.mont_finish_s1(&mut scratch[s..]);
                acc.copy_from_slice(&scratch[s..2 * s]);
                if e.bit(i) {
                    self.mont_mul_core(&acc, &base, &mut scratch);
                    self.mont_finish_s1(&mut scratch[s..]);
                    acc.copy_from_slice(&scratch[s..2 * s]);
                }
            }
            return Bn { limbs: acc };
        }

        // 4-bit window table of precomputed powers a^0..a^15 (Montgomery
        // form, each reduced below the modulus).
        let mut table = alloc::vec![0u64; 16 * s];
        let top = &one_m.limbs[..s.min(one_m.limbs.len())];
        table[..top.len()].copy_from_slice(top);
        table[s..2 * s].copy_from_slice(&base);
        for i in 2..16 {
            self.mont_mul_core(&table[(i - 1) * s..i * s], &base, &mut scratch);
            self.mont_finish_s1(&mut scratch[s..]);
            table[i * s..(i + 1) * s].copy_from_slice(&scratch[s..2 * s]);
        }

        acc.copy_from_slice(&table[..s]);
        let mut i = bits;
        while i > 0 {
            // consume a 4-bit window
            let w = 4usize.min(i);
            for _ in 0..w {
                self.mont_mul_core(&acc, &acc, &mut scratch);
                self.mont_finish_s1(&mut scratch[s..]);
                acc.copy_from_slice(&scratch[s..2 * s]);
            }
            let mut nib = 0u8;
            for k in 0..w {
                // bit i-w+k maps to nibble bit k (k = w-1 is the window's
                // most significant bit).
                if e.bit(i - w + k) {
                    nib |= 1 << k;
                }
            }
            let entry = &table[nib as usize * s..nib as usize * s + s];
            self.mont_mul_core(&acc, entry, &mut scratch);
            self.mont_finish_s1(&mut scratch[s..]);
            acc.copy_from_slice(&scratch[s..2 * s]);
            i -= w;
        }
        Bn { limbs: acc }
    }

    /// Constant-time `a^e mod n` via the mont5 5-bit-window power table
    /// (`bn_scatter5` / `bn_power5` / `bn_mul_mont_gather5`). Falls back to
    /// the 4-bit window when the asm is unavailable or the limb count is
    /// unsupported.
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    pub fn pow_consttime(&self, a_mont: &Bn, e: &Bn) -> Bn {
        let num = self.limbs;
        if !(2..=64).contains(&num) {
            return self.pow(a_mont, e);
        }

        let pad = |b: &Bn| -> alloc::vec::Vec<u64> {
            let mut v = alloc::vec![0u64; num];
            #[allow(clippy::manual_memcpy)]
            for i in 0..num.min(b.limbs.len()) {
                v[i] = b.limbs[i];
            }
            v
        };
        let a = pad(a_mont);
        let n0 = self.n0;

        // scatter5 places limb i of entry idx at tbl[i*32 + idx]; the asm
        // walks 256 bytes (=32 slots) per limb. Buffer covers num limbs.
        let mut powerbuf = alloc::vec![0u64; num * 32 + 32];

        // Montgomery 1 is R mod n = to_mont(1); a^1 = a.
        let one_m = pad(&self.to_mont(&Bn::one()));
        asm::scatter5(&one_m, &mut powerbuf, 0);
        asm::scatter5(&a, &mut powerbuf, 1);

        let sq = |x: &alloc::vec::Vec<u64>| -> alloc::vec::Vec<u64> {
            // mul_mont returns at most `num` limbs with capacity `num`, so
            // re-padding never reallocates.
            let mut v = asm::mul_mont(x, x, &self.n.limbs, n0).unwrap_or_else(|| x.clone());
            v.resize(num, 0);
            v
        };

        let mut tmp = sq(&a);
        asm::scatter5(&tmp, &mut powerbuf, 2);
        let mut i = 4;
        while i < 32 {
            tmp = sq(&tmp);
            asm::scatter5(&tmp, &mut powerbuf, i);
            i *= 2;
        }
        i = 3;
        while i < 32 {
            let g = match asm::mul_mont_gather5(&a, &powerbuf, &self.n.limbs, n0, i - 1) {
                Some(mut v) => {
                    v.resize(num, 0);
                    v
                }
                None => return self.pow(a_mont, e),
            };
            asm::scatter5(&g, &mut powerbuf, i);
            let mut cur = g;
            let mut j = 2 * i;
            while j < 32 {
                cur = sq(&cur);
                asm::scatter5(&cur, &mut powerbuf, j);
                j *= 2;
            }
            i += 2;
        }

        let bit = |b: usize| -> bool {
            let limb = b / 64;
            limb < e.limbs.len() && ((e.limbs[limb] >> (b % 64)) & 1) == 1
        };

        let mut bi = e.bit_len() as i64 - 1;
        if bi < 0 {
            // a^0 = 1 in Montgomery form
            return self.from_mont(&self.to_mont(&Bn::one()));
        }

        let first = (bi % 5 + 1) as usize;
        let mut w = 0usize;
        for _ in 0..first {
            w = (w << 1) | (bit(bi as usize) as usize);
            bi -= 1;
        }
        let mut acc = alloc::vec![0u64; num];
        asm::gather5(&mut acc, &powerbuf, w);

        let use_power5 = num.is_multiple_of(8);
        while bi >= 0 {
            let mut w = 0usize;
            for _ in 0..5 {
                w = (w << 1) | (bit(bi as usize) as usize);
                bi -= 1;
            }
            if use_power5 {
                let mut v = match asm::power5(&acc, &powerbuf, &self.n.limbs, n0, w) {
                    Some(v) => v,
                    None => return self.pow(a_mont, e),
                };
                v.resize(num, 0);
                acc = v;
            } else {
                for _ in 0..5 {
                    acc = sq(&acc);
                }
                let mut v = match asm::mul_mont_gather5(&acc, &powerbuf, &self.n.limbs, n0, w) {
                    Some(v) => v,
                    None => return self.pow(a_mont, e),
                };
                v.resize(num, 0);
                acc = v;
            }
        }

        let mut res = Bn { limbs: acc };
        res.normalize();
        if !res.lt(&self.n) {
            res = res.sub(&self.n).unwrap_or(res);
        }
        res
    }
}
