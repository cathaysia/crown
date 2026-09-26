//! Scalar arithmetic modulo the group order
//! `L = 2^252 + 27742317777372353535851937790883648493`.
//!
//! The reduction walks the input bit by bit with a conditional subtract,
//! which is simple, branch-free and sufficient for a software reference.
//! Scalars are little-endian 32-byte strings, as in the ed25519 wire format.

/// The group order, little-endian.
pub const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// 1 if `x >= L` (branch-free borrow chain).
fn ct_ge_l(x: &[u8; 32]) -> u8 {
    let mut borrow = 0u8;
    for i in 0..32 {
        let (d1, b1) = x[i].overflowing_sub(L[i]);
        let (_, b2) = d1.overflowing_sub(borrow);
        borrow = (b1 as u8) | (b2 as u8);
    }
    1 - borrow
}

/// `x -= L` when `set` is 1 (branch-free).
fn ct_sub_l(x: &mut [u8; 32], set: u8) {
    let mask = set.wrapping_neg();
    let mut borrow = 0u8;
    for i in 0..32 {
        let (d1, b1) = x[i].overflowing_sub(L[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        borrow = (b1 as u8) | (b2 as u8);
        x[i] = (x[i] & !mask) | (d2 & mask);
    }
}

/// Reduce a 64-byte little-endian integer modulo L.
pub fn reduce_wide(wide: &[u8; 64]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for i in (0..512).rev() {
        // acc = acc * 2 + bit; acc < L < 2^253 keeps everything in 256 bits.
        let mut carry = (wide[i / 8] >> (i % 8)) & 1;
        for b in acc.iter_mut() {
            let next = *b >> 7;
            *b = (*b << 1) | carry;
            carry = next;
        }
        let ge = ct_ge_l(&acc);
        ct_sub_l(&mut acc, ge);
    }
    acc
}

/// Multiply two 512-bit little-endian integers into 64 little-endian bytes.
fn mul_wide(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
    let a_limbs: [u64; 4] =
        core::array::from_fn(|i| u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap()));
    let b_limbs: [u64; 4] =
        core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()));

    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = (a_limbs[i] as u128) * (b_limbs[j] as u128) + (r[i + j] as u128) + carry;
            r[i + j] = t as u64;
            carry = t >> 64;
        }
        // carry cannot overflow the remaining limbs for 4x4 limbs.
        let mut k = i + 4;
        while carry != 0 && k < 8 {
            let t = (r[k] as u128) + carry;
            r[k] = t as u64;
            carry = t >> 64;
            k += 1;
        }
    }

    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..i * 8 + 8].copy_from_slice(&r[i].to_le_bytes());
    }
    out
}

fn add_wide(wide: &mut [u8; 64], addend: &[u8; 32]) {
    let mut carry = 0u16;
    for i in 0..32 {
        let s = wide[i] as u16 + addend[i] as u16 + carry;
        wide[i] = s as u8;
        carry = s >> 8;
    }
    let mut i = 32;
    while carry != 0 && i < 64 {
        let s = wide[i] as u16 + carry;
        wide[i] = s as u8;
        carry = s >> 8;
        i += 1;
    }
}

/// `(a * b + c) mod L` with all inputs below L (ref10 `sc_muladd`).
pub fn muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut wide = mul_wide(a, b);
    add_wide(&mut wide, c);
    reduce_wide(&wide)
}

/// 1 if `s` is a canonical scalar (< L), 0 otherwise (variable time; the
/// input is public).
pub fn is_canonical(s: &[u8; 32]) -> bool {
    // Reject s >= 2^252 outright (most significant byte > 0x10).
    if s[31] > 0x10 {
        return false;
    }
    if s[31] == 0x10 {
        // Compare the low 16 bytes against the low half of L.
        let mut nonzero = 0u8;
        for b in &s[16..31] {
            nonzero |= *b;
        }
        if nonzero != 0 {
            return false;
        }
        for i in (0..16).rev() {
            if s[i] < L[i] {
                return true;
            }
            if s[i] > L[i] {
                return false;
            }
        }
        return false; // s == L itself is not canonical
    }
    true
}

#[cfg(test)]
mod sc_tests {
    use super::*;

    #[test]
    fn reduce_small() {
        let mut s = [0u8; 32];
        s[0] = 5;
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&s);
        assert_eq!(reduce_wide(&wide), s);
    }

    #[test]
    fn reduce_l_is_zero() {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&L);
        assert_eq!(reduce_wide(&wide), [0u8; 32]);
    }

    // (L - 1) + 1 == 0; muladd(2, 3, 4) == 10.
    #[test]
    fn muladd_basics() {
        let mut a = L;
        a[0] -= 1;
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(muladd(&one, &one, &a), [0u8; 32]);

        let mut two = [0u8; 32];
        let mut three = [0u8; 32];
        let mut four = [0u8; 32];
        two[0] = 2;
        three[0] = 3;
        four[0] = 4;
        let mut ten = [0u8; 32];
        ten[0] = 10;
        assert_eq!(muladd(&two, &three, &four), ten);
    }

    #[test]
    fn canonicality() {
        assert!(is_canonical(&[0u8; 32]));
        assert!(!is_canonical(&L));
        let mut too_big = [0xffu8; 32];
        too_big[31] = 0xff;
        assert!(!is_canonical(&too_big));
    }
}
