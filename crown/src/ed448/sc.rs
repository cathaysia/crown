//! Scalar arithmetic modulo the group order
//! `L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885`
//! (RFC 8032 §5.2).
//!
//! Scalars are little-endian 57-byte strings. Reduction walks the input
//! bit by bit with a conditional subtract, mirroring [`crate::ed25519::sc`].

/// The group order `L`, little-endian (57 bytes).
pub const L: [u8; 57] = [
    0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
    0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x00,
];

/// 1 if `x >= L` (branch-free borrow chain).
fn ct_ge_l(x: &[u8; 57]) -> u8 {
    let mut borrow = 0u8;
    for i in 0..57 {
        let (d1, b1) = x[i].overflowing_sub(L[i]);
        let (_, b2) = d1.overflowing_sub(borrow);
        borrow = (b1 as u8) | (b2 as u8);
    }
    1 - borrow
}

/// `x -= L` when `set` is 1 (branch-free).
fn ct_sub_l(x: &mut [u8; 57], set: u8) {
    let mask = set.wrapping_neg();
    let mut borrow = 0u8;
    for i in 0..57 {
        let (d1, b1) = x[i].overflowing_sub(L[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        borrow = (b1 as u8) | (b2 as u8);
        x[i] = (x[i] & !mask) | (d2 & mask);
    }
}

/// Reduce a 114-byte little-endian integer modulo L.
pub fn reduce_wide(wide: &[u8; 114]) -> [u8; 57] {
    let mut acc = [0u8; 57];
    for i in (0..114 * 8).rev() {
        // acc = acc * 2 + bit; acc < L < 2^447 keeps everything in 57 bytes.
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

/// Multiply two 57-byte little-endian integers into 114 little-endian bytes.
fn mul_wide(a: &[u8; 57], b: &[u8; 57]) -> [u8; 114] {
    let mut r = [0u8; 114];
    for i in 0..57 {
        let mut carry = 0u16;
        for j in 0..57 {
            let t = r[i + j] as u16 + (a[i] as u16) * (b[j] as u16) + carry;
            r[i + j] = t as u8;
            carry = t >> 8;
        }
        let mut k = i + 57;
        while carry != 0 {
            let t = r[k] as u16 + carry;
            r[k] = t as u8;
            carry = t >> 8;
            k += 1;
        }
    }
    r
}

fn add_wide(wide: &mut [u8; 114], addend: &[u8; 57]) {
    let mut carry = 0u16;
    for i in 0..57 {
        let s = wide[i] as u16 + addend[i] as u16 + carry;
        wide[i] = s as u8;
        carry = s >> 8;
    }
    let mut i = 57;
    while carry != 0 {
        let s = wide[i] as u16 + carry;
        wide[i] = s as u8;
        carry = s >> 8;
        i += 1;
    }
}

/// `(a * b + c) mod L` (ref10 `sc_muladd` shape).
pub fn muladd(a: &[u8; 57], b: &[u8; 57], c: &[u8; 57]) -> [u8; 57] {
    let mut wide = mul_wide(a, b);
    add_wide(&mut wide, c);
    reduce_wide(&wide)
}

/// 1 if `s` is a canonical scalar (`s < L`), 0 otherwise (variable time;
/// the input is public).
pub fn is_canonical(s: &[u8; 57]) -> bool {
    for i in (0..57).rev() {
        if s[i] < L[i] {
            return true;
        }
        if s[i] > L[i] {
            return false;
        }
    }
    false // s == L itself is not canonical
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_small() {
        let mut s = [0u8; 57];
        s[0] = 5;
        let mut wide = [0u8; 114];
        wide[..57].copy_from_slice(&s);
        assert_eq!(reduce_wide(&wide), s);
    }

    #[test]
    fn reduce_l_is_zero() {
        let mut wide = [0u8; 114];
        wide[..57].copy_from_slice(&L);
        assert_eq!(reduce_wide(&wide), [0u8; 57]);
    }

    #[test]
    fn muladd_basics() {
        let mut one = [0u8; 57];
        one[0] = 1;
        let mut two = [0u8; 57];
        two[0] = 2;
        let mut three = [0u8; 57];
        three[0] = 3;
        let mut four = [0u8; 57];
        four[0] = 4;
        let mut ten = [0u8; 57];
        ten[0] = 10;
        assert_eq!(muladd(&two, &three, &four), ten);
        assert_eq!(muladd(&one, &one, &one), two); // 1*1 + 1
    }

    #[test]
    fn canonicality() {
        assert!(is_canonical(&[0u8; 57]));
        assert!(!is_canonical(&L));
        let mut too_big = [0xffu8; 57];
        too_big[56] = 0xff;
        assert!(!is_canonical(&too_big));
        let mut almost = L;
        almost[0] = almost[0].wrapping_sub(1);
        assert!(is_canonical(&almost));
    }
}
