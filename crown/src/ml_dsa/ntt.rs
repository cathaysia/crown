//! Number-theoretic transform and Montgomery arithmetic for ML-DSA.
//!
//! Ported from OpenSSL `crypto/ml_dsa/ml_dsa_ntt.c`. Montgomery reduction
//! uses R = 2^32 with `q^-1` satisfying `q^-1 * q ≡ 1 (mod 2^32)`.

use super::params::{N, Q};

/// Inverse of -q modulo 2^32 (`-q^{-1} mod 2^32`).
const Q_NEG_INV: u64 = 4_236_238_847;

/// 256^-1 mod q in Montgomery form (FIPS 204 Algorithm 42 final multiply).
const DEGREE_INV_MONTGOMERY: u64 = 41_978;

/// ζ_k = 1753^bitrev(k) mod q, pre-converted into Montgomery form.
/// Index 0 is unused by the NTT butterflies but kept for FIPS 204 parity.
static ZETAS_MONTGOMERY: [u32; 256] = [
    4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2353451,
    8021166, 6288512, 3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928,
    7830929, 7260833, 2619752, 6271868, 6262231, 4520680, 6980856, 5102745, 1757237, 8360995,
    4010497, 280005, 2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150, 6736599,
    3505694, 4558682, 3507263, 6239768, 6779997, 3699596, 811944, 531354, 954230, 3881043,
    3900724, 5823537, 2071892, 5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950,
    2176455, 6795196, 7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370, 7709315, 7151892,
    8357436, 7072248, 7998430, 1349076, 1852771, 6949987, 5037034, 264944, 508951, 3097992,
    44288, 7280319, 904516, 3958618, 4656075, 8371839, 1653064, 5130689, 2389356, 8169440,
    759969, 7063561, 189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961, 2091667, 3407706,
    2316500, 3817976, 5037939, 2244091, 5933984, 4817955, 266997, 2434439, 7144689, 3513181,
    4860065, 4621053, 7183191, 5187039, 900702, 1859098, 909542, 819034, 495491, 6767243,
    8337157, 7857917, 7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044, 2842341, 2691481,
    5790267, 1265009, 4055324, 1247620, 2486353, 1595974, 4613401, 1250494, 2635921, 4832145,
    5386378, 1869119, 1903435, 7329447, 7047359, 1237275, 5062207, 6950192, 7929317, 1312455,
    3306115, 6417775, 7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136, 4603424, 6366809, 2432395,
    2454455, 8215696, 1957272, 3369112, 185531, 7173032, 5196991, 162844, 1616392, 3014001,
    810149, 1652634, 4686184, 6581310, 5341501, 3523897, 3866901, 269760, 2213111, 7404533,
    1717735, 472078, 7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730, 7826001, 3919660,
    8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
];

/// Montgomery reduction of a product `a` of two Montgomery-form values.
/// Returns `a * 2^-32 mod q` in the range `0..q`.
///
/// See FIPS 204 Algorithm 49 (`MontgomeryReduce`); adapted for the
/// positive input range produced by `u32 * u32`.
#[inline(always)]
pub(crate) fn reduce_montgomery(a: u64) -> u32 {
    let t = (a as u32 as u64).wrapping_mul(Q_NEG_INV) & 0xFFFF_FFFF;
    let b = a.wrapping_add(t.wrapping_mul(Q as u64));
    let c = (b >> 32) as u32;
    reduce_once(c as u64)
}

/// Reduce `x` assumed `< 2q` into `0..q`, in constant time.
#[inline(always)]
pub(crate) fn reduce_once(x: u64) -> u32 {
    let x = x as u32;
    // mask = 0xFFFF_FFFF if x < q, else 0.
    let mask = (((x as u64) < (Q as u64)) as u32).wrapping_neg();
    (x & mask) | (x.wrapping_sub(Q) & !mask)
}

/// `(a - b) mod q` for `a, b ∈ 0..q`, returned in `0..q` (constant time).
#[inline(always)]
pub(crate) fn mod_sub(a: u32, b: u32) -> u32 {
    reduce_once(Q as u64 + a as u64 - b as u64)
}

/// In-place forward NTT (FIPS 204 Algorithm 41), Montgomery form.
pub(crate) fn ntt(p: &mut [u32; N]) {
    let mut offset = N;
    let mut step = 1;
    while step < N {
        offset >>= 1;
        let mut k = 0;
        for i in 0..step {
            let z = ZETAS_MONTGOMERY[step + i] as u64;
            for j in k..k + offset {
                let w_even = p[j] as u64;
                let t_odd = reduce_montgomery(z * p[j + offset] as u64) as u64;
                p[j] = reduce_once(w_even + t_odd);
                p[j + offset] = mod_sub(w_even as u32, t_odd as u32);
            }
            k += 2 * offset;
        }
        step <<= 1;
    }
}

/// In-place inverse NTT (FIPS 204 Algorithm 42), Montgomery form.
pub(crate) fn ntt_inverse(p: &mut [u32; N]) {
    let mut offset = 1;
    let mut step = N;
    while offset < N {
        step >>= 1;
        let mut k = 0;
        for i in 0..step {
            let z = Q - ZETAS_MONTGOMERY[step + (step - 1 - i)];
            for j in k..k + offset {
                let even = p[j];
                let odd = p[j + offset];
                p[j] = reduce_once(odd as u64 + even as u64);
                p[j + offset] =
                    reduce_montgomery(z as u64 * (Q as u64 + even as u64 - odd as u64));
            }
            k += 2 * offset;
        }
        offset <<= 1;
    }
    for c in p.iter_mut() {
        *c = reduce_montgomery(*c as u64 * DEGREE_INV_MONTGOMERY);
    }
}

/// Pointwise product of two NTT-form polynomials (FIPS 204 Algorithm 45).
pub(crate) fn ntt_mult(lhs: &[u32; N], rhs: &[u32; N], out: &mut [u32; N]) {
    for i in 0..N {
        out[i] = reduce_montgomery(lhs[i] as u64 * rhs[i] as u64);
    }
}
