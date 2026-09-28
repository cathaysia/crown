//! SLH-DSA parameter sets (FIPS 205 Section 11, Table 2).

/// SLH-DSA parameter set.
///
/// Covers the twelve parameter sets of FIPS 205 Table 2, distinguished by the
/// underlying hash family (`SHA2` or `SHAKE`) and the speed/security trade-off
/// (`s` for small signatures, `f` for fast signing).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(non_camel_case_types)]
pub enum SlhDsaVariant {
    Sha2_128s,
    Sha2_128f,
    Sha2_192s,
    Sha2_192f,
    Sha2_256s,
    Sha2_256f,
    Shake_128s,
    Shake_128f,
    Shake_192s,
    Shake_192f,
    Shake_256s,
    Shake_256f,
}

/// Constants of one SLH-DSA parameter set.
///
/// `lg_w` is fixed at 4 (w = 16) for all FIPS 205 parameter sets and is
/// therefore not stored.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Algorithm name, e.g. `"SLH-DSA-SHA2-128s"`.
    pub name: &'static str,
    /// True for the SHAKE parameter sets (SHAKE-256 is used for all functions).
    pub is_shake: bool,
    /// Security parameter: byte length of seeds and of signature elements.
    pub n: usize,
    /// Total height of the hypertree (number of key pairs = 2^h).
    pub h: u32,
    /// Number of XMSS layers in the hypertree.
    pub d: u32,
    /// Height of each XMSS tree (h = d * hm).
    pub hm: u32,
    /// Height of each FORS tree.
    pub a: u32,
    /// Number of FORS trees.
    pub k: u32,
    /// Byte length of the H_msg() output.
    pub m: usize,
    /// Public key byte length (2n).
    pub pk_len: usize,
    /// Signature byte length.
    pub sig_len: usize,
    /// Zero padding width used by the SHA2 H()/T() functions (64 or 128).
    pub ht_bound: usize,
    /// True when H()/T() use SHA-512 (security categories 3 and 5).
    pub big_hash: bool,
}

/// WOTS+ chain length parameter: w = 16, so `len1 = 2n` digits and `len2 = 3`
/// checksum digits, giving `len = 2n + 3` chains.
pub(crate) const WOTS_W: u8 = 16;
pub(crate) const WOTS_LEN2: usize = 3;

/// Maximum security parameter `n` across the parameter sets (bytes).
pub(crate) const MAX_N: usize = 32;
/// Maximum number of FORS trees `k` across the parameter sets.
pub(crate) const MAX_K: usize = 35;

impl Params {
    /// `len` = number of WOTS+ chains (FIPS 205 Section 5).
    pub(crate) fn wots_len(&self) -> usize {
        2 * self.n + WOTS_LEN2
    }

    /// Byte length of the message digest `md` consumed by FORS.
    pub(crate) fn md_len(&self) -> usize {
        (self.k as usize * self.a as usize + 7) / 8
    }

}

macro_rules! params {
    ($variant:ident, $name:literal, $is_shake:expr, $n:expr, $h:expr, $d:expr,
     $hm:expr, $a:expr, $k:expr, $m:expr, $bound:expr, $big:expr) => {
        Params {
            name: $name,
            is_shake: $is_shake,
            n: $n,
            h: $h,
            d: $d,
            hm: $hm,
            a: $a,
            k: $k,
            m: $m,
            pk_len: 2 * $n,
            sig_len: $n * (1 + $k as usize * (1 + $a as usize) + $d as usize * (2 * $n + 3 + $hm as usize)),
            ht_bound: $bound,
            big_hash: $big,
        }
    };
}

/// FIPS 205 Table 2 parameter sets.
pub(crate) static PARAMS: [Params; 12] = [
    // SLH-DSA-SHA2-128s: n=16, h=63, d=7, h'=9, a=12, k=14, m=30
    params!(Sha2_128s, "SLH-DSA-SHA2-128s", false, 16, 63, 7, 9, 12, 14, 30, 64, false),
    // SLH-DSA-SHA2-128f: n=16, h=66, d=22, h'=3, a=6, k=33, m=34
    params!(Sha2_128f, "SLH-DSA-SHA2-128f", false, 16, 66, 22, 3, 6, 33, 34, 64, false),
    // SLH-DSA-SHA2-192s: n=24, h=63, d=7, h'=9, a=14, k=17, m=39
    params!(Sha2_192s, "SLH-DSA-SHA2-192s", false, 24, 63, 7, 9, 14, 17, 39, 128, true),
    // SLH-DSA-SHA2-192f: n=24, h=66, d=22, h'=3, a=8, k=33, m=42
    params!(Sha2_192f, "SLH-DSA-SHA2-192f", false, 24, 66, 22, 3, 8, 33, 42, 128, true),
    // SLH-DSA-SHA2-256s: n=32, h=64, d=8, h'=8, a=14, k=22, m=47
    params!(Sha2_256s, "SLH-DSA-SHA2-256s", false, 32, 64, 8, 8, 14, 22, 47, 128, true),
    // SLH-DSA-SHA2-256f: n=32, h=68, d=17, h'=4, a=9, k=35, m=49
    params!(Sha2_256f, "SLH-DSA-SHA2-256f", false, 32, 68, 17, 4, 9, 35, 49, 128, true),
    // SLH-DSA-SHAKE-128s
    params!(Shake_128s, "SLH-DSA-SHAKE-128s", true, 16, 63, 7, 9, 12, 14, 30, 0, false),
    // SLH-DSA-SHAKE-128f
    params!(Shake_128f, "SLH-DSA-SHAKE-128f", true, 16, 66, 22, 3, 6, 33, 34, 0, false),
    // SLH-DSA-SHAKE-192s
    params!(Shake_192s, "SLH-DSA-SHAKE-192s", true, 24, 63, 7, 9, 14, 17, 39, 0, true),
    // SLH-DSA-SHAKE-192f
    params!(Shake_192f, "SLH-DSA-SHAKE-192f", true, 24, 66, 22, 3, 8, 33, 42, 0, true),
    // SLH-DSA-SHAKE-256s
    params!(Shake_256s, "SLH-DSA-SHAKE-256s", true, 32, 64, 8, 8, 14, 22, 47, 0, true),
    // SLH-DSA-SHAKE-256f
    params!(Shake_256f, "SLH-DSA-SHAKE-256f", true, 32, 68, 17, 4, 9, 35, 49, 0, true),
];

impl SlhDsaVariant {
    /// Number of variants in the FIPS 205 parameter table.
    pub const COUNT: usize = 12;

    /// All variants, in FIPS 205 Table 2 order.
    pub fn all() -> &'static [SlhDsaVariant; Self::COUNT] {
        &ALL_VARIANTS
    }

    /// Algorithm name of this variant, e.g. `"SLH-DSA-SHA2-128s"`.
    pub fn name(self) -> &'static str {
        self.params().name
    }

    /// Byte length of the public key (2n).
    pub fn public_key_len(self) -> usize {
        self.params().pk_len
    }

    /// Byte length of the private key (4n).
    pub fn private_key_len(self) -> usize {
        4 * self.params().n
    }

    /// Byte length of a signature.
    pub fn signature_len(self) -> usize {
        self.params().sig_len
    }

    /// Look up the parameter table entry.
    pub(crate) fn params(self) -> &'static Params {
        &PARAMS[self as usize]
    }

    /// Parse an algorithm name such as `"SLH-DSA-SHA2-128s"`.
    pub fn from_name(name: &str) -> Option<SlhDsaVariant> {
        Self::all()
            .iter()
            .copied()
            .find(|v| v.params().name == name)
    }
}

static ALL_VARIANTS: [SlhDsaVariant; 12] = [
    SlhDsaVariant::Sha2_128s,
    SlhDsaVariant::Sha2_128f,
    SlhDsaVariant::Sha2_192s,
    SlhDsaVariant::Sha2_192f,
    SlhDsaVariant::Sha2_256s,
    SlhDsaVariant::Sha2_256f,
    SlhDsaVariant::Shake_128s,
    SlhDsaVariant::Shake_128f,
    SlhDsaVariant::Shake_192s,
    SlhDsaVariant::Shake_192f,
    SlhDsaVariant::Shake_256s,
    SlhDsaVariant::Shake_256f,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 205 Table 2 signature and public key lengths.
    #[test]
    fn table_2_lengths() {
        let expect: &[(SlhDsaVariant, usize, usize, usize)] = &[
            (SlhDsaVariant::Sha2_128s, 32, 7856, 64),
            (SlhDsaVariant::Sha2_128f, 32, 17088, 64),
            (SlhDsaVariant::Sha2_192s, 48, 16224, 96),
            (SlhDsaVariant::Sha2_192f, 48, 35664, 96),
            (SlhDsaVariant::Sha2_256s, 64, 29792, 128),
            (SlhDsaVariant::Sha2_256f, 64, 49856, 128),
            (SlhDsaVariant::Shake_128s, 32, 7856, 64),
            (SlhDsaVariant::Shake_128f, 32, 17088, 64),
            (SlhDsaVariant::Shake_192s, 48, 16224, 96),
            (SlhDsaVariant::Shake_192f, 48, 35664, 96),
            (SlhDsaVariant::Shake_256s, 64, 29792, 128),
            (SlhDsaVariant::Shake_256f, 64, 49856, 128),
        ];
        for (v, pk, sig, sk) in expect {
            assert_eq!(v.public_key_len(), *pk, "{}", v.name());
            assert_eq!(v.signature_len(), *sig, "{}", v.name());
            assert_eq!(v.private_key_len(), *sk, "{}", v.name());
            let p = v.params();
            assert_eq!(p.h, p.d * p.hm, "{} h = d*h'", v.name());
        }
    }

    #[test]
    fn name_roundtrip() {
        for v in SlhDsaVariant::all() {
            assert_eq!(SlhDsaVariant::from_name(v.name()), Some(*v));
        }
        assert_eq!(SlhDsaVariant::from_name("SLH-DSA-SHA2-129s"), None);
    }
}
