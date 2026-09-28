//! ML-DSA parameter sets (FIPS 204 Table 1 & Table 2).

/// The ML-DSA parameter set / security category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    /// ML-DSA-44 (security category 2).
    MlDsa44,
    /// ML-DSA-65 (security category 3).
    MlDsa65,
    /// ML-DSA-87 (security category 5).
    MlDsa87,
}

/// Shared constants for all ML-DSA parameter sets (FIPS 204 §4).
pub(crate) const Q: u32 = 8_380_417;
pub(crate) const Q_MINUS1_DIV2: u32 = (Q - 1) / 2;
pub(crate) const D_BITS: u32 = 13;
pub(crate) const N: usize = 256;

pub(crate) const RHO_BYTES: usize = 32;
pub(crate) const PRIV_SEED_BYTES: usize = 64;
pub(crate) const K_BYTES: usize = 32;
pub(crate) const TR_BYTES: usize = 64;
pub(crate) const MU_BYTES: usize = 64;
pub(crate) const RHO_PRIME_BYTES: usize = 64;
pub(crate) const SEED_BYTES: usize = 32;

/// Maximum context string length accepted by `ML-DSA.Sign` / `ML-DSA.Verify`.
pub const MAX_CONTEXT_STRING_LEN: usize = 255;

/// Eta values: bound on secret key coefficients.
pub(crate) const ETA_2: u32 = 2;
pub(crate) const ETA_4: u32 = 4;

/// Gamma1 values (signed coefficient bound of the mask y).
pub(crate) const GAMMA1_17: u32 = 1 << 17;
pub(crate) const GAMMA1_19: u32 = 1 << 19;

/// Gamma2 values (low-order rounding bound).
pub(crate) const GAMMA2_Q_MINUS1_DIV32: u32 = (Q - 1) / 32;
pub(crate) const GAMMA2_Q_MINUS1_DIV88: u32 = (Q - 1) / 88;

/// Parameter set for one ML-DSA variant.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Params {
    /// Collision strength λ in bits; `c_tilde` is λ/4 bytes.
    pub lambda: usize,
    /// Matrix rows.
    pub k: usize,
    /// Matrix columns.
    pub l: usize,
    /// Hamming weight of the challenge polynomial.
    pub tau: u32,
    /// Secret coefficient bound η.
    pub eta: u32,
    /// Rejection bound β.
    pub beta: u32,
    /// Maximum number of 1s in the hint vector.
    pub omega: u32,
    /// Mask coefficient bound γ1.
    pub gamma1: u32,
    /// Low-order rounding bound γ2.
    pub gamma2: u32,
    /// Encoded public key length in bytes.
    pub pk_len: usize,
    /// Encoded private key length in bytes.
    pub sk_len: usize,
    /// Encoded signature length in bytes.
    pub sig_len: usize,
}

impl Params {
    /// Bytes per encoded `w1` polynomial.
    pub(crate) fn w1_poly_bytes(&self) -> usize {
        if self.gamma2 == GAMMA2_Q_MINUS1_DIV88 {
            192 // 6 bits per coefficient
        } else {
            128 // 4 bits per coefficient
        }
    }



    /// Total `w1` encoded length.
    pub(crate) fn w1_encoded_len(&self) -> usize {
        self.k * self.w1_poly_bytes()
    }

    /// Length of `c_tilde`.
    pub(crate) fn c_tilde_len(&self) -> usize {
        self.lambda / 4
    }
}

/// Look up the parameter set for a variant (FIPS 204 Table 1 & Table 2).
pub(crate) fn params(variant: MlDsaVariant) -> Params {
    match variant {
        MlDsaVariant::MlDsa44 => Params {
            lambda: 128,
            k: 4,
            l: 4,
            tau: 39,
            eta: ETA_2,
            beta: 78,
            omega: 80,
            gamma1: GAMMA1_17,
            gamma2: GAMMA2_Q_MINUS1_DIV88,
            pk_len: 1312,
            sk_len: 2560,
            sig_len: 2420,
        },
        MlDsaVariant::MlDsa65 => Params {
            lambda: 192,
            k: 6,
            l: 5,
            tau: 49,
            eta: ETA_4,
            beta: 196,
            omega: 55,
            gamma1: GAMMA1_19,
            gamma2: GAMMA2_Q_MINUS1_DIV32,
            pk_len: 1952,
            sk_len: 4032,
            sig_len: 3309,
        },
        MlDsaVariant::MlDsa87 => Params {
            lambda: 256,
            k: 8,
            l: 7,
            tau: 60,
            eta: ETA_2,
            beta: 120,
            omega: 75,
            gamma1: GAMMA1_19,
            gamma2: GAMMA2_Q_MINUS1_DIV32,
            pk_len: 2592,
            sk_len: 4896,
            sig_len: 4627,
        },
    }
}
