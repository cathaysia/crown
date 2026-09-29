use super::*;
use crown::ml_kem::{
    decapsulate, encapsulate, keygen, MlKemPrivateKey, MlKemPublicKey, MlKemVariant,
};

fn variant_of(v: u32) -> Option<MlKemVariant> {
    match v {
        512 => Some(MlKemVariant::MlKem512),
        768 => Some(MlKemVariant::MlKem768),
        1024 => Some(MlKemVariant::MlKem1024),
        _ => None,
    }
}

/// Keygen from 64-byte seed. `variant` is 512/768/1024.
/// `public` and `private` buffers must be large enough (see ml_kem lengths).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_keygen(
    variant: u32,
    seed: *const u8,
    seed_len: usize,
    public: *mut u8,
    public_len: *mut usize,
    private: *mut u8,
    private_len: *mut usize,
) -> i32 {
    let Some(var) = variant_of(variant) else {
        return -1;
    };
    unsafe {
        let seed = match slice_from_raw_parts(seed, seed_len) {
            Some(s) if s.len() == 64 => s,
            _ => return -1,
        };
        let mut s = [0u8; 64];
        s.copy_from_slice(seed);
        let (pk, sk) = match keygen(var, &s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let pkb = pk.to_bytes();
        let skb = sk.to_bytes();
        if public.is_null() || private.is_null() {
            if !public_len.is_null() {
                *public_len = pkb.len();
            }
            if !private_len.is_null() {
                *private_len = skb.len();
            }
            return -2;
        }
        std::ptr::copy_nonoverlapping(pkb.as_ptr(), public, pkb.len());
        std::ptr::copy_nonoverlapping(skb.as_ptr(), private, skb.len());
        if !public_len.is_null() {
            *public_len = pkb.len();
        }
        if !private_len.is_null() {
            *private_len = skb.len();
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_encapsulate(
    variant: u32,
    public: *const u8,
    public_len: usize,
    message: *const u8,
    message_len: usize,
    ciphertext: *mut u8,
    ciphertext_len: *mut usize,
    shared: *mut u8,
) -> i32 {
    let Some(var) = variant_of(variant) else {
        return -1;
    };
    unsafe {
        let pkb = match slice_from_raw_parts(public, public_len) {
            Some(s) => s,
            None => return -1,
        };
        let pk = match MlKemPublicKey::from_bytes(var, pkb) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let mut m = [0u8; 32];
        if message.is_null() || message_len != 32 {
            return -1;
        }
        m.copy_from_slice(slice_from_raw_parts(message, 32).unwrap());
        let (ct, ss) = match encapsulate(&pk, &m) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        if ciphertext.is_null() || shared.is_null() {
            if !ciphertext_len.is_null() {
                *ciphertext_len = ct.len();
            }
            return -2;
        }
        std::ptr::copy_nonoverlapping(ct.as_ptr(), ciphertext, ct.len());
        std::ptr::copy_nonoverlapping(ss.as_ptr(), shared, 32);
        if !ciphertext_len.is_null() {
            *ciphertext_len = ct.len();
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_decapsulate(
    variant: u32,
    private: *const u8,
    private_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    shared: *mut u8,
) -> i32 {
    let Some(var) = variant_of(variant) else {
        return -1;
    };
    unsafe {
        let skb = match slice_from_raw_parts(private, private_len) {
            Some(s) => s,
            None => return -1,
        };
        let sk = match MlKemPrivateKey::from_bytes(var, skb) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let ct = match slice_from_raw_parts(ciphertext, ciphertext_len) {
            Some(s) => s,
            None => return -1,
        };
        let ss = match decapsulate(&sk, ct) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        std::ptr::copy_nonoverlapping(ss.as_ptr(), shared, 32);
    }
    0
}
