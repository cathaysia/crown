use super::*;

fn variant_mldsa(bits: u32) -> Option<crown::ml_dsa::MlDsaVariant> {
    use crown::ml_dsa::MlDsaVariant;
    match bits {
        44 => Some(MlDsaVariant::MlDsa44),
        65 => Some(MlDsaVariant::MlDsa65),
        87 => Some(MlDsaVariant::MlDsa87),
        _ => None,
    }
}

fn variant_slh(name: &str) -> Option<crown::slh_dsa::SlhDsaVariant> {
    crown::slh_dsa::SlhDsaVariant::from_name(name)
}

/// ML-DSA keygen from 32-byte seed. variant = 44/65/87.
/// On success writes pk/sk; call with null buffers first to get lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_dsa_keygen(
    variant: u32,
    seed: *const u8,
    seed_len: usize,
    public: *mut u8,
    public_len: *mut usize,
    private: *mut u8,
    private_len: *mut usize,
) -> i32 {
    let Some(var) = variant_mldsa(variant) else { return -1 };
    unsafe {
        let seed = match slice_from_raw_parts(seed, seed_len) {
            Some(s) if s.len() == 32 => s,
            _ => return -1,
        };
        let mut s = [0u8; 32];
        s.copy_from_slice(seed);
        let (pk, sk) = match crown::ml_dsa::keygen(var, &s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let pkb = pk.to_bytes().to_vec();
        let skb = sk.to_bytes().to_vec();
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
pub unsafe extern "C" fn ml_dsa_sign(
    variant: u32,
    private: *const u8,
    private_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> i32 {
    let Some(var) = variant_mldsa(variant) else { return -1 };
    use crown::ml_dsa::{sign, MlDsaPrivateKey};
    unsafe {
        let skb = match slice_from_raw_parts(private, private_len) {
            Some(s) => s,
            None => return -1,
        };
        let sk = match MlDsaPrivateKey::from_bytes(var, skb) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let msg = if msg.is_null() {
            &[][..]
        } else {
            match slice_from_raw_parts(msg, msg_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let ctx = if ctx.is_null() {
            &[][..]
        } else {
            match slice_from_raw_parts(ctx, ctx_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let out = match sign(&sk, msg, ctx, None) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        if sig.is_null() {
            if !sig_len.is_null() {
                *sig_len = out.len();
            }
            return -2;
        }
        std::ptr::copy_nonoverlapping(out.as_ptr(), sig, out.len());
        if !sig_len.is_null() {
            *sig_len = out.len();
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_dsa_verify(
    variant: u32,
    public: *const u8,
    public_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    let Some(var) = variant_mldsa(variant) else { return -1 };
    use crown::ml_dsa::{verify, MlDsaPublicKey};
    unsafe {
        let pkb = match slice_from_raw_parts(public, public_len) {
            Some(s) => s,
            None => return -1,
        };
        let pk = match MlDsaPublicKey::from_bytes(var, pkb) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let msg = if msg.is_null() {
            &[][..]
        } else {
            match slice_from_raw_parts(msg, msg_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let ctx = if ctx.is_null() {
            &[][..]
        } else {
            match slice_from_raw_parts(ctx, ctx_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let sig = match slice_from_raw_parts(sig, sig_len) {
            Some(s) => s,
            None => return -1,
        };
        match verify(&pk, msg, ctx, sig) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    }
}

/// SLH-DSA keygen. `name` is e.g. "SLH-DSA-SHA2-128s". seed is 3n bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slh_dsa_keygen(
    name: *const u8,
    name_len: usize,
    seed: *const u8,
    seed_len: usize,
    public: *mut u8,
    public_len: *mut usize,
    private: *mut u8,
    private_len: *mut usize,
) -> i32 {
    let name = unsafe {
        match slice_from_raw_parts(name, name_len) {
            Some(s) => match std::str::from_utf8(s) {
                Ok(s) => s,
                Err(_) => return -1,
            },
            None => return -1,
        }
    };
    let Some(var) = variant_slh(name) else { return -1 };
    unsafe {
        let seed = match slice_from_raw_parts(seed, seed_len) {
            Some(s) => s,
            None => return -1,
        };
        let (pk, sk) = match crown::slh_dsa::keygen(var, seed) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let pkb = pk.to_bytes().to_vec();
        let skb = sk.to_bytes().to_vec();
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
pub unsafe extern "C" fn slh_dsa_sign(
    name: *const u8,
    name_len: usize,
    private: *const u8,
    private_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> i32 {
    let name = unsafe {
        match slice_from_raw_parts(name, name_len) {
            Some(s) => match std::str::from_utf8(s) {
                Ok(s) => s,
                Err(_) => return -1,
            },
            None => return -1,
        }
    };
    let Some(var) = variant_slh(name) else { return -1 };
    use crown::slh_dsa::{sign, SlhDsaPrivateKey};
    unsafe {
        let skb = match slice_from_raw_parts(private, private_len) {
            Some(s) => s,
            None => return -1,
        };
        let sk = match SlhDsaPrivateKey::from_bytes(var, skb) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let msg = if msg.is_null() {
            &[][..]
        } else {
            match slice_from_raw_parts(msg, msg_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let ctx = if ctx.is_null() {
            &[][..]
        } else {
            match slice_from_raw_parts(ctx, ctx_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let out = match sign(&sk, msg, ctx, false) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        if sig.is_null() {
            if !sig_len.is_null() {
                *sig_len = out.len();
            }
            return -2;
        }
        std::ptr::copy_nonoverlapping(out.as_ptr(), sig, out.len());
        if !sig_len.is_null() {
            *sig_len = out.len();
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn slh_dsa_verify(
    name: *const u8,
    name_len: usize,
    public: *const u8,
    public_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    let name = unsafe {
        match slice_from_raw_parts(name, name_len) {
            Some(s) => match std::str::from_utf8(s) {
                Ok(s) => s,
                Err(_) => return -1,
            },
            None => return -1,
        }
    };
    let Some(var) = variant_slh(name) else { return -1 };
    use crown::slh_dsa::{verify, SlhDsaPublicKey};
    unsafe {
        let pkb = match slice_from_raw_parts(public, public_len) {
            Some(s) => s,
            None => return -1,
        };
        let pk = match SlhDsaPublicKey::from_bytes(var, pkb) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let msg = if msg.is_null() {
            &[][..]
        } else {
            match slice_from_raw_parts(msg, msg_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let ctx = if ctx.is_null() {
            &[][..]
        } else {
            match slice_from_raw_parts(ctx, ctx_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let sig = match slice_from_raw_parts(sig, sig_len) {
            Some(s) => s,
            None => return -1,
        };
        match verify(&pk, msg, ctx, sig, false) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    }
}
