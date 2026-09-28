use super::*;

/// Ed25519 keygen. Writes 32-byte seed to `seed`, 32-byte public to `public`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ed25519_keygen(seed: *mut u8, public: *mut u8) -> i32 {
    if seed.is_null() || public.is_null() {
        return -1;
    }
    let mut s = [0u8; 32];
    getrandom_fill(&mut s);
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr(), seed, 32);
    }
    let pk = crown::ed25519::public_from_secret(&s);
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_ptr(), public, 32);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ed25519_sign(
    secret: *const u8,
    secret_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *mut u8,
) -> i32 {
    unsafe {
        let secret = match slice_from_raw_parts(secret, secret_len) {
            Some(s) if s.len() == 32 => s,
            _ => return -1,
        };
        let msg = if msg.is_null() && msg_len == 0 {
            &[][..]
        } else {
            match slice_from_raw_parts(msg, msg_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let mut sk = [0u8; 32];
        sk.copy_from_slice(secret);
        let out = crown::ed25519::sign(&sk, msg);
        std::ptr::copy_nonoverlapping(out.as_ptr(), sig, 64);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ed25519_verify(
    public: *const u8,
    public_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    unsafe {
        let public = match slice_from_raw_parts(public, public_len) {
            Some(s) if s.len() == 32 => s,
            _ => return -1,
        };
        let msg = if msg.is_null() && msg_len == 0 {
            &[][..]
        } else {
            match slice_from_raw_parts(msg, msg_len) {
                Some(s) => s,
                None => return -1,
            }
        };
        let sig = match slice_from_raw_parts(sig, sig_len) {
            Some(s) if s.len() == 64 => s,
            _ => return -1,
        };
        let mut pk = [0u8; 32];
        let mut sg = [0u8; 64];
        pk.copy_from_slice(public);
        sg.copy_from_slice(sig);
        if crown::ed25519::verify(&pk, &sg, msg) {
            1
        } else {
            0
        }
    }
}

fn getrandom_fill(buf: &mut [u8]) {
    use std::io::Read;
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf));
}
