use super::*;

fn out_vec(v: Vec<u8>, out_len: *mut usize) -> *mut u8 {
    unsafe {
        if !out_len.is_null() {
            *out_len = v.len();
        }
    }
    let mut b = v.into_boxed_slice();
    let p = b.as_mut_ptr();
    std::mem::forget(b);
    p
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_key_wrap(
    key: *const u8,
    key_len: usize,
    pt: *const u8,
    pt_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let key = match slice_from_raw_parts(key, key_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let pt = match slice_from_raw_parts(pt, pt_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        match crown::envelope::aes_key_wrap(key, pt) {
            Ok(v) => out_vec(v, out_len),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_key_unwrap(
    key: *const u8,
    key_len: usize,
    ct: *const u8,
    ct_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let key = match slice_from_raw_parts(key, key_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let ct = match slice_from_raw_parts(ct, ct_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        match crown::envelope::aes_key_unwrap(key, ct) {
            Ok(v) => out_vec(v, out_len),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_key_wrap_padded(
    key: *const u8,
    key_len: usize,
    pt: *const u8,
    pt_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let key = match slice_from_raw_parts(key, key_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let pt = match slice_from_raw_parts(pt, pt_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        match crown::envelope::aes_key_wrap_padded(key, pt) {
            Ok(v) => out_vec(v, out_len),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_key_unwrap_padded(
    key: *const u8,
    key_len: usize,
    ct: *const u8,
    ct_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let key = match slice_from_raw_parts(key, key_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let ct = match slice_from_raw_parts(ct, ct_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        match crown::envelope::aes_key_unwrap_padded(key, ct) {
            Ok(v) => out_vec(v, out_len),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// FF1 decimal encrypt. Returns a newly allocated ASCII string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ff1_encrypt_decimal(
    key: *const u8,
    key_len: usize,
    tweak: *const u8,
    tweak_len: usize,
    input: *const u8,
    input_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let key = match slice_from_raw_parts(key, key_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let tweak = match slice_from_raw_parts(tweak, tweak_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let raw = match slice_from_raw_parts(input, input_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let s = match std::str::from_utf8(raw) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        match crown::envelope::ff1_encrypt_decimal(key, tweak, s) {
            Ok(v) => out_vec(v.into_bytes(), out_len),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ff1_decrypt_decimal(
    key: *const u8,
    key_len: usize,
    tweak: *const u8,
    tweak_len: usize,
    input: *const u8,
    input_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let key = match slice_from_raw_parts(key, key_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let tweak = match slice_from_raw_parts(tweak, tweak_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let raw = match slice_from_raw_parts(input, input_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let s = match std::str::from_utf8(raw) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        match crown::envelope::ff1_decrypt_decimal(key, tweak, s) {
            Ok(v) => out_vec(v.into_bytes(), out_len),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crown_free_buf(p: *mut u8, len: usize) {
    if !p.is_null() {
        unsafe { drop(Vec::from_raw_parts(p, len, len)) };
    }
}
