use super::*;
use crown::envelope::EvpMac;

pub struct Mac(EvpMac);

impl Mac {
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mac_new_siphash(
        key: *const u8,
        key_len: usize,
        output_len: usize,
    ) -> *mut Self {
        unsafe {
            let key = match slice_from_raw_parts(key, key_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            match EvpMac::new_siphash(key, output_len) {
                Ok(m) => Box::into_raw(Box::new(Self(m))),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mac_new_kmac128(
        key: *const u8,
        key_len: usize,
        custom: *const u8,
        custom_len: usize,
        output_len: usize,
    ) -> *mut Self {
        unsafe {
            let key = match slice_from_raw_parts(key, key_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            let custom = if custom.is_null() {
                &[][..]
            } else {
                match slice_from_raw_parts(custom, custom_len) {
                    Some(s) => s,
                    None => return std::ptr::null_mut(),
                }
            };
            match EvpMac::new_kmac128(key, custom, output_len) {
                Ok(m) => Box::into_raw(Box::new(Self(m))),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mac_new_kmac256(
        key: *const u8,
        key_len: usize,
        custom: *const u8,
        custom_len: usize,
        output_len: usize,
    ) -> *mut Self {
        unsafe {
            let key = match slice_from_raw_parts(key, key_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            let custom = if custom.is_null() {
                &[][..]
            } else {
                match slice_from_raw_parts(custom, custom_len) {
                    Some(s) => s,
                    None => return std::ptr::null_mut(),
                }
            };
            match EvpMac::new_kmac256(key, custom, output_len) {
                Ok(m) => Box::into_raw(Box::new(Self(m))),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mac_new_cmac_aes(key: *const u8, key_len: usize) -> *mut Self {
        unsafe {
            let key = match slice_from_raw_parts(key, key_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            match EvpMac::new_cmac_aes(key) {
                Ok(m) => Box::into_raw(Box::new(Self(m))),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mac_new_gmac_aes(
        key: *const u8,
        key_len: usize,
        iv: *const u8,
        iv_len: usize,
    ) -> *mut Self {
        unsafe {
            let key = match slice_from_raw_parts(key, key_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            let iv = match slice_from_raw_parts(iv, iv_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            match EvpMac::new_gmac_aes(key, iv) {
                Ok(m) => Box::into_raw(Box::new(Self(m))),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mac_write(&mut self, data: *const u8, len: usize) {
        if let Some(s) = unsafe { slice_from_raw_parts(data, len) } {
            self.0.write(s);
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mac_sum(&mut self, out: *mut u8, out_len: usize) -> i32 {
        let tag = self.0.sum();
        if out.is_null() || out_len < tag.len() {
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(tag.as_ptr(), out, tag.len());
        }
        tag.len() as i32
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mac_free(this: *mut Self) {
        if !this.is_null() {
            unsafe { drop(Box::from_raw(this)) };
        }
    }
}
