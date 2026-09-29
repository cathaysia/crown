use super::*;
use crown::envelope::EvpXts;

pub struct Xts(EvpXts);

impl Xts {
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xts_new_aes(key: *const u8, key_len: usize) -> *mut Self {
        unsafe {
            let key_slice = match slice_from_raw_parts(key, key_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            match EvpXts::new_aes_xts(key_slice) {
                Ok(x) => Box::into_raw(Box::new(Self(x))),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xts_new_sm4_gb(key: *const u8, key_len: usize) -> *mut Self {
        unsafe {
            let key_slice = match slice_from_raw_parts(key, key_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            match EvpXts::new_sm4_xts_gb(key_slice) {
                Ok(x) => Box::into_raw(Box::new(Self(x))),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xts_new_sm4(key: *const u8, key_len: usize) -> *mut Self {
        unsafe {
            let key_slice = match slice_from_raw_parts(key, key_len) {
                Some(s) => s,
                None => return std::ptr::null_mut(),
            };
            match EvpXts::new_sm4_xts(key_slice) {
                Ok(x) => Box::into_raw(Box::new(Self(x))),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xts_encrypt(
        &self,
        tweak: *const u8,
        tweak_len: usize,
        data: *mut u8,
        data_len: usize,
    ) -> i32 {
        unsafe {
            let tweak = match slice_from_raw_parts(tweak, tweak_len) {
                Some(s) => s,
                None => return -1,
            };
            let data = if data.is_null() {
                return -1;
            } else {
                std::slice::from_raw_parts_mut(data, data_len)
            };
            match self.0.encrypt(tweak, data) {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xts_decrypt(
        &self,
        tweak: *const u8,
        tweak_len: usize,
        data: *mut u8,
        data_len: usize,
    ) -> i32 {
        unsafe {
            let tweak = match slice_from_raw_parts(tweak, tweak_len) {
                Some(s) => s,
                None => return -1,
            };
            let data = if data.is_null() {
                return -1;
            } else {
                std::slice::from_raw_parts_mut(data, data_len)
            };
            match self.0.decrypt(tweak, data) {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xts_free(this: *mut Self) {
        if !this.is_null() {
            unsafe { drop(Box::from_raw(this)) };
        }
    }
}
