use super::*;
use crown::envelope::EvpAeadCipher;

pub struct AeadCipher(EvpAeadCipher);

macro_rules! impl_aead_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?],
        special: [$($special:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<aead_cipher_new_ $basic:lower _gcm>](
                    key: *const u8,
                    key_len: usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };

                        match EvpAeadCipher::[<new_ $basic:lower _gcm>](key_slice) {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }

                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<aead_cipher_new_ $basic:lower _ocb3>](
                    key: *const u8,
                    key_len: usize,
                    tag_size: usize,
                    nonce_size: usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };

                        let result = match (tag_size, nonce_size) {
                            (16, 12) => EvpAeadCipher::[<new_ $basic:lower _ocb3>]::<16, 12>(key_slice),
                            (16, 15) => EvpAeadCipher::[<new_ $basic:lower _ocb3>]::<16, 15>(key_slice),
                            _ => return std::ptr::null_mut(),
                        };

                        match result {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<aead_cipher_new_ $rc:lower _gcm>](
                    key: *const u8,
                    key_len: usize,
                    rounds: *const usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let rounds_opt = option_from_ptr(rounds);

                        match EvpAeadCipher::[<new_ $rc:lower _gcm>](key_slice, rounds_opt) {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }
            }
        )*
        $(
            impl_aead_cipher!(@special $special);
        )*
    };
    (@special chacha20_poly1305) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn aead_cipher_new_chacha20_poly1305(
            key: *const u8,
            key_len: usize
        ) -> *mut Self {
            unsafe {
                let key_slice = match slice_from_raw_parts(key, key_len) {
                    Some(slice) => slice,
                    None => return std::ptr::null_mut(),
                };

                match EvpAeadCipher::new_chacha20_poly1305(key_slice) {
                    Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                    Err(_) => std::ptr::null_mut(),
                }
            }
        }
    };
    (@special xchacha20_poly1305) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn aead_cipher_new_xchacha20_poly1305(
            key: *const u8,
            key_len: usize
        ) -> *mut Self {
            unsafe {
                let key_slice = match slice_from_raw_parts(key, key_len) {
                    Some(slice) => slice,
                    None => return std::ptr::null_mut(),
                };

                match EvpAeadCipher::new_xchacha20_poly1305(key_slice) {
                    Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                    Err(_) => std::ptr::null_mut(),
                }
            }
        }
    };
}

impl AeadCipher {
    impl_aead_cipher!(
        basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6, Sm4, Skipjack],
        rounds: [Rc2, Rc5, Camellia],
        special: [chacha20_poly1305, xchacha20_poly1305],
    );

    #[unsafe(no_mangle)]
    pub extern "C" fn aead_cipher_nonce_size(&self) -> usize {
        self.0.nonce_size()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn aead_cipher_tag_size(&self) -> usize {
        self.0.tag_size()
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn aead_cipher_seal_in_place_separate_tag(
        &self,
        inout: *mut u8,
        inout_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        aad: *const u8,
        aad_len: usize,
        tag: *mut u8,
        tag_len: usize,
    ) -> i32 {
        if inout.is_null() || nonce.is_null() || tag.is_null() {
            return -1;
        }

        let inout_slice = unsafe { std::slice::from_raw_parts_mut(inout, inout_len) };
        let nonce_slice = unsafe {
            match slice_from_raw_parts(nonce, nonce_len) {
                Some(slice) => slice,
                None => return -1,
            }
        };
        let aad_slice = if aad.is_null() {
            &[]
        } else {
            unsafe {
                match slice_from_raw_parts(aad, aad_len) {
                    Some(slice) => slice,
                    None => return -1,
                }
            }
        };

        let mac = match self
            .0
            .seal_in_place_separate_tag(inout_slice, nonce_slice, aad_slice)
        {
            Ok(mac) => mac,
            Err(_) => return -1,
        };

        if tag_len < mac.len() {
            return -1;
        }

        let tag_slice = unsafe { std::slice::from_raw_parts_mut(tag, tag_len) };
        tag_slice[..mac.len()].copy_from_slice(&mac);
        mac.len() as i32
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn aead_cipher_open_in_place_separate_tag(
        &self,
        inout: *mut u8,
        inout_len: usize,
        tag: *const u8,
        tag_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        aad: *const u8,
        aad_len: usize,
    ) -> i32 {
        if inout.is_null() || tag.is_null() || nonce.is_null() {
            return -1;
        }

        let inout_slice = unsafe { std::slice::from_raw_parts_mut(inout, inout_len) };
        let tag_slice = unsafe {
            match slice_from_raw_parts(tag, tag_len) {
                Some(slice) => slice,
                None => return -1,
            }
        };
        let nonce_slice = unsafe {
            match slice_from_raw_parts(nonce, nonce_len) {
                Some(slice) => slice,
                None => return -1,
            }
        };
        let aad_slice = if aad.is_null() {
            &[]
        } else {
            unsafe {
                match slice_from_raw_parts(aad, aad_len) {
                    Some(slice) => slice,
                    None => return -1,
                }
            }
        };

        match self
            .0
            .open_in_place_separate_tag(inout_slice, tag_slice, nonce_slice, aad_slice)
        {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn aead_cipher_free(cipher: *mut Self) {
        if !cipher.is_null() {
            unsafe {
                let _ = Box::from_raw(cipher);
            }
        }
    }
}
