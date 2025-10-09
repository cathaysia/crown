use super::*;
use kittycrypto::envelope::EvpStreamCipher;

pub struct StreamCipher(EvpStreamCipher);

macro_rules! impl_stream_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?],
        special: [$($special:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<stream_cipher_new_ $basic:lower _cfb>](
                    key: *const u8,
                    key_len: usize,
                    iv: *const u8,
                    iv_len: usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let iv_slice = match slice_from_raw_parts(iv, iv_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };

                        match EvpStreamCipher::[<new_ $basic:lower _cfb>](key_slice, iv_slice) {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }

                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<stream_cipher_new_ $basic:lower _ctr>](
                    key: *const u8,
                    key_len: usize,
                    iv: *const u8,
                    iv_len: usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let iv_slice = match slice_from_raw_parts(iv, iv_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };

                        match EvpStreamCipher::[<new_ $basic:lower _ctr>](key_slice, iv_slice) {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }

                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<stream_cipher_new_ $basic:lower _ofb>](
                    key: *const u8,
                    key_len: usize,
                    iv: *const u8,
                    iv_len: usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let iv_slice = match slice_from_raw_parts(iv, iv_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };

                        match EvpStreamCipher::[<new_ $basic:lower _ofb>](key_slice, iv_slice) {
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
                pub unsafe extern "C" fn [<stream_cipher_new_ $rc:lower _cfb>](
                    key: *const u8,
                    key_len: usize,
                    iv: *const u8,
                    iv_len: usize,
                    rounds: *const usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let iv_slice = match slice_from_raw_parts(iv, iv_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let rounds_opt = option_from_ptr(rounds);

                        match EvpStreamCipher::[<new_ $rc:lower _cfb>](key_slice, iv_slice, rounds_opt) {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }

                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<stream_cipher_new_ $rc:lower _ctr>](
                    key: *const u8,
                    key_len: usize,
                    iv: *const u8,
                    iv_len: usize,
                    rounds: *const usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let iv_slice = match slice_from_raw_parts(iv, iv_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let rounds_opt = option_from_ptr(rounds);

                        match EvpStreamCipher::[<new_ $rc:lower _ctr>](key_slice, iv_slice, rounds_opt) {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }

                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<stream_cipher_new_ $rc:lower _ofb>](
                    key: *const u8,
                    key_len: usize,
                    iv: *const u8,
                    iv_len: usize,
                    rounds: *const usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let iv_slice = match slice_from_raw_parts(iv, iv_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };
                        let rounds_opt = option_from_ptr(rounds);

                        match EvpStreamCipher::[<new_ $rc:lower _ofb>](key_slice, iv_slice, rounds_opt) {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }
            }
        )*
        $(
            impl_stream_cipher!(@special $special);
        )*
    };
    (@special rc4) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn stream_cipher_new_rc4(key: *const u8, key_len: usize) -> *mut Self {
            unsafe {
                let key_slice = match slice_from_raw_parts(key, key_len) {
                    Some(slice) => slice,
                    None => return std::ptr::null_mut(),
                };

                match EvpStreamCipher::new_rc4(key_slice) {
                    Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                    Err(_) => std::ptr::null_mut(),
                }
            }
        }
    };
    (@special salsa20) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn stream_cipher_new_salsa20(
            key: *const u8,
            key_len: usize,
            iv: *const u8,
            iv_len: usize
        ) -> *mut Self {
            unsafe {
                let key_slice = match slice_from_raw_parts(key, key_len) {
                    Some(slice) => slice,
                    None => return std::ptr::null_mut(),
                };
                let iv_slice = match slice_from_raw_parts(iv, iv_len) {
                    Some(slice) => slice,
                    None => return std::ptr::null_mut(),
                };

                match EvpStreamCipher::new_salsa20(key_slice, iv_slice) {
                    Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                    Err(_) => std::ptr::null_mut(),
                }
            }
        }
    };
    (@special chacha20) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn stream_cipher_new_chacha20(
            key: *const u8,
            key_len: usize,
            iv: *const u8,
            iv_len: usize
        ) -> *mut Self {
            unsafe {
                let key_slice = match slice_from_raw_parts(key, key_len) {
                    Some(slice) => slice,
                    None => return std::ptr::null_mut(),
                };
                let iv_slice = match slice_from_raw_parts(iv, iv_len) {
                    Some(slice) => slice,
                    None => return std::ptr::null_mut(),
                };

                match EvpStreamCipher::new_chacha20(key_slice, iv_slice) {
                    Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                    Err(_) => std::ptr::null_mut(),
                }
            }
        }
    };
}

impl StreamCipher {
    impl_stream_cipher!(
        basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack],
        rounds: [Rc2, Rc5, Camellia],
        special: [rc4, salsa20, chacha20],
    );

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn stream_cipher_encrypt(&mut self, inout: *mut u8, len: usize) -> i32 {
        if inout.is_null() || len == 0 {
            return 0;
        }
        let inout = unsafe { std::slice::from_raw_parts_mut(inout, len) };
        if self.0.encrypt(inout).is_err() {
            return -1;
        }

        0
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn stream_cipher_decrypt(&mut self, inout: *mut u8, len: usize) -> i32 {
        if inout.is_null() || len == 0 {
            return 0;
        }
        let inout = unsafe { std::slice::from_raw_parts_mut(inout, len) };
        if self.0.decrypt(inout).is_err() {
            return -1;
        }

        0
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn stream_cipher_free(cipher: *mut Self) {
        if !cipher.is_null() {
            unsafe {
                let _ = Box::from_raw(cipher);
            }
        }
    }
}
