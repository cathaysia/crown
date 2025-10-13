use super::*;
use crown::envelope::EvpBlockCipher;

pub struct BlockCipher(EvpBlockCipher);

macro_rules! impl_block_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<block_cipher_new_ $basic:lower _cbc>](
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

                        match EvpBlockCipher::[<new_ $basic:lower _cbc>](key_slice, iv_slice) {
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
                pub unsafe extern "C" fn [<block_cipher_new_ $rc:lower _cbc>](
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

                        match EvpBlockCipher::[<new_ $rc:lower _cbc>](key_slice, iv_slice, rounds_opt) {
                            Ok(cipher) => Box::into_raw(Box::new(Self(cipher))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }
            }
        )*
    };
}

impl BlockCipher {
    impl_block_cipher!(
        basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack],
        rounds: [Rc2, Rc5, Camellia],
    );

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn block_cipher_encrypt(
        &mut self,
        inout: *mut u8,
        inout_len: usize,
        pos: usize,
        output_len: *mut usize,
    ) -> i32 {
        if inout.is_null() || output_len.is_null() {
            return -1;
        }

        let inout_slice = unsafe { std::slice::from_raw_parts_mut(inout, inout_len) };

        match self.0.encrypt(inout_slice, pos) {
            Ok(len) => {
                unsafe { *output_len = len };
                0
            }
            Err(_) => -1,
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn block_cipher_decrypt(
        &mut self,
        inout: *mut u8,
        inout_len: usize,
        output_len: *mut usize,
    ) -> i32 {
        if inout.is_null() || output_len.is_null() {
            return -1;
        }

        let inout_slice = unsafe { std::slice::from_raw_parts_mut(inout, inout_len) };

        match self.0.decrypt(inout_slice) {
            Ok(len) => {
                unsafe { *output_len = len };
                0
            }
            Err(_) => -1,
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn block_cipher_free(cipher: *mut Self) {
        if !cipher.is_null() {
            unsafe {
                let _ = Box::from_raw(cipher);
            }
        }
    }
}
