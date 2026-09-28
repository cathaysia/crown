use wasm_bindgen::prelude::*;

pub mod evp_aead;
pub mod evp_block;
pub mod evp_hash;
pub mod evp_stream;
pub mod evp_xts;
pub mod evp_misc;
pub mod evp_mac;
pub mod evp_sign;
pub mod evp_kem;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}
