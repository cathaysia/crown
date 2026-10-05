use wasm_bindgen::prelude::*;

pub mod evp_aead;
pub mod evp_block;
pub mod evp_hash;
pub mod evp_kdf;
pub mod evp_kem;
pub mod evp_mac;
pub mod evp_misc;
pub mod evp_pki;
pub mod evp_pq_sign;
pub mod evp_sign;
pub mod evp_stream;
pub mod evp_xts;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}
