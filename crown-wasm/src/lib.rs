use wasm_bindgen::prelude::*;

pub mod evp_aead;
pub mod evp_block;
pub mod evp_hash;
pub mod evp_stream;
pub mod evp_xts;
pub mod evp_misc;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}
