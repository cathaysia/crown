use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn ed25519_keygen() -> Result<Vec<u8>, JsValue> {
    let mut seed = [0u8; 32];
    getrandom_fill(&mut seed);
    let public = crown::ed25519::public_from_secret(&seed);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&seed);
    out.extend_from_slice(&public);
    Ok(out)
}

#[wasm_bindgen]
pub fn ed25519_sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret.len() != 32 {
        return Err(JsValue::from_str("secret must be 32 bytes"));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(secret);
    Ok(crown::ed25519::sign(&sk, msg).to_vec())
}

#[wasm_bindgen]
pub fn ed25519_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, JsValue> {
    if public.len() != 32 || sig.len() != 64 {
        return Err(JsValue::from_str("bad key/signature length"));
    }
    let mut pk = [0u8; 32];
    let mut sg = [0u8; 64];
    pk.copy_from_slice(public);
    sg.copy_from_slice(sig);
    Ok(crown::ed25519::verify(&pk, &sg, msg))
}

fn getrandom_fill(buf: &mut [u8]) {
    use std::io::Read;
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf));
}
