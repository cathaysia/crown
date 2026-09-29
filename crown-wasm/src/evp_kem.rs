use crown::ml_kem::{
    decapsulate, encapsulate, keygen, MlKemPrivateKey, MlKemPublicKey, MlKemVariant,
};
use wasm_bindgen::prelude::*;

fn variant_of(bits: u32) -> Result<MlKemVariant, JsValue> {
    match bits {
        512 => Ok(MlKemVariant::MlKem512),
        768 => Ok(MlKemVariant::MlKem768),
        1024 => Ok(MlKemVariant::MlKem1024),
        _ => Err(JsValue::from_str("variant must be 512/768/1024")),
    }
}

/// Returns `public || private`.
#[wasm_bindgen]
pub fn ml_kem_keygen(variant: u32, seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let var = variant_of(variant)?;
    if seed.len() != 64 {
        return Err(JsValue::from_str("seed must be 64 bytes"));
    }
    let mut s = [0u8; 64];
    s.copy_from_slice(seed);
    let (pk, sk) = keygen(var, &s).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let mut out = pk.to_bytes().to_vec();
    out.extend_from_slice(sk.to_bytes());
    Ok(out)
}

/// Returns `ciphertext || shared_secret`.
#[wasm_bindgen]
pub fn ml_kem_encapsulate(variant: u32, public: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let var = variant_of(variant)?;
    if message.len() != 32 {
        return Err(JsValue::from_str("message must be 32 bytes"));
    }
    let pk = MlKemPublicKey::from_bytes(var, public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let mut m = [0u8; 32];
    m.copy_from_slice(message);
    let (ct, ss) = encapsulate(&pk, &m).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let mut out = ct;
    out.extend_from_slice(&ss);
    Ok(out)
}

#[wasm_bindgen]
pub fn ml_kem_decapsulate(
    variant: u32,
    private: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let var = variant_of(variant)?;
    let sk = MlKemPrivateKey::from_bytes(var, private)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    decapsulate(&sk, ciphertext)
        .map(|ss| ss.to_vec())
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}
