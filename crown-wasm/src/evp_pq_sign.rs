use wasm_bindgen::prelude::*;

fn variant_mldsa(bits: u32) -> Result<crown::ml_dsa::MlDsaVariant, JsValue> {
    use crown::ml_dsa::MlDsaVariant;
    match bits {
        44 => Ok(MlDsaVariant::MlDsa44),
        65 => Ok(MlDsaVariant::MlDsa65),
        87 => Ok(MlDsaVariant::MlDsa87),
        _ => Err(JsValue::from_str("ML-DSA variant must be 44/65/87")),
    }
}

/// Returns `public || private`.
#[wasm_bindgen]
pub fn ml_dsa_keygen(variant: u32, seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let var = variant_mldsa(variant)?;
    if seed.len() != 32 {
        return Err(JsValue::from_str("seed must be 32 bytes"));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    let (pk, sk) = crown::ml_dsa::keygen(var, &s)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let mut out = pk.to_bytes().to_vec();
    out.extend_from_slice(&sk.to_bytes());
    Ok(out)
}

#[wasm_bindgen]
pub fn ml_dsa_sign(
    variant: u32,
    private: &[u8],
    msg: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let var = variant_mldsa(variant)?;
    let sk = crown::ml_dsa::MlDsaPrivateKey::from_bytes(var, private)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    crown::ml_dsa::sign(&sk, msg, ctx, None)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn ml_dsa_verify(
    variant: u32,
    public: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let var = variant_mldsa(variant)?;
    let pk = crown::ml_dsa::MlDsaPublicKey::from_bytes(var, public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    crown::ml_dsa::verify(&pk, msg, ctx, sig)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

/// Returns `public || private`.
#[wasm_bindgen]
pub fn slh_dsa_keygen(name: &str, seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let var = crown::slh_dsa::SlhDsaVariant::from_name(name)
        .ok_or_else(|| JsValue::from_str("unknown SLH-DSA variant"))?;
    let (pk, sk) = crown::slh_dsa::keygen(var, seed)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let mut out = pk.to_bytes().to_vec();
    out.extend_from_slice(&sk.to_bytes());
    Ok(out)
}

#[wasm_bindgen]
pub fn slh_dsa_sign(
    name: &str,
    private: &[u8],
    msg: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let var = crown::slh_dsa::SlhDsaVariant::from_name(name)
        .ok_or_else(|| JsValue::from_str("unknown SLH-DSA variant"))?;
    let sk = crown::slh_dsa::SlhDsaPrivateKey::from_bytes(var, private)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    crown::slh_dsa::sign(&sk, msg, ctx, false)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn slh_dsa_verify(
    name: &str,
    public: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let var = crown::slh_dsa::SlhDsaVariant::from_name(name)
        .ok_or_else(|| JsValue::from_str("unknown SLH-DSA variant"))?;
    let pk = crown::slh_dsa::SlhDsaPublicKey::from_bytes(var, public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    crown::slh_dsa::verify(&pk, msg, ctx, sig, false)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}
