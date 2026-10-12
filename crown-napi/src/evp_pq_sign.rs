use crate::crypto_err;
use napi::bindgen_prelude::*;

fn variant_mldsa(bits: u32) -> Result<crown::ml_dsa::MlDsaVariant> {
    use crown::ml_dsa::MlDsaVariant;
    match bits {
        44 => Ok(MlDsaVariant::MlDsa44),
        65 => Ok(MlDsaVariant::MlDsa65),
        87 => Ok(MlDsaVariant::MlDsa87),
        _ => Err(Error::new(
            Status::GenericFailure,
            "ML-DSA variant must be 44/65/87",
        )),
    }
}

/// Returns `public || private`.
#[napi]
pub fn ml_dsa_keygen(variant: u32, seed: &[u8]) -> Result<Buffer> {
    let var = variant_mldsa(variant)?;
    if seed.len() != 32 {
        return Err(Error::new(Status::GenericFailure, "seed must be 32 bytes"));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    let (pk, sk) = crown::ml_dsa::keygen(var, &s).map_err(|e| crypto_err("keygen", e))?;
    let mut out = pk.to_bytes().to_vec();
    out.extend_from_slice(&sk.to_bytes());
    Ok(Buffer::from(out))
}

#[napi]
pub fn ml_dsa_sign(variant: u32, private: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Buffer> {
    let var = variant_mldsa(variant)?;
    let sk = crown::ml_dsa::MlDsaPrivateKey::from_bytes(var, private)
        .map_err(|e| crypto_err("private key", e))?;
    crown::ml_dsa::sign(&sk, msg, ctx, None)
        .map(Buffer::from)
        .map_err(|e| crypto_err("sign", e))
}

#[napi]
pub fn ml_dsa_verify(
    variant: u32,
    public: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool> {
    let var = variant_mldsa(variant)?;
    let pk = crown::ml_dsa::MlDsaPublicKey::from_bytes(var, public)
        .map_err(|e| crypto_err("public key", e))?;
    crown::ml_dsa::verify(&pk, msg, ctx, sig).map_err(|e| crypto_err("verify", e))
}

/// Returns `public || private`.
#[napi]
pub fn slh_dsa_keygen(name: String, seed: &[u8]) -> Result<Buffer> {
    let var = crown::slh_dsa::SlhDsaVariant::from_name(&name)
        .ok_or_else(|| Error::new(Status::GenericFailure, "unknown SLH-DSA variant"))?;
    let (pk, sk) = crown::slh_dsa::keygen(var, seed).map_err(|e| crypto_err("keygen", e))?;
    let mut out = pk.to_bytes().to_vec();
    out.extend_from_slice(sk.to_bytes());
    Ok(Buffer::from(out))
}

#[napi]
pub fn slh_dsa_sign(name: String, private: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Buffer> {
    let var = crown::slh_dsa::SlhDsaVariant::from_name(&name)
        .ok_or_else(|| Error::new(Status::GenericFailure, "unknown SLH-DSA variant"))?;
    let sk = crown::slh_dsa::SlhDsaPrivateKey::from_bytes(var, private)
        .map_err(|e| crypto_err("private key", e))?;
    crown::slh_dsa::sign(&sk, msg, ctx, false)
        .map(Buffer::from)
        .map_err(|e| crypto_err("sign", e))
}

#[napi]
pub fn slh_dsa_verify(
    name: String,
    public: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool> {
    let var = crown::slh_dsa::SlhDsaVariant::from_name(&name)
        .ok_or_else(|| Error::new(Status::GenericFailure, "unknown SLH-DSA variant"))?;
    let pk = crown::slh_dsa::SlhDsaPublicKey::from_bytes(var, public)
        .map_err(|e| crypto_err("public key", e))?;
    crown::slh_dsa::verify(&pk, msg, ctx, sig, false).map_err(|e| crypto_err("verify", e))
}
