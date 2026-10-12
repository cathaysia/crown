use napi::bindgen_prelude::*;

#[napi]
pub fn ed25519_keygen() -> Buffer {
    let mut seed = [0u8; 32];
    let _ = getrandom::fill(&mut seed);
    let public = crown::ed25519::public_from_secret(&seed);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&seed);
    out.extend_from_slice(&public);
    Buffer::from(out)
}

#[napi]
pub fn ed25519_sign(secret: &[u8], msg: &[u8]) -> Result<Buffer> {
    if secret.len() != 32 {
        return Err(Error::new(
            Status::GenericFailure,
            "secret must be 32 bytes",
        ));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(secret);
    Ok(Buffer::from(crown::ed25519::sign(&sk, msg).to_vec()))
}

#[napi]
pub fn ed25519_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
    if public.len() != 32 || sig.len() != 64 {
        return Err(Error::new(
            Status::GenericFailure,
            "bad key/signature length",
        ));
    }
    let mut pk = [0u8; 32];
    let mut sg = [0u8; 64];
    pk.copy_from_slice(public);
    sg.copy_from_slice(sig);
    Ok(crown::ed25519::verify(&pk, &sg, msg))
}
