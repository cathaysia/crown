import {
  ml_kem_decapsulate,
  ml_kem_encapsulate,
  ml_kem_keygen,
  ml_dsa_keygen,
  ml_dsa_sign,
  ml_dsa_verify,
  slh_dsa_keygen,
  slh_dsa_sign,
  slh_dsa_verify,
  ed25519_keygen,
  ed25519_sign,
  ed25519_verify,
} from 'crown-wasm';

export { ml_dsa_sign, ml_dsa_verify, slh_dsa_sign, slh_dsa_verify };

export type MlKemVariant = 512 | 768 | 1024;
export type MlDsaVariant = 44 | 65 | 87;

export function mlKemKeygen(variant: MlKemVariant, seed: Uint8Array) {
  return ml_kem_keygen(variant, seed);
}

export function mlKemEncapsulate(
  variant: MlKemVariant,
  publicKey: Uint8Array,
  message: Uint8Array,
) {
  return ml_kem_encapsulate(variant, publicKey, message);
}

export function mlKemDecapsulate(
  variant: MlKemVariant,
  privateKey: Uint8Array,
  ciphertext: Uint8Array,
) {
  return ml_kem_decapsulate(variant, privateKey, ciphertext);
}

export function mlDsaKeygen(variant: MlDsaVariant, seed: Uint8Array) {
  return ml_dsa_keygen(variant, seed);
}

export function ed25519Keygen() {
  return ed25519_keygen();
}

export function ed25519Sign(secret: Uint8Array, msg: Uint8Array) {
  return ed25519_sign(secret, msg);
}

export function ed25519Verify(
  public: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
) {
  return ed25519_verify(public, msg, sig);
}

export const slhDsaVariants = [
  'SLH-DSA-SHA2-128s',
  'SLH-DSA-SHA2-128f',
  'SLH-DSA-SHAKE-128s',
  'SLH-DSA-SHAKE-128f',
];

export function slhDsaKeygen(name: string, seed: Uint8Array) {
  return slh_dsa_keygen(name, seed);
}
