import {
  aes_key_unwrap,
  aes_key_unwrap_padded,
  aes_key_wrap,
  aes_key_wrap_padded,
  ff1_decrypt_decimal,
  ff1_encrypt_decimal,
  Xts,
} from 'crown-wasm';

export function aesKeyWrap(key: Uint8Array, pt: Uint8Array, padded = false) {
  return padded ? aes_key_wrap_padded(key, pt) : aes_key_wrap(key, pt);
}

export function aesKeyUnwrap(key: Uint8Array, ct: Uint8Array, padded = false) {
  return padded ? aes_key_unwrap_padded(key, ct) : aes_key_unwrap(key, ct);
}

export function ff1EncryptDecimal(
  key: Uint8Array,
  tweak: Uint8Array,
  s: string,
) {
  return ff1_encrypt_decimal(key, tweak, s);
}

export function ff1DecryptDecimal(
  key: Uint8Array,
  tweak: Uint8Array,
  s: string,
) {
  return ff1_decrypt_decimal(key, tweak, s);
}

export function newXtsAes(key: Uint8Array) {
  return Xts.new_aes(key);
}

export function newXtsSm4(key: Uint8Array) {
  return Xts.new_sm4(key);
}
