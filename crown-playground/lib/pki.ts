import {
  pkcs7_parse,
  pkcs7_verify,
  pkcs8_decrypt,
  pkcs12_parse,
  x509_parse,
} from 'crown-wasm';

export function x509Parse(data: Uint8Array) {
  return JSON.parse(x509_parse(data));
}

export function pkcs7Parse(data: Uint8Array) {
  return JSON.parse(pkcs7_parse(data));
}

export function pkcs7Verify(
  data: Uint8Array,
  detached?: Uint8Array,
  sm2Id?: string,
) {
  return pkcs7_verify(data, detached || undefined, sm2Id || undefined);
}

export function pkcs12Parse(data: Uint8Array, password: string) {
  return JSON.parse(pkcs12_parse(data, password));
}

export function pkcs8Decrypt(data: Uint8Array, password: string) {
  return JSON.parse(pkcs8_decrypt(data, password));
}
