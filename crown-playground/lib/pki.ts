import {
  cms_decrypt,
  cms_encrypt,
  ocsp_verify,
  pkcs7_parse,
  pkcs7_verify,
  pkcs8_decrypt,
  pkcs12_parse,
  x509_parse,
  x509_verify,
} from 'crown-wasm';

export function x509Parse(data: Uint8Array) {
  return JSON.parse(x509_parse(data));
}

export function x509Verify(
  leaf: Uint8Array,
  trust: Uint8Array,
  untrusted: Uint8Array,
  crl?: Uint8Array,
  purpose?: string,
) {
  return JSON.parse(
    x509_verify(leaf, trust, untrusted, crl, purpose, undefined),
  );
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

export function cmsEncrypt(
  content: Uint8Array,
  certificate: Uint8Array,
  password?: string,
) {
  return cms_encrypt(content, certificate, password || undefined);
}

export function cmsDecrypt(
  data: Uint8Array,
  key?: Uint8Array,
  certificate?: Uint8Array,
  password?: string,
) {
  return cms_decrypt(
    data,
    key || undefined,
    certificate || undefined,
    password || undefined,
  );
}

export function ocspVerify(response: Uint8Array, issuer: Uint8Array) {
  return JSON.parse(ocsp_verify(response, issuer));
}
