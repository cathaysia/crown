import { Hash } from 'crown-wasm';

export type HashAlgorithm =
  | 'md2'
  | 'md4'
  | 'md5'
  | 'sha1'
  | 'sha224'
  | 'sha256'
  | 'sha384'
  | 'sha512'
  | 'sha512_224'
  | 'sha512_256'
  | 'sha3_224'
  | 'sha3_256'
  | 'sha3_384'
  | 'sha3_512'
  | 'shake128'
  | 'shake256'
  | 'blake2s'
  | 'blake2b'
  | 'sm3';

export function createHash(
  algorithm: HashAlgorithm,
  hmacKey?: Uint8Array,
): Hash {
  const isHmac = hmacKey !== undefined;

  if (algorithm === 'blake2s' || algorithm === 'blake2b') {
    return Hash[`new_${algorithm}`](hmacKey, 32);
  }

  const methodName =
    `new_${algorithm}${isHmac ? '_hmac' : ''}` as keyof typeof Hash;
  const method = Hash[methodName] as any;

  if (typeof method !== 'function') {
    throw new Error(
      `Unsupported algorithm: ${algorithm}${isHmac ? ' with HMAC' : ''}`,
    );
  }

  return isHmac ? method(hmacKey) : method();
}

export function supportsHmac(algorithm: HashAlgorithm): boolean {
  if (algorithm === 'blake2s' || algorithm === 'blake2b') {
    return true;
  }

  const hmacMethodName = `new_${algorithm}_hmac` as keyof typeof Hash;
  return typeof Hash[hmacMethodName] === 'function';
}

export function getAvailableAlgorithms(): {
  value: HashAlgorithm;
  label: string;
  supportsHmac: boolean;
}[] {
  const algorithms: {
    value: HashAlgorithm;
    label: string;
    supportsHmac: boolean;
  }[] = [
    // MD family
    { value: 'md2', label: 'MD2', supportsHmac: supportsHmac('md2') },
    { value: 'md4', label: 'MD4', supportsHmac: supportsHmac('md4') },
    { value: 'md5', label: 'MD5', supportsHmac: supportsHmac('md5') },

    // SHA-1
    { value: 'sha1', label: 'SHA-1', supportsHmac: supportsHmac('sha1') },

    // SHA-2 family
    { value: 'sha224', label: 'SHA-224', supportsHmac: supportsHmac('sha224') },
    { value: 'sha256', label: 'SHA-256', supportsHmac: supportsHmac('sha256') },
    { value: 'sha384', label: 'SHA-384', supportsHmac: supportsHmac('sha384') },
    { value: 'sha512', label: 'SHA-512', supportsHmac: supportsHmac('sha512') },
    {
      value: 'sha512_224',
      label: 'SHA-512/224',
      supportsHmac: supportsHmac('sha512_224'),
    },
    {
      value: 'sha512_256',
      label: 'SHA-512/256',
      supportsHmac: supportsHmac('sha512_256'),
    },

    // SHA-3 family
    {
      value: 'sha3_224',
      label: 'SHA3-224',
      supportsHmac: supportsHmac('sha3_224'),
    },
    {
      value: 'sha3_256',
      label: 'SHA3-256',
      supportsHmac: supportsHmac('sha3_256'),
    },
    {
      value: 'sha3_384',
      label: 'SHA3-384',
      supportsHmac: supportsHmac('sha3_384'),
    },
    {
      value: 'sha3_512',
      label: 'SHA3-512',
      supportsHmac: supportsHmac('sha3_512'),
    },

    // SHAKE (extendable-output functions)
    {
      value: 'shake128',
      label: 'SHAKE128',
      supportsHmac: supportsHmac('shake128'),
    },
    {
      value: 'shake256',
      label: 'SHAKE256',
      supportsHmac: supportsHmac('shake256'),
    },

    // BLAKE2 family
    {
      value: 'blake2s',
      label: 'BLAKE2s',
      supportsHmac: supportsHmac('blake2s'),
    },
    {
      value: 'blake2b',
      label: 'BLAKE2b',
      supportsHmac: supportsHmac('blake2b'),
    },

    // SM3 (Chinese national standard)
    { value: 'sm3', label: 'SM3', supportsHmac: supportsHmac('sm3') },
  ];

  return algorithms;
}
