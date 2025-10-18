import { AeadCipher, stringToUint8Array, uint8ArrayToString } from '@/lib/wasm';

export type AeadAlgorithm = string;

export interface AeadAlgorithmInfo {
  value: AeadAlgorithm;
  label: string;
  keySize: number;
  requiresParams?: boolean;
  defaultTagSize?: number;
  defaultNonceSize?: number;
}

export interface AeadCipherParams {
  tagSize?: number;
  nonceSize?: number;
  rounds?: number;
}

export function createAeadCipher(
  algorithm: AeadAlgorithm,
  keyBytes: Uint8Array,
  params?: AeadCipherParams,
): AeadCipher {
  const methodName = `new_${algorithm}` as keyof typeof AeadCipher;
  const method = AeadCipher[methodName] as any;

  if (typeof method !== 'function') {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  if (algorithm.endsWith('_ocb3')) {
    const tagSize = params?.tagSize || 16;
    const nonceSize = params?.nonceSize || 12;
    return method(keyBytes, tagSize, nonceSize);
  }

  if (
    algorithm.includes('rc2') ||
    algorithm.includes('rc5') ||
    algorithm.includes('camellia')
  ) {
    return method(keyBytes, params?.rounds || null);
  }

  return method(keyBytes);
}

export function getAlgorithmSizes(
  algorithm: AeadAlgorithm,
  params?: AeadCipherParams,
): {
  nonceSize: number;
  tagSize: number;
} {
  try {
    const algorithmInfo = getAeadAlgorithmInfo(algorithm);
    const dummyKey = new Uint8Array(algorithmInfo.keySize);
    const cipher = createAeadCipher(algorithm, dummyKey, params);

    try {
      const nonceSize = cipher.nonce_size();
      const tagSize = cipher.tag_size();
      return { nonceSize, tagSize };
    } finally {
      cipher.free();
    }
  } catch {
    return {
      nonceSize: params?.nonceSize || 12,
      tagSize: params?.tagSize || 16,
    };
  }
}

export interface EncryptParams {
  algorithm: AeadAlgorithm;
  key: string;
  nonce: string;
  aad: string;
  plaintext: string;
  inputFormat: 'utf8' | 'hex' | 'base64';
  outputFormat: 'hex' | 'base64';
  cipherParams?: AeadCipherParams;
}

export interface EncryptResult {
  ciphertext: string;
  tag: string;
}

export function encryptAead(params: EncryptParams): EncryptResult {
  const keyBytes = stringToUint8Array(params.key, 'hex');
  const nonceBytes = stringToUint8Array(params.nonce, 'hex');
  const aadBytes = stringToUint8Array(params.aad, params.inputFormat);
  const plaintextBytes = stringToUint8Array(
    params.plaintext,
    params.inputFormat,
  );

  const cipher = createAeadCipher(
    params.algorithm,
    keyBytes,
    params.cipherParams,
  );

  try {
    const data = new Uint8Array(plaintextBytes);
    const tagBytes = cipher.seal_in_place_separate_tag(
      data,
      nonceBytes,
      aadBytes,
    );

    const ciphertext = uint8ArrayToString(data, params.outputFormat);
    const tag = uint8ArrayToString(tagBytes, params.outputFormat);

    return { ciphertext, tag };
  } finally {
    cipher.free();
  }
}

export interface DecryptParams {
  algorithm: AeadAlgorithm;
  key: string;
  nonce: string;
  aad: string;
  ciphertext: string;
  tag: string;
  inputFormat: 'utf8' | 'hex' | 'base64';
  outputFormat: 'hex' | 'base64';
  cipherParams?: AeadCipherParams;
}

export function decryptAead(params: DecryptParams): string {
  try {
    const keyBytes = stringToUint8Array(params.key, 'hex');
    const nonceBytes = stringToUint8Array(params.nonce, 'hex');
    const aadBytes = stringToUint8Array(params.aad, params.inputFormat);
    const ciphertextBytes = stringToUint8Array(
      params.ciphertext,
      params.outputFormat,
    );
    const tagBytes = stringToUint8Array(params.tag, params.outputFormat);

    const algorithmInfo = getAeadAlgorithmInfo(params.algorithm);

    if (keyBytes.length !== algorithmInfo.keySize) {
      throw new Error(
        `Invalid key size: expected ${algorithmInfo.keySize} bytes, got ${keyBytes.length} bytes`,
      );
    }

    const cipher = createAeadCipher(
      params.algorithm,
      keyBytes,
      params.cipherParams,
    );

    try {
      const data = new Uint8Array(ciphertextBytes);
      cipher.open_in_place_separate_tag(data, tagBytes, nonceBytes, aadBytes);

      return uint8ArrayToString(data, params.inputFormat);
    } finally {
      cipher.free();
    }
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('Invalid hex')) {
        throw new Error(`Input format error: ${error.message}`);
      }
      if (error.message.includes('authentication')) {
        throw new Error(`Authentication failed: Invalid tag or corrupted data`);
      }
      if (error.message.includes('nonce')) {
        throw new Error(`Nonce error: ${error.message}`);
      }
      if (error.message.includes('key')) {
        throw new Error(`Key error: ${error.message}`);
      }
      if (error.message.includes('tag')) {
        throw new Error(`Tag error: ${error.message}`);
      }
      throw new Error(`Decryption failed: ${error.message}`);
    }
    throw new Error('Decryption failed: Unknown error');
  }
}

export function getAvailableAlgorithms(): AeadAlgorithmInfo[] {
  const algorithms: AeadAlgorithmInfo[] = [
    { value: 'aes_gcm', label: 'AES-GCM', keySize: 32 },
    {
      value: 'aes_ocb3',
      label: 'AES-OCB3',
      keySize: 32,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'blowfish_gcm', label: 'Blowfish-GCM', keySize: 56 },
    {
      value: 'blowfish_ocb3',
      label: 'Blowfish-OCB3',
      keySize: 56,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'cast5_gcm', label: 'CAST5-GCM', keySize: 16 },
    {
      value: 'cast5_ocb3',
      label: 'CAST5-OCB3',
      keySize: 16,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'des_gcm', label: 'DES-GCM', keySize: 8 },
    {
      value: 'des_ocb3',
      label: 'DES-OCB3',
      keySize: 8,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'tripledes_gcm', label: '3DES-GCM', keySize: 24 },
    {
      value: 'tripledes_ocb3',
      label: '3DES-OCB3',
      keySize: 24,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'tea_gcm', label: 'TEA-GCM', keySize: 16 },
    {
      value: 'tea_ocb3',
      label: 'TEA-OCB3',
      keySize: 16,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'twofish_gcm', label: 'Twofish-GCM', keySize: 32 },
    {
      value: 'twofish_ocb3',
      label: 'Twofish-OCB3',
      keySize: 32,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'xtea_gcm', label: 'XTEA-GCM', keySize: 16 },
    {
      value: 'xtea_ocb3',
      label: 'XTEA-OCB3',
      keySize: 16,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'rc6_gcm', label: 'RC6-GCM', keySize: 32 },
    {
      value: 'rc6_ocb3',
      label: 'RC6-OCB3',
      keySize: 32,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'sm4_gcm', label: 'SM4-GCM', keySize: 16 },
    {
      value: 'sm4_ocb3',
      label: 'SM4-OCB3',
      keySize: 16,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'skipjack_gcm', label: 'Skipjack-GCM', keySize: 10 },
    {
      value: 'skipjack_ocb3',
      label: 'Skipjack-OCB3',
      keySize: 10,
      requiresParams: true,
      defaultTagSize: 16,
      defaultNonceSize: 12,
    },

    { value: 'rc2_gcm', label: 'RC2-GCM', keySize: 16 },
    { value: 'rc5_gcm', label: 'RC5-GCM', keySize: 16 },
    { value: 'camellia_gcm', label: 'Camellia-GCM', keySize: 32 },

    { value: 'chacha20_poly1305', label: 'ChaCha20-Poly1305', keySize: 32 },
    { value: 'xchacha20_poly1305', label: 'XChaCha20-Poly1305', keySize: 32 },
  ];

  return algorithms.filter(alg => {
    try {
      const methodName = `new_${alg.value}` as keyof typeof AeadCipher;
      return typeof AeadCipher[methodName] === 'function';
    } catch {
      return false;
    }
  });
}

export function getAeadAlgorithmInfo(
  algorithm: AeadAlgorithm,
): AeadAlgorithmInfo {
  const info = getAvailableAlgorithms().find(alg => alg.value === algorithm);
  if (!info) {
    throw new Error(`Unknown algorithm: ${algorithm}`);
  }
  return info;
}
