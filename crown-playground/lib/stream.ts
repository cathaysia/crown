import {
  StreamCipher,
  stringToUint8Array,
  uint8ArrayToString,
} from '@/lib/wasm';

export type StreamAlgorithm = string;

export interface StreamAlgorithmInfo {
  value: StreamAlgorithm;
  label: string;
  keySize: number;
  ivSize: number;
  requiresParams?: boolean;
}

export interface StreamCipherParams {
  rounds?: number;
}

export function createStreamCipher(
  algorithm: StreamAlgorithm,
  keyBytes: Uint8Array,
  ivBytes?: Uint8Array,
  params?: StreamCipherParams,
): StreamCipher {
  const methodName = `new_${algorithm}` as keyof typeof StreamCipher;
  const method = StreamCipher[methodName] as any;

  if (typeof method !== 'function') {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  if (algorithm === 'rc4') {
    return method(keyBytes);
  }

  if (!ivBytes) {
    throw new Error(`Algorithm ${algorithm} requires IV/nonce`);
  }

  if (
    algorithm.includes('rc2') ||
    algorithm.includes('rc5') ||
    algorithm.includes('camellia')
  ) {
    return method(keyBytes, ivBytes, params?.rounds || null);
  }

  return method(keyBytes, ivBytes);
}

export interface EncryptParams {
  algorithm: StreamAlgorithm;
  key: string;
  iv?: string;
  plaintext: string;
  inputFormat: 'utf8' | 'hex' | 'base64';
  outputFormat: 'hex' | 'base64';
  cipherParams?: StreamCipherParams;
}

export function encryptStream(params: EncryptParams): string {
  try {
    const keyBytes = stringToUint8Array(params.key, 'hex');
    const plaintextBytes = stringToUint8Array(
      params.plaintext,
      params.inputFormat,
    );

    const algorithmInfo = getStreamAlgorithmInfo(params.algorithm);

    if (keyBytes.length !== algorithmInfo.keySize) {
      throw new Error(
        `Invalid key size: expected ${algorithmInfo.keySize} bytes, got ${keyBytes.length} bytes`,
      );
    }

    let ivBytes: Uint8Array | undefined;
    if (algorithmInfo.ivSize > 0) {
      if (!params.iv) {
        throw new Error(`Algorithm ${params.algorithm} requires IV/nonce`);
      }
      ivBytes = stringToUint8Array(params.iv, 'hex');
      if (ivBytes.length !== algorithmInfo.ivSize) {
        throw new Error(
          `Invalid IV size: expected ${algorithmInfo.ivSize} bytes, got ${ivBytes.length} bytes`,
        );
      }
    }

    const cipher = createStreamCipher(
      params.algorithm,
      keyBytes,
      ivBytes,
      params.cipherParams,
    );

    try {
      const data = new Uint8Array(plaintextBytes);
      cipher.encrypt(data);

      return uint8ArrayToString(data, params.outputFormat);
    } finally {
      cipher.free();
    }
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('Invalid hex')) {
        throw new Error(`Input format error: ${error.message}`);
      }
      if (error.message.includes('key')) {
        throw new Error(`Key error: ${error.message}`);
      }
      if (
        error.message.includes('iv') ||
        error.message.includes('IV') ||
        error.message.includes('nonce')
      ) {
        throw new Error(`IV/Nonce error: ${error.message}`);
      }
      throw new Error(`Encryption failed: ${error.message}`);
    }
    throw new Error('Encryption failed: Unknown error');
  }
}

export interface DecryptParams {
  algorithm: StreamAlgorithm;
  key: string;
  iv?: string;
  ciphertext: string;
  inputFormat: 'utf8' | 'hex' | 'base64';
  outputFormat: 'hex' | 'base64';
  cipherParams?: StreamCipherParams;
}

export function decryptStream(params: DecryptParams): string {
  try {
    const keyBytes = stringToUint8Array(params.key, 'hex');
    const ciphertextBytes = stringToUint8Array(
      params.ciphertext,
      params.outputFormat,
    );

    const algorithmInfo = getStreamAlgorithmInfo(params.algorithm);

    if (keyBytes.length !== algorithmInfo.keySize) {
      throw new Error(
        `Invalid key size: expected ${algorithmInfo.keySize} bytes, got ${keyBytes.length} bytes`,
      );
    }

    let ivBytes: Uint8Array | undefined;
    if (algorithmInfo.ivSize > 0) {
      if (!params.iv) {
        throw new Error(`Algorithm ${params.algorithm} requires IV/nonce`);
      }
      ivBytes = stringToUint8Array(params.iv, 'hex');
      if (ivBytes.length !== algorithmInfo.ivSize) {
        throw new Error(
          `Invalid IV size: expected ${algorithmInfo.ivSize} bytes, got ${ivBytes.length} bytes`,
        );
      }
    }

    const cipher = createStreamCipher(
      params.algorithm,
      keyBytes,
      ivBytes,
      params.cipherParams,
    );

    try {
      const data = new Uint8Array(ciphertextBytes);
      cipher.decrypt(data);

      return uint8ArrayToString(data, params.inputFormat);
    } finally {
      cipher.free();
    }
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('Invalid hex')) {
        throw new Error(`Input format error: ${error.message}`);
      }
      if (error.message.includes('key')) {
        throw new Error(`Key error: ${error.message}`);
      }
      if (
        error.message.includes('iv') ||
        error.message.includes('IV') ||
        error.message.includes('nonce')
      ) {
        throw new Error(`IV/Nonce error: ${error.message}`);
      }
      throw new Error(`Decryption failed: ${error.message}`);
    }
    throw new Error('Decryption failed: Unknown error');
  }
}

export function getAvailableAlgorithms(): StreamAlgorithmInfo[] {
  const algorithms: StreamAlgorithmInfo[] = [
    { value: 'aes_cfb', label: 'AES-CFB', keySize: 32, ivSize: 16 },
    { value: 'aes_ctr', label: 'AES-CTR', keySize: 32, ivSize: 16 },
    { value: 'aes_ofb', label: 'AES-OFB', keySize: 32, ivSize: 16 },

    { value: 'blowfish_cfb', label: 'Blowfish-CFB', keySize: 56, ivSize: 8 },
    { value: 'blowfish_ctr', label: 'Blowfish-CTR', keySize: 56, ivSize: 8 },
    { value: 'blowfish_ofb', label: 'Blowfish-OFB', keySize: 56, ivSize: 8 },

    { value: 'cast5_cfb', label: 'CAST5-CFB', keySize: 16, ivSize: 8 },
    { value: 'cast5_ctr', label: 'CAST5-CTR', keySize: 16, ivSize: 8 },
    { value: 'cast5_ofb', label: 'CAST5-OFB', keySize: 16, ivSize: 8 },

    { value: 'des_cfb', label: 'DES-CFB', keySize: 8, ivSize: 8 },
    { value: 'des_ctr', label: 'DES-CTR', keySize: 8, ivSize: 8 },
    { value: 'des_ofb', label: 'DES-OFB', keySize: 8, ivSize: 8 },

    { value: 'tripledes_cfb', label: '3DES-CFB', keySize: 24, ivSize: 8 },
    { value: 'tripledes_ctr', label: '3DES-CTR', keySize: 24, ivSize: 8 },
    { value: 'tripledes_ofb', label: '3DES-OFB', keySize: 24, ivSize: 8 },

    { value: 'tea_cfb', label: 'TEA-CFB', keySize: 16, ivSize: 8 },
    { value: 'tea_ctr', label: 'TEA-CTR', keySize: 16, ivSize: 8 },
    { value: 'tea_ofb', label: 'TEA-OFB', keySize: 16, ivSize: 8 },

    { value: 'twofish_cfb', label: 'Twofish-CFB', keySize: 32, ivSize: 16 },
    { value: 'twofish_ctr', label: 'Twofish-CTR', keySize: 32, ivSize: 16 },
    { value: 'twofish_ofb', label: 'Twofish-OFB', keySize: 32, ivSize: 16 },

    { value: 'xtea_cfb', label: 'XTEA-CFB', keySize: 16, ivSize: 8 },
    { value: 'xtea_ctr', label: 'XTEA-CTR', keySize: 16, ivSize: 8 },
    { value: 'xtea_ofb', label: 'XTEA-OFB', keySize: 16, ivSize: 8 },

    { value: 'idea_cfb', label: 'IDEA-CFB', keySize: 16, ivSize: 8 },
    { value: 'idea_ctr', label: 'IDEA-CTR', keySize: 16, ivSize: 8 },
    { value: 'idea_ofb', label: 'IDEA-OFB', keySize: 16, ivSize: 8 },

    { value: 'rc6_cfb', label: 'RC6-CFB', keySize: 32, ivSize: 16 },
    { value: 'rc6_ctr', label: 'RC6-CTR', keySize: 32, ivSize: 16 },
    { value: 'rc6_ofb', label: 'RC6-OFB', keySize: 32, ivSize: 16 },

    { value: 'sm4_cfb', label: 'SM4-CFB', keySize: 16, ivSize: 16 },
    { value: 'sm4_ctr', label: 'SM4-CTR', keySize: 16, ivSize: 16 },
    { value: 'sm4_ofb', label: 'SM4-OFB', keySize: 16, ivSize: 16 },

    { value: 'skipjack_cfb', label: 'Skipjack-CFB', keySize: 10, ivSize: 8 },
    { value: 'skipjack_ctr', label: 'Skipjack-CTR', keySize: 10, ivSize: 8 },
    { value: 'skipjack_ofb', label: 'Skipjack-OFB', keySize: 10, ivSize: 8 },

    {
      value: 'rc2_cfb',
      label: 'RC2-CFB',
      keySize: 16,
      ivSize: 8,
      requiresParams: true,
    },
    {
      value: 'rc2_ctr',
      label: 'RC2-CTR',
      keySize: 16,
      ivSize: 8,
      requiresParams: true,
    },
    {
      value: 'rc2_ofb',
      label: 'RC2-OFB',
      keySize: 16,
      ivSize: 8,
      requiresParams: true,
    },

    {
      value: 'rc5_cfb',
      label: 'RC5-CFB',
      keySize: 16,
      ivSize: 8,
      requiresParams: true,
    },
    {
      value: 'rc5_ctr',
      label: 'RC5-CTR',
      keySize: 16,
      ivSize: 8,
      requiresParams: true,
    },
    {
      value: 'rc5_ofb',
      label: 'RC5-OFB',
      keySize: 16,
      ivSize: 8,
      requiresParams: true,
    },

    {
      value: 'camellia_cfb',
      label: 'Camellia-CFB',
      keySize: 32,
      ivSize: 16,
      requiresParams: true,
    },
    {
      value: 'camellia_ctr',
      label: 'Camellia-CTR',
      keySize: 32,
      ivSize: 16,
      requiresParams: true,
    },
    {
      value: 'camellia_ofb',
      label: 'Camellia-OFB',
      keySize: 32,
      ivSize: 16,
      requiresParams: true,
    },

    { value: 'rc4', label: 'RC4', keySize: 16, ivSize: 0 },
    { value: 'salsa20', label: 'Salsa20', keySize: 32, ivSize: 8 },
    { value: 'chacha20', label: 'ChaCha20', keySize: 32, ivSize: 12 },
  ];

  return algorithms.filter(alg => {
    try {
      const methodName = `new_${alg.value}` as keyof typeof StreamCipher;
      return typeof StreamCipher[methodName] === 'function';
    } catch {
      return false;
    }
  });
}

export function getStreamAlgorithmInfo(
  algorithm: StreamAlgorithm,
): StreamAlgorithmInfo {
  const info = getAvailableAlgorithms().find(alg => alg.value === algorithm);
  if (!info) {
    throw new Error(`Unknown algorithm: ${algorithm}`);
  }
  return info;
}
