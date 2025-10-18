import {
  BlockCipher,
  stringToUint8Array,
  uint8ArrayToString,
} from '@/lib/wasm';

export type BlockAlgorithm = string;

export interface BlockAlgorithmInfo {
  value: BlockAlgorithm;
  label: string;
  keySize: number;
  ivSize: number;
  blockSize: number;
  requiresParams?: boolean;
}

export interface BlockCipherParams {
  rounds?: number;
}

export function createBlockCipher(
  algorithm: BlockAlgorithm,
  keyBytes: Uint8Array,
  ivBytes: Uint8Array,
  params?: BlockCipherParams,
): BlockCipher {
  const methodName = `new_${algorithm}` as keyof typeof BlockCipher;
  const method = BlockCipher[methodName] as any;

  if (typeof method !== 'function') {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
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
  algorithm: BlockAlgorithm;
  key: string;
  iv: string;
  plaintext: string;
  inputFormat: 'utf8' | 'hex' | 'base64';
  outputFormat: 'hex' | 'base64';
  cipherParams?: BlockCipherParams;
}

export function encryptBlock(params: EncryptParams): string {
  try {
    const keyBytes = stringToUint8Array(params.key, 'hex');
    const ivBytes = stringToUint8Array(params.iv, 'hex');
    const plaintextBytes = stringToUint8Array(
      params.plaintext,
      params.inputFormat,
    );

    const algorithmInfo = getBlockAlgorithmInfo(params.algorithm);

    if (keyBytes.length !== algorithmInfo.keySize) {
      throw new Error(
        `Invalid key size: expected ${algorithmInfo.keySize} bytes, got ${keyBytes.length} bytes`,
      );
    }

    if (ivBytes.length !== algorithmInfo.ivSize) {
      throw new Error(
        `Invalid IV size: expected ${algorithmInfo.ivSize} bytes, got ${ivBytes.length} bytes`,
      );
    }

    const cipher = createBlockCipher(
      params.algorithm,
      keyBytes,
      ivBytes,
      params.cipherParams,
    );

    try {
      const blockSize = algorithmInfo.blockSize;
      const paddedLength =
        Math.ceil(plaintextBytes.length / blockSize) * blockSize;
      const paddedData = new Uint8Array(paddedLength);
      paddedData.set(plaintextBytes);

      for (let i = plaintextBytes.length; i < paddedLength; i++) {
        paddedData[i] = paddedLength - plaintextBytes.length;
      }

      const outputLength = cipher.encrypt(paddedData, 0);
      const result = paddedData.slice(0, outputLength);

      return uint8ArrayToString(result, params.outputFormat);
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
      if (error.message.includes('iv') || error.message.includes('IV')) {
        throw new Error(`IV error: ${error.message}`);
      }
      throw new Error(`Encryption failed: ${error.message}`);
    }
    throw new Error('Encryption failed: Unknown error');
  }
}

export interface DecryptParams {
  algorithm: BlockAlgorithm;
  key: string;
  iv: string;
  ciphertext: string;
  inputFormat: 'utf8' | 'hex' | 'base64';
  outputFormat: 'hex' | 'base64';
  cipherParams?: BlockCipherParams;
}

export function decryptBlock(params: DecryptParams): string {
  try {
    const keyBytes = stringToUint8Array(params.key, 'hex');
    const ivBytes = stringToUint8Array(params.iv, 'hex');
    const ciphertextBytes = stringToUint8Array(
      params.ciphertext,
      params.outputFormat,
    );

    const algorithmInfo = getBlockAlgorithmInfo(params.algorithm);

    if (keyBytes.length !== algorithmInfo.keySize) {
      throw new Error(
        `Invalid key size: expected ${algorithmInfo.keySize} bytes, got ${keyBytes.length} bytes`,
      );
    }

    if (ivBytes.length !== algorithmInfo.ivSize) {
      throw new Error(
        `Invalid IV size: expected ${algorithmInfo.ivSize} bytes, got ${ivBytes.length} bytes`,
      );
    }

    const cipher = createBlockCipher(
      params.algorithm,
      keyBytes,
      ivBytes,
      params.cipherParams,
    );

    try {
      const data = new Uint8Array(ciphertextBytes);
      const outputLength = cipher.decrypt(data);

      const paddingLength = data[data.length - 1];
      if (paddingLength > data.length || paddingLength === 0) {
        throw new Error('Invalid padding');
      }

      const result = data.slice(0, data.length - paddingLength);
      return uint8ArrayToString(result, params.inputFormat);
    } finally {
      cipher.free();
    }
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('Invalid hex')) {
        throw new Error(`Input format error: ${error.message}`);
      }
      if (error.message.includes('padding')) {
        throw new Error(`Padding error: Invalid or corrupted data`);
      }
      if (error.message.includes('key')) {
        throw new Error(`Key error: ${error.message}`);
      }
      if (error.message.includes('iv') || error.message.includes('IV')) {
        throw new Error(`IV error: ${error.message}`);
      }
      throw new Error(`Decryption failed: ${error.message}`);
    }
    throw new Error('Decryption failed: Unknown error');
  }
}

export function getAvailableAlgorithms(): BlockAlgorithmInfo[] {
  const algorithms: BlockAlgorithmInfo[] = [
    {
      value: 'aes_cbc',
      label: 'AES-CBC',
      keySize: 32,
      ivSize: 16,
      blockSize: 16,
    },
    {
      value: 'blowfish_cbc',
      label: 'Blowfish-CBC',
      keySize: 56,
      ivSize: 8,
      blockSize: 8,
    },
    {
      value: 'cast5_cbc',
      label: 'CAST5-CBC',
      keySize: 16,
      ivSize: 8,
      blockSize: 8,
    },
    { value: 'des_cbc', label: 'DES-CBC', keySize: 8, ivSize: 8, blockSize: 8 },
    {
      value: 'tripledes_cbc',
      label: '3DES-CBC',
      keySize: 24,
      ivSize: 8,
      blockSize: 8,
    },
    {
      value: 'tea_cbc',
      label: 'TEA-CBC',
      keySize: 16,
      ivSize: 8,
      blockSize: 8,
    },
    {
      value: 'twofish_cbc',
      label: 'Twofish-CBC',
      keySize: 32,
      ivSize: 16,
      blockSize: 16,
    },
    {
      value: 'xtea_cbc',
      label: 'XTEA-CBC',
      keySize: 16,
      ivSize: 8,
      blockSize: 8,
    },
    {
      value: 'idea_cbc',
      label: 'IDEA-CBC',
      keySize: 16,
      ivSize: 8,
      blockSize: 8,
    },
    {
      value: 'rc6_cbc',
      label: 'RC6-CBC',
      keySize: 32,
      ivSize: 16,
      blockSize: 16,
    },
    {
      value: 'sm4_cbc',
      label: 'SM4-CBC',
      keySize: 16,
      ivSize: 16,
      blockSize: 16,
    },
    {
      value: 'skipjack_cbc',
      label: 'Skipjack-CBC',
      keySize: 10,
      ivSize: 8,
      blockSize: 8,
    },
    {
      value: 'rc2_cbc',
      label: 'RC2-CBC',
      keySize: 16,
      ivSize: 8,
      blockSize: 8,
      requiresParams: true,
    },
    {
      value: 'rc5_cbc',
      label: 'RC5-CBC',
      keySize: 16,
      ivSize: 8,
      blockSize: 8,
      requiresParams: true,
    },
    {
      value: 'camellia_cbc',
      label: 'Camellia-CBC',
      keySize: 32,
      ivSize: 16,
      blockSize: 16,
      requiresParams: true,
    },
  ];

  return algorithms.filter(alg => {
    try {
      const methodName = `new_${alg.value}` as keyof typeof BlockCipher;
      return typeof BlockCipher[methodName] === 'function';
    } catch {
      return false;
    }
  });
}

export function getBlockAlgorithmInfo(
  algorithm: BlockAlgorithm,
): BlockAlgorithmInfo {
  const info = getAvailableAlgorithms().find(alg => alg.value === algorithm);
  if (!info) {
    throw new Error(`Unknown algorithm: ${algorithm}`);
  }
  return info;
}
