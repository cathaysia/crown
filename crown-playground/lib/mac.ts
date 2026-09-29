import { Mac } from 'crown-wasm';

export type MacAlgorithm =
  | 'siphash'
  | 'kmac128'
  | 'kmac256'
  | 'cmac_aes'
  | 'gmac_aes';

export function createMac(
  algorithm: MacAlgorithm,
  key: Uint8Array,
  opts?: { custom?: Uint8Array; outputLen?: number; iv?: Uint8Array },
): Mac {
  const outputLen = opts?.outputLen ?? 16;
  switch (algorithm) {
    case 'siphash':
      return Mac.new_siphash(key, outputLen);
    case 'kmac128':
      return Mac.new_kmac128(key, opts?.custom ?? new Uint8Array(0), outputLen);
    case 'kmac256':
      return Mac.new_kmac256(key, opts?.custom ?? new Uint8Array(0), outputLen);
    case 'cmac_aes':
      return Mac.new_cmac_aes(key);
    case 'gmac_aes':
      return Mac.new_gmac_aes(key, opts?.iv ?? new Uint8Array(12));
    default:
      throw new Error(`Unsupported MAC: ${algorithm}`);
  }
}

export function getAvailableMacAlgorithms(): {
  value: MacAlgorithm;
  label: string;
  keySize: number;
  needsIv?: boolean;
  needsCustom?: boolean;
}[] {
  return [
    { value: 'siphash', label: 'SipHash-2-4', keySize: 16 },
    {
      value: 'kmac128',
      label: 'KMAC128',
      keySize: 16,
      needsCustom: true,
    },
    {
      value: 'kmac256',
      label: 'KMAC256',
      keySize: 32,
      needsCustom: true,
    },
    { value: 'cmac_aes', label: 'AES-CMAC', keySize: 16 },
    { value: 'gmac_aes', label: 'AES-GMAC', keySize: 16, needsIv: true },
  ];
}
