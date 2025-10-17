import init, { AeadCipher, BlockCipher, Hash, StreamCipher } from 'crown-wasm';

let wasmInitialized = false;

export async function initWasm() {
  if (!wasmInitialized) {
    try {
      await init();
      wasmInitialized = true;
      console.log('WASM initialized successfully');
    } catch (error) {
      console.error('Failed to initialize WASM:', error);
      throw error;
    }
  }
}

export function stringToUint8Array(
  str: string,
  encoding: 'utf8' | 'hex' | 'base64' = 'utf8',
): Uint8Array {
  switch (encoding) {
    case 'hex':
      const hex = str.replace(/\s/g, '');
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
      return bytes;
    case 'base64':
      const binaryString = atob(str);
      const bytes2 = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes2[i] = binaryString.charCodeAt(i);
      }
      return bytes2;
    default:
      return new TextEncoder().encode(str);
  }
}

export function uint8ArrayToString(
  bytes: Uint8Array,
  encoding: 'utf8' | 'hex' | 'base64' = 'hex',
): string {
  switch (encoding) {
    case 'hex':
      return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    case 'base64':
      const binaryString = String.fromCharCode(...bytes);
      return btoa(binaryString);
    default:
      return new TextDecoder().decode(bytes);
  }
}

export function generateRandomKey(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export { AeadCipher, BlockCipher, Hash, StreamCipher };
