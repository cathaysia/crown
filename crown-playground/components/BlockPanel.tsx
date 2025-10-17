'use client';

import React, { useEffect, useState } from 'react';
import {
  BlockCipher,
  generateRandomKey,
  initWasm,
  stringToUint8Array,
  uint8ArrayToString,
} from '@/lib/wasm';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from './ui/textarea';

const blockAlgorithms = [
  { value: 'aes_cbc', label: 'AES-CBC', keySize: 32, ivSize: 16 },
  { value: 'des_cbc', label: 'DES-CBC', keySize: 8, ivSize: 8 },
  { value: 'tripledes_cbc', label: '3DES-CBC', keySize: 24, ivSize: 8 },
  { value: 'blowfish_cbc', label: 'Blowfish-CBC', keySize: 16, ivSize: 8 },
  { value: 'twofish_cbc', label: 'Twofish-CBC', keySize: 32, ivSize: 16 },
];

export function BlockPanel() {
  const [algorithm, setAlgorithm] = useState('aes_cbc');
  const [key, setKey] = useState('');
  const [iv, setIv] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [inputFormat, setInputFormat] = useState<'utf8' | 'hex' | 'base64'>(
    'utf8',
  );
  const [outputFormat, setOutputFormat] = useState<'hex' | 'base64'>('hex');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  const generateKey = () => {
    const alg = blockAlgorithms.find(a => a.value === algorithm);
    if (alg) {
      const keyBytes = generateRandomKey(alg.keySize);
      setKey(uint8ArrayToString(keyBytes, 'hex'));
    }
  };

  const generateIv = () => {
    const alg = blockAlgorithms.find(a => a.value === algorithm);
    if (alg) {
      const ivBytes = generateRandomKey(alg.ivSize);
      setIv(uint8ArrayToString(ivBytes, 'hex'));
    }
  };

  const encrypt = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const keyBytes = stringToUint8Array(key, 'hex');
      const ivBytes = stringToUint8Array(iv, 'hex');
      const plaintextBytes = stringToUint8Array(plaintext, inputFormat);

      let cipher: BlockCipher;
      switch (algorithm) {
        case 'aes_cbc':
          cipher = BlockCipher.new_aes_cbc(keyBytes, ivBytes);
          break;
        case 'des_cbc':
          cipher = BlockCipher.new_des_cbc(keyBytes, ivBytes);
          break;
        case 'tripledes_cbc':
          cipher = BlockCipher.new_tripledes_cbc(keyBytes, ivBytes);
          break;
        case 'blowfish_cbc':
          cipher = BlockCipher.new_blowfish_cbc(keyBytes, ivBytes);
          break;
        case 'twofish_cbc':
          cipher = BlockCipher.new_twofish_cbc(keyBytes, ivBytes);
          break;
        default:
          throw new Error('Unsupported algorithm');
      }

      const blockSize =
        algorithm === 'aes_cbc' || algorithm === 'twofish_cbc' ? 16 : 8;
      const paddedLength =
        Math.ceil(plaintextBytes.length / blockSize) * blockSize;
      const paddedData = new Uint8Array(paddedLength);
      paddedData.set(plaintextBytes);

      for (let i = plaintextBytes.length; i < paddedLength; i++) {
        paddedData[i] = paddedLength - plaintextBytes.length;
      }

      const outputLength = cipher.encrypt(paddedData, 0);
      const result = paddedData.slice(0, outputLength);

      setCiphertext(uint8ArrayToString(result, outputFormat));

      cipher.free();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Encryption failed');
    }
  };

  const decrypt = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const keyBytes = stringToUint8Array(key, 'hex');
      const ivBytes = stringToUint8Array(iv, 'hex');
      const ciphertextBytes = stringToUint8Array(ciphertext, outputFormat);

      let cipher: BlockCipher;
      switch (algorithm) {
        case 'aes_cbc':
          cipher = BlockCipher.new_aes_cbc(keyBytes, ivBytes);
          break;
        case 'des_cbc':
          cipher = BlockCipher.new_des_cbc(keyBytes, ivBytes);
          break;
        case 'tripledes_cbc':
          cipher = BlockCipher.new_tripledes_cbc(keyBytes, ivBytes);
          break;
        case 'blowfish_cbc':
          cipher = BlockCipher.new_blowfish_cbc(keyBytes, ivBytes);
          break;
        case 'twofish_cbc':
          cipher = BlockCipher.new_twofish_cbc(keyBytes, ivBytes);
          break;
        default:
          throw new Error('Unsupported algorithm');
      }

      const data = new Uint8Array(ciphertextBytes);
      const outputLength = cipher.decrypt(data);

      const paddingLength = data[data.length - 1];
      const result = data.slice(0, data.length - paddingLength);

      setPlaintext(uint8ArrayToString(result, inputFormat));

      cipher.free();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Decryption failed');
    }
  };

  if (!wasmReady) {
    return <div className="p-6">Loading WASM module...</div>;
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h2 className="text-2xl font-bold mb-4">Block Cipher</h2>
        <p className="text-gray-600">Block ciphers with CBC mode</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Algorithm</label>
          <select
            value={algorithm}
            onChange={e => setAlgorithm(e.target.value)}
            className="w-full p-2 border rounded-md"
          >
            {blockAlgorithms.map(alg => (
              <option key={alg.value} value={alg.value}>
                {alg.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">Format</label>
          <div className="flex gap-2">
            <select
              value={inputFormat}
              onChange={e => setInputFormat(e.target.value as any)}
              className="flex-1 p-2 border rounded-md"
            >
              <option value="utf8">UTF-8</option>
              <option value="hex">Hex</option>
              <option value="base64">Base64</option>
            </select>
            <select
              value={outputFormat}
              onChange={e => setOutputFormat(e.target.value as any)}
              className="flex-1 p-2 border rounded-md"
            >
              <option value="hex">Hex</option>
              <option value="base64">Base64</option>
            </select>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Key (Hex)</label>
          <div className="flex gap-2">
            <Input
              value={key}
              onChange={e => setKey(e.target.value)}
              placeholder="Enter key in hex format"
              className="flex-1"
            />
            <Button onClick={generateKey} variant="outline">
              Generate
            </Button>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">IV (Hex)</label>
          <div className="flex gap-2">
            <Input
              value={iv}
              onChange={e => setIv(e.target.value)}
              placeholder="Enter IV in hex format"
              className="flex-1"
            />
            <Button onClick={generateIv} variant="outline">
              Generate
            </Button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Plaintext</label>
          <Textarea
            value={plaintext}
            onChange={e => setPlaintext(e.target.value)}
            placeholder="Enter plaintext to encrypt"
            rows={4}
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">Ciphertext</label>
          <Textarea
            value={ciphertext}
            onChange={e => setCiphertext(e.target.value)}
            placeholder="Encrypted data will appear here"
            rows={4}
          />
        </div>
      </div>

      <div className="flex gap-4">
        <Button onClick={encrypt} className="flex-1">
          Encrypt
        </Button>
        <Button onClick={decrypt} variant="outline" className="flex-1">
          Decrypt
        </Button>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-md">
          <p className="text-red-700">{error}</p>
        </div>
      )}
    </div>
  );
}
