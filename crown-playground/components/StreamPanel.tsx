'use client';

import React, { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  generateRandomKey,
  initWasm,
  StreamCipher,
  stringToUint8Array,
  uint8ArrayToString,
} from '@/lib/wasm';
import { Textarea } from './ui/textarea';

const streamAlgorithms = [
  { value: 'aes_ctr', label: 'AES-CTR', keySize: 32, ivSize: 16 },
  { value: 'chacha20', label: 'ChaCha20', keySize: 32, ivSize: 12 },
  { value: 'rc4', label: 'RC4', keySize: 16, ivSize: 0 },
  { value: 'salsa20', label: 'Salsa20', keySize: 32, ivSize: 8 },
  { value: 'aes_cfb', label: 'AES-CFB', keySize: 32, ivSize: 16 },
  { value: 'aes_ofb', label: 'AES-OFB', keySize: 32, ivSize: 16 },
];

export function StreamPanel() {
  const [algorithm, setAlgorithm] = useState('aes_ctr');
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
    const alg = streamAlgorithms.find(a => a.value === algorithm);
    if (alg) {
      const keyBytes = generateRandomKey(alg.keySize);
      setKey(uint8ArrayToString(keyBytes, 'hex'));
    }
  };

  const generateIv = () => {
    const alg = streamAlgorithms.find(a => a.value === algorithm);
    if (alg && alg.ivSize > 0) {
      const ivBytes = generateRandomKey(alg.ivSize);
      setIv(uint8ArrayToString(ivBytes, 'hex'));
    }
  };

  const encrypt = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const keyBytes = stringToUint8Array(key, 'hex');
      const plaintextBytes = stringToUint8Array(plaintext, inputFormat);

      let cipher: StreamCipher;

      if (algorithm === 'rc4') {
        cipher = StreamCipher.new_rc4(keyBytes);
      } else {
        const ivBytes = stringToUint8Array(iv, 'hex');
        switch (algorithm) {
          case 'aes_ctr':
            cipher = StreamCipher.new_aes_ctr(keyBytes, ivBytes);
            break;
          case 'aes_cfb':
            cipher = StreamCipher.new_aes_cfb(keyBytes, ivBytes);
            break;
          case 'aes_ofb':
            cipher = StreamCipher.new_aes_ofb(keyBytes, ivBytes);
            break;
          case 'chacha20':
            cipher = StreamCipher.new_chacha20(keyBytes, ivBytes);
            break;
          case 'salsa20':
            cipher = StreamCipher.new_salsa20(keyBytes, ivBytes);
            break;
          default:
            throw new Error('Unsupported algorithm');
        }
      }

      const data = new Uint8Array(plaintextBytes);
      cipher.encrypt(data);

      setCiphertext(uint8ArrayToString(data, outputFormat));

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
      const ciphertextBytes = stringToUint8Array(ciphertext, outputFormat);

      let cipher: StreamCipher;

      if (algorithm === 'rc4') {
        cipher = StreamCipher.new_rc4(keyBytes);
      } else {
        const ivBytes = stringToUint8Array(iv, 'hex');
        switch (algorithm) {
          case 'aes_ctr':
            cipher = StreamCipher.new_aes_ctr(keyBytes, ivBytes);
            break;
          case 'aes_cfb':
            cipher = StreamCipher.new_aes_cfb(keyBytes, ivBytes);
            break;
          case 'aes_ofb':
            cipher = StreamCipher.new_aes_ofb(keyBytes, ivBytes);
            break;
          case 'chacha20':
            cipher = StreamCipher.new_chacha20(keyBytes, ivBytes);
            break;
          case 'salsa20':
            cipher = StreamCipher.new_salsa20(keyBytes, ivBytes);
            break;
          default:
            throw new Error('Unsupported algorithm');
        }
      }

      const data = new Uint8Array(ciphertextBytes);
      cipher.decrypt(data);

      setPlaintext(uint8ArrayToString(data, inputFormat));

      cipher.free();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Decryption failed');
    }
  };

  const currentAlg = streamAlgorithms.find(a => a.value === algorithm);
  const needsIv = currentAlg && currentAlg.ivSize > 0;

  if (!wasmReady) {
    return <div className="p-6">Loading WASM module...</div>;
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h2 className="text-2xl font-bold mb-4">Stream Cipher</h2>
        <p className="text-gray-600">
          Stream ciphers for continuous encryption
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Algorithm</label>
          <select
            value={algorithm}
            onChange={e => setAlgorithm(e.target.value)}
            className="w-full p-2 border rounded-md"
          >
            {streamAlgorithms.map(alg => (
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

      <div className={needsIv ? 'grid grid-cols-2 gap-4' : ''}>
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

        {needsIv && (
          <div>
            <label className="block text-sm font-medium mb-2">
              IV/Nonce (Hex)
            </label>
            <div className="flex gap-2">
              <Input
                value={iv}
                onChange={e => setIv(e.target.value)}
                placeholder="Enter IV/nonce in hex format"
                className="flex-1"
              />
              <Button onClick={generateIv} variant="outline">
                Generate
              </Button>
            </div>
          </div>
        )}
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
