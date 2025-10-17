'use client';

import React, { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { getParamValue, updateUrlParams } from '@/lib/url-state';
import {
  AeadCipher,
  generateRandomKey,
  initWasm,
  stringToUint8Array,
  uint8ArrayToString,
} from '../lib/wasm';

const aeadAlgorithms = [
  { value: 'aes_gcm', label: 'AES-GCM', keySize: 32 },
  { value: 'chacha20_poly1305', label: 'ChaCha20-Poly1305', keySize: 32 },
  { value: 'xchacha20_poly1305', label: 'XChaCha20-Poly1305', keySize: 32 },
];

export function AeadPanel() {
  const [algorithm, setAlgorithm] = useState('aes_gcm');
  const [key, setKey] = useState('');
  const [nonce, setNonce] = useState('');
  const [aad, setAad] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [tag, setTag] = useState('');
  const [inputFormat, setInputFormat] = useState<'utf8' | 'hex' | 'base64'>(
    'utf8',
  );
  const [outputFormat, setOutputFormat] = useState<'hex' | 'base64'>('hex');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));

    setAlgorithm(getParamValue('algorithm', 'aes_gcm'));
    setKey(getParamValue('key', ''));
    setNonce(getParamValue('nonce', ''));
    setAad(getParamValue('aad', ''));
    setPlaintext(getParamValue('plaintext', ''));
    setCiphertext(getParamValue('ciphertext', ''));
    setTag(getParamValue('tag', ''));
    setInputFormat(
      getParamValue('inputFormat', 'utf8') as 'utf8' | 'hex' | 'base64',
    );
    setOutputFormat(getParamValue('outputFormat', 'hex') as 'hex' | 'base64');
  }, []);

  const updateState = (updates: Record<string, string>) => {
    updateUrlParams(updates);
  };

  const generateKey = () => {
    const alg = aeadAlgorithms.find(a => a.value === algorithm);
    if (alg) {
      const keyBytes = generateRandomKey(alg.keySize);
      const keyHex = uint8ArrayToString(keyBytes, 'hex');
      setKey(keyHex);
      updateState({ key: keyHex });
    }
  };

  const generateNonce = () => {
    const nonceBytes = generateRandomKey(12);
    const nonceHex = uint8ArrayToString(nonceBytes, 'hex');
    setNonce(nonceHex);
    updateState({ nonce: nonceHex });
  };

  const encrypt = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const keyBytes = stringToUint8Array(key, 'hex');
      const nonceBytes = stringToUint8Array(nonce, 'hex');
      const aadBytes = stringToUint8Array(aad, inputFormat);
      const plaintextBytes = stringToUint8Array(plaintext, inputFormat);

      let cipher: AeadCipher;
      switch (algorithm) {
        case 'aes_gcm':
          cipher = AeadCipher.new_aes_gcm(keyBytes);
          break;
        case 'chacha20_poly1305':
          cipher = AeadCipher.new_chacha20_poly1305(keyBytes);
          break;
        case 'xchacha20_poly1305':
          cipher = AeadCipher.new_xchacha20_poly1305(keyBytes);
          break;
        default:
          throw new Error('Unsupported algorithm');
      }

      const data = new Uint8Array(plaintextBytes);
      const tagBytes = cipher.seal_in_place_separate_tag(
        data,
        nonceBytes,
        aadBytes,
      );

      const ciphertextResult = uint8ArrayToString(data, outputFormat);
      const tagResult = uint8ArrayToString(tagBytes, outputFormat);

      setCiphertext(ciphertextResult);
      setTag(tagResult);
      updateState({ ciphertext: ciphertextResult, tag: tagResult });

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
      const nonceBytes = stringToUint8Array(nonce, 'hex');
      const aadBytes = stringToUint8Array(aad, inputFormat);
      const ciphertextBytes = stringToUint8Array(ciphertext, outputFormat);
      const tagBytes = stringToUint8Array(tag, outputFormat);

      let cipher: AeadCipher;
      switch (algorithm) {
        case 'aes_gcm':
          cipher = AeadCipher.new_aes_gcm(keyBytes);
          break;
        case 'chacha20_poly1305':
          cipher = AeadCipher.new_chacha20_poly1305(keyBytes);
          break;
        case 'xchacha20_poly1305':
          cipher = AeadCipher.new_xchacha20_poly1305(keyBytes);
          break;
        default:
          throw new Error('Unsupported algorithm');
      }

      const data = new Uint8Array(ciphertextBytes);
      cipher.open_in_place_separate_tag(data, tagBytes, nonceBytes, aadBytes);

      const plaintextResult = uint8ArrayToString(data, inputFormat);
      setPlaintext(plaintextResult);
      updateState({ plaintext: plaintextResult });

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
        <h2 className="text-2xl font-bold mb-4">AEAD Cipher</h2>
        <p className="text-muted-foreground">
          Authenticated Encryption with Associated Data
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Algorithm</label>
          <select
            value={algorithm}
            onChange={e => {
              setAlgorithm(e.target.value);
              updateState({ algorithm: e.target.value });
            }}
            className="w-full p-2 border rounded-md bg-background text-foreground"
          >
            {aeadAlgorithms.map(alg => (
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
              onChange={e => {
                setInputFormat(e.target.value as any);
                updateState({ inputFormat: e.target.value });
              }}
              className="flex-1 p-2 border rounded-md bg-background text-foreground"
            >
              <option value="utf8">UTF-8</option>
              <option value="hex">Hex</option>
              <option value="base64">Base64</option>
            </select>
            <select
              value={outputFormat}
              onChange={e => {
                setOutputFormat(e.target.value as any);
                updateState({ outputFormat: e.target.value });
              }}
              className="flex-1 p-2 border rounded-md bg-background text-foreground"
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
              onChange={e => {
                setKey(e.target.value);
                updateState({ key: e.target.value });
              }}
              placeholder="Enter key in hex format"
              className="flex-1"
            />
            <Button onClick={generateKey} variant="outline">
              Generate
            </Button>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">Nonce (Hex)</label>
          <div className="flex gap-2">
            <Input
              value={nonce}
              onChange={e => {
                setNonce(e.target.value);
                updateState({ nonce: e.target.value });
              }}
              placeholder="Enter nonce in hex format"
              className="flex-1"
            />
            <Button onClick={generateNonce} variant="outline">
              Generate
            </Button>
          </div>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium mb-2">
          Additional Authenticated Data (AAD)
        </label>
        <Input
          value={aad}
          onChange={e => {
            setAad(e.target.value);
            updateState({ aad: e.target.value });
          }}
          placeholder="Optional additional data"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Plaintext</label>
          <Textarea
            value={plaintext}
            onChange={e => {
              setPlaintext(e.target.value);
              updateState({ plaintext: e.target.value });
            }}
            placeholder="Enter plaintext to encrypt"
            rows={4}
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">Ciphertext</label>
          <Textarea
            value={ciphertext}
            onChange={e => {
              setCiphertext(e.target.value);
              updateState({ ciphertext: e.target.value });
            }}
            placeholder="Encrypted data will appear here"
            rows={4}
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium mb-2">
          Authentication Tag
        </label>
        <Input
          value={tag}
          onChange={e => {
            setTag(e.target.value);
            updateState({ tag: e.target.value });
          }}
          placeholder="Authentication tag"
        />
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
        <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-md">
          <p className="text-destructive">{error}</p>
        </div>
      )}
    </div>
  );
}
