'use client';

import React, { useEffect, useState } from 'react';
import { getParamValue, updateUrlParams } from '@/lib/url-state';
import {
  generateRandomKey,
  Hash,
  initWasm,
  stringToUint8Array,
  uint8ArrayToString,
} from '../lib/wasm';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Textarea } from './ui/textarea';

const hashAlgorithms = [
  { value: 'sha256', label: 'SHA-256' },
  { value: 'sha512', label: 'SHA-512' },
  { value: 'sha3_256', label: 'SHA3-256' },
  { value: 'sha3_512', label: 'SHA3-512' },
  { value: 'md5', label: 'MD5' },
  { value: 'sha1', label: 'SHA-1' },
  { value: 'blake2s', label: 'BLAKE2s' },
  { value: 'blake2b', label: 'BLAKE2b' },
];

export function HashPanel() {
  const [algorithm, setAlgorithm] = useState('sha256');
  const [message, setMessage] = useState('');
  const [hash, setHash] = useState('');
  const [hmacKey, setHmacKey] = useState('');
  const [useHmac, setUseHmac] = useState(false);
  const [inputFormat, setInputFormat] = useState<'utf8' | 'hex' | 'base64'>(
    'utf8',
  );
  const [outputFormat, setOutputFormat] = useState<'hex' | 'base64'>('hex');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));

    setAlgorithm(getParamValue('algorithm', 'sha256'));
    setMessage(getParamValue('message', ''));
    setHash(getParamValue('hash', ''));
    setHmacKey(getParamValue('hmacKey', ''));
    setUseHmac(getParamValue('useHmac', 'false') === 'true');
    setInputFormat(
      getParamValue('inputFormat', 'utf8') as 'utf8' | 'hex' | 'base64',
    );
    setOutputFormat(getParamValue('outputFormat', 'hex') as 'hex' | 'base64');
  }, []);

  const updateState = (updates: Record<string, string>) => {
    updateUrlParams(updates);
  };

  const generateHmacKey = () => {
    const keyBytes = generateRandomKey(32);
    const keyHex = uint8ArrayToString(keyBytes, 'hex');
    setHmacKey(keyHex);
    updateState({ hmacKey: keyHex });
  };

  const computeHash = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const messageBytes = stringToUint8Array(message, inputFormat);

      let hasher: Hash;

      if (useHmac && hmacKey) {
        const keyBytes = stringToUint8Array(hmacKey, 'hex');
        switch (algorithm) {
          case 'sha256':
            hasher = Hash.new_sha256_hmac(keyBytes);
            break;
          case 'sha512':
            hasher = Hash.new_sha512_hmac(keyBytes);
            break;
          case 'sha3_256':
            hasher = Hash.new_sha3_256_hmac(keyBytes);
            break;
          case 'sha3_512':
            hasher = Hash.new_sha3_512_hmac(keyBytes);
            break;
          case 'md5':
            hasher = Hash.new_md5_hmac(keyBytes);
            break;
          case 'sha1':
            hasher = Hash.new_sha1_hmac(keyBytes);
            break;
          default:
            throw new Error('HMAC not supported for this algorithm');
        }
      } else {
        switch (algorithm) {
          case 'sha256':
            hasher = Hash.new_sha256();
            break;
          case 'sha512':
            hasher = Hash.new_sha512();
            break;
          case 'sha3_256':
            hasher = Hash.new_sha3_256();
            break;
          case 'sha3_512':
            hasher = Hash.new_sha3_512();
            break;
          case 'md5':
            hasher = Hash.new_md5();
            break;
          case 'sha1':
            hasher = Hash.new_sha1();
            break;
          case 'blake2s':
            hasher = Hash.new_blake2s(null, 32);
            break;
          case 'blake2b':
            hasher = Hash.new_blake2b(null, 64);
            break;
          default:
            throw new Error('Unsupported algorithm');
        }
      }

      hasher.write(messageBytes);
      const hashBytes = hasher.sum();
      const hashResult = uint8ArrayToString(hashBytes, outputFormat);
      setHash(hashResult);
      updateState({ hash: hashResult });

      hasher.free();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Hash computation failed');
    }
  };

  if (!wasmReady) {
    return <div className="p-6">Loading WASM module...</div>;
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h2 className="text-2xl font-bold mb-4">Hash Functions</h2>
        <p className="text-muted-foreground">
          Cryptographic hash functions and HMAC
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
            {hashAlgorithms.map(alg => (
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

      <div>
        <div className="flex items-center mb-2">
          <input
            type="checkbox"
            id="useHmac"
            checked={useHmac}
            onChange={e => {
              setUseHmac(e.target.checked);
              updateState({ useHmac: e.target.checked.toString() });
            }}
            className="mr-2"
          />
          <label htmlFor="useHmac" className="text-sm font-medium">
            Use HMAC
          </label>
        </div>

        {useHmac && (
          <div className="flex gap-2">
            <Input
              value={hmacKey}
              onChange={e => {
                setHmacKey(e.target.value);
                updateState({ hmacKey: e.target.value });
              }}
              placeholder="Enter HMAC key in hex format"
              className="flex-1"
            />
            <Button onClick={generateHmacKey} variant="outline">
              Generate Key
            </Button>
          </div>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium mb-2">Message</label>
        <Textarea
          value={message}
          onChange={e => {
            setMessage(e.target.value);
            updateState({ message: e.target.value });
          }}
          placeholder="Enter message to hash"
          rows={4}
        />
      </div>

      <div>
        <label className="block text-sm font-medium mb-2">Hash Output</label>
        <Textarea
          value={hash}
          readOnly
          placeholder="Hash will appear here"
          rows={3}
          className="bg-muted"
        />
      </div>

      <Button onClick={computeHash} className="w-full">
        Compute Hash
      </Button>

      {error && (
        <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-md">
          <p className="text-destructive">{error}</p>
        </div>
      )}
    </div>
  );
}
