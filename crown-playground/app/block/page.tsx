'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import React, { useCallback, useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  type BlockAlgorithm,
  decryptBlock,
  encryptBlock,
  getAvailableAlgorithms,
  getBlockAlgorithmInfo,
} from '@/lib/block';
import { getParamValue, updateUrlParams } from '@/lib/url-state';
import { generateRandomKey, initWasm, uint8ArrayToString } from '@/lib/wasm';
import { Textarea } from '@/ui/textarea';

export default function Page() {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();

  const pushQuery = useCallback(
    (name: string, value: string) => {
      const params = new URLSearchParams(searchParams.toString());
      params.set(name, value);
      router.push(`${pathname}?${params.toString()}`);
    },
    [searchParams, pathname, router],
  );

  const algorithm = searchParams.get('algorithm') || 'aes_cbc';
  const key = searchParams.get('key') || '';
  const iv = searchParams.get('iv') || '';
  const inputFormat = (searchParams.get('inputFormat') || 'utf8') as
    | 'utf8'
    | 'hex'
    | 'base64';
  const outputFormat = (searchParams.get('outputFormat') || 'hex') as
    | 'hex'
    | 'base64';

  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  const algorithmInfo = getBlockAlgorithmInfo(algorithm as BlockAlgorithm);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));

    setPlaintext(getParamValue('plaintext', ''));
    setCiphertext(getParamValue('ciphertext', ''));
  }, []);

  const updateState = (updates: Record<string, string>) => {
    updateUrlParams(updates);
  };

  const generateKey = () => {
    const keyBytes = generateRandomKey(algorithmInfo.keySize);
    const keyHex = uint8ArrayToString(keyBytes, 'hex');
    pushQuery('key', keyHex);
  };

  const generateIv = () => {
    const ivBytes = generateRandomKey(algorithmInfo.ivSize);
    const ivHex = uint8ArrayToString(ivBytes, 'hex');
    pushQuery('iv', ivHex);
  };

  const encrypt = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const result = encryptBlock({
        algorithm: algorithm as BlockAlgorithm,
        key,
        iv,
        plaintext,
        inputFormat,
        outputFormat,
      });

      setCiphertext(result);
      updateState({ ciphertext: result });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Encryption failed');
    }
  };

  const decrypt = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const result = decryptBlock({
        algorithm: algorithm as BlockAlgorithm,
        key,
        iv,
        ciphertext,
        inputFormat,
        outputFormat,
      });

      setPlaintext(result);
      updateState({ plaintext: result });
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
          <Select
            value={algorithm}
            onValueChange={e => pushQuery('algorithm', e)}
          >
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Select an algorithm" />
            </SelectTrigger>
            <SelectContent>
              {getAvailableAlgorithms().map(alg => (
                <SelectItem key={alg.value} value={alg.value}>
                  {alg.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">Format</label>
          <div className="flex gap-2">
            <Select
              value={inputFormat}
              onValueChange={e => pushQuery('inputFormat', e)}
            >
              <SelectTrigger className="flex-1">
                <SelectValue placeholder="Input Format" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="utf8">UTF-8</SelectItem>
                <SelectItem value="hex">Hex</SelectItem>
                <SelectItem value="base64">Base64</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={outputFormat}
              onValueChange={e => pushQuery('outputFormat', e)}
            >
              <SelectTrigger className="flex-1">
                <SelectValue placeholder="Output Format" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hex">Hex</SelectItem>
                <SelectItem value="base64">Base64</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">
            Key (Hex) - {algorithmInfo.keySize} bytes (
            {algorithmInfo.keySize * 2} hex chars)
          </label>
          <div className="flex gap-2">
            <Input
              value={key}
              onChange={e => pushQuery('key', e.target.value)}
              placeholder={`Enter ${algorithmInfo.keySize * 2} hex characters`}
              className="flex-1"
            />
            <Button onClick={generateKey} variant="outline">
              Generate
            </Button>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">
            IV (Hex) - {algorithmInfo.ivSize} bytes ({algorithmInfo.ivSize * 2}{' '}
            hex chars)
          </label>
          <div className="flex gap-2">
            <Input
              value={iv}
              onChange={e => pushQuery('iv', e.target.value)}
              placeholder={`Enter ${algorithmInfo.ivSize * 2} hex characters`}
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
