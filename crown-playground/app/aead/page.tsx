'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import {
  type AeadAlgorithm,
  decryptAead,
  encryptAead,
  getAeadAlgorithmInfo,
  getAlgorithmSizes,
  getAvailableAlgorithms,
} from '@/lib/aead';
import { getParamValue, updateUrlParams } from '@/lib/url-state';
import { generateRandomKey, initWasm, uint8ArrayToString } from '@/lib/wasm';
import { Label } from '@/ui/label';

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
    [searchParams, pathname],
  );

  const algorithm = searchParams.get('algorithm') || 'aes_gcm';
  const key = searchParams.get('key') || '';
  const nonce = searchParams.get('nonce') || '';
  const aad = searchParams.get('aad') || '';
  const inputFormat = (searchParams.get('inputFormat') || 'utf8') as
    | 'utf8'
    | 'hex'
    | 'base64';
  const outputFormat = (searchParams.get('outputFormat') || 'hex') as
    | 'hex'
    | 'base64';

  const algorithmInfo = getAeadAlgorithmInfo(algorithm as AeadAlgorithm);
  const algorithmSizes = getAlgorithmSizes(algorithm as AeadAlgorithm);

  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [tag, setTag] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));

    setPlaintext(getParamValue('plaintext', ''));
    setCiphertext(getParamValue('ciphertext', ''));
    setTag(getParamValue('tag', ''));
  }, []);

  const updateState = (updates: Record<string, string>) => {
    updateUrlParams(updates);
  };

  const encrypt = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const result = encryptAead({
        algorithm: algorithm as AeadAlgorithm,
        key,
        nonce,
        aad,
        plaintext,
        inputFormat,
        outputFormat,
      });

      setCiphertext(result.ciphertext);
      setTag(result.tag);
      updateState({ ciphertext: result.ciphertext, tag: result.tag });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Encryption failed');
    }
  };

  const decrypt = async () => {
    if (!wasmReady) return;

    try {
      setError('');
      const plaintextResult = decryptAead({
        algorithm: algorithm as AeadAlgorithm,
        key,
        nonce,
        aad,
        ciphertext,
        tag,
        inputFormat,
        outputFormat,
      });

      setPlaintext(plaintextResult);
      updateState({ plaintext: plaintextResult });
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
          <Label className="block text-sm font-medium mb-2">Algorithm</Label>
          <Select
            value={algorithm}
            onValueChange={e => {
              pushQuery('algorithm', e);
            }}
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
          <Label className="block text-sm font-medium mb-2">Format</Label>
          <div className="flex gap-2">
            <Select
              value={inputFormat}
              onValueChange={e => pushQuery('inputFormat', e)}
            >
              <SelectTrigger className="flex-1 p-2">
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
              <SelectTrigger className="flex-1 p-2">
                <SelectValue placeholder="Input Format" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="utf8">UTF-8</SelectItem>
                <SelectItem value="hex">Hex</SelectItem>
                <SelectItem value="base64">Base64</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="block text-sm font-medium mb-2">
            Key (Hex) - {algorithmInfo.keySize} bytes
          </Label>
          <div className="flex gap-2">
            <Input
              value={key}
              onChange={e => {
                pushQuery('key', e.target.value);
              }}
              placeholder={`Enter ${algorithmInfo.keySize * 2} hex characters`}
              className="flex-1"
            />
            <Button
              onClick={() => {
                const keyBytes = generateRandomKey(algorithmInfo.keySize);
                const keyHex = uint8ArrayToString(keyBytes, 'hex');
                pushQuery('key', keyHex);
              }}
              variant="outline"
            >
              Generate
            </Button>
          </div>
        </div>

        <div>
          <Label className="block text-sm font-medium mb-2">
            Nonce (Hex) - {algorithmSizes.nonceSize} bytes
          </Label>
          <div className="flex gap-2">
            <Input
              value={nonce}
              onChange={e => {
                pushQuery('nonce', e.target.value);
              }}
              placeholder={`Enter ${algorithmSizes.nonceSize * 2} hex characters`}
              className="flex-1"
            />
            <Button
              onClick={() => {
                const nonceSize = algorithmSizes.nonceSize;
                const nonceBytes = generateRandomKey(nonceSize);
                const nonceHex = uint8ArrayToString(nonceBytes, 'hex');
                pushQuery('nonce', nonceHex);
              }}
              variant="outline"
            >
              Generate
            </Button>
          </div>
        </div>
      </div>

      <div>
        <Label className="block text-sm font-medium mb-2">
          Additional Authenticated Data (AAD)
        </Label>
        <Input
          value={aad}
          onChange={e => {
            pushQuery('aad', e.target.value);
          }}
          placeholder="Optional additional data"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="block text-sm font-medium mb-2">Plaintext</Label>
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
          <Label className="block text-sm font-medium mb-2">Ciphertext</Label>
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
        <Label className="block text-sm font-medium mb-2">
          Authentication Tag
        </Label>
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
