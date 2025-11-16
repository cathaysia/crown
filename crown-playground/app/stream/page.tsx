'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  createStreamCipher,
  decryptStream,
  encryptStream,
  getAvailableAlgorithms,
  getStreamAlgorithmInfo,
  type StreamAlgorithm,
} from '@/lib/stream';
import { getParamValue, updateUrlParams } from '@/lib/url-state';
import {
  generateRandomKey,
  initWasm,
  stringToUint8Array,
  uint8ArrayToString,
} from '@/lib/wasm';
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

  const algorithm = searchParams.get('algorithm') || 'aes_ctr';
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
  const [keyError, setKeyError] = useState('');
  const [ivError, setIvError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [mode, setMode] = useState<'text' | 'file'>('text');
  const [encryptedFileData, setEncryptedFileData] = useState<{
    data: Uint8Array;
    filename: string;
  } | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const algorithmInfo = getStreamAlgorithmInfo(algorithm as StreamAlgorithm);
  const needsIv = algorithmInfo.ivSize > 0;

  const createKeySchema = (expectedLength: number) =>
    z
      .string()
      .regex(/^[0-9a-fA-F]*$/, 'Key must contain only hexadecimal characters')
      .refine(
        val => val.length === expectedLength * 2,
        `Key must be exactly ${expectedLength * 2} hex characters (${expectedLength} bytes)`,
      );

  const createIvSchema = (expectedLength: number) =>
    z
      .string()
      .regex(/^[0-9a-fA-F]*$/, 'IV must contain only hexadecimal characters')
      .refine(
        val => val.length === expectedLength * 2,
        `IV must be exactly ${expectedLength * 2} hex characters (${expectedLength} bytes)`,
      );

  const validateKey = (value: string) => {
    try {
      createKeySchema(algorithmInfo.keySize).parse(value);
      setKeyError('');
      return true;
    } catch (error) {
      if (error instanceof z.ZodError) {
        setKeyError(error.issues[0].message);
      }
      return false;
    }
  };

  const validateIv = (value: string) => {
    if (!needsIv) return true;
    try {
      createIvSchema(algorithmInfo.ivSize).parse(value);
      setIvError('');
      return true;
    } catch (error) {
      if (error instanceof z.ZodError) {
        setIvError(error.issues[0].message);
      }
      return false;
    }
  };

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
    if (algorithmInfo.ivSize > 0) {
      const ivBytes = generateRandomKey(algorithmInfo.ivSize);
      const ivHex = uint8ArrayToString(ivBytes, 'hex');
      pushQuery('iv', ivHex);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setUploadedFile(file);
    }
  };

  const clearFile = () => {
    setUploadedFile(null);
    setEncryptedFileData(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleModeChange = (newMode: string) => {
    setMode(newMode as 'text' | 'file');
    setError('');
    setEncryptedFileData(null);
    if (newMode === 'text') {
      setUploadedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } else {
      setPlaintext('');
      setCiphertext('');
      updateState({ plaintext: '', ciphertext: '' });
    }
  };

  const downloadEncryptedFile = () => {
    if (!encryptedFileData) return;

    const blob = new Blob([new Uint8Array(encryptedFileData.data)], {
      type: 'application/octet-stream',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${encryptedFileData.filename}.encrypted`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const encrypt = async () => {
    if (!wasmReady || isEncrypting) return;

    const keyValid = validateKey(key);
    const ivValid = validateIv(iv);

    if (!keyValid || (needsIv && !ivValid)) {
      return;
    }

    setIsEncrypting(true);
    try {
      setError('');

      if (mode === 'file' && uploadedFile) {
        const reader = new FileReader();
        reader.onload = e => {
          try {
            const arrayBuffer = e.target?.result as ArrayBuffer;
            const fileData = new Uint8Array(arrayBuffer);

            const keyBytes = stringToUint8Array(key, 'hex');
            let ivBytes: Uint8Array | undefined;

            if (needsIv) {
              ivBytes = stringToUint8Array(iv, 'hex');
            }

            const cipher = createStreamCipher(
              algorithm as StreamAlgorithm,
              keyBytes,
              ivBytes,
            );

            try {
              const data = new Uint8Array(fileData);
              cipher.encrypt(data);

              setEncryptedFileData({
                data,
                filename: uploadedFile.name,
              });
            } finally {
              cipher.free();
            }
          } catch (err) {
            setError(err instanceof Error ? err.message : 'Encryption failed');
          } finally {
            setIsEncrypting(false);
          }
        };
        reader.readAsArrayBuffer(uploadedFile);
      } else {
        const result = encryptStream({
          algorithm: algorithm as StreamAlgorithm,
          key,
          iv: needsIv ? iv : undefined,
          plaintext,
          inputFormat,
          outputFormat,
        });

        setCiphertext(result);
        updateState({ ciphertext: result });
        setIsEncrypting(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Encryption failed');
      setIsEncrypting(false);
    }
  };

  const decrypt = async () => {
    if (!wasmReady) return;

    const keyValid = validateKey(key);
    const ivValid = validateIv(iv);

    if (!keyValid || (needsIv && !ivValid)) {
      return;
    }

    try {
      setError('');
      const result = decryptStream({
        algorithm: algorithm as StreamAlgorithm,
        key,
        iv: needsIv ? iv : undefined,
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
        <h2 className="text-2xl font-bold mb-4">Stream Cipher</h2>
        <p className="text-gray-600">
          Stream ciphers for continuous encryption
        </p>
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

        <div></div>
      </div>

      <div className={needsIv ? 'flex flex-col gap-4' : ''}>
        <div>
          <label className="block text-sm font-medium mb-2">
            Key (Hex) - {algorithmInfo.keySize} bytes (
            {algorithmInfo.keySize * 2} hex chars)
          </label>
          <div className="flex gap-2">
            <div className="flex-1">
              <Input
                value={key}
                onChange={e => {
                  const value = e.target.value;
                  pushQuery('key', value);
                  if (value) validateKey(value);
                }}
                placeholder={`Enter ${algorithmInfo.keySize * 2} hex characters`}
                className={keyError ? 'border-red-500' : ''}
              />
              {keyError && (
                <p className="text-sm text-red-500 mt-1">{keyError}</p>
              )}
            </div>
            <Button onClick={generateKey} variant="outline">
              Generate
            </Button>
          </div>
        </div>

        {needsIv && (
          <div>
            <label className="block text-sm font-medium mb-2">
              IV/Nonce (Hex) - {algorithmInfo.ivSize} bytes (
              {algorithmInfo.ivSize * 2} hex chars)
            </label>
            <div className="flex gap-2">
              <div className="flex-1">
                <Input
                  value={iv}
                  onChange={e => {
                    const value = e.target.value;
                    pushQuery('iv', value);
                    if (value) validateIv(value);
                  }}
                  placeholder={`Enter ${algorithmInfo.ivSize * 2} hex characters`}
                  className={ivError ? 'border-red-500' : ''}
                />
                {ivError && (
                  <p className="text-sm text-red-500 mt-1">{ivError}</p>
                )}
              </div>
              <Button onClick={generateIv} variant="outline">
                Generate
              </Button>
            </div>
          </div>
        )}
      </div>

      <Tabs value={mode} onValueChange={handleModeChange} className="w-full">
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium">Input Mode</label>
          <TabsList className="grid w-fit grid-cols-2">
            <TabsTrigger value="text" className="text-xs">
              Text
            </TabsTrigger>
            <TabsTrigger value="file" className="text-xs">
              File
            </TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="text" className="space-y-4">
          <div className="flex flex-col gap-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium">Plaintext</label>
                <Select
                  value={inputFormat}
                  onValueChange={e => pushQuery('inputFormat', e)}
                >
                  <SelectTrigger className="w-24">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="utf8">UTF-8</SelectItem>
                    <SelectItem value="hex">Hex</SelectItem>
                    <SelectItem value="base64">Base64</SelectItem>
                  </SelectContent>
                </Select>
              </div>
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
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium">Ciphertext</label>
                <Select
                  value={outputFormat}
                  onValueChange={e => pushQuery('outputFormat', e)}
                >
                  <SelectTrigger className="w-24">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="hex">Hex</SelectItem>
                    <SelectItem value="base64">Base64</SelectItem>
                  </SelectContent>
                </Select>
              </div>
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
        </TabsContent>

        <TabsContent value="file" className="space-y-4">
          <div className="flex flex-col gap-4">
            <div className="space-y-3">
              <label className="text-sm font-medium">File Upload</label>
              <div className="border-2 border-dashed border-muted-foreground/25 rounded-lg p-6 text-center">
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="file-upload"
                />
                <label
                  htmlFor="file-upload"
                  className="cursor-pointer flex flex-col items-center space-y-2"
                >
                  <div className="w-12 h-12 rounded-full bg-muted flex items-center justify-center">
                    <svg
                      className="w-6 h-6 text-muted-foreground"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                      />
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm font-medium">
                      {uploadedFile
                        ? uploadedFile.name
                        : 'Click to upload file'}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {uploadedFile
                        ? `${(uploadedFile.size / 1024).toFixed(2)} KB`
                        : 'Any file type supported'}
                    </p>
                  </div>
                </label>
              </div>
              {uploadedFile && (
                <Button onClick={clearFile} variant="outline" size="sm">
                  Clear File
                </Button>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">
                Encrypted File
              </label>
              {encryptedFileData ? (
                <div className="p-4 border rounded-md bg-muted">
                  <p className="text-sm text-muted-foreground mb-2">
                    Encrypted file ready for download
                  </p>
                  <Button onClick={downloadEncryptedFile} className="w-full">
                    Download Encrypted File
                  </Button>
                </div>
              ) : (
                <div className="p-4 border rounded-md bg-muted/50">
                  <p className="text-sm text-muted-foreground">
                    Encrypted file will be available here after encryption
                  </p>
                </div>
              )}
            </div>
          </div>
        </TabsContent>
      </Tabs>

      <div className="flex gap-4">
        <Button onClick={encrypt} className="flex-1" disabled={isEncrypting}>
          {isEncrypting ? 'Encrypting...' : 'Encrypt'}
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
