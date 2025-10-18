'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useRef, useState } from 'react';
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
import { Textarea } from '@/components/ui/textarea';
import {
  type AeadAlgorithm,
  createAeadCipher,
  decryptAead,
  encryptAead,
  getAeadAlgorithmInfo,
  getAlgorithmSizes,
  getAvailableAlgorithms,
} from '@/lib/aead';
import { getParamValue, updateUrlParams } from '@/lib/url-state';
import {
  generateRandomKey,
  initWasm,
  stringToUint8Array,
  uint8ArrayToString,
} from '@/lib/wasm';
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
  const [keyError, setKeyError] = useState('');
  const [nonceError, setNonceError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [mode, setMode] = useState<'text' | 'file'>('text');
  const [encryptedFileData, setEncryptedFileData] = useState<{
    data: Uint8Array;
    tag: Uint8Array;
    filename: string;
  } | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const createKeySchema = (expectedLength: number) =>
    z
      .string()
      .regex(/^[0-9a-fA-F]*$/, 'Key must contain only hexadecimal characters')
      .refine(
        val => val.length === expectedLength * 2,
        `Key must be exactly ${expectedLength * 2} hex characters (${expectedLength} bytes)`,
      );

  const createNonceSchema = (expectedLength: number) =>
    z
      .string()
      .regex(/^[0-9a-fA-F]*$/, 'Nonce must contain only hexadecimal characters')
      .refine(
        val => val.length === expectedLength * 2,
        `Nonce must be exactly ${expectedLength * 2} hex characters (${expectedLength} bytes)`,
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

  const validateNonce = (value: string) => {
    try {
      createNonceSchema(algorithmSizes.nonceSize).parse(value);
      setNonceError('');
      return true;
    } catch (error) {
      if (error instanceof z.ZodError) {
        setNonceError(error.issues[0].message);
      }
      return false;
    }
  };

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));

    setPlaintext(getParamValue('plaintext', ''));
    setCiphertext(getParamValue('ciphertext', ''));
    setTag(getParamValue('tag', ''));
  }, []);

  const updateState = (updates: Record<string, string>) => {
    updateUrlParams(updates);
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
      setTag('');
      updateState({ plaintext: '', ciphertext: '', tag: '' });
    }
  };

  const encrypt = async () => {
    if (!wasmReady || isEncrypting) return;

    const keyValid = validateKey(key);
    const nonceValid = validateNonce(nonce);

    if (!keyValid || !nonceValid) {
      return;
    }

    setIsEncrypting(true);
    try {
      setError('');

      if (mode === 'file' && uploadedFile) {
        const keyBytes = stringToUint8Array(key, 'hex');
        const nonceBytes = stringToUint8Array(nonce, 'hex');
        const aadBytes = stringToUint8Array(aad, inputFormat);

        const reader = new FileReader();
        reader.onload = e => {
          try {
            const arrayBuffer = e.target?.result as ArrayBuffer;
            const plaintextBytes = new Uint8Array(arrayBuffer);

            const cipher = createAeadCipher(
              algorithm as AeadAlgorithm,
              keyBytes,
            );

            try {
              const data = new Uint8Array(plaintextBytes);
              const tagBytes = cipher.seal_in_place_separate_tag(
                data,
                nonceBytes,
                aadBytes,
              );

              setEncryptedFileData({
                data,
                tag: tagBytes,
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
        setIsEncrypting(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Encryption failed');
      setIsEncrypting(false);
    }
  };

  const downloadEncryptedFile = () => {
    if (!encryptedFileData) return;

    const combinedData = new Uint8Array(
      encryptedFileData.data.length + encryptedFileData.tag.length,
    );
    combinedData.set(encryptedFileData.data);
    combinedData.set(encryptedFileData.tag, encryptedFileData.data.length);

    const blob = new Blob([combinedData], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${encryptedFileData.filename}.encrypted`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
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
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="block text-sm font-medium mb-2">
            Key (Hex) - {algorithmInfo.keySize} bytes
          </Label>
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
            <div className="flex-1">
              <Input
                value={nonce}
                onChange={e => {
                  const value = e.target.value;
                  pushQuery('nonce', value);
                  if (value) validateNonce(value);
                }}
                placeholder={`Enter ${algorithmSizes.nonceSize * 2} hex characters`}
                className={nonceError ? 'border-red-500' : ''}
              />
              {nonceError && (
                <p className="text-sm text-red-500 mt-1">{nonceError}</p>
              )}
            </div>
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

      <Tabs value={mode} onValueChange={handleModeChange} className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="text">Text Mode</TabsTrigger>
          <TabsTrigger value="file">File Mode</TabsTrigger>
        </TabsList>

        <TabsContent value="text" className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label className="block text-sm font-medium">Plaintext</Label>
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
                <Label className="block text-sm font-medium">Ciphertext</Label>
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
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="block text-sm font-medium mb-2">
                File Upload
              </Label>
              <div className="space-y-2">
                <div className="flex gap-2">
                  <input
                    ref={fileInputRef}
                    type="file"
                    onChange={handleFileUpload}
                    className="hidden"
                    id="file-upload"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => fileInputRef.current?.click()}
                    className="flex-1"
                  >
                    Upload File
                  </Button>
                  {uploadedFile && (
                    <Button type="button" variant="outline" onClick={clearFile}>
                      Clear
                    </Button>
                  )}
                </div>

                {uploadedFile && (
                  <div className="p-3 border rounded-md bg-muted">
                    <p className="text-sm font-medium">{uploadedFile.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {(uploadedFile.size / 1024).toFixed(2)} KB
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div>
              <Label className="block text-sm font-medium mb-2">
                Encrypted File
              </Label>
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
