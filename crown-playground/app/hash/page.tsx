'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useDebounce } from 'use-debounce';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Format } from '@/lib/format';
import {
  createHash,
  getAvailableAlgorithms,
  HashAlgorithm,
  supportsHmac,
} from '@/lib/hash';
import {
  generateRandomKey,
  initWasm,
  stringToUint8Array,
  uint8ArrayToString,
} from '@/lib/wasm';
import { Button } from '@/ui/button';
import { Input } from '@/ui/input';
import { Label } from '@/ui/label';
import { Switch } from '@/ui/switch';
import { Textarea } from '@/ui/textarea';

const hashAlgorithms = getAvailableAlgorithms();

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

  const algorithm = (searchParams.get('algorithm') ||
    'sha256') as HashAlgorithm;
  const message = searchParams.get('message') || '';
  const messageFormat = Format.fromString(
    searchParams.get('messageFormat'),
    'utf8',
  );
  const outputFormat = Format.fromString(
    searchParams.get('outputFormat'),
    'hex',
  );
  const hmacKey = searchParams.get('hmacKey');
  const useHmac = searchParams.get('useHmac') === 'true';

  const [hash, setHash] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);
  const [isComputing, setIsComputing] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [inputMode, setInputMode] = useState<'text' | 'file'>('text');

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  const [input, setInput] = useState(message);
  const [debouncedInput] = useDebounce(input, 500);

  // Create a dependency object for debouncing
  const hashDependencies = useMemo(
    () => ({
      algorithm,
      message,
      messageFormat,
      outputFormat,
      hmacKey,
      useHmac,
      wasmReady,
      inputMode,
      selectedFile:
        selectedFile?.name + selectedFile?.size + selectedFile?.lastModified,
    }),
    [
      algorithm,
      debouncedInput,
      messageFormat,
      outputFormat,
      hmacKey,
      useHmac,
      wasmReady,
      inputMode,
      selectedFile,
    ],
  );

  // Debounce the dependencies
  const debouncedDependencies = useDebounce(hashDependencies, 500);

  const computeHash = useCallback(async () => {
    if (!wasmReady) {
      setHash('');
      setError('');
      return;
    }

    // Check if we have input data
    const hasTextInput = inputMode === 'text' && message.trim();
    const hasFileInput = inputMode === 'file' && selectedFile;

    if (!hasTextInput && !hasFileInput) {
      setHash('');
      setError('');
      return;
    }

    try {
      setIsComputing(true);
      setError('');

      let messageBytes: Uint8Array;

      if (inputMode === 'file' && selectedFile) {
        // Read file as ArrayBuffer and convert to Uint8Array
        const arrayBuffer = await selectedFile.arrayBuffer();
        messageBytes = new Uint8Array(arrayBuffer);
      } else {
        // Use text input
        messageBytes = stringToUint8Array(message, messageFormat);
      }

      // Use the type-safe hash creation function
      const hmacKeyBytes =
        useHmac && hmacKey ? stringToUint8Array(hmacKey, 'hex') : undefined;

      // Check if HMAC is requested but not supported
      if (useHmac && hmacKey && !supportsHmac(algorithm)) {
        throw new Error(`HMAC not supported for ${algorithm}`);
      }

      const hasher = createHash(algorithm, hmacKeyBytes);

      // For large files, process in chunks to avoid blocking the UI
      const chunkSize = 64 * 1024; // 64KB chunks
      for (let i = 0; i < messageBytes.length; i += chunkSize) {
        const chunk = messageBytes.slice(i, i + chunkSize);
        hasher.write(chunk);

        // Allow UI to update for large files
        if (messageBytes.length > chunkSize && i % (chunkSize * 10) === 0) {
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      }

      const hashBytes = hasher.sum();
      const hashResult = uint8ArrayToString(hashBytes, outputFormat);
      setHash(hashResult);

      hasher.free();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Hash computation failed');
      setHash('');
    } finally {
      setIsComputing(false);
    }
  }, [
    wasmReady,
    message,
    messageFormat,
    algorithm,
    outputFormat,
    hmacKey,
    useHmac,
    inputMode,
    selectedFile,
  ]);

  // Auto-compute hash when dependencies change
  useEffect(() => {
    const hasTextInput = inputMode === 'text' && message.trim();
    const hasFileInput = inputMode === 'file' && selectedFile;

    if (!wasmReady || (!hasTextInput && !hasFileInput)) {
      setHash('');
      setError('');
      return;
    }

    computeHash();
  }, [debouncedDependencies, computeHash]);

  if (!wasmReady) {
    return <div className="p-6">Loading WASM module...</div>;
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="mb-8">
        <h2 className="text-2xl font-bold mb-2">Hash Functions</h2>
        <p className="text-muted-foreground">
          Cryptographic hash functions and HMAC
        </p>
      </div>

      <div className="space-y-6">
        {/* Algorithm Selection */}
        <div className="space-y-2">
          <Label className="text-sm font-medium">Algorithm</Label>
          <Select
            onValueChange={e => {
              pushQuery('algorithm', e);
            }}
            value={algorithm}
          >
            <SelectTrigger className="w-full max-w-md">
              <SelectValue placeholder="Select an algorithm" />
            </SelectTrigger>
            <SelectContent>
              {hashAlgorithms.map(alg => (
                <SelectItem key={alg.value} value={alg.value}>
                  {alg.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* HMAC Configuration */}
        <div className="space-y-3">
          <div className="flex items-center space-x-2">
            <Switch
              id="useHmac"
              checked={useHmac}
              disabled={!supportsHmac(algorithm)}
              onCheckedChange={e => {
                pushQuery('useHmac', e ? 'true' : 'false');
              }}
            />
            <Label htmlFor="useHmac" className="text-sm font-medium">
              Use HMAC
              {!supportsHmac(algorithm) && (
                <span className="text-muted-foreground ml-1">
                  (not supported)
                </span>
              )}
            </Label>
          </div>

          {useHmac && supportsHmac(algorithm) && (
            <div className="flex flex-col sm:flex-row gap-2">
              <Input
                value={hmacKey || ''}
                onChange={e => {
                  pushQuery('hmacKey', e.target.value);
                }}
                placeholder="Enter HMAC key in hex format"
                className="flex-1"
              />
              <Button
                onClick={() => {
                  const keyBytes = generateRandomKey(32);
                  const keyHex = uint8ArrayToString(keyBytes, 'hex');
                  pushQuery('hmacKey', keyHex);
                }}
                variant="outline"
                className="sm:w-auto w-full"
              >
                Generate Key
              </Button>
            </div>
          )}
        </div>

        <div className="flex items-center justify-between">
          <Label className="text-sm font-medium">Input Source</Label>
          <Tabs
            value={inputMode}
            onValueChange={(value: 'text' | 'file') => setInputMode(value)}
            className="w-fit"
          >
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="text" className="text-xs">
                Text
              </TabsTrigger>
              <TabsTrigger value="file" className="text-xs">
                File
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </div>

        {/* Text Input */}
        {inputMode === 'text' && (
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <Label className="text-sm font-medium">Message</Label>
              <Select
                onValueChange={e => {
                  pushQuery('messageFormat', e);
                }}
                value={messageFormat}
              >
                <SelectTrigger className="w-full sm:w-[140px]">
                  <SelectValue placeholder="Format" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="hex">Hex</SelectItem>
                  <SelectItem value="base64">Base64</SelectItem>
                  <SelectItem value="utf8">UTF-8</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <Textarea
              value={input}
              onChange={e => {
                setInput(e.target.value);
                pushQuery('message', e.target.value);
              }}
              placeholder="Enter message to hash"
              rows={4}
              className="resize-none"
            />
          </div>
        )}

        {/* File Upload */}
        {inputMode === 'file' && (
          <div className="space-y-3">
            <Label className="text-sm font-medium">File Upload</Label>
            <div className="border-2 border-dashed border-muted-foreground/25 rounded-lg p-6 text-center">
              <Input
                type="file"
                id="fileInput"
                onChange={e => {
                  const file = e.target.files?.[0];
                  setSelectedFile(file || null);
                }}
                className="hidden"
              />
              <Label
                htmlFor="fileInput"
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
                    {selectedFile ? selectedFile.name : 'Click to upload file'}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {selectedFile
                      ? `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB`
                      : 'Any file type supported'}
                  </p>
                </div>
              </Label>
            </div>
            {selectedFile && (
              <Button
                onClick={() => {
                  setSelectedFile(null);
                  const fileInput = document.getElementById(
                    'fileInput',
                  ) as HTMLInputElement;
                  if (fileInput) fileInput.value = '';
                }}
                variant="outline"
                size="sm"
              >
                Clear File
              </Button>
            )}
          </div>
        )}

        {/* Hash Output */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <Label className="text-sm font-medium">Hash Output</Label>
            <Select
              onValueChange={e => {
                pushQuery('outputFormat', e);
              }}
              value={outputFormat}
            >
              <SelectTrigger className="w-full sm:w-[140px]">
                <SelectValue placeholder="Format" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hex">Hex</SelectItem>
                <SelectItem value="base64">Base64</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Textarea
            value={hash}
            readOnly
            placeholder={isComputing ? 'Computing...' : 'Hash will appear here'}
            rows={3}
            className="bg-muted resize-none font-mono text-sm"
          />
        </div>

        {/* Status and Manual Compute */}
        <div className="flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            {(() => {
              const hasTextInput = inputMode === 'text' && message.trim();
              const hasFileInput = inputMode === 'file' && selectedFile;
              const hasInput = hasTextInput || hasFileInput;

              if (!hasInput) {
                return inputMode === 'text'
                  ? 'Enter a message to compute hash'
                  : 'Upload a file to compute hash';
              }

              if (isComputing) {
                return inputMode === 'file' && selectedFile
                  ? `Computing hash for ${selectedFile.name}...`
                  : 'Computing hash...';
              }

              if (hash) {
                return inputMode === 'file' && selectedFile
                  ? `Hash computed for ${selectedFile.name}`
                  : 'Hash computed automatically';
              }

              return 'Ready to compute';
            })()}
          </div>
          <Button
            onClick={computeHash}
            variant="outline"
            size="sm"
            disabled={
              (inputMode === 'text' && !message.trim()) ||
              (inputMode === 'file' && !selectedFile) ||
              isComputing
            }
          >
            {isComputing ? 'Computing...' : 'Compute Now'}
          </Button>
        </div>

        {/* Error Display */}
        {error && (
          <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-md">
            <p className="text-destructive text-sm">{error}</p>
          </div>
        )}
      </div>
    </div>
  );
}
