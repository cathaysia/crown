'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
import { Textarea } from '@/ui/textarea';
import { Switch } from './ui/switch';

const hashAlgorithms = getAvailableAlgorithms();

export function HashPanel() {
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

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  // Debounce hook
  const useDebounce = (value: any, delay: number) => {
    const [debouncedValue, setDebouncedValue] = useState(value);

    useEffect(() => {
      const handler = setTimeout(() => {
        setDebouncedValue(value);
      }, delay);

      return () => {
        clearTimeout(handler);
      };
    }, [value, delay]);

    return debouncedValue;
  };

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
    }),
    [
      algorithm,
      message,
      messageFormat,
      outputFormat,
      hmacKey,
      useHmac,
      wasmReady,
    ],
  );

  // Debounce the dependencies
  const debouncedDependencies = useDebounce(hashDependencies, 500);

  const computeHash = useCallback(async () => {
    if (!wasmReady || !message.trim()) {
      setHash('');
      setError('');
      return;
    }

    try {
      setIsComputing(true);
      setError('');
      const messageBytes = stringToUint8Array(message, messageFormat);

      // Use the type-safe hash creation function
      const hmacKeyBytes =
        useHmac && hmacKey ? stringToUint8Array(hmacKey, 'hex') : undefined;

      // Check if HMAC is requested but not supported
      if (useHmac && hmacKey && !supportsHmac(algorithm)) {
        throw new Error(`HMAC not supported for ${algorithm}`);
      }

      const hasher = createHash(algorithm, hmacKeyBytes);

      hasher.write(messageBytes);
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
  ]);

  // Auto-compute hash when dependencies change
  useEffect(() => {
    if (!wasmReady || !message.trim()) {
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

        {/* Message Input */}
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
            value={message}
            onChange={e => {
              pushQuery('message', e.target.value);
            }}
            placeholder="Enter message to hash"
            rows={4}
            className="resize-none"
          />
        </div>

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
            {message.trim()
              ? isComputing
                ? 'Computing hash...'
                : hash
                  ? 'Hash computed automatically'
                  : 'Ready to compute'
              : 'Enter a message to compute hash'}
          </div>
          <Button
            onClick={computeHash}
            variant="outline"
            size="sm"
            disabled={!message.trim() || isComputing}
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
