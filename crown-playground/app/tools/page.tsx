'use client';

import { useEffect, useState } from 'react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  aesKeyUnwrap,
  aesKeyWrap,
  ff1DecryptDecimal,
  ff1EncryptDecimal,
  newXtsAes,
} from '@/lib/tools';
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

export default function ToolsPage() {
  const [tool, setTool] = useState('xts');
  const [key, setKey] = useState('');
  const [input, setInput] = useState('');
  const [tweak, setTweak] = useState('');
  const [padded, setPadded] = useState(false);
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  const run = (decrypt: boolean) => {
    if (!wasmReady) return;
    try {
      setError('');
      const keyBytes = stringToUint8Array(key, 'hex');
      if (tool === 'xts') {
        const xts = newXtsAes(keyBytes);
        const tweakBytes = stringToUint8Array(
          tweak || '00000000000000000000000000000000',
          'hex',
        );
        const data = stringToUint8Array(input, 'utf8');
        // XTS needs at least one block
        const buf =
          data.length >= 16
            ? data
            : new Uint8Array([...data, ...new Uint8Array(16 - data.length)]);
        if (decrypt) xts.decrypt(tweakBytes, buf);
        else xts.encrypt(tweakBytes, buf);
        setOutput(uint8ArrayToString(buf, 'hex'));
      } else if (tool === 'kw') {
        const data = stringToUint8Array(input, 'utf8');
        const out = decrypt
          ? aesKeyUnwrap(keyBytes, data, padded)
          : aesKeyWrap(keyBytes, data, padded);
        setOutput(uint8ArrayToString(out, 'hex'));
      } else {
        const tweakBytes = stringToUint8Array(tweak, 'utf8');
        const out = decrypt
          ? ff1DecryptDecimal(keyBytes, tweakBytes, input.trim())
          : ff1EncryptDecimal(keyBytes, tweakBytes, input.trim());
        setOutput(out);
      }
    } catch (e: any) {
      setError(String(e?.message || e));
      setOutput('');
    }
  };

  return (
    <div className="flex flex-col gap-6 p-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Crypto Tools</h1>
        <p className="text-muted-foreground">
          AES-XTS / AES Key Wrap / FF1 format-preserving encryption
        </p>
      </div>
      <div className="grid gap-4">
        <div className="grid gap-2">
          <Label>Tool</Label>
          <Select value={tool} onValueChange={setTool}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="xts">AES-XTS</SelectItem>
              <SelectItem value="kw">AES Key Wrap</SelectItem>
              <SelectItem value="ff1">FF1 (decimal)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label>Key (hex{tool === 'xts' ? ', 32/64 bytes' : ', 16/24/32 bytes'})</Label>
          <div className="flex gap-2">
            <Input value={key} onChange={e => setKey(e.target.value)} />
            <Button
              variant="outline"
              onClick={() =>
                setKey(
                  uint8ArrayToString(
                    generateRandomKey(tool === 'xts' ? 32 : 16),
                    'hex',
                  ),
                )
              }
            >
              Random
            </Button>
          </div>
        </div>
        {tool === 'kw' && (
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={padded}
              onChange={e => setPadded(e.target.checked)}
            />
            RFC 5649 padded mode
          </label>
        )}
        {(tool === 'xts' || tool === 'ff1') && (
          <div className="grid gap-2">
            <Label>{tool === 'xts' ? 'Tweak (hex, 16 bytes)' : 'Tweak'}</Label>
            <Input value={tweak} onChange={e => setTweak(e.target.value)} />
          </div>
        )}
        <div className="grid gap-2">
          <Label>
            {tool === 'ff1' ? 'Decimal digit string' : 'Input'}
            {tool !== 'ff1' && tool !== 'xts' && ' (raw bytes)'}
          </Label>
          <Textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            rows={3}
            placeholder={tool === 'ff1' ? '1234567890' : ''}
          />
        </div>
        <div className="flex gap-2">
          <Button onClick={() => run(false)}>Encrypt / Wrap</Button>
          <Button variant="outline" onClick={() => run(true)}>
            Decrypt / Unwrap
          </Button>
        </div>
        <div className="grid gap-2">
          <Label>Output</Label>
          <Textarea value={output} readOnly rows={3} />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      </div>
    </div>
  );
}
