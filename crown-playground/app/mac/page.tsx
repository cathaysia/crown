'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Format } from '@/lib/format';
import { createMac, getAvailableMacAlgorithms, MacAlgorithm } from '@/lib/mac';
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

const algorithms = getAvailableMacAlgorithms();

export default function MacPage() {
  const [algorithm, setAlgorithm] = useState<MacAlgorithm>('cmac_aes');
  const [key, setKey] = useState('');
  const [message, setMessage] = useState('');
  const [custom, setCustom] = useState('');
  const [iv, setIv] = useState('');
  const [outputLen, setOutputLen] = useState('16');
  const [tag, setTag] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  const info = useMemo(
    () => algorithms.find(a => a.value === algorithm),
    [algorithm],
  );

  useEffect(() => {
    if (!wasmReady) return;
    try {
      setError('');
      const keyBytes = stringToUint8Array(key, 'hex');
      const msgBytes = stringToUint8Array(message, 'utf8');
      const mac = createMac(algorithm, keyBytes, {
        custom: stringToUint8Array(custom, 'hex'),
        iv: stringToUint8Array(iv || '000000000000000000000000', 'hex'),
        outputLen: parseInt(outputLen) || 16,
      });
      // write message via wasm method
      (mac as any).write(msgBytes);
      const result = (mac as any).sum();
      setTag(uint8ArrayToString(result, 'hex'));
    } catch (e: any) {
      setError(String(e?.message || e));
      setTag('');
    }
  }, [algorithm, key, message, custom, iv, outputLen, wasmReady]);

  return (
    <div className="flex flex-col gap-6 p-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Message Authentication Code</h1>
        <p className="text-muted-foreground">
          SipHash / KMAC / AES-CMAC / AES-GMAC
        </p>
      </div>

      <div className="grid gap-4">
        <div className="grid gap-2">
          <Label>Algorithm</Label>
          <Select
            value={algorithm}
            onValueChange={v => setAlgorithm(v as MacAlgorithm)}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {algorithms.map(a => (
                <SelectItem key={a.value} value={a.value}>
                  {a.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="grid gap-2">
          <Label>Key (hex)</Label>
          <div className="flex gap-2">
            <Input
              value={key}
              onChange={e => setKey(e.target.value)}
              placeholder={`${info?.keySize ?? 16} bytes hex`}
            />
            <Button
              variant="outline"
              onClick={() =>
                setKey(
                  uint8ArrayToString(
                    generateRandomKey(info?.keySize ?? 16),
                    'hex',
                  ),
                )
              }
            >
              Random
            </Button>
          </div>
        </div>

        {info?.needsCustom && (
          <div className="grid gap-2">
            <Label>Custom / salt (hex)</Label>
            <Input value={custom} onChange={e => setCustom(e.target.value)} />
          </div>
        )}
        {info?.needsIv && (
          <div className="grid gap-2">
            <Label>IV (hex, 12 bytes)</Label>
            <Input value={iv} onChange={e => setIv(e.target.value)} />
          </div>
        )}
        {(algorithm === 'siphash' ||
          algorithm === 'kmac128' ||
          algorithm === 'kmac256') && (
          <div className="grid gap-2">
            <Label>Output length</Label>
            <Input
              value={outputLen}
              onChange={e => setOutputLen(e.target.value)}
            />
          </div>
        )}

        <div className="grid gap-2">
          <Label>Message</Label>
          <Textarea
            value={message}
            onChange={e => setMessage(e.target.value)}
            rows={4}
          />
        </div>

        <div className="grid gap-2">
          <Label>Tag (hex)</Label>
          <Input value={tag} readOnly />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      </div>
    </div>
  );
}
