'use client';

import { hkdf, pbkdf2, sskdf, tls1_prf, x963_kdf } from 'crown-wasm';
import { useEffect, useState } from 'react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { initWasm, stringToUint8Array, uint8ArrayToString } from '@/lib/wasm';
import { Button } from '@/ui/button';
import { Input } from '@/ui/input';
import { Label } from '@/ui/label';
import { Textarea } from '@/ui/textarea';

const algorithms = [
  { value: 'pbkdf2', label: 'PBKDF2-HMAC-SHA256' },
  { value: 'hkdf', label: 'HKDF-SHA256' },
  { value: 'tls1_prf', label: 'TLS1-PRF (SHA256)' },
  { value: 'sskdf', label: 'SSKDF (SHA256)' },
  { value: 'x963', label: 'X963KDF (SHA256)' },
];

export default function KdfPage() {
  const [algorithm, setAlgorithm] = useState('pbkdf2');
  const [secret, setSecret] = useState('');
  const [salt, setSalt] = useState('');
  const [info, setInfo] = useState('');
  const [iterations, setIterations] = useState('1000');
  const [length, setLength] = useState('32');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  useEffect(() => {
    if (!wasmReady) return;
    try {
      setError('');
      const s = stringToUint8Array(secret, 'utf8');
      const sa = stringToUint8Array(salt, 'utf8');
      const i = stringToUint8Array(info, 'utf8');
      const len = parseInt(length) || 32;
      let out: Uint8Array;
      switch (algorithm) {
        case 'pbkdf2':
          out = pbkdf2(s, sa, parseInt(iterations) || 1000, len);
          break;
        case 'hkdf':
          out = hkdf(s, sa, i, len);
          break;
        case 'tls1_prf':
          out = tls1_prf(s, stringToUint8Array(info || salt, 'utf8'), len);
          break;
        case 'sskdf':
          out = sskdf(s, i, len);
          break;
        case 'x963':
          out = x963_kdf(s, i, len);
          break;
        default:
          out = new Uint8Array(0);
      }
      setOutput(uint8ArrayToString(out, 'hex'));
    } catch (e: any) {
      setError(String(e?.message || e));
      setOutput('');
    }
  }, [algorithm, secret, salt, info, iterations, length, wasmReady]);

  return (
    <div className="flex flex-col gap-6 p-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Key Derivation</h1>
        <p className="text-muted-foreground">PBKDF2 / HKDF / TLS-PRF / SSKDF</p>
      </div>
      <div className="grid gap-4">
        <div className="grid gap-2">
          <Label>Algorithm</Label>
          <Select value={algorithm} onValueChange={setAlgorithm}>
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
          <Label>Secret / password</Label>
          <Input value={secret} onChange={e => setSecret(e.target.value)} />
        </div>
        <div className="grid gap-2">
          <Label>Salt</Label>
          <Input value={salt} onChange={e => setSalt(e.target.value)} />
        </div>
        <div className="grid gap-2">
          <Label>Info / label</Label>
          <Input value={info} onChange={e => setInfo(e.target.value)} />
        </div>
        {algorithm === 'pbkdf2' && (
          <div className="grid gap-2">
            <Label>Iterations</Label>
            <Input
              value={iterations}
              onChange={e => setIterations(e.target.value)}
            />
          </div>
        )}
        <div className="grid gap-2">
          <Label>Output length (bytes)</Label>
          <Input value={length} onChange={e => setLength(e.target.value)} />
        </div>
        <div className="grid gap-2">
          <Label>Derived key (hex)</Label>
          <Textarea value={output} readOnly rows={3} />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      </div>
    </div>
  );
}
