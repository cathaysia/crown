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
  ed25519Keygen,
  ed25519Sign,
  ed25519Verify,
  mlDsaKeygen,
  mlKemEncapsulate,
  mlKemKeygen,
  slhDsaKeygen,
  slhDsaVariants,
} from '@/lib/kem';
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

export default function KemPage() {
  const [mode, setMode] = useState<'sign' | 'kem'>('sign');
  const [algorithm, setAlgorithm] = useState('ed25519');
  const [seed, setSeed] = useState('');
  const [message, setMessage] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  const run = () => {
    if (!wasmReady) return;
    try {
      setError('');
      if (mode === 'sign') {
        if (algorithm === 'ed25519') {
          const keys = ed25519Keygen();
          const secret = keys.slice(0, 32);
          const publicK = keys.slice(32);
          const sig = ed25519Sign(secret, stringToUint8Array(message, 'utf8'));
          const ok = ed25519Verify(
            publicK,
            stringToUint8Array(message, 'utf8'),
            sig,
          );
          setOutput(
            `public=${uint8ArrayToString(publicK, 'hex')}\nsignature=${uint8ArrayToString(sig, 'hex')}\nverify=${ok}`,
          );
        } else if (algorithm.startsWith('mldsa')) {
          const variant = parseInt(algorithm.replace('mldsa', ''), 10) as
            | 44
            | 65
            | 87;
          const keys = mlDsaKeygen(variant, generateRandomKey(32));
          setOutput(`keys generated (${keys.length} bytes) — use bin for sign`);
        } else {
          const keys = slhDsaKeygen(algorithm, generateRandomKey(48));
          setOutput(`keys generated (${keys.length} bytes) — use bin for sign`);
        }
      } else {
        const variant =
          algorithm === 'mlkem512'
            ? 512
            : algorithm === 'mlkem768'
              ? 768
              : 1024;
        const keys = mlKemKeygen(
          variant as 512 | 768 | 1024,
          generateRandomKey(64),
        );
        // keys = public || private; public length depends on variant
        const pubLens: Record<number, number> = {
          512: 800,
          768: 1184,
          1024: 1568,
        };
        const pubLen = pubLens[variant];
        const publicK = keys.slice(0, pubLen);
        const message = generateRandomKey(32);
        const enc = mlKemEncapsulate(
          variant as 512 | 768 | 1024,
          publicK,
          message,
        );
        setOutput(
          `encapsulated ok, output=${enc.length} bytes (ct||ss)\npublic=${uint8ArrayToString(publicK, 'hex').slice(0, 32)}...`,
        );
      }
    } catch (e: any) {
      setError(String(e?.message || e));
      setOutput('');
    }
  };

  return (
    <div className="flex flex-col gap-6 p-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Signatures &amp; KEM</h1>
        <p className="text-muted-foreground">
          Ed25519 / ML-DSA / SLH-DSA / ML-KEM
        </p>
      </div>
      <div className="grid gap-4">
        <div className="grid gap-2">
          <Label>Mode</Label>
          <Select
            value={mode}
            onValueChange={v => {
              setMode(v as 'sign' | 'kem');
              setAlgorithm(v === 'kem' ? 'mlkem768' : 'ed25519');
            }}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="sign">Sign / Verify</SelectItem>
              <SelectItem value="kem">KEM (ML-KEM)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label>Algorithm</Label>
          <Select value={algorithm} onValueChange={setAlgorithm}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {mode === 'sign' ? (
                <>
                  <SelectItem value="ed25519">Ed25519</SelectItem>
                  <SelectItem value="mldsa44">ML-DSA-44</SelectItem>
                  <SelectItem value="mldsa65">ML-DSA-65</SelectItem>
                  <SelectItem value="mldsa87">ML-DSA-87</SelectItem>
                  {slhDsaVariants.map(v => (
                    <SelectItem key={v} value={v}>
                      {v}
                    </SelectItem>
                  ))}
                </>
              ) : (
                <>
                  <SelectItem value="mlkem512">ML-KEM-512</SelectItem>
                  <SelectItem value="mlkem768">ML-KEM-768</SelectItem>
                  <SelectItem value="mlkem1024">ML-KEM-1024</SelectItem>
                </>
              )}
            </SelectContent>
          </Select>
        </div>
        {mode === 'sign' && (
          <div className="grid gap-2">
            <Label>Message</Label>
            <Textarea
              value={message}
              onChange={e => setMessage(e.target.value)}
              rows={3}
            />
          </div>
        )}
        <Button onClick={run}>Run</Button>
        <div className="grid gap-2">
          <Label>Output</Label>
          <Textarea value={output} readOnly rows={5} />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      </div>
    </div>
  );
}
