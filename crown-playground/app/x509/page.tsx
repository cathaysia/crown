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
  pkcs7Parse,
  pkcs7Verify,
  pkcs8Decrypt,
  pkcs12Parse,
  x509Parse,
} from '@/lib/pki';
import { initWasm, stringToUint8Array } from '@/lib/wasm';
import { Button } from '@/ui/button';
import { Input } from '@/ui/input';
import { Label } from '@/ui/label';
import { Textarea } from '@/ui/textarea';

type Mode = 'x509' | 'pkcs7' | 'pkcs12' | 'pkcs8';

export default function X509Page() {
  const [mode, setMode] = useState<Mode>('x509');
  const [encoding, setEncoding] = useState<'utf8' | 'base64' | 'hex'>('utf8');
  const [input, setInput] = useState('');
  const [content, setContent] = useState('');
  const [password, setPassword] = useState('');
  const [sm2Id, setSm2Id] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  const run = (verify: boolean) => {
    if (!wasmReady) return;
    try {
      setError('');
      const data = stringToUint8Array(input, encoding);
      if (mode === 'x509') {
        setOutput(JSON.stringify(x509Parse(data), null, 2));
      } else if (mode === 'pkcs7') {
        if (verify) {
          const detached = content
            ? stringToUint8Array(content, 'utf8')
            : undefined;
          const ok = pkcs7Verify(data, detached, sm2Id);
          setOutput(
            ok ? 'Signature verification OK' : 'Signature verification FAILED',
          );
        } else {
          setOutput(JSON.stringify(pkcs7Parse(data), null, 2));
        }
      } else if (mode === 'pkcs12') {
        setOutput(JSON.stringify(pkcs12Parse(data, password), null, 2));
      } else {
        setOutput(JSON.stringify(pkcs8Decrypt(data, password), null, 2));
      }
    } catch (e: any) {
      setError(String(e?.message || e));
      setOutput('');
    }
  };

  return (
    <div className="flex flex-col gap-6 p-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Certificates (X.509 / PKCS)</h1>
        <p className="text-muted-foreground">
          Parse certificates, CSRs and CRLs; verify CMS signatures; open PKCS#12
          containers and encrypted PKCS#8 keys
        </p>
      </div>
      <div className="grid gap-4">
        <div className="grid gap-2">
          <Label>Mode</Label>
          <Select
            value={mode}
            onValueChange={value => {
              setMode(value as Mode);
              setOutput('');
              setError('');
            }}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="x509">
                Certificate / CSR / CRL (PEM or DER)
              </SelectItem>
              <SelectItem value="pkcs7">CMS / PKCS#7</SelectItem>
              <SelectItem value="pkcs12">PKCS#12</SelectItem>
              <SelectItem value="pkcs8">
                Encrypted PKCS#8 private key
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label>Input encoding</Label>
          <Select
            value={encoding}
            onValueChange={value => setEncoding(value as typeof encoding)}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="utf8">PEM / text (UTF-8)</SelectItem>
              <SelectItem value="base64">Base64 (DER / PFX)</SelectItem>
              <SelectItem value="hex">Hex (DER / PFX)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label>
            {mode === 'x509'
              ? 'Certificate, CSR or CRL'
              : mode === 'pkcs7'
                ? 'CMS / PKCS#7 object'
                : mode === 'pkcs12'
                  ? 'PKCS#12 PFX'
                  : 'Encrypted PKCS#8'}
          </Label>
          <Textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            rows={8}
            className="font-mono text-xs"
            placeholder={mode === 'x509' ? '-----BEGIN CERTIFICATE-----' : ''}
          />
        </div>
        {mode === 'pkcs7' && (
          <>
            <div className="grid gap-2">
              <Label>Detached content (optional)</Label>
              <Textarea
                value={content}
                onChange={e => setContent(e.target.value)}
                rows={3}
              />
            </div>
            <div className="grid gap-2">
              <Label>SM2 identity (optional, defaults to the GM/T value)</Label>
              <Input value={sm2Id} onChange={e => setSm2Id(e.target.value)} />
            </div>
          </>
        )}
        {(mode === 'pkcs12' || mode === 'pkcs8') && (
          <div className="grid gap-2">
            <Label>Password</Label>
            <Input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
            />
          </div>
        )}
        <div className="flex gap-2">
          <Button onClick={() => run(false)}>
            {mode === 'x509'
              ? 'Parse'
              : mode === 'pkcs7'
                ? 'Parse'
                : mode === 'pkcs12'
                  ? 'Open'
                  : 'Decrypt'}
          </Button>
          {mode === 'pkcs7' && (
            <Button variant="outline" onClick={() => run(true)}>
              Verify
            </Button>
          )}
        </div>
        <div className="grid gap-2">
          <Label>Output</Label>
          <Textarea
            value={output}
            readOnly
            rows={16}
            className="font-mono text-xs"
          />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      </div>
    </div>
  );
}
