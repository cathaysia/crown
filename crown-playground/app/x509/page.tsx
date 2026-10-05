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
  acParse,
  acVerify,
  cmpParse,
  cmpVerify,
  cmsAuthVerify,
  cmsDecrypt,
  cmsEncrypt,
  ocspVerify,
  pkcs7Parse,
  pkcs7Verify,
  pkcs8Decrypt,
  pkcs12Parse,
  tsVerify,
  x509Parse,
  x509Verify,
} from '@/lib/pki';
import { initWasm, stringToUint8Array, uint8ArrayToString } from '@/lib/wasm';
import { Button } from '@/ui/button';
import { Input } from '@/ui/input';
import { Label } from '@/ui/label';
import { Textarea } from '@/ui/textarea';

type Mode =
  | 'x509'
  | 'pkcs7'
  | 'pkcs12'
  | 'pkcs8'
  | 'verify'
  | 'cms'
  | 'ocsp'
  | 'ac'
  | 'ts'
  | 'cmp';

export default function X509Page() {
  const [mode, setMode] = useState<Mode>('x509');
  const [cmsMode, setCmsMode] = useState<'encrypt' | 'decrypt' | 'auth'>(
    'encrypt',
  );
  const [encoding, setEncoding] = useState<'utf8' | 'base64' | 'hex'>('utf8');
  const [input, setInput] = useState('');
  const [extra, setExtra] = useState('');
  const [extra2, setExtra2] = useState('');
  const [extra3, setExtra3] = useState('');
  const [content, setContent] = useState('');
  const [password, setPassword] = useState('');
  const [purpose, setPurpose] = useState('any');
  const [sm2Id, setSm2Id] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    initWasm().then(() => setWasmReady(true));
  }, []);

  const decode = (value: string, fallback: 'utf8' | 'base64' | 'hex') =>
    stringToUint8Array(value, value ? fallback : 'utf8');

  const run = (verify: boolean) => {
    if (!wasmReady) return;
    try {
      setError('');
      if (mode === 'x509') {
        setOutput(JSON.stringify(x509Parse(decode(input, encoding)), null, 2));
      } else if (mode === 'pkcs7') {
        if (verify) {
          const detached = content
            ? stringToUint8Array(content, 'utf8')
            : undefined;
          const ok = pkcs7Verify(decode(input, encoding), detached, sm2Id);
          setOutput(
            ok ? 'Signature verification OK' : 'Signature verification FAILED',
          );
        } else {
          setOutput(
            JSON.stringify(pkcs7Parse(decode(input, encoding)), null, 2),
          );
        }
      } else if (mode === 'pkcs12') {
        setOutput(
          JSON.stringify(
            pkcs12Parse(decode(input, encoding), password),
            null,
            2,
          ),
        );
      } else if (mode === 'pkcs8') {
        setOutput(
          JSON.stringify(
            pkcs8Decrypt(decode(input, encoding), password),
            null,
            2,
          ),
        );
      } else if (mode === 'cmp') {
        setOutput(
          JSON.stringify(
            verify
              ? {
                  verified: cmpVerify(
                    decode(input, encoding),
                    password || undefined,
                  ),
                }
              : cmpParse(decode(input, encoding)),
            null,
            2,
          ),
        );
      } else if (mode === 'ac') {
        const report = extra
          ? acVerify(decode(input, encoding), stringToUint8Array(extra, 'utf8'))
          : acParse(decode(input, encoding));
        setOutput(JSON.stringify(report, null, 2));
      } else if (mode === 'ts') {
        setOutput(
          JSON.stringify(
            tsVerify(
              decode(input, encoding),
              stringToUint8Array(extra, 'utf8'),
              extra2 ? stringToUint8Array(extra2, 'utf8') : undefined,
              extra3 ? stringToUint8Array(extra3, 'utf8') : undefined,
            ),
            null,
            2,
          ),
        );
      } else if (mode === 'verify') {
        const crl = extra3 ? stringToUint8Array(extra3, 'utf8') : undefined;
        setOutput(
          JSON.stringify(
            x509Verify(
              stringToUint8Array(input, 'utf8'),
              stringToUint8Array(extra, 'utf8'),
              stringToUint8Array(extra2, 'utf8'),
              crl,
              purpose,
            ),
            null,
            2,
          ),
        );
      } else if (mode === 'cms') {
        if (cmsMode === 'auth') {
          const plaintext = cmsAuthVerify(
            stringToUint8Array(input, encoding),
            extra ? stringToUint8Array(extra, 'utf8') : undefined,
            extra2 ? stringToUint8Array(extra2, 'utf8') : undefined,
            password || undefined,
          );
          setOutput(uint8ArrayToString(plaintext, 'utf8'));
        } else if (cmsMode === 'encrypt') {
          const enveloped = cmsEncrypt(
            stringToUint8Array(input, 'utf8'),
            stringToUint8Array(extra, 'utf8'),
            password || undefined,
          );
          setOutput(uint8ArrayToString(enveloped, 'base64'));
        } else {
          const plaintext = cmsDecrypt(
            stringToUint8Array(input, encoding),
            extra ? stringToUint8Array(extra, 'utf8') : undefined,
            extra2 ? stringToUint8Array(extra2, 'utf8') : undefined,
            password || undefined,
          );
          setOutput(uint8ArrayToString(plaintext, 'utf8'));
        }
      } else {
        setOutput(
          JSON.stringify(
            ocspVerify(
              decode(input, encoding),
              stringToUint8Array(extra, 'utf8'),
            ),
            null,
            2,
          ),
        );
      }
    } catch (e: any) {
      setError(String(e?.message || e));
      setOutput('');
    }
  };

  const runLabel =
    mode === 'x509' || mode === 'pkcs7'
      ? 'Parse'
      : mode === 'pkcs12'
        ? 'Open'
        : mode === 'pkcs8'
          ? 'Decrypt'
          : mode === 'verify'
            ? 'Verify chain'
            : mode === 'cms'
              ? cmsMode === 'encrypt'
                ? 'Encrypt'
                : 'Decrypt'
              : 'Verify';

  return (
    <div className="flex flex-col gap-6 p-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Certificates (X.509 / PKCS)</h1>
        <p className="text-muted-foreground">
          Parse certificates, CSRs and CRLs; validate chains; verify CMS and
          OCSP; open PKCS#12 containers and encrypted PKCS#8 keys
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
              <SelectItem value="verify">Path validation (chain)</SelectItem>
              <SelectItem value="pkcs7">CMS / PKCS#7 signed data</SelectItem>
              <SelectItem value="cms">CMS encrypt / decrypt</SelectItem>
              <SelectItem value="ocsp">OCSP response</SelectItem>
              <SelectItem value="ac">Attribute certificate</SelectItem>
              <SelectItem value="ts">Timestamp response</SelectItem>
              <SelectItem value="cmp">CMP message</SelectItem>
              <SelectItem value="pkcs12">PKCS#12</SelectItem>
              <SelectItem value="pkcs8">
                Encrypted PKCS#8 private key
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
        {mode === 'cms' && (
          <div className="grid gap-2">
            <Label>Operation</Label>
            <Select
              value={cmsMode}
              onValueChange={value =>
                setCmsMode(value as 'encrypt' | 'decrypt')
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="encrypt">Encrypt</SelectItem>
                <SelectItem value="decrypt">Decrypt</SelectItem>
                <SelectItem value="auth">Verify authenticated data</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}
        {(mode === 'x509' ||
          mode === 'pkcs8' ||
          mode === 'pkcs7' ||
          mode === 'ocsp' ||
          (mode === 'cms' && cmsMode === 'decrypt')) && (
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
        )}
        <div className="grid gap-2">
          <Label>
            {mode === 'verify'
              ? 'Leaf certificate'
              : mode === 'cms'
                ? cmsMode === 'encrypt'
                  ? 'Content to encrypt'
                  : 'CMS EnvelopedData'
                : mode === 'ocsp'
                  ? 'OCSP response'
                  : 'Input'}
          </Label>
          <Textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            rows={mode === 'verify' || mode === 'cms' ? 6 : 8}
            className="font-mono text-xs"
            placeholder={mode === 'x509' ? '-----BEGIN CERTIFICATE-----' : ''}
          />
        </div>
        {mode === 'verify' && (
          <>
            <div className="grid gap-2">
              <Label>Trust anchors (PEM bundle)</Label>
              <Textarea
                value={extra}
                onChange={e => setExtra(e.target.value)}
                rows={4}
                className="font-mono text-xs"
              />
            </div>
            <div className="grid gap-2">
              <Label>Untrusted intermediates (PEM bundle)</Label>
              <Textarea
                value={extra2}
                onChange={e => setExtra2(e.target.value)}
                rows={4}
                className="font-mono text-xs"
              />
            </div>
            <div className="grid gap-2">
              <Label>CRL (optional, enables revocation checking)</Label>
              <Textarea
                value={extra3}
                onChange={e => setExtra3(e.target.value)}
                rows={3}
                className="font-mono text-xs"
              />
            </div>
            <div className="grid gap-2">
              <Label>Purpose</Label>
              <Select value={purpose} onValueChange={setPurpose}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">Any</SelectItem>
                  <SelectItem value="ssl-server">TLS server</SelectItem>
                  <SelectItem value="ssl-client">TLS client</SelectItem>
                  <SelectItem value="smime-sign">S/MIME signing</SelectItem>
                  <SelectItem value="smime-encrypt">
                    S/MIME encryption
                  </SelectItem>
                  <SelectItem value="code-signing">Code signing</SelectItem>
                  <SelectItem value="ocsp-helper">OCSP helper</SelectItem>
                  <SelectItem value="time-stamping">Time stamping</SelectItem>
                  <SelectItem value="crl-sign">CRL signing</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </>
        )}
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
        {mode === 'cms' && (
          <>
            <div className="grid gap-2">
              <Label>
                {cmsMode === 'encrypt'
                  ? 'Recipient certificate'
                  : 'Recipient private key (PKCS#8 PEM, optional with password)'}
              </Label>
              <Textarea
                value={extra}
                onChange={e => setExtra(e.target.value)}
                rows={4}
                className="font-mono text-xs"
              />
            </div>
            {(cmsMode === 'decrypt' || cmsMode === 'auth') && (
              <div className="grid gap-2">
                <Label>Recipient certificate</Label>
                <Textarea
                  value={extra2}
                  onChange={e => setExtra2(e.target.value)}
                  rows={4}
                  className="font-mono text-xs"
                />
              </div>
            )}
            <div className="grid gap-2">
              <Label>Password (optional: adds/uses a password recipient)</Label>
              <Input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
            </div>
          </>
        )}
        {mode === 'ac' && (
          <div className="grid gap-2">
            <Label>Issuer certificate (optional: verify when given)</Label>
            <Textarea
              value={extra}
              onChange={e => setExtra(e.target.value)}
              rows={4}
              className="font-mono text-xs"
            />
          </div>
        )}
        {mode === 'ts' && (
          <>
            <div className="grid gap-2">
              <Label>TSA certificate</Label>
              <Textarea
                value={extra}
                onChange={e => setExtra(e.target.value)}
                rows={4}
                className="font-mono text-xs"
              />
            </div>
            <div className="grid gap-2">
              <Label>Query (optional: checks imprint and nonce)</Label>
              <Textarea
                value={extra2}
                onChange={e => setExtra2(e.target.value)}
                rows={3}
                className="font-mono text-xs"
              />
            </div>
            <div className="grid gap-2">
              <Label>Data (optional: checks the message imprint)</Label>
              <Textarea
                value={extra3}
                onChange={e => setExtra3(e.target.value)}
                rows={2}
              />
            </div>
          </>
        )}
        {mode === 'ocsp' && (
          <div className="grid gap-2">
            <Label>Issuer certificate</Label>
            <Textarea
              value={extra}
              onChange={e => setExtra(e.target.value)}
              rows={4}
              className="font-mono text-xs"
            />
          </div>
        )}
        {mode === 'cmp' && (
          <div className="grid gap-2">
            <Label>Password (for password-based protection)</Label>
            <Input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
            />
          </div>
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
          <Button onClick={() => run(false)}>{runLabel}</Button>
          {mode === 'cmp' && (
            <Button variant="outline" onClick={() => run(true)}>
              Verify protection
            </Button>
          )}
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
