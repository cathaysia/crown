/**
 * aesni_cbc_sha1_enc for x86_64 (stitched AES-NI CBC + SHA-1).
 *
 * TypeScript port of OpenSSL crypto/aes/asm/aesni-sha1-x86_64.pl.
 * Written by Andy Polyakov, @dot-asm.
 * Copyright 2008-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $win64=0 (unix SysV),
 * $avx=1 (the avx body is emitted), $shaext=1 (the shaext body is
 * emitted), $stitched_decrypt=0 (the aesni256_cbc_sha1_dec family is
 * omitted, matching upstream default).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// ---------------------------------------------------------------------------
// perlasm AUTOLOAD thunk
// ---------------------------------------------------------------------------
function isNumericLiteral(arg: string): boolean {
  return /^-?[0-9]+$/.test(arg) || /^[0-9]+$/.test(arg);
}

function AUTOLOAD(opcode: string, ...args: string[]): void {
  let arg = args.pop() as string;
  if (isNumericLiteral(arg) || /^-?[0-9]+$/.test(arg)) {
    arg = '$' + arg;
  }
  const rest = [...args].reverse();
  code += `\t${opcode}\t${[arg, ...rest].join(',')}\n`;
}

type Thunk = () => void;
interface Insn extends Thunk {
  isRor?: boolean;
  isRol?: boolean;
  isAssign?: boolean;
  isJinc?: boolean;
}

function insn(fn: Thunk, flags: Partial<Insn> = {}): Insn {
  const t = fn as Insn;
  Object.assign(t, flags);
  return t;
}

// ---------------------------------------------------------------------------
// Shared instruction emitters used by the body thunks
// ---------------------------------------------------------------------------
function xor(dst: string, src: string): void {
  AUTOLOAD('xor', dst, src);
}
function add(dst: string, src: string): void {
  AUTOLOAD('add', dst, src);
}
function mov(dst: string, src: string): void {
  AUTOLOAD('mov', dst, src);
}
function and_(dst: string, src: string): void {
  AUTOLOAD('and', dst, src);
}

// ---------------------------------------------------------------------------
// State for the software-pipelined SHA-1 + AES-NI generator
// ---------------------------------------------------------------------------
type Mode = 'ssse3' | 'avx' | 'shaext';

// $sn is file-scope in the perl and is NOT reset between the ssse3, avx
// and shaext bodies (Laesenclast labels are numbered across all of them).
let SN = 0;

interface GenState {
  Xi: number;
  j: number;
  jj: number;
  r: number;
  rx: number;
  X: string[];
  Tx: string[];
  V: string[];
  T: string[];
  rndkey: string[];
  // argument registers (reassigned mid-prologue)
  in0: string;
  out: string;
  len: string;
  key: string;
  ivp: string;
  ctx: string;
  inp: string;
  rounds: string;
  K_XX_XX: string;
  iv: string;
  in: string;
  rndkey0: string;
  Kx: string;
  mode: Mode;
}

function makeState(mode: Mode): GenState {
  // initial argument registers
  const st: GenState = {
    Xi: 4,
    j: 0,
    jj: 0,
    r: 0,
    rx: 0,
    X: [],
    Tx: [],
    V: ['%eax', '%ebx', '%ecx', '%edx', '%ebp'],
    T: ['%esi', '%edi'],
    rndkey: [],
    in0: '%rdi',
    out: '%rsi',
    len: '%rdx',
    key: '%rcx',
    ivp: '%r8',
    ctx: '%r9',
    inp: '%r10',
    rounds: '%r8d',
    K_XX_XX: '%r11',
    iv: '%xmm2',
    in: '%xmm14',
    rndkey0: '%xmm15',
    Kx: '',
    mode,
  };
  if (mode === 'avx') {
    st.X = [
      '%xmm4',
      '%xmm5',
      '%xmm6',
      '%xmm7',
      '%xmm0',
      '%xmm1',
      '%xmm2',
      '%xmm3',
    ];
    st.Tx = ['%xmm8', '%xmm9', '%xmm10'];
    // perl: ($rndkey0,$iv,$in)=map("%xmm$_",(11..13))
    st.rndkey0 = '%xmm11';
    st.iv = '%xmm12';
    st.in = '%xmm13';
    st.rndkey = ['%xmm14', '%xmm15'];
    st.Kx = st.Tx[2];
  } else {
    // Atom Silvermont allocation (if (1) in the perl)
    st.X = [
      '%xmm8',
      '%xmm9',
      '%xmm10',
      '%xmm11',
      '%xmm4',
      '%xmm5',
      '%xmm6',
      '%xmm7',
    ];
    st.Tx = ['%xmm12', '%xmm13', '%xmm3'];
    st.iv = '%xmm2';
    st.in = '%xmm14';
    st.rndkey0 = '%xmm15';
    st.rndkey = ['%xmm0', '%xmm1'];
  }
  return st;
}

// active state (set by genSsse3/genAvx/genShaext)
let S: GenState = makeState('ssse3');
// locals bound by the first instruction of each body block
let A = '%eax',
  B = '%ebx',
  C = '%ecx',
  D = '%edx',
  E = '%ebp';

function X(idx: number): string {
  return S.X[idx & 7];
}
function Tx(idx: number): string {
  return S.Tx[idx % 3];
}

function rotateX(): void {
  S.X.push(S.X.shift() as string);
}
function rotateTx(): void {
  S.Tx.push(S.Tx.shift() as string);
}
// perl: unshift(@V,pop(@V)) / unshift(@T,pop(@T)) / unshift(@rndkey,pop(@rndkey))
function rotateV(): void {
  S.V.unshift(S.V.pop() as string);
}
function rotateT(): void {
  S.T.unshift(S.T.pop() as string);
}
function rotateRndkey(): void {
  S.rndkey.unshift(S.rndkey.pop() as string);
}

// ---------------------------------------------------------------------------
// AES-NI round stitching ($aesenc closures)
// ---------------------------------------------------------------------------
function aesencSsse3(): void {
  // use integer: n = r/10, k = r%10
  const n = (S.r / 10) | 0;
  const k = S.r % 10;
  const rndkey0 = S.rndkey0;
  const iv = S.iv;
  const inReg = S.in;
  const rndkey = S.rndkey;
  const key = S.key;
  const in0 = S.in0;
  const out = S.out;
  const rounds = S.rounds;
  if (k === 0) {
    code += `	movups		${16 * n}(${in0}),${inReg}		# load input
	xorps		${rndkey0},${inReg}
`;
    if (n) {
      code += `	movups		${iv},${16 * (n - 1)}(${out},${in0})	# write output
`;
    }
    code += `	xorps		${inReg},${iv}
	movups		${32 + 16 * k - 112}(${key}),${rndkey[1]}
	aesenc		${rndkey[0]},${iv}
`;
  } else if (k === 9) {
    SN++;
    const sn = SN;
    code += `	cmp		$11,${rounds}
	jb		.Laesenclast${sn}
	movups		${32 + 16 * (k + 0) - 112}(${key}),${rndkey[1]}
	aesenc		${rndkey[0]},${iv}
	movups		${32 + 16 * (k + 1) - 112}(${key}),${rndkey[0]}
	aesenc		${rndkey[1]},${iv}
	je		.Laesenclast${sn}
	movups		${32 + 16 * (k + 2) - 112}(${key}),${rndkey[1]}
	aesenc		${rndkey[0]},${iv}
	movups		${32 + 16 * (k + 3) - 112}(${key}),${rndkey[0]}
	aesenc		${rndkey[1]},${iv}
.Laesenclast${sn}:
	aesenclast	${rndkey[0]},${iv}
	movups		16-112(${key}),${rndkey[1]}		# forward reference
`;
  } else {
    code += `	movups		${32 + 16 * k - 112}(${key}),${rndkey[1]}
	aesenc		${rndkey[0]},${iv}
`;
  }
  S.r++;
  rotateRndkey();
}

function aesencAvx(): void {
  const n = (S.r / 10) | 0;
  const k = S.r % 10;
  const rndkey0 = S.rndkey0;
  const iv = S.iv;
  const inReg = S.in;
  const rndkey = S.rndkey;
  const key = S.key;
  const in0 = S.in0;
  const out = S.out;
  const rounds = S.rounds;
  if (k === 0) {
    code += `	vmovdqu		${16 * n}(${in0}),${inReg}		# load input
	vpxor		${rndkey[1]},${inReg},${inReg}
`;
    if (n) {
      code += `	vmovups		${iv},${16 * (n - 1)}(${out},${in0})	# write output
`;
    }
    code += `	vpxor		${inReg},${iv},${iv}
	vaesenc		${rndkey[0]},${iv},${iv}
	vmovups		${32 + 16 * k - 112}(${key}),${rndkey[1]}
`;
  } else if (k === 9) {
    SN++;
    const sn = SN;
    code += `	cmp		$11,${rounds}
	jb		.Lvaesenclast${sn}
	vaesenc		${rndkey[0]},${iv},${iv}
	vmovups		${32 + 16 * (k + 0) - 112}(${key}),${rndkey[1]}
	vaesenc		${rndkey[1]},${iv},${iv}
	vmovups		${32 + 16 * (k + 1) - 112}(${key}),${rndkey[0]}
	je		.Lvaesenclast${sn}
	vaesenc		${rndkey[0]},${iv},${iv}
	vmovups		${32 + 16 * (k + 2) - 112}(${key}),${rndkey[1]}
	vaesenc		${rndkey[1]},${iv},${iv}
	vmovups		${32 + 16 * (k + 3) - 112}(${key}),${rndkey[0]}
.Lvaesenclast${sn}:
	vaesenclast	${rndkey[0]},${iv},${iv}
	vmovups		-112(${key}),${rndkey[0]}
	vmovups		16-112(${key}),${rndkey[1]}		# forward reference
`;
  } else {
    code += `	vaesenc		${rndkey[0]},${iv},${iv}
	vmovups		${32 + 16 * k - 112}(${key}),${rndkey[1]}
`;
  }
  S.r++;
  rotateRndkey();
}

function aesenc(): void {
  if (S.mode === 'avx') aesencAvx();
  else aesencSsse3();
}

// ---------------------------------------------------------------------------
// SHA-1 body blocks (return thunks; state read at emit time)
// ---------------------------------------------------------------------------
function rol(reg: string, imm: number): void {
  if (S.mode === 'avx') {
    AUTOLOAD('shld', reg, reg, String(imm));
  } else {
    AUTOLOAD('rol', reg, String(imm));
  }
}
function ror(reg: string, imm: number): void {
  if (S.mode === 'avx') {
    AUTOLOAD('shrd', reg, reg, String(imm));
  } else {
    AUTOLOAD('ror', reg, String(imm));
  }
}

function body00_19(): Insn[] {
  if (S.rx === 19) {
    // fall through into body_20_39, exactly like the perl
    return body20_39();
  }
  S.rx++;
  // perl concatenates the @V assignment onto the ror (". " operator)
  const r: Insn[] = [
    insn(
      () => {
        [A, B, C, D, E] = S.V;
        ror(B, S.j ? 7 : 2);
      },
      { isRor: true },
    ),
    insn(() => xor(S.T[0], D)),
    insn(() => mov(S.T[1], A)),
    insn(() => add(E, `${4 * (S.j & 15)}(%rsp)`)),
    insn(() => xor(B, C)),
    insn(() => rol(A, 5), { isRol: true }),
    insn(() => add(E, S.T[0])),
    insn(() => and_(S.T[1], B)),
    insn(() => xor(B, C)),
    insn(
      () => {
        add(E, A);
        S.j++;
        rotateV();
        rotateT();
      },
      { isJinc: true },
    ),
  ];
  const n = r.length;
  // integer division, perl `use integer`
  const kFinal = ((((((S.jj + 1) * 12) / 20) | 0) * 20 * n) / 12) | 0;
  if (S.jj === ((kFinal / n) | 0)) {
    const idx = kFinal % n;
    const orig = r[idx];
    r[idx] = insn(
      () => {
        orig();
        aesenc();
      },
      {
        isRor: orig.isRor,
        isRol: orig.isRol,
        isJinc: orig.isJinc,
        isAssign: orig.isAssign,
      },
    );
  }
  S.jj++;
  return r;
}

function body20_39(): Insn[] {
  if (S.rx === 39) {
    return body40_59();
  }
  S.rx++;
  // perl: assign+add concatenated; the two T[0] xors concatenated
  const r: Insn[] = [
    insn(() => {
      [A, B, C, D, E] = S.V;
      add(E, `${4 * (S.j & 15)}(%rsp)`);
    }),
    insn(() => {
      if (S.j === 19) xor(S.T[0], D);
      if (S.j > 19) xor(S.T[0], C);
    }),
    insn(() => mov(S.T[1], A)),
    insn(() => rol(A, 5), { isRol: true }),
    insn(() => add(E, S.T[0])),
    insn(() => {
      if (S.j < 79) xor(S.T[1], C);
    }),
    insn(() => ror(B, 7), { isRor: true }),
    insn(
      () => {
        add(E, A);
        S.j++;
        rotateV();
        rotateT();
      },
      { isJinc: true },
    ),
  ];
  const n = r.length;
  const kFinal = ((((((S.jj + 1) * 8) / 20) | 0) * 20 * n) / 8) | 0;
  if (S.jj === ((kFinal / n) | 0) && S.rx !== 20) {
    const idx = kFinal % n;
    const orig = r[idx];
    r[idx] = insn(
      () => {
        orig();
        aesenc();
      },
      {
        isRor: orig.isRor,
        isRol: orig.isRol,
        isJinc: orig.isJinc,
        isAssign: orig.isAssign,
      },
    );
  }
  S.jj++;
  return r;
}

function body40_59(): Insn[] {
  S.rx++;
  // perl: assign+add concatenated; the two T[1] xors concatenated
  const r: Insn[] = [
    insn(() => {
      [A, B, C, D, E] = S.V;
      add(E, `${4 * (S.j & 15)}(%rsp)`);
    }),
    insn(() => {
      if (S.j >= 40) and_(S.T[0], C);
    }),
    insn(() => {
      if (S.j >= 40) xor(C, D);
    }),
    insn(() => ror(B, 7), { isRor: true }),
    insn(() => mov(S.T[1], A)),
    insn(() => xor(S.T[0], C)),
    insn(() => rol(A, 5), { isRol: true }),
    insn(() => add(E, S.T[0])),
    insn(() => {
      if (S.j === 59) xor(S.T[1], C);
      if (S.j < 59) xor(S.T[1], B);
    }),
    insn(() => {
      if (S.j < 59) xor(B, C);
    }),
    insn(
      () => {
        add(E, A);
        S.j++;
        rotateV();
        rotateT();
      },
      { isJinc: true },
    ),
  ];
  const n = r.length;
  const kFinal = ((((((S.jj + 1) * 12) / 20) | 0) * 20 * n) / 12) | 0;
  if (S.jj === ((kFinal / n) | 0) && S.rx !== 40) {
    const idx = kFinal % n;
    const orig = r[idx];
    r[idx] = insn(
      () => {
        orig();
        aesenc();
      },
      {
        isRor: orig.isRor,
        isRol: orig.isRol,
        isJinc: orig.isJinc,
        isAssign: orig.isAssign,
      },
    );
  }
  S.jj++;
  return r;
}

type BodyFn = () => Insn[];

function gather(body: BodyFn): Insn[] {
  return [...body(), ...body(), ...body(), ...body()];
}

function run(insns: Insn[]): Insn | undefined {
  return insns.shift();
}

function doEval(t: Insn | undefined): void {
  if (t) t();
}

// ---------------------------------------------------------------------------
// SSSE3 Xupdate schedule
// ---------------------------------------------------------------------------
function xupdateSsse3_16_31(body: BodyFn): void {
  const insns = gather(body);
  const shift = () => insns.shift();

  doEval(shift());
  AUTOLOAD('pshufd', X(0), X(-4), '238');
  doEval(shift());
  AUTOLOAD('movdqa', Tx(0), X(-1));
  AUTOLOAD('paddd', Tx(1), X(-1));
  doEval(shift());
  doEval(shift());

  AUTOLOAD('punpcklqdq', X(0), X(-3));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('psrldq', Tx(0), '4');
  doEval(shift());
  doEval(shift());

  AUTOLOAD('pxor', X(0), X(-4));
  doEval(shift());
  doEval(shift());
  AUTOLOAD('pxor', Tx(0), X(-2));
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('pxor', X(0), Tx(0));
  doEval(shift());
  doEval(shift());
  AUTOLOAD('movdqa', `${16 * ((S.Xi - 1) & 3)}(%rsp)`, Tx(1));
  doEval(shift());
  doEval(shift());

  AUTOLOAD('movdqa', Tx(2), X(0));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('movdqa', Tx(0), X(0));
  doEval(shift());

  AUTOLOAD('pslldq', Tx(2), '12');
  AUTOLOAD('paddd', X(0), X(0));
  doEval(shift());
  doEval(shift());

  AUTOLOAD('psrld', Tx(0), '31');
  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('movdqa', Tx(1), Tx(2));
  doEval(shift());
  doEval(shift());

  AUTOLOAD('psrld', Tx(2), '30');
  doEval(shift());
  doEval(shift());
  AUTOLOAD('por', X(0), Tx(0));
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('pslld', Tx(1), '2');
  AUTOLOAD('pxor', X(0), Tx(2));
  doEval(shift());
  AUTOLOAD('movdqa', Tx(2), `${16 * ((S.Xi / 5) | 0)}(${S.K_XX_XX})`);
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('pxor', X(0), Tx(1));
  if (S.Xi === 7) {
    AUTOLOAD('pshufd', Tx(1), X(-1), '238');
  }

  for (let t = shift(); t; t = shift()) doEval(t);

  S.Xi++;
  rotateX();
  rotateTx();
}

function xupdateSsse3_32_79(body: BodyFn): void {
  const insns = gather(body);
  const shift = () => insns.shift();
  const peek = (i: number) => insns[i];

  if (S.Xi === 8) doEval(shift());
  AUTOLOAD('pxor', X(0), X(-4));
  if (S.Xi === 8) doEval(shift());
  doEval(shift());
  doEval(shift());
  if (peek(1) && peek(1).isRor) doEval(shift());
  if (peek(0) && peek(0).isRor) doEval(shift());
  AUTOLOAD('punpcklqdq', Tx(0), X(-1));
  doEval(shift());
  doEval(shift());

  AUTOLOAD('pxor', X(0), X(-7));
  doEval(shift());
  doEval(shift());
  if (S.Xi % 5) {
    AUTOLOAD('movdqa', Tx(2), Tx(1));
  } else {
    AUTOLOAD('movdqa', Tx(2), `${16 * ((S.Xi / 5) | 0)}(${S.K_XX_XX})`);
  }
  doEval(shift());
  AUTOLOAD('paddd', Tx(1), X(-1));
  doEval(shift());

  AUTOLOAD('pxor', X(0), Tx(0));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  if (peek(0) && peek(0).isRor) doEval(shift());

  AUTOLOAD('movdqa', Tx(0), X(0));
  doEval(shift());
  doEval(shift());
  AUTOLOAD('movdqa', `${16 * ((S.Xi - 1) & 3)}(%rsp)`, Tx(1));
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('pslld', X(0), '2');
  doEval(shift());
  doEval(shift());
  AUTOLOAD('psrld', Tx(0), '30');
  if (peek(0) && peek(0).isRol) doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('por', X(0), Tx(0));
  doEval(shift());
  doEval(shift());
  if (peek(1) && peek(1).isRol) doEval(shift());
  if (peek(0) && peek(0).isRol) doEval(shift());
  if (S.Xi < 19) {
    AUTOLOAD('pshufd', Tx(1), X(-1), '238');
  }
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  for (let t = shift(); t; t = shift()) doEval(t);

  S.Xi++;
  rotateX();
  rotateTx();
}

function xuplastSsse3_80(body: BodyFn, doneLabel: string): void {
  const insns = gather(body);
  const shift = () => insns.shift();

  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('paddd', Tx(1), X(-1));
  doEval(shift());
  doEval(shift());

  AUTOLOAD('movdqa', `${16 * ((S.Xi - 1) & 3)}(%rsp)`, Tx(1));

  for (let t = shift(); t; t = shift()) doEval(t);

  AUTOLOAD('cmp', S.inp, S.len);
  code += `	je	${doneLabel}\n`;

  // unshift(@Tx,pop(@Tx))  — rotate right: last element goes to front
  S.Tx.unshift(S.Tx.pop() as string);

  AUTOLOAD('movdqa', Tx(2), `64(${S.K_XX_XX})`);
  AUTOLOAD('movdqa', Tx(1), `0(${S.K_XX_XX})`);
  AUTOLOAD('movdqu', X(-4), `0(${S.inp})`);
  AUTOLOAD('movdqu', X(-3), `16(${S.inp})`);
  AUTOLOAD('movdqu', X(-2), `32(${S.inp})`);
  AUTOLOAD('movdqu', X(-1), `48(${S.inp})`);
  AUTOLOAD('pshufb', X(-4), Tx(2));
  AUTOLOAD('add', S.inp, '64');

  S.Xi = 0;
}

function xloopSsse3(body: BodyFn): void {
  const insns = gather(body);
  const shift = () => insns.shift();

  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('pshufb', X(S.Xi - 3), Tx(2));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('paddd', X(S.Xi - 4), Tx(1));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('movdqa', `${16 * S.Xi}(%rsp)`, X(S.Xi - 4));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('psubd', X(S.Xi - 4), Tx(1));

  for (let t = shift(); t; t = shift()) doEval(t);
  S.Xi++;
}

function xtailSsse3(body: BodyFn): void {
  const insns = gather(body);
  for (const t of insns) doEval(t);
}

// ---------------------------------------------------------------------------
// AVX Xupdate schedule
// ---------------------------------------------------------------------------
function xupdateAvx_16_31(body: BodyFn): void {
  const insns = gather(body);
  const shift = () => insns.shift();

  doEval(shift());
  doEval(shift());
  AUTOLOAD('vpalignr', X(0), X(-3), X(-4), '8');
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpaddd', Tx(1), S.Kx, X(-1));
  doEval(shift());
  doEval(shift());
  AUTOLOAD('vpsrldq', Tx(0), X(-1), '4');
  doEval(shift());
  doEval(shift());
  AUTOLOAD('vpxor', X(0), X(0), X(-4));
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpxor', Tx(0), Tx(0), X(-2));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpxor', X(0), X(0), Tx(0));
  doEval(shift());
  doEval(shift());
  AUTOLOAD('vmovdqa', `${16 * ((S.Xi - 1) & 3)}(%rsp)`, Tx(1));
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpsrld', Tx(0), X(0), '31');
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpslldq', Tx(1), X(0), '12');
  AUTOLOAD('vpaddd', X(0), X(0), X(0));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpor', X(0), X(0), Tx(0));
  AUTOLOAD('vpsrld', Tx(0), Tx(1), '30');
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpslld', Tx(1), Tx(1), '2');
  AUTOLOAD('vpxor', X(0), X(0), Tx(0));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpxor', X(0), X(0), Tx(1));
  doEval(shift());
  doEval(shift());
  if (S.Xi % 5 === 0) {
    AUTOLOAD('vmovdqa', S.Kx, `${16 * ((S.Xi / 5) | 0)}(${S.K_XX_XX})`);
  }
  doEval(shift());
  doEval(shift());

  for (let t = shift(); t; t = shift()) doEval(t);

  S.Xi++;
  rotateX();
}

function xupdateAvx_32_79(body: BodyFn): void {
  const insns = gather(body);
  const shift = () => insns.shift();
  // perl: @insns[0] !~ /&ro[rl]/  — body strings carry $_rol/$_ror, which
  // never match &rol/&ror, so this guard is always true. Ported as such.
  const notRolRor = true;

  AUTOLOAD('vpalignr', Tx(0), X(-1), X(-2), '8');
  AUTOLOAD('vpxor', X(0), X(0), X(-4));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpxor', X(0), X(0), X(-7));
  doEval(shift());
  if (notRolRor) doEval(shift());
  AUTOLOAD('vpaddd', Tx(1), S.Kx, X(-1));
  if (S.Xi % 5 === 0) {
    AUTOLOAD('vmovdqa', S.Kx, `${16 * ((S.Xi / 5) | 0)}(${S.K_XX_XX})`);
  }
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpxor', X(0), X(0), Tx(0));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpsrld', Tx(0), X(0), '30');
  AUTOLOAD('vmovdqa', `${16 * ((S.Xi - 1) & 3)}(%rsp)`, Tx(1));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpslld', X(0), X(0), '2');
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vpor', X(0), X(0), Tx(0));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  for (let t = shift(); t; t = shift()) doEval(t);

  S.Xi++;
  rotateX();
}

function xuplastAvx_80(body: BodyFn, doneLabel: string): void {
  const insns = gather(body);
  const shift = () => insns.shift();

  doEval(shift());
  AUTOLOAD('vpaddd', Tx(1), S.Kx, X(-1));
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());

  AUTOLOAD('vmovdqa', `${16 * ((S.Xi - 1) & 3)}(%rsp)`, Tx(1));

  for (let t = shift(); t; t = shift()) doEval(t);

  AUTOLOAD('cmp', S.inp, S.len);
  code += `	je	${doneLabel}\n`;

  AUTOLOAD('vmovdqa', Tx(1), `64(${S.K_XX_XX})`);
  AUTOLOAD('vmovdqa', S.Kx, `0(${S.K_XX_XX})`);
  AUTOLOAD('vmovdqu', X(-4), `0(${S.inp})`);
  AUTOLOAD('vmovdqu', X(-3), `16(${S.inp})`);
  AUTOLOAD('vmovdqu', X(-2), `32(${S.inp})`);
  AUTOLOAD('vmovdqu', X(-1), `48(${S.inp})`);
  AUTOLOAD('vpshufb', X(-4), X(-4), Tx(1));
  AUTOLOAD('add', S.inp, '64');

  S.Xi = 0;
}

function xloopAvx(body: BodyFn): void {
  const insns = gather(body);
  const shift = () => insns.shift();

  doEval(shift());
  doEval(shift());
  AUTOLOAD('vpshufb', X(S.Xi - 3), X(S.Xi - 3), Tx(1));
  doEval(shift());
  doEval(shift());
  AUTOLOAD('vpaddd', Tx(0), X(S.Xi - 4), S.Kx);
  doEval(shift());
  doEval(shift());
  doEval(shift());
  doEval(shift());
  AUTOLOAD('vmovdqa', `${16 * S.Xi}(%rsp)`, Tx(0));
  doEval(shift());
  doEval(shift());

  for (let t = shift(); t; t = shift()) doEval(t);
  S.Xi++;
}

function xtailAvx(body: BodyFn): void {
  const insns = gather(body);
  for (const t of insns) doEval(t);
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------
function genDispatch(): void {
  code += `.text
.extern	OPENSSL_ia32cap_P

.globl	aesni_cbc_sha1_enc
.type	aesni_cbc_sha1_enc,@abi-omnipotent
.align	32
aesni_cbc_sha1_enc:
.cfi_startproc
	# caller should check for SSSE3 and AES-NI bits
	mov	OPENSSL_ia32cap_P+0(%rip),%r10d
	mov	OPENSSL_ia32cap_P+4(%rip),%r11
	bt	$61,%r11		# check SHA bit
	jc	aesni_cbc_sha1_enc_shaext
	and	$${1 << 28},%r11d		# mask AVX bit
	and	$${1 << 30},%r10d		# mask "Intel CPU" bit
	or	%r11d,%r10d
	cmp	$${(1 << 28) | (1 << 30)},%r10d
	je	aesni_cbc_sha1_enc_avx
	jmp	aesni_cbc_sha1_enc_ssse3
	ret
.cfi_endproc
.size	aesni_cbc_sha1_enc,.-aesni_cbc_sha1_enc
`;
}

// ---------------------------------------------------------------------------
// SSSE3 body
// ---------------------------------------------------------------------------
function genSsse3Prologue(): void {
  const inp = '%r10';
  code += `.type	aesni_cbc_sha1_enc_ssse3,@function,6
.align	32
aesni_cbc_sha1_enc_ssse3:
.cfi_startproc
	mov	8(%rsp),${inp}	# load 7th argument
	#shr	$6,${S.len}			# debugging artefact
	#jz	.Lepilogue_ssse3		# debugging artefact
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	lea	-104(%rsp),%rsp
.cfi_adjust_cfa_offset	104
	#mov	${S.in0},${inp}			# debugging artefact
	#lea	64(%rsp),${S.ctx}			# debugging artefact
	mov	${S.in0},%r12			# reassign arguments
	mov	${S.out},%r13
	mov	${S.len},%r14
	lea	112(${S.key}),%r15			# size optimization
	movdqu	(${S.ivp}),${S.iv}			# load IV
	mov	${S.ivp},88(%rsp)			# save $ivp
`;
  // ($in0,$out,$len,$key)=map("%r$_",(12..15));
  S.in0 = '%r12';
  S.out = '%r13';
  S.len = '%r14';
  S.key = '%r15';
  code += `	shl	$6,${S.len}
	sub	${S.in0},${S.out}
	mov	240-112(${S.key}),${S.rounds}
	add	${inp},${S.len}		# end of input

	lea	aesni_sha1_K_XX_XX(%rip),${S.K_XX_XX}
	mov	0(${S.ctx}),${S.V[0]}		# load context
	mov	4(${S.ctx}),${S.V[1]}
	mov	8(${S.ctx}),${S.V[2]}
	mov	12(${S.ctx}),${S.V[3]}
	mov	${S.V[1]},${S.T[0]}		# magic seed
	mov	16(${S.ctx}),${S.V[4]}
	mov	${S.V[2]},${S.T[1]}
	xor	${S.V[3]},${S.T[1]}
	and	${S.T[1]},${S.T[0]}

	movdqa	64(${S.K_XX_XX}),${S.Tx[2]}	# pbswap mask
	movdqa	0(${S.K_XX_XX}),${S.Tx[1]}	# K_00_19
	movdqu	0(${inp}),${X(-4)}	# load input to %xmm[0-3]
	movdqu	16(${inp}),${X(-3)}
	movdqu	32(${inp}),${X(-2)}
	movdqu	48(${inp}),${X(-1)}
	pshufb	${S.Tx[2]},${X(-4)}		# byte swap
	pshufb	${S.Tx[2]},${X(-3)}
	pshufb	${S.Tx[2]},${X(-2)}
	add	$64,${inp}
	paddd	${S.Tx[1]},${X(-4)}		# add K_00_19
	pshufb	${S.Tx[2]},${X(-1)}
	paddd	${S.Tx[1]},${X(-3)}
	paddd	${S.Tx[1]},${X(-2)}
	movdqa	${X(-4)},0(%rsp)	# X[]+K xfer to IALU
	psubd	${S.Tx[1]},${X(-4)}		# restore X[]
	movdqa	${X(-3)},16(%rsp)
	psubd	${S.Tx[1]},${X(-3)}
	movdqa	${X(-2)},32(%rsp)
	psubd	${S.Tx[1]},${X(-2)}
	movups	-112(${S.key}),${S.rndkey0}	# $key[0]
	movups	16-112(${S.key}),${S.rndkey[0]}	# forward reference
	jmp	.Loop_ssse3
`;
}

function genSsse3Epilogue(): void {
  code += `	lea	104(%rsp),%rsi
.cfi_def_cfa	%rsi,56
	mov	0(%rsi),%r15
.cfi_restore	%r15
	mov	8(%rsi),%r14
.cfi_restore	%r14
	mov	16(%rsi),%r13
.cfi_restore	%r13
	mov	24(%rsi),%r12
.cfi_restore	%r12
	mov	32(%rsi),%rbp
.cfi_restore	%rbp
	mov	40(%rsi),%rbx
.cfi_restore	%rbx
	lea	48(%rsi),%rsp
.cfi_def_cfa	%rsp,8
.Lepilogue_ssse3:
	ret
.cfi_endproc
.size	aesni_cbc_sha1_enc_ssse3,.-aesni_cbc_sha1_enc_ssse3
`;
}

function genSsse3(): void {
  S = makeState('ssse3');
  genSsse3Prologue();

  code += `.align	32
.Loop_ssse3:
`;
  xupdateSsse3_16_31(body00_19);
  xupdateSsse3_16_31(body00_19);
  xupdateSsse3_16_31(body00_19);
  xupdateSsse3_16_31(body00_19);
  xupdateSsse3_32_79(body00_19);
  xupdateSsse3_32_79(body20_39);
  xupdateSsse3_32_79(body20_39);
  xupdateSsse3_32_79(body20_39);
  xupdateSsse3_32_79(body20_39);
  xupdateSsse3_32_79(body20_39);
  xupdateSsse3_32_79(body40_59);
  xupdateSsse3_32_79(body40_59);
  xupdateSsse3_32_79(body40_59);
  xupdateSsse3_32_79(body40_59);
  xupdateSsse3_32_79(body40_59);
  xupdateSsse3_32_79(body20_39);
  xuplastSsse3_80(body20_39, '.Ldone_ssse3');

  // save state for the tail
  const saved_j = S.j;
  const saved_V = [...S.V];
  const saved_r = S.r;
  const saved_rndkey = [...S.rndkey];

  xloopSsse3(body20_39);
  xloopSsse3(body20_39);
  xloopSsse3(body20_39);

  code += `	movups	${S.iv},48(${S.out},${S.in0})		# write output
	lea	64(${S.in0}),${S.in0}

	add	0(${S.ctx}),${S.V[0]}			# update context
	add	4(${S.ctx}),${S.T[0]}
	add	8(${S.ctx}),${S.V[2]}
	add	12(${S.ctx}),${S.V[3]}
	mov	${S.V[0]},0(${S.ctx})
	add	16(${S.ctx}),${S.V[4]}
	mov	${S.T[0]},4(${S.ctx})
	mov	${S.T[0]},${S.V[1]}			# magic seed
	mov	${S.V[2]},8(${S.ctx})
	mov	${S.V[2]},${S.T[1]}
	mov	${S.V[3]},12(${S.ctx})
	xor	${S.V[3]},${S.T[1]}
	mov	${S.V[4]},16(${S.ctx})
	and	${S.T[1]},${S.T[0]}
	jmp	.Loop_ssse3

.Ldone_ssse3:
`;
  // restore
  // perl: $jj=$j=$saved_j; @V=@saved_V; $r=$saved_r; @rndkey=@saved_rndkey
  S.jj = saved_j;
  S.j = saved_j;
  S.V = saved_V;
  S.r = saved_r;
  S.rndkey = saved_rndkey;

  xtailSsse3(body20_39);
  xtailSsse3(body20_39);
  xtailSsse3(body20_39);

  code += `	movups	${S.iv},48(${S.out},${S.in0})		# write output
	mov	88(%rsp),${S.ivp}			# restore $ivp

	add	0(${S.ctx}),${S.V[0]}			# update context
	add	4(${S.ctx}),${S.T[0]}
	add	8(${S.ctx}),${S.V[2]}
	mov	${S.V[0]},0(${S.ctx})
	add	12(${S.ctx}),${S.V[3]}
	mov	${S.T[0]},4(${S.ctx})
	add	16(${S.ctx}),${S.V[4]}
	mov	${S.V[2]},8(${S.ctx})
	mov	${S.V[3]},12(${S.ctx})
	mov	${S.V[4]},16(${S.ctx})
	movups	${S.iv},(${S.ivp})			# write IV
`;
  genSsse3Epilogue();
}

// ---------------------------------------------------------------------------
// AVX body
// ---------------------------------------------------------------------------
function genAvxPrologue(): void {
  const inp = '%r10';
  code += `.type	aesni_cbc_sha1_enc_avx,@function,6
.align	32
aesni_cbc_sha1_enc_avx:
.cfi_startproc
	mov	8(%rsp),${inp}	# load 7th argument
	#shr	$6,${S.len}			# debugging artefact
	#jz	.Lepilogue_avx			# debugging artefact
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	lea	-104(%rsp),%rsp
.cfi_adjust_cfa_offset	104
	#mov	${S.in0},${inp}			# debugging artefact
	#lea	64(%rsp),${S.ctx}			# debugging artefact
	vzeroall
	mov	${S.in0},%r12			# reassign arguments
	mov	${S.out},%r13
	mov	${S.len},%r14
	lea	112(${S.key}),%r15			# size optimization
	vmovdqu	(${S.ivp}),${S.iv}			# load IV
	mov	${S.ivp},88(%rsp)			# save $ivp
`;
  S.in0 = '%r12';
  S.out = '%r13';
  S.len = '%r14';
  S.key = '%r15';
  code += `	shl	$6,${S.len}
	sub	${S.in0},${S.out}
	mov	240-112(${S.key}),${S.rounds}
	add	${inp},${S.len}		# end of input

	lea	aesni_sha1_K_XX_XX(%rip),${S.K_XX_XX}
	mov	0(${S.ctx}),${S.V[0]}		# load context
	mov	4(${S.ctx}),${S.V[1]}
	mov	8(${S.ctx}),${S.V[2]}
	mov	12(${S.ctx}),${S.V[3]}
	mov	${S.V[1]},${S.T[0]}		# magic seed
	mov	16(${S.ctx}),${S.V[4]}
	mov	${S.V[2]},${S.T[1]}
	xor	${S.V[3]},${S.T[1]}
	and	${S.T[1]},${S.T[0]}

	vmovdqa	64(${S.K_XX_XX}),${S.X[2]}	# pbswap mask
	vmovdqa	0(${S.K_XX_XX}),${S.Kx}		# K_00_19
	vmovdqu	0(${inp}),${X(-4)}	# load input to %xmm[0-3]
	vmovdqu	16(${inp}),${X(-3)}
	vmovdqu	32(${inp}),${X(-2)}
	vmovdqu	48(${inp}),${X(-1)}
	vpshufb	${S.X[2]},${X(-4)},${X(-4)}	# byte swap
	add	$64,${inp}
	vpshufb	${S.X[2]},${X(-3)},${X(-3)}
	vpshufb	${S.X[2]},${X(-2)},${X(-2)}
	vpshufb	${S.X[2]},${X(-1)},${X(-1)}
	vpaddd	${S.Kx},${X(-4)},${X(0)}	# add K_00_19
	vpaddd	${S.Kx},${X(-3)},${X(1)}
	vpaddd	${S.Kx},${X(-2)},${X(2)}
	vmovdqa	${X(0)},0(%rsp)		# X[]+K xfer to IALU
	vmovdqa	${X(1)},16(%rsp)
	vmovdqa	${X(2)},32(%rsp)
	vmovups	-112(${S.key}),${S.rndkey[1]}	# $key[0]
	vmovups	16-112(${S.key}),${S.rndkey[0]}	# forward reference
	jmp	.Loop_avx
`;
}

function genAvxEpilogue(): void {
  code += `	lea	104(%rsp),%rsi
.cfi_def_cfa	%rsi,56
	mov	0(%rsi),%r15
.cfi_restore	%r15
	mov	8(%rsi),%r14
.cfi_restore	%r14
	mov	16(%rsi),%r13
.cfi_restore	%r13
	mov	24(%rsi),%r12
.cfi_restore	%r12
	mov	32(%rsi),%rbp
.cfi_restore	%rbp
	mov	40(%rsi),%rbx
.cfi_restore	%rbx
	lea	48(%rsi),%rsp
.cfi_def_cfa	%rsp,8
.Lepilogue_avx:
	ret
.cfi_endproc
.size	aesni_cbc_sha1_enc_avx,.-aesni_cbc_sha1_enc_avx
`;
}

function genAvx(): void {
  S = makeState('avx');
  genAvxPrologue();

  code += `.align	32
.Loop_avx:
`;
  xupdateAvx_16_31(body00_19);
  xupdateAvx_16_31(body00_19);
  xupdateAvx_16_31(body00_19);
  xupdateAvx_16_31(body00_19);
  xupdateAvx_32_79(body00_19);
  xupdateAvx_32_79(body20_39);
  xupdateAvx_32_79(body20_39);
  xupdateAvx_32_79(body20_39);
  xupdateAvx_32_79(body20_39);
  xupdateAvx_32_79(body20_39);
  xupdateAvx_32_79(body40_59);
  xupdateAvx_32_79(body40_59);
  xupdateAvx_32_79(body40_59);
  xupdateAvx_32_79(body40_59);
  xupdateAvx_32_79(body40_59);
  xupdateAvx_32_79(body20_39);
  xuplastAvx_80(body20_39, '.Ldone_avx');

  const saved_j = S.j;
  const saved_V = [...S.V];
  const saved_r = S.r;
  const saved_rndkey = [...S.rndkey];

  xloopAvx(body20_39);
  xloopAvx(body20_39);
  xloopAvx(body20_39);

  code += `	vmovups	${S.iv},48(${S.out},${S.in0})		# write output
	lea	64(${S.in0}),${S.in0}

	add	0(${S.ctx}),${S.V[0]}			# update context
	add	4(${S.ctx}),${S.T[0]}
	add	8(${S.ctx}),${S.V[2]}
	add	12(${S.ctx}),${S.V[3]}
	mov	${S.V[0]},0(${S.ctx})
	add	16(${S.ctx}),${S.V[4]}
	mov	${S.T[0]},4(${S.ctx})
	mov	${S.T[0]},${S.V[1]}			# magic seed
	mov	${S.V[2]},8(${S.ctx})
	mov	${S.V[2]},${S.T[1]}
	mov	${S.V[3]},12(${S.ctx})
	xor	${S.V[3]},${S.T[1]}
	mov	${S.V[4]},16(${S.ctx})
	and	${S.T[1]},${S.T[0]}
	jmp	.Loop_avx

.Ldone_avx:
`;
  // perl: $jj=$j=$saved_j; @V=@saved_V; $r=$saved_r; @rndkey=@saved_rndkey
  S.jj = saved_j;
  S.j = saved_j;
  S.V = saved_V;
  S.r = saved_r;
  S.rndkey = saved_rndkey;

  xtailAvx(body20_39);
  xtailAvx(body20_39);
  xtailAvx(body20_39);

  code += `	vmovups	${S.iv},48(${S.out},${S.in0})		# write output
	mov	88(%rsp),${S.ivp}			# restore $ivp

	add	0(${S.ctx}),${S.V[0]}			# update context
	add	4(${S.ctx}),${S.T[0]}
	add	8(${S.ctx}),${S.V[2]}
	mov	${S.V[0]},0(${S.ctx})
	add	12(${S.ctx}),${S.V[3]}
	mov	${S.T[0]},4(${S.ctx})
	add	16(${S.ctx}),${S.V[4]}
	mov	${S.V[2]},8(${S.ctx})
	mov	${S.V[3]},12(${S.ctx})
	mov	${S.V[4]},16(${S.ctx})
	vmovups	${S.iv},(${S.ivp})			# write IV
	vzeroall
`;
  genAvxEpilogue();
}

// ---------------------------------------------------------------------------
// K_XX_XX data
// ---------------------------------------------------------------------------
function genData(): void {
  code += `.section .rodata align=64
.align	64
aesni_sha1_K_XX_XX:
.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999	# K_00_19
.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1	# K_20_39
.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc	# K_40_59
.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6	# K_60_79
.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap mask
.byte	0xf,0xe,0xd,0xc,0xb,0xa,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0

.asciz	"AESNI-CBC+SHA1 stitch for x86_64, CRYPTOGAMS by <appro@openssl.org>"
.align	64
.previous
`;
}

// ---------------------------------------------------------------------------
// SHAEXT body
// ---------------------------------------------------------------------------
function genShaext(): void {
  S = makeState('ssse3');
  S.rounds = '%r11d';
  S.iv = '%xmm2';
  S.in = '%xmm14';
  S.rndkey0 = '%xmm15';
  S.rndkey = ['%xmm0', '%xmm1'];
  S.r = 0;
  const BSWAP = '%xmm7';
  const ABCD = '%xmm8';
  const E = '%xmm9';
  let E_ = '%xmm10';
  const ABCD_SAVE = '%xmm11';
  const E_SAVE = '%xmm12';
  const MSG = ['%xmm3', '%xmm4', '%xmm5', '%xmm6'];
  let Ecur = E;
  let Esave = E_;

  code += `.type	aesni_cbc_sha1_enc_shaext,@function,6
.align	32
aesni_cbc_sha1_enc_shaext:
.cfi_startproc
	mov	8(%rsp),${S.inp}	# load 7th argument
	movdqu	(${S.ctx}),${ABCD}
	movd	16(${S.ctx}),${Ecur}
	movdqa	aesni_sha1_K_XX_XX+0x50(%rip),${BSWAP}	# byte-n-word swap

	mov	240(${S.key}),${S.rounds}
	sub	${S.in0},${S.out}
	movups	(${S.key}),${S.rndkey0}			# $key[0]
	movups	(${S.ivp}),${S.iv}			# load IV
	movups	16(${S.key}),${S.rndkey[0]}		# forward reference
	lea	112(${S.key}),${S.key}			# size optimization

	pshufd	$27,${ABCD},${ABCD}	# flip word order
	pshufd	$27,${Ecur},${Ecur}		# flip word order
	jmp	.Loop_shaext

.align	16
.Loop_shaext:
`;
  aesencSsse3();
  code += `	movdqu		(${S.inp}),${MSG[0]}
	movdqa		${Ecur},${E_SAVE}		# offload $E
	pshufb		${BSWAP},${MSG[0]}
	movdqu		0x10(${S.inp}),${MSG[1]}
	movdqa		${ABCD},${ABCD_SAVE}	# offload $ABCD
`;
  aesencSsse3();
  code += `	pshufb		${BSWAP},${MSG[1]}

	paddd		${MSG[0]},${Ecur}
	movdqu		0x20(${S.inp}),${MSG[2]}
	lea		0x40(${S.inp}),${S.inp}
	pxor		${E_SAVE},${MSG[0]}		# black magic
`;
  aesencSsse3();
  code += `	pxor		${E_SAVE},${MSG[0]}		# black magic
	movdqa		${ABCD},${Esave}
	pshufb		${BSWAP},${MSG[2]}
	sha1rnds4	$0,${Ecur},${ABCD}		# 0-3
	sha1nexte	${MSG[1]},${Esave}
`;
  aesencSsse3();
  code += `	sha1msg1	${MSG[1]},${MSG[0]}
	movdqu		-0x10(${S.inp}),${MSG[3]}
	movdqa		${ABCD},${Ecur}
	pshufb		${BSWAP},${MSG[3]}
`;
  aesencSsse3();
  code += `	sha1rnds4	$0,${Esave},${ABCD}		# 4-7
	sha1nexte	${MSG[2]},${Ecur}
	pxor		${MSG[2]},${MSG[0]}
	sha1msg1	${MSG[2]},${MSG[1]}
`;
  aesencSsse3();

  for (let i = 2; i < 20 - 4; i++) {
    code += `	movdqa		${ABCD},${Esave}
	sha1rnds4	$${(i / 5) | 0},${Ecur},${ABCD}	# 8-11
	sha1nexte	${MSG[3]},${Esave}
`;
    aesencSsse3();
    code += `	sha1msg2	${MSG[3]},${MSG[0]}
	pxor		${MSG[3]},${MSG[1]}
	sha1msg1	${MSG[3]},${MSG[2]}
`;
    // ($E,$E_)=($E_,$E);
    {
      const tmp = Ecur;
      Ecur = Esave;
      Esave = tmp;
    }
    // push(@MSG,shift(@MSG));
    MSG.push(MSG.shift() as string);
    aesencSsse3();
  }
  code += `	movdqa		${ABCD},${Esave}
	sha1rnds4	$3,${Ecur},${ABCD}		# 64-67
	sha1nexte	${MSG[3]},${Esave}
	sha1msg2	${MSG[3]},${MSG[0]}
	pxor		${MSG[3]},${MSG[1]}
`;
  aesencSsse3();
  code += `	movdqa		${ABCD},${Ecur}
	sha1rnds4	$3,${Esave},${ABCD}		# 68-71
	sha1nexte	${MSG[0]},${Ecur}
	sha1msg2	${MSG[0]},${MSG[1]}
`;
  aesencSsse3();
  code += `	movdqa		${E_SAVE},${MSG[0]}
	movdqa		${ABCD},${Esave}
	sha1rnds4	$3,${Ecur},${ABCD}		# 72-75
	sha1nexte	${MSG[1]},${Esave}
`;
  aesencSsse3();
  code += `	movdqa		${ABCD},${Ecur}
	sha1rnds4	$3,${Esave},${ABCD}		# 76-79
	sha1nexte	${MSG[0]},${Ecur}
`;
  while (S.r < 40) {
    aesencSsse3();
  }
  code += `	dec		${S.len}

	paddd		${ABCD_SAVE},${ABCD}
	movups		${S.iv},48(${S.out},${S.in0})	# write output
	lea		64(${S.in0}),${S.in0}
	jnz		.Loop_shaext

	pshufd	$27,${ABCD},${ABCD}
	pshufd	$27,${Ecur},${Ecur}
	movups	${S.iv},(${S.ivp})			# write IV
	movdqu	${ABCD},(${S.ctx})
	movd	${Ecur},16(${S.ctx})
	ret
.cfi_endproc
.size	aesni_cbc_sha1_enc_shaext,.-aesni_cbc_sha1_enc_shaext
`;
  void BSWAP;
  void ABCD_SAVE;
  void E_SAVE;
  void E_;
}

// ---------------------------------------------------------------------------
// post-process: sha1rnds4 / sha1op38 / aesenc -> .byte encodings
// (mirror of the perl's final foreach pass)
// ---------------------------------------------------------------------------
function rexBits(dst: number, src: number): number {
  let rex = 0;
  if (dst >= 8) rex |= 0x04;
  if (src >= 8) rex |= 0x01;
  return rex;
}

function regNum(r: string): number {
  const m = r.match(/%r(?:\d+|1[0-5]|ax|bx|cx|dx|si|di|bp|sp)/);
  if (!m) {
    // xmm
    const x = r.match(/%xmm(\d+)/);
    return x ? parseInt(x[1]) : 0;
  }
  const named: Record<string, number> = {
    '%rax': 0,
    '%rcx': 1,
    '%rdx': 2,
    '%rbx': 3,
    '%rsp': 4,
    '%rbp': 5,
    '%rsi': 6,
    '%rdi': 7,
  };
  if (named[r] !== undefined) return named[r];
  const n = r.match(/%r(\d+)/);
  return n ? parseInt(n[1]) : 0;
}

function sha1rnds4Sub(args: string): string {
  const m = args.match(/\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!m) return 'sha1rnds4\t' + args;
  const opcode = [0x0f, 0x3a, 0xcc];
  const dst = parseInt(m[3]);
  const src = parseInt(m[2]);
  const rex = rexBits(dst, src);
  if (rex) opcode.unshift(0x40 | rex);
  opcode.push(0xc0 | (src & 7) | ((dst & 7) << 3));
  const c = m[1];
  opcode.push(c.startsWith('0') ? parseInt(c, 8) : parseInt(c));
  return '.byte\t' + opcode.join(',');
}

function sha1op38(instr: string, args: string): string {
  const opcodelet: Record<string, number> = {
    sha1nexte: 0xc8,
    sha1msg1: 0xc9,
    sha1msg2: 0xca,
  };
  const m = args.match(/%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (opcodelet[instr] !== undefined && m) {
    const opcodes = [0x0f, 0x38];
    const src = parseInt(m[1]);
    const dst = parseInt(m[2]);
    const rex = rexBits(dst, src);
    if (rex) opcodes.unshift(0x40 | rex);
    opcodes.push(opcodelet[instr]);
    opcodes.push(0xc0 | (src & 7) | ((dst & 7) << 3));
    return '.byte\t' + opcodes.join(',');
  }
  return instr + '\t' + args;
}

function aesniSub(args: string): string {
  const m = args.match(/(aes[a-z]+)\s+%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!m) return args;
  const opcodelet: Record<string, number> = {
    aesenc: 0xdc,
    aesenclast: 0xdd,
    aesdec: 0xde,
    aesdeclast: 0xdf,
  };
  if (opcodelet[m[1]] === undefined) return args;
  const src = parseInt(m[2]);
  const dst = parseInt(m[3]);
  const opcodes = [0x66, 0x0f, 0x38];
  const rex = rexBits(dst, src);
  if (rex) opcodes.push(0x40 | rex);
  opcodes.push(opcodelet[m[1]], 0xc0 | (src & 7) | ((dst & 7) << 3));
  return '.byte\t' + opcodes.join(',');
}

function postProcess(): void {
  code = code
    .split('\n')
    .map(line => {
      const m = line.match(/\b(sha1rnds4)\s+(.*)/);
      if (m) {
        return line.slice(0, m.index) + sha1rnds4Sub(m[2]);
      }
      const m2 = line.match(/\b(sha1[^\s]*)\s+(.*)/);
      if (m2) {
        return line.slice(0, m2.index) + sha1op38(m2[1], m2[2]);
      }
      // perl: s/\b(aes.*%xmm[0-9]+).*$/aesni($1)/  — only un-prefixed AES-NI
      const m3 = line.match(/\b(aes.*%xmm[0-9]+).*$/);
      if (m3 && !line.match(/\bvaes/)) {
        return line.slice(0, m3.index) + aesniSub(m3[1]);
      }
      return line;
    })
    .join('\n');
}

genDispatch();
genSsse3();
genAvx();
genData();
genShaext();
postProcess();

export default translateAssembly(code);
