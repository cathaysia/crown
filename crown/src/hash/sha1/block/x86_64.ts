/**
 * sha1_block procedure for x86_64.
 *
 * TypeScript port of OpenSSL crypto/sha/asm/sha1-x86_64.pl.
 * Written by Andy Polyakov, @dot-asm.
 * Copyright 2006-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $shaext=1, $avx=0 (the perl
 * script auto-detects the assembler; without $ENV{CC} it emits the
 * ialu + shaext + ssse3 code paths).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// ---------------------------------------------------------------------------
// perlasm AUTOLOAD thunk: emits "$opcode\t$arg,<reversed remaining args>"
// with a numeric last argument turned into an immediate.
// ---------------------------------------------------------------------------
function isNumericLiteral(arg: string): boolean {
  return /^[0-9]+$/.test(arg);
}

function AUTOLOAD(opcode: string, ...args: string[]): void {
  let arg = args.pop() as string;
  if (isNumericLiteral(arg)) {
    arg = '$' + arg;
  }
  const rest = [...args].reverse();
  code += `\t${opcode}\t${[arg, ...rest].join(',')}\n`;
}

// ---------------------------------------------------------------------------
// ialu implementation
// ---------------------------------------------------------------------------
const ctx = '%r8'; // reassigned argument
const inp = '%r9'; // reassigned argument
const num = '%r10'; // reassigned argument

const t0 = '%eax';
const t1 = '%ebx';
const t2 = '%ecx';
const xi = ['%edx', '%ebp', '%r14d'];
const ialuA = '%esi';
const ialuB = '%edi';
const ialuC = '%r11d';
const ialuD = '%r12d';
const ialuE = '%r13d';

function ialuBody00_19(
  i: number,
  a: string,
  b: string,
  c: string,
  d: string,
  e: string,
): void {
  const j = i + 1;
  if (i === 0) {
    code += `	mov	${4 * i}(${inp}),${xi[0]}
	bswap	${xi[0]}
`;
  }
  if (i < 15) {
    code += `	mov	${4 * j}(${inp}),${xi[1]}
	mov	${d},${t0}
	mov	${xi[0]},${4 * i}(%rsp)
	mov	${a},${t2}
	bswap	${xi[1]}
	xor	${c},${t0}
	rol	$5,${t2}
	and	${b},${t0}
	lea	0x5a827999(${xi[0]},${e}),${e}
	add	${t2},${e}
	xor	${d},${t0}
	rol	$30,${b}
	add	${t0},${e}
`;
  }
  if (i >= 15) {
    code += `	xor	${4 * (j % 16)}(%rsp),${xi[1]}
	mov	${d},${t0}
	mov	${xi[0]},${4 * (i % 16)}(%rsp)
	mov	${a},${t2}
	xor	${4 * ((j + 2) % 16)}(%rsp),${xi[1]}
	xor	${c},${t0}
	rol	$5,${t2}
	xor	${4 * ((j + 8) % 16)}(%rsp),${xi[1]}
	and	${b},${t0}
	lea	0x5a827999(${xi[0]},${e}),${e}
	rol	$30,${b}
	xor	${d},${t0}
	add	${t2},${e}
	rol	$1,${xi[1]}
	add	${t0},${e}
`;
  }
  xi.push(xi.shift() as string);
}

function ialuBody20_39(
  i: number,
  a: string,
  b: string,
  c: string,
  d: string,
  e: string,
): void {
  const j = i + 1;
  const K = i < 40 ? '0x6ed9eba1' : '0xca62c1d6';
  if (i < 79) {
    code += `	xor	${4 * (j % 16)}(%rsp),${xi[1]}
	mov	${b},${t0}
`;
    if (i < 72) {
      code += `	mov	${xi[0]},${4 * (i % 16)}(%rsp)
`;
    } else {
      code += '	\n';
    }
    code += `	mov	${a},${t2}
	xor	${4 * ((j + 2) % 16)}(%rsp),${xi[1]}
	xor	${d},${t0}
	rol	$5,${t2}
	xor	${4 * ((j + 8) % 16)}(%rsp),${xi[1]}
	lea	${K}(${xi[0]},${e}),${e}
	xor	${c},${t0}
	add	${t2},${e}
	rol	$30,${b}
	add	${t0},${e}
	rol	$1,${xi[1]}
`;
  }
  if (i === 79) {
    code += `	mov	${b},${t0}
	mov	${a},${t2}
	xor	${d},${t0}
	lea	${K}(${xi[0]},${e}),${e}
	rol	$5,${t2}
	xor	${c},${t0}
	add	${t2},${e}
	rol	$30,${b}
	add	${t0},${e}
`;
  }
  xi.push(xi.shift() as string);
}

function ialuBody40_59(
  i: number,
  a: string,
  b: string,
  c: string,
  d: string,
  e: string,
): void {
  const j = i + 1;
  code += `	xor	${4 * (j % 16)}(%rsp),${xi[1]}
	mov	${d},${t0}
	mov	${xi[0]},${4 * (i % 16)}(%rsp)
	mov	${d},${t1}
	xor	${4 * ((j + 2) % 16)}(%rsp),${xi[1]}
	and	${c},${t0}
	mov	${a},${t2}
	xor	${4 * ((j + 8) % 16)}(%rsp),${xi[1]}
	lea	0x8f1bbcdc(${xi[0]},${e}),${e}
	xor	${c},${t1}
	rol	$5,${t2}
	add	${t0},${e}
	rol	$1,${xi[1]}
	and	${b},${t1}
	add	${t2},${e}
	rol	$30,${b}
	add	${t1},${e}
`;
  xi.push(xi.shift() as string);
}

function genIalu(): void {
  const V = [ialuA, ialuB, ialuC, ialuD, ialuE];

  code += `.text
.extern	OPENSSL_ia32cap_P

.globl	sha1_block_data_order
.type	sha1_block_data_order,@function,3
.align	16
sha1_block_data_order:
.cfi_startproc
	mov	OPENSSL_ia32cap_P+0(%rip),%r9d
	mov	OPENSSL_ia32cap_P+4(%rip),%r8d
	mov	OPENSSL_ia32cap_P+8(%rip),%r10d
	test	$${1 << 9},%r8d		# check SSSE3 bit
	jz	.Lialu
	test	$${1 << 29},%r10d		# check SHA bit
	jnz	_shaext_shortcut
	jmp	_ssse3_shortcut

.align	16
.Lialu:
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
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
	mov	%rdi,${ctx}	# reassigned argument
	sub	$${8 + 16 * 4},%rsp
	mov	%rsi,${inp}	# reassigned argument
	and	$-64,%rsp
	mov	%rdx,${num}	# reassigned argument
	mov	%rax,${16 * 4}(%rsp)
.cfi_cfa_expression	%rsp+64,deref,+8
.Lprologue:

	mov	0(${ctx}),${ialuA}
	mov	4(${ctx}),${ialuB}
	mov	8(${ctx}),${ialuC}
	mov	12(${ctx}),${ialuD}
	mov	16(${ctx}),${ialuE}
	jmp	.Lloop

.align	16
.Lloop:
`;
  for (let i = 0; i < 20; i++) {
    ialuBody00_19(i, V[0], V[1], V[2], V[3], V[4]);
    V.unshift(V.pop() as string);
  }
  for (let i = 20; i < 40; i++) {
    ialuBody20_39(i, V[0], V[1], V[2], V[3], V[4]);
    V.unshift(V.pop() as string);
  }
  for (let i = 40; i < 60; i++) {
    ialuBody40_59(i, V[0], V[1], V[2], V[3], V[4]);
    V.unshift(V.pop() as string);
  }
  for (let i = 60; i < 80; i++) {
    ialuBody20_39(i, V[0], V[1], V[2], V[3], V[4]);
    V.unshift(V.pop() as string);
  }
  code += `	add	0(${ctx}),${ialuA}
	add	4(${ctx}),${ialuB}
	add	8(${ctx}),${ialuC}
	add	12(${ctx}),${ialuD}
	add	16(${ctx}),${ialuE}
	mov	${ialuA},0(${ctx})
	mov	${ialuB},4(${ctx})
	mov	${ialuC},8(${ctx})
	mov	${ialuD},12(${ctx})
	mov	${ialuE},16(${ctx})

	sub	$1,${num}
	lea	${16 * 4}(${inp}),${inp}
	jnz	.Lloop

	mov	${16 * 4}(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	mov	-40(%rsi),%r14
.cfi_restore	%r14
	mov	-32(%rsi),%r13
.cfi_restore	%r13
	mov	-24(%rsi),%r12
.cfi_restore	%r12
	mov	-16(%rsi),%rbp
.cfi_restore	%rbp
	mov	-8(%rsi),%rbx
.cfi_restore	%rbx
	lea	(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Lepilogue:
	ret
.cfi_endproc
.size	sha1_block_data_order,.-sha1_block_data_order
`;
}

// ---------------------------------------------------------------------------
// Intel SHA Extensions implementation of SHA1 update function.
// ---------------------------------------------------------------------------
function genShaext(): void {
  const seCtx = '%rdi';
  const seInp = '%rsi';
  const seNum = '%rdx';
  const ABCD = '%xmm0';
  const E = '%xmm1';
  const E_ = '%xmm2';
  const BSWAP = '%xmm3';
  const ABCD_SAVE = '%xmm8';
  const E_SAVE = '%xmm9';
  const MSG = ['%xmm4', '%xmm5', '%xmm6', '%xmm7'];

  code += `.type	sha1_block_data_order_shaext,@function,3
.align	32
sha1_block_data_order_shaext:
_shaext_shortcut:
.cfi_startproc
	movdqu	(${seCtx}),${ABCD}
	movd	16(${seCtx}),${E}
	movdqa	K_XX_XX+0xa0(%rip),${BSWAP}	# byte-n-word swap

	movdqu	(${seInp}),${MSG[0]}
	pshufd	$0b00011011,${ABCD},${ABCD}	# flip word order
	movdqu	0x10(${seInp}),${MSG[1]}
	pshufd	$0b00011011,${E},${E}		# flip word order
	movdqu	0x20(${seInp}),${MSG[2]}
	pshufb	${BSWAP},${MSG[0]}
	movdqu	0x30(${seInp}),${MSG[3]}
	pshufb	${BSWAP},${MSG[1]}
	pshufb	${BSWAP},${MSG[2]}
	movdqa	${E},${E_SAVE}			# offload ${E}
	pshufb	${BSWAP},${MSG[3]}
	jmp	.Loop_shaext

.align	16
.Loop_shaext:
	dec		${seNum}
	lea		0x40(${seInp}),%r8		# next input block
	paddd		${MSG[0]},${E}
	cmovne		%r8,${seInp}
	movdqa		${ABCD},${ABCD_SAVE}	# offload ${ABCD}
`;
  for (let i = 0; i < 20 - 4; i += 2) {
    code += `	sha1msg1	${MSG[1]},${MSG[0]}
	movdqa		${ABCD},${E_}
	sha1rnds4	$${Math.trunc(i / 5)},${E},${ABCD}	# 0-3...
	sha1nexte	${MSG[1]},${E_}
	pxor		${MSG[2]},${MSG[0]}
	sha1msg1	${MSG[2]},${MSG[1]}
	sha1msg2	${MSG[3]},${MSG[0]}

	movdqa		${ABCD},${E}
	sha1rnds4	$${Math.trunc((i + 1) / 5)},${E_},${ABCD}
	sha1nexte	${MSG[2]},${E}
	pxor		${MSG[3]},${MSG[1]}
	sha1msg2	${MSG[0]},${MSG[1]}
`;
    MSG.push(MSG.shift() as string);
    MSG.push(MSG.shift() as string);
  }
  code += `	movdqu		(${seInp}),${MSG[0]}
	movdqa		${ABCD},${E_}
	sha1rnds4	$3,${E},${ABCD}		# 64-67
	sha1nexte	${MSG[1]},${E_}
	movdqu		0x10(${seInp}),${MSG[1]}
	pshufb		${BSWAP},${MSG[0]}

	movdqa		${ABCD},${E}
	sha1rnds4	$3,${E_},${ABCD}		# 68-71
	sha1nexte	${MSG[2]},${E}
	movdqu		0x20(${seInp}),${MSG[2]}
	pshufb		${BSWAP},${MSG[1]}

	movdqa		${ABCD},${E_}
	sha1rnds4	$3,${E},${ABCD}		# 72-75
	sha1nexte	${MSG[3]},${E_}
	movdqu		0x30(${seInp}),${MSG[3]}
	pshufb		${BSWAP},${MSG[2]}

	movdqa		${ABCD},${E}
	sha1rnds4	$3,${E_},${ABCD}		# 76-79
	sha1nexte	${E_SAVE},${E}
	pshufb		${BSWAP},${MSG[3]}

	paddd		${ABCD_SAVE},${ABCD}
	movdqa		${E},${E_SAVE}		# offload ${E}

	jnz		.Loop_shaext

	pshufd	$0b00011011,${ABCD},${ABCD}
	pshufd	$0b00011011,${E},${E}
	movdqu	${ABCD},(${seCtx})
	movd	${E},16(${seCtx})
	ret
.cfi_endproc
.size	sha1_block_data_order_shaext,.-sha1_block_data_order_shaext
`;
}

// ---------------------------------------------------------------------------
// ssse3 implementation
//
// The perl script schedules the ialu body instructions between the SIMD
// message schedule updates with the help of code-fragment lists. The
// fragments are modelled here as {text, run} pairs; text keeps the perl
// fragment markers (e.g. "_ror") that the schedulers branch on.
// ---------------------------------------------------------------------------
interface Insn {
  text: string;
  run: () => void;
}

function insn(text: string, run: () => void): Insn {
  return { text, run };
}

const _rol = (...args: string[]): void => AUTOLOAD('rol', ...args);
const _ror = (...args: string[]): void => AUTOLOAD('ror', ...args);

// ssse3 register assignments (perl rebinds A..E and @V here)
let A = '%eax';
let B = '%ebx';
let C = '%ecx';
let D = '%edx';
let E = '%ebp';
let V = [A, B, C, D, E];
const T = ['%esi', '%edi'];
let j = 0;
let rx = 0;
let Xi = 4;
const X = [
  '%xmm4',
  '%xmm5',
  '%xmm6',
  '%xmm7',
  '%xmm0',
  '%xmm1',
  '%xmm2',
  '%xmm3',
];
const Tx = ['%xmm8', '%xmm9', '%xmm10'];
const Kx = '%xmm11';
const K_XX_XX = '%r14';
const fp = '%r11';

let sn = 0;

function align32(): void {
  ++sn;
  code += `	jmp	.Lalign32_${sn}	# see "Decoded ICache" in manual
.align	32
.Lalign32_${sn}:
`;
}

function body_00_19(): Insn[] {
  // ((c^d)&b)^d; on start @T[0]=(c^d)&b
  if (rx === 19) {
    return body_20_39();
  }
  rx++;
  let a = '';
  let b = '';
  let c = '';
  let d = '';
  let e = '';
  return [
    insn('($a,$b,$c,$d,$e)=@V;&$_ror($b,$j?7:2)', () => {
      [a, b, c, d, e] = V;
      _ror(b, j !== 0 ? '7' : '2'); // $b>>>2
    }),
    insn('&xor(@T[0],$d)', () => {
      AUTOLOAD('xor', T[0], d);
    }),
    insn('&mov(@T[1],$a)', () => {
      AUTOLOAD('mov', T[1], a); // $b for next round
    }),
    insn('&add($e,X[]+K xfer)', () => {
      AUTOLOAD('add', e, (4 * (j & 15)).toString() + '(%rsp)');
    }),
    insn('&xor($b,$c)', () => {
      AUTOLOAD('xor', b, c); // $c^$d for next round
    }),
    insn('&$_rol($a,5)', () => {
      _rol(a, '5');
    }),
    insn('&add($e,@T[0])', () => {
      AUTOLOAD('add', e, T[0]);
    }),
    insn('&and(@T[1],$b)', () => {
      AUTOLOAD('and', T[1], b); // ($b&($c^$d)) for next round
    }),
    insn('&xor($b,$c)', () => {
      AUTOLOAD('xor', b, c); // restore $b
    }),
    insn('&add($e,$a);$j++;unshift(@V,pop(@V));unshift(@T,pop(@T));', () => {
      AUTOLOAD('add', e, a);
      j++;
      V.unshift(V.pop() as string);
      T.unshift(T.pop() as string);
    }),
  ];
}

function body_20_39(): Insn[] {
  // b^d^c; on entry @T[0]=b^d
  if (rx === 39) {
    return body_40_59();
  }
  rx++;
  let a = '';
  let b = '';
  let c = '';
  let d = '';
  let e = '';
  return [
    insn('($a,$b,$c,$d,$e)=@V;&add($e,X[]+K xfer)', () => {
      [a, b, c, d, e] = V;
      AUTOLOAD('add', e, (4 * (j & 15)).toString() + '(%rsp)');
    }),
    insn('&xor(@T[0],$d) if($j==19);&xor(@T[0],$c) if($j> 19)', () => {
      if (j === 19) {
        AUTOLOAD('xor', T[0], d);
      }
      if (j > 19) {
        AUTOLOAD('xor', T[0], c); // ($b^$d^$c)
      }
    }),
    insn('&mov(@T[1],$a)', () => {
      AUTOLOAD('mov', T[1], a); // $b for next round
    }),
    insn('&$_rol($a,5)', () => {
      _rol(a, '5');
    }),
    insn('&add($e,@T[0])', () => {
      AUTOLOAD('add', e, T[0]);
    }),
    insn('&xor(@T[1],$c) if ($j< 79)', () => {
      if (j < 79) {
        AUTOLOAD('xor', T[1], c); // $b^$d for next round
      }
    }),
    insn('&$_ror($b,7)', () => {
      _ror(b, '7'); // $b>>>2
    }),
    insn('&add($e,$a);$j++;unshift(@V,pop(@V));unshift(@T,pop(@T));', () => {
      AUTOLOAD('add', e, a);
      j++;
      V.unshift(V.pop() as string);
      T.unshift(T.pop() as string);
    }),
  ];
}

function body_40_59(): Insn[] {
  // ((b^c)&(c^d))^c; on entry @T[0]=(b^c), (c^=d)
  rx++;
  let a = '';
  let b = '';
  let c = '';
  let d = '';
  let e = '';
  return [
    insn('($a,$b,$c,$d,$e)=@V;&add($e,X[]+K xfer)', () => {
      [a, b, c, d, e] = V;
      AUTOLOAD('add', e, (4 * (j & 15)).toString() + '(%rsp)');
    }),
    insn('&and(@T[0],$c) if ($j>=40)', () => {
      if (j >= 40) {
        AUTOLOAD('and', T[0], c); // (b^c)&(c^d)
      }
    }),
    insn('&xor($c,$d) if ($j>=40)', () => {
      if (j >= 40) {
        AUTOLOAD('xor', c, d); // restore $c
      }
    }),
    insn('&$_ror($b,7)', () => {
      _ror(b, '7'); // $b>>>2
    }),
    insn('&mov(@T[1],$a)', () => {
      AUTOLOAD('mov', T[1], a); // $b for next round
    }),
    insn('&xor(@T[0],$c)', () => {
      AUTOLOAD('xor', T[0], c);
    }),
    insn('&$_rol($a,5)', () => {
      _rol(a, '5');
    }),
    insn('&add($e,@T[0])', () => {
      AUTOLOAD('add', e, T[0]);
    }),
    insn('&xor(@T[1],$c) if ($j==59);&xor(@T[1],$b) if ($j< 59)', () => {
      if (j === 59) {
        AUTOLOAD('xor', T[1], c);
      }
      if (j < 59) {
        AUTOLOAD('xor', T[1], b); // b^c for next round
      }
    }),
    insn('&xor($b,$c) if ($j< 59)', () => {
      if (j < 59) {
        AUTOLOAD('xor', b, c); // c^d for next round
      }
    }),
    insn('&add($e,$a);$j++;unshift(@V,pop(@V));unshift(@T,pop(@T));', () => {
      AUTOLOAD('add', e, a);
      j++;
      V.unshift(V.pop() as string);
      T.unshift(T.pop() as string);
    }),
  ];
}

function Xupdate_ssse3_16_31(body: () => Insn[]): void {
  // recall that Xi starts with 4
  const insns = [...body(), ...body(), ...body(), ...body()]; // 40 instructions
  const ev = (): void => {
    const s = insns.shift();
    if (s) {
      s.run();
    }
  };

  ev(); // ror
  AUTOLOAD('pshufd', X[0], X[-4 & 7], '238'); // was &movdqa (@X[0],@X[-3&7]);
  ev();
  AUTOLOAD('movdqa', Tx[0], X[-1 & 7]);
  AUTOLOAD('paddd', Tx[1], X[-1 & 7]);
  ev();
  ev();

  AUTOLOAD('punpcklqdq', X[0], X[-3 & 7]); // compose "X[-14]" in "X[0]", was &palignr(@X[0],@X[-4&7],8);
  ev();
  ev(); // rol
  ev();
  AUTOLOAD('psrldq', Tx[0], '4'); // "X[-3]", 3 dwords
  ev();
  ev();

  AUTOLOAD('pxor', X[0], X[-4 & 7]); // "X[0]"^="X[-16]"
  ev();
  ev(); // ror
  AUTOLOAD('pxor', Tx[0], X[-2 & 7]); // "X[-3]"^"X[-8]"
  ev();
  ev();
  ev();

  AUTOLOAD('pxor', X[0], Tx[0]); // "X[0]"^="X[-3]"^"X[-8]"
  ev();
  ev(); // rol
  AUTOLOAD('movdqa', (16 * ((Xi - 1) & 3)).toString() + '(%rsp)', Tx[1]); // X[]+K xfer to IALU
  ev();
  ev();

  AUTOLOAD('movdqa', Tx[2], X[0]);
  ev();
  ev();
  ev(); // ror
  AUTOLOAD('movdqa', Tx[0], X[0]);
  ev();

  AUTOLOAD('pslldq', Tx[2], '12'); // "X[0]"<<96, extract one dword
  AUTOLOAD('paddd', X[0], X[0]);
  ev();
  ev();

  AUTOLOAD('psrld', Tx[0], '31');
  ev();
  ev(); // rol
  ev();
  AUTOLOAD('movdqa', Tx[1], Tx[2]);
  ev();
  ev();

  AUTOLOAD('psrld', Tx[2], '30');
  ev();
  ev(); // ror
  AUTOLOAD('por', X[0], Tx[0]); // "X[0]"<<<=1
  ev();
  ev();
  ev();

  AUTOLOAD('pslld', Tx[1], '2');
  AUTOLOAD('pxor', X[0], Tx[2]);
  ev();
  AUTOLOAD(
    'movdqa',
    Tx[2],
    (2 * 16 * Math.floor(Xi / 5) - 64).toString() + `(${K_XX_XX})`,
  ); // K_XX_XX
  ev(); // rol
  ev();
  ev();

  AUTOLOAD('pxor', X[0], Tx[1]); // "X[0]"^=("X[0]">>96)<<<2
  if (Xi === 7) {
    AUTOLOAD('pshufd', Tx[1], X[-1 & 7], '238'); // was &movdqa (@Tx[0],@X[-1&7]) in Xupdate_ssse3_32_79
  }

  for (const s of insns) {
    s.run();
  } // remaining instructions [if any]

  Xi++;
  X.push(X.shift() as string); // "rotate" X[]
  Tx.push(Tx.shift() as string);
}

function Xupdate_ssse3_32_79(body: () => Insn[]): void {
  const insns = [...body(), ...body(), ...body(), ...body()]; // 32 to 44 instructions
  const ev = (): void => {
    const s = insns.shift();
    if (s) {
      s.run();
    }
  };

  if (Xi === 8) {
    ev();
  }
  AUTOLOAD('pxor', X[0], X[-4 & 7]); // "X[0]"="X[-32]"^"X[-16]"
  if (Xi === 8) {
    ev();
  }
  ev(); // body_20_39
  ev();
  if (/_ror/.test(insns[1]?.text ?? '')) {
    ev();
  }
  if (/_ror/.test(insns[0]?.text ?? '')) {
    ev();
  }
  AUTOLOAD('punpcklqdq', Tx[0], X[-1 & 7]); // compose "X[-6]", was &palignr(@Tx[0],@X[-2&7],8);
  ev();
  ev(); // rol

  AUTOLOAD('pxor', X[0], X[-7 & 7]); // "X[0]"^="X[-28]"
  ev();
  ev();
  if (Xi % 5 !== 0) {
    AUTOLOAD('movdqa', Tx[2], Tx[1]); // "perpetuate" K_XX_XX...
  } else {
    // ... or load next one
    AUTOLOAD(
      'movdqa',
      Tx[2],
      (2 * 16 * Math.floor(Xi / 5) - 64).toString() + `(${K_XX_XX})`,
    );
  }
  ev(); // ror
  AUTOLOAD('paddd', Tx[1], X[-1 & 7]);
  ev();

  AUTOLOAD('pxor', X[0], Tx[0]); // "X[0]"^="X[-6]"
  ev(); // body_20_39
  ev();
  ev();
  ev(); // rol
  if (/_ror/.test(insns[0]?.text ?? '')) {
    ev();
  }

  AUTOLOAD('movdqa', Tx[0], X[0]);
  ev();
  ev();
  AUTOLOAD('movdqa', (16 * ((Xi - 1) & 3)).toString() + '(%rsp)', Tx[1]); // X[]+K xfer to IALU
  ev(); // ror
  ev();
  ev(); // body_20_39

  AUTOLOAD('pslld', X[0], '2');
  ev();
  ev();
  AUTOLOAD('psrld', Tx[0], '30');
  if (/_rol/.test(insns[0]?.text ?? '')) {
    ev(); // rol
  }
  ev();
  ev();
  ev(); // ror

  AUTOLOAD('por', X[0], Tx[0]); // "X[0]"<<<=2
  ev();
  ev(); // body_20_39
  if (/_rol/.test(insns[1]?.text ?? '')) {
    ev();
  }
  if (/_rol/.test(insns[0]?.text ?? '')) {
    ev();
  }
  if (Xi < 19) {
    AUTOLOAD('pshufd', Tx[1], X[-1 & 7], '238'); // was &movdqa (@Tx[1],@X[0])
  }
  ev();
  ev(); // rol
  ev();
  ev();
  ev(); // rol
  ev();

  for (const s of insns) {
    s.run();
  } // remaining instructions

  Xi++;
  X.push(X.shift() as string); // "rotate" X[]
  Tx.push(Tx.shift() as string);
}

function Xuplast_ssse3_80(body: () => Insn[]): void {
  const insns = [...body(), ...body(), ...body(), ...body()]; // 32 instructions
  const ev = (): void => {
    const s = insns.shift();
    if (s) {
      s.run();
    }
  };

  ev();
  ev();
  ev();
  ev();
  AUTOLOAD('paddd', Tx[1], X[-1 & 7]);
  ev();
  ev();

  AUTOLOAD('movdqa', (16 * ((Xi - 1) & 3)).toString() + '(%rsp)', Tx[1]); // X[]+K xfer IALU

  for (const s of insns) {
    s.run();
  } // remaining instructions

  AUTOLOAD('cmp', inp, num);
  AUTOLOAD('je', '.Ldone_ssse3');

  Tx.unshift(Tx.pop() as string);

  AUTOLOAD('movdqa', X[2], `64(${K_XX_XX})`); // pbswap mask
  AUTOLOAD('movdqa', Tx[1], `-64(${K_XX_XX})`); // K_00_19
  AUTOLOAD('movdqu', X[-4 & 7], `0(${inp})`); // load input
  AUTOLOAD('movdqu', X[-3 & 7], `16(${inp})`);
  AUTOLOAD('movdqu', X[-2 & 7], `32(${inp})`);
  AUTOLOAD('movdqu', X[-1 & 7], `48(${inp})`);
  AUTOLOAD('pshufb', X[-4 & 7], X[2]); // byte swap
  AUTOLOAD('add', inp, '64');

  Xi = 0;
}

function Xloop_ssse3(body: () => Insn[]): void {
  const insns = [...body(), ...body(), ...body(), ...body()]; // 32 instructions
  const ev = (): void => {
    const s = insns.shift();
    if (s) {
      s.run();
    }
  };

  ev();
  ev();
  ev();
  AUTOLOAD('pshufb', X[(Xi - 3) & 7], X[2]);
  ev();
  ev();
  ev();
  ev();
  AUTOLOAD('paddd', X[(Xi - 4) & 7], Tx[1]);
  ev();
  ev();
  ev();
  ev();
  AUTOLOAD('movdqa', (16 * Xi).toString() + '(%rsp)', X[(Xi - 4) & 7]); // X[]+K xfer to IALU
  ev();
  ev();
  ev();
  ev();
  AUTOLOAD('psubd', X[(Xi - 4) & 7], Tx[1]);

  for (const s of insns) {
    s.run();
  }
  Xi++;
}

function Xtail_ssse3(body: () => Insn[]): void {
  const insns = [...body(), ...body(), ...body(), ...body()]; // 32 instructions

  for (const s of insns) {
    s.run();
  }
}

function genSsse3(): void {
  code += `.type	sha1_block_data_order_ssse3,@function,3
.align	16
sha1_block_data_order_ssse3:
_ssse3_shortcut:
.cfi_startproc
	mov	%rsp,${fp}	# frame pointer
.cfi_def_cfa_register	${fp}
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13		# redundant, done to share Win64 SE handler
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	lea	${-64 - (0 ? 6 * 16 : 0)}(%rsp),%rsp
	and	$-64,%rsp
	mov	%rdi,${ctx}	# reassigned argument
	mov	%rsi,${inp}	# reassigned argument
	mov	%rdx,${num}	# reassigned argument

	shl	$6,${num}
	add	${inp},${num}
	lea	K_XX_XX+64(%rip),${K_XX_XX}

	mov	0(${ctx}),${A}		# load context
	mov	4(${ctx}),${B}
	mov	8(${ctx}),${C}
	mov	12(${ctx}),${D}
	mov	${B},${T[0]}		# magic seed
	mov	16(${ctx}),${E}
	mov	${C},${T[1]}
	xor	${D},${T[1]}
	and	${T[1]},${T[0]}

	movdqa	64(${K_XX_XX}),${X[2]}	# pbswap mask
	movdqa	-64(${K_XX_XX}),${Tx[1]}	# K_00_19
	movdqu	0(${inp}),${X[(-4) & 7]}	# load input to %xmm[0-3]
	movdqu	16(${inp}),${X[(-3) & 7]}
	movdqu	32(${inp}),${X[(-2) & 7]}
	movdqu	48(${inp}),${X[(-1) & 7]}
	pshufb	${X[2]},${X[(-4) & 7]}		# byte swap
	pshufb	${X[2]},${X[(-3) & 7]}
	pshufb	${X[2]},${X[(-2) & 7]}
	add	$64,${inp}
	paddd	${Tx[1]},${X[(-4) & 7]}		# add K_00_19
	pshufb	${X[2]},${X[(-1) & 7]}
	paddd	${Tx[1]},${X[(-3) & 7]}
	paddd	${Tx[1]},${X[(-2) & 7]}
	movdqa	${X[(-4) & 7]},0(%rsp)	# X[]+K xfer to IALU
	psubd	${Tx[1]},${X[(-4) & 7]}		# restore X[]
	movdqa	${X[(-3) & 7]},16(%rsp)
	psubd	${Tx[1]},${X[(-3) & 7]}
	movdqa	${X[(-2) & 7]},32(%rsp)
	psubd	${Tx[1]},${X[(-2) & 7]}
	jmp	.Loop_ssse3
.align	16
.Loop_ssse3:
`;
  Xupdate_ssse3_16_31(body_00_19);
  Xupdate_ssse3_16_31(body_00_19);
  Xupdate_ssse3_16_31(body_00_19);
  Xupdate_ssse3_16_31(body_00_19);
  Xupdate_ssse3_32_79(body_00_19);
  Xupdate_ssse3_32_79(body_20_39);
  Xupdate_ssse3_32_79(body_20_39);
  Xupdate_ssse3_32_79(body_20_39);
  Xupdate_ssse3_32_79(body_20_39);
  Xupdate_ssse3_32_79(body_20_39);
  Xupdate_ssse3_32_79(body_40_59);
  Xupdate_ssse3_32_79(body_40_59);
  Xupdate_ssse3_32_79(body_40_59);
  Xupdate_ssse3_32_79(body_40_59);
  Xupdate_ssse3_32_79(body_40_59);
  Xupdate_ssse3_32_79(body_20_39);
  Xuplast_ssse3_80(body_20_39); // can jump to "done"

  const saved_j = j;
  const saved_V = [...V];

  Xloop_ssse3(body_20_39);
  Xloop_ssse3(body_20_39);
  Xloop_ssse3(body_20_39);

  code += `	add	0(${ctx}),${A}			# update context
	add	4(${ctx}),${T[0]}
	add	8(${ctx}),${C}
	add	12(${ctx}),${D}
	mov	${A},0(${ctx})
	add	16(${ctx}),${E}
	mov	${T[0]},4(${ctx})
	mov	${T[0]},${B}			# magic seed
	mov	${C},8(${ctx})
	mov	${C},${T[1]}
	mov	${D},12(${ctx})
	xor	${D},${T[1]}
	mov	${E},16(${ctx})
	and	${T[1]},${T[0]}
	jmp	.Loop_ssse3

.align	16
.Ldone_ssse3:
`;
  j = saved_j;
  V = [...saved_V];

  Xtail_ssse3(body_20_39);
  Xtail_ssse3(body_20_39);
  Xtail_ssse3(body_20_39);

  code += `	add	0(${ctx}),${A}			# update context
	add	4(${ctx}),${T[0]}
	add	8(${ctx}),${C}
	mov	${A},0(${ctx})
	add	12(${ctx}),${D}
	mov	${T[0]},4(${ctx})
	add	16(${ctx}),${E}
	mov	${C},8(${ctx})
	mov	${D},12(${ctx})
	mov	${E},16(${ctx})
	mov	-40(${fp}),%r14
.cfi_restore	%r14
	mov	-32(${fp}),%r13
.cfi_restore	%r13
	mov	-24(${fp}),%r12
.cfi_restore	%r12
	mov	-16(${fp}),%rbp
.cfi_restore	%rbp
	mov	-8(${fp}),%rbx
.cfi_restore	%rbx
	lea	(${fp}),%rsp
.cfi_def_cfa_register	%rsp
.Lepilogue_ssse3:
	ret
.cfi_endproc
.size	sha1_block_data_order_ssse3,.-sha1_block_data_order_ssse3
`;
}

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------
function genData(): void {
  code += `.section .rodata align=64
.align	64
K_XX_XX:
.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999	# K_00_19
.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999	# K_00_19
.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1	# K_20_39
.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1	# K_20_39
.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc	# K_40_59
.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc	# K_40_59
.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6	# K_60_79
.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6	# K_60_79
.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap mask
.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap mask
.byte	0xf,0xe,0xd,0xc,0xb,0xa,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0
.previous
.asciz	"SHA1 block transform for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.align	64
`;
}

// ---------------------------------------------------------------------------
// per-line post processing (mirrors the perl print loop)
// ---------------------------------------------------------------------------
function sha1rnds4Sub(args: string): string {
  const m = args.match(/\$([x0-9a-f]+),\s*%xmm([0-7]),\s*%xmm([0-7])/);
  if (m) {
    const opcodes = [0x0f, 0x3a, 0xcc];
    opcodes.push(0xc0 | (parseInt(m[2]) & 7) | ((parseInt(m[3]) & 7) << 3)); // ModR/M
    const c = m[1];
    opcodes.push(c.startsWith('0') ? parseInt(c, 8) : parseInt(c));
    return '.byte\t' + opcodes.join(',');
  }
  return 'sha1rnds4\t' + args;
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
    let rex = 0;
    if (parseInt(m[2]) >= 8) {
      rex |= 0x04;
    }
    if (parseInt(m[1]) >= 8) {
      rex |= 0x01;
    }
    if (rex) {
      opcodes.unshift(0x40 | rex);
    }
    opcodes.push(opcodelet[instr]);
    opcodes.push(0xc0 | (parseInt(m[1]) & 7) | ((parseInt(m[2]) & 7) << 3)); // ModR/M
    return '.byte\t' + opcodes.join(',');
  }
  return instr + '\t' + args;
}

function postProcess(): void {
  code = code
    .split('\n')
    .map(line => {
      const m = line.match(/\b(sha1rnds4)\s+(.*)/);
      if (m) {
        // keep the leading part of the line before the match (perl s///e)
        return line.slice(0, m.index) + sha1rnds4Sub(m[2]);
      }
      const m2 = line.match(/\b(sha1[^\s]*)\s+(.*)/);
      if (m2) {
        return line.slice(0, m2.index) + sha1op38(m2[1], m2[2]);
      }
      return line;
    })
    .join('\n');
}

genIalu();
genShaext();
genSsse3();
genData();
postProcess();

export default translateAssembly(code);
