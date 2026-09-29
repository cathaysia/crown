/**
 * sha1_multi_block (multi-buffer SHA-1) for x86_64 — SSSE3 4-way.
 *
 * TypeScript port of OpenSSL crypto/sha/asm/sha1-mb-x86_64.pl.
 * Written by Andy Polyakov, @dot-asm.
 * Copyright 2013-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $win64=0 (unix SysV).
 * Only the SSSE3 4-lane body of `sha1_multi_block` is emitted. The
 * shaext / avx / avx2 tiers are deferred — see NOTES.md.
 *
 * C ABI:
 *   void sha1_multi_block(
 *       struct { unsigned int A[8]; B[8]; C[8]; D[8]; E[8]; } *ctx,
 *       struct { void *ptr; int blocks; } inp[8],
 *       int num);   // number of 4-lane groups
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// ---------------------------------------------------------------------------
// perlasm AUTOLOAD thunk (kept for parity with the other ports)
// ---------------------------------------------------------------------------
function isNumericLiteral(arg: string): boolean {
  return /^-?[0-9]+$/.test(arg);
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
// Register assignments (after the Atom-specific `if (1)` swap in the perl)
// ---------------------------------------------------------------------------
const ctx = '%rdi';
const inp = '%rsi';
const num = '%edx';
const ptr = ['%r8', '%r9', '%r10', '%r11'];
const Tbl = '%rbp';

// @Xi = (xmm0..xmm4) for the message-schedule sliding window
// ($tx,$t0,$t1,$t2,$t3) = (xmm5..xmm9) temporaries
// @V  = ($A,$B,$C,$D,$E) = (xmm10..xmm14) the 5 hash-state registers
// $K = xmm15
const XiReg = ['%xmm0', '%xmm1', '%xmm2', '%xmm3', '%xmm4'];
const tx = '%xmm5';
const t0 = '%xmm6';
const t1 = '%xmm7';
const t2 = '%xmm8';
const t3 = '%xmm9';
const K = '%xmm15';
const Vreg = ['%xmm10', '%xmm11', '%xmm12', '%xmm13', '%xmm14'];

const REG_SZ = 16;
const inp_elm_size = 16; // 2 * pointer_size

// Local labels prefixed to avoid clashes with other global_asm! blocks.
const L_body = '.Lsha1mb_body';
const L_loop_grande = '.Lsha1mb_loop_grande';
const L_loop = '.Lsha1mb_loop';
const L_done = '.Lsha1mb_done';
const L_epilogue = '.Lsha1mb_epilogue';

// Data label with a unique prefix.
const K_TBL = 'sha1mb_K_XX_XX';

// ---------------------------------------------------------------------------
// Xi_off: circular-buffer spill slot for X[i mod 16]
// ---------------------------------------------------------------------------
function Xi_off(off: number): string {
  const o = (off % 16) * REG_SZ;
  return o < 256 ? `${o}-128(%rax)` : `${o - 256 - 128}(%rbx)`;
}

// ---------------------------------------------------------------------------
// SHA-1 round-body emitters (4-way SIMD, software-pipelined loads)
// ---------------------------------------------------------------------------
// V rotates RIGHT each round: (A,B,C,D,E) -> (E,A,B,C,D).
// XiArr rotates LEFT each round: [0,1,2,3,4] -> [1,2,3,4,0].

function rotVRight(V: string[]): void {
  const last = V.pop() as string;
  V.unshift(last);
}

function rotXiLeft(X: string[]): void {
  const first = X.shift() as string;
  X.push(first);
}

function emitBody00_19(i: number, V: string[], X: string[]): void {
  const a = V[0], b = V[1], c = V[2], d = V[3], e = V[4];
  const j = i + 1;
  const k = i + 2;

  if (i === 0) {
    code += `	movd		(${ptr[0]}),${X[0]}
	 lea		${16 * 4}(${ptr[0]}),${ptr[0]}
	movd		(${ptr[1]}),${X[2]}	# borrow ${X[2]}
	 lea		${16 * 4}(${ptr[1]}),${ptr[1]}
	movd		(${ptr[2]}),${X[3]}	# borrow ${X[3]}
	 lea		${16 * 4}(${ptr[2]}),${ptr[2]}
	movd		(${ptr[3]}),${X[4]}	# borrow ${X[4]}
	 lea		${16 * 4}(${ptr[3]}),${ptr[3]}
	punpckldq	${X[3]},${X[0]}
	 movd		${4 * j - 16 * 4}(${ptr[0]}),${X[1]}
	punpckldq	${X[4]},${X[2]}
	 movd		${4 * j - 16 * 4}(${ptr[1]}),${t3}
	punpckldq	${X[2]},${X[0]}
	 movd		${4 * j - 16 * 4}(${ptr[2]}),${t2}
	pshufb		${tx},${X[0]}
`;
  }
  if (i < 14) {
    code += `	 movd		${4 * j - 16 * 4}(${ptr[3]}),${t1}
	 punpckldq	${t2},${X[1]}
	movdqa	${a},${t2}
	paddd	${K},${e}				# e+=K_00_19
	 punpckldq	${t1},${t3}
	movdqa	${b},${t1}
	movdqa	${b},${t0}
	pslld	$5,${t2}
	pandn	${d},${t1}
	pand	${c},${t0}
	 punpckldq	${t3},${X[1]}
	movdqa	${a},${t3}

	movdqa	${X[0]},${Xi_off(i)}
	paddd	${X[0]},${e}			# e+=X[i]
	 movd		${4 * k - 16 * 4}(${ptr[0]}),${X[2]}
	psrld	$27,${t3}
	pxor	${t1},${t0}				# Ch(b,c,d)
	movdqa	${b},${t1}

	por	${t3},${t2}				# rol(a,5)
	 movd		${4 * k - 16 * 4}(${ptr[1]}),${t3}
	pslld	$30,${t1}
	paddd	${t0},${e}				# e+=Ch(b,c,d)

	psrld	$2,${b}
	paddd	${t2},${e}				# e+=rol(a,5)
	 pshufb	${tx},${X[1]}
	 movd		${4 * k - 16 * 4}(${ptr[2]}),${t2}
	por	${t1},${b}				# b=rol(b,30)
`;
  }
  if (i === 14) {
    code += `	 movd		${4 * j - 16 * 4}(${ptr[3]}),${t1}
	 punpckldq	${t2},${X[1]}
	movdqa	${a},${t2}
	paddd	${K},${e}				# e+=K_00_19
	 punpckldq	${t1},${t3}
	movdqa	${b},${t1}
	movdqa	${b},${t0}
	pslld	$5,${t2}
	 prefetcht0	63(${ptr[0]})
	pandn	${d},${t1}
	pand	${c},${t0}
	 punpckldq	${t3},${X[1]}
	movdqa	${a},${t3}

	movdqa	${X[0]},${Xi_off(i)}
	paddd	${X[0]},${e}			# e+=X[i]
	psrld	$27,${t3}
	pxor	${t1},${t0}				# Ch(b,c,d)
	movdqa	${b},${t1}
	 prefetcht0	63(${ptr[1]})

	por	${t3},${t2}				# rol(a,5)
	pslld	$30,${t1}
	paddd	${t0},${e}				# e+=Ch(b,c,d)
	 prefetcht0	63(${ptr[2]})

	psrld	$2,${b}
	paddd	${t2},${e}				# e+=rol(a,5)
	 pshufb	${tx},${X[1]}
	 prefetcht0	63(${ptr[3]})
	por	${t1},${b}				# b=rol(b,30)
`;
  }
  if (i >= 13 && i < 15) {
    code += `	movdqa	${Xi_off(j + 2)},${X[3]}		# preload "X[2]"
`;
  }
  if (i >= 15) {
    code += `	pxor	${X[3]},${X[1]}			# "X[13]"
	movdqa	${Xi_off(j + 2)},${X[3]}		# "X[2]"

	movdqa	${a},${t2}
	 pxor	${Xi_off(j + 8)},${X[1]}
	paddd	${K},${e}				# e+=K_00_19
	movdqa	${b},${t1}
	pslld	$5,${t2}
	 pxor	${X[3]},${X[1]}
	movdqa	${b},${t0}
	pandn	${d},${t1}
	 movdqa	${X[1]},${tx}
	pand	${c},${t0}
	movdqa	${a},${t3}
	 psrld	$31,${tx}
	 paddd	${X[1]},${X[1]}

	movdqa	${X[0]},${Xi_off(i)}
	paddd	${X[0]},${e}			# e+=X[i]
	psrld	$27,${t3}
	pxor	${t1},${t0}				# Ch(b,c,d)

	movdqa	${b},${t1}
	por	${t3},${t2}				# rol(a,5)
	pslld	$30,${t1}
	paddd	${t0},${e}				# e+=Ch(b,c,d)

	psrld	$2,${b}
	paddd	${t2},${e}				# e+=rol(a,5)
	 por	${tx},${X[1]}			# rol	$1,${X[1]}
	por	${t1},${b}				# b=rol(b,30)
`;
  }
  rotXiLeft(X);
}

function emitBody20_39(i: number, V: string[], X: string[]): void {
  const a = V[0], b = V[1], c = V[2], d = V[3], e = V[4];
  const j = i + 1;

  if (i < 79) {
    code += `	pxor	${X[3]},${X[1]}			# "X[13]"
	movdqa	${Xi_off(j + 2)},${X[3]}		# "X[2]"

	movdqa	${a},${t2}
	movdqa	${d},${t0}
	 pxor	${Xi_off(j + 8)},${X[1]}
	paddd	${K},${e}				# e+=K_20_39
	pslld	$5,${t2}
	pxor	${b},${t0}

	movdqa	${a},${t3}
`;
  }
  if (i < 72) {
    code += `	movdqa	${X[0]},${Xi_off(i)}
`;
  }
  if (i < 79) {
    code += `	paddd	${X[0]},${e}			# e+=X[i]
	 pxor	${X[3]},${X[1]}
	psrld	$27,${t3}
	pxor	${c},${t0}				# Parity(b,c,d)
	movdqa	${b},${t1}

	pslld	$30,${t1}
	 movdqa	${X[1]},${tx}
	por	${t3},${t2}				# rol(a,5)
	 psrld	$31,${tx}
	paddd	${t0},${e}				# e+=Parity(b,c,d)
	 paddd	${X[1]},${X[1]}

	psrld	$2,${b}
	paddd	${t2},${e}				# e+=rol(a,5)
	 por	${tx},${X[1]}			# rol(${X[1]},1)
	por	${t1},${b}				# b=rol(b,30)
`;
  }
  if (i === 79) {
    code += `	movdqa	${a},${t2}
	paddd	${K},${e}				# e+=K_20_39
	movdqa	${d},${t0}
	pslld	$5,${t2}
	pxor	${b},${t0}

	movdqa	${a},${t3}
	paddd	${X[0]},${e}			# e+=X[i]
	psrld	$27,${t3}
	movdqa	${b},${t1}
	pxor	${c},${t0}				# Parity(b,c,d)

	pslld	$30,${t1}
	por	${t3},${t2}				# rol(a,5)
	paddd	${t0},${e}				# e+=Parity(b,c,d)

	psrld	$2,${b}
	paddd	${t2},${e}				# e+=rol(a,5)
	por	${t1},${b}				# b=rol(b,30)
`;
  }
  rotXiLeft(X);
}

function emitBody40_59(i: number, V: string[], X: string[]): void {
  const a = V[0], b = V[1], c = V[2], d = V[3], e = V[4];
  const j = i + 1;

  code += `	pxor	${X[3]},${X[1]}			# "X[13]"
	movdqa	${Xi_off(j + 2)},${X[3]}		# "X[2]"

	movdqa	${a},${t2}
	movdqa	${d},${t1}
	 pxor	${Xi_off(j + 8)},${X[1]}
	pxor	${X[3]},${X[1]}
	paddd	${K},${e}				# e+=K_40_59
	pslld	$5,${t2}
	movdqa	${a},${t3}
	pand	${c},${t1}

	movdqa	${d},${t0}
	 movdqa	${X[1]},${tx}
	psrld	$27,${t3}
	paddd	${t1},${e}
	pxor	${c},${t0}

	movdqa	${X[0]},${Xi_off(i)}
	paddd	${X[0]},${e}			# e+=X[i]
	por	${t3},${t2}				# rol(a,5)
	 psrld	$31,${tx}
	pand	${b},${t0}
	movdqa	${b},${t1}

	pslld	$30,${t1}
	 paddd	${X[1]},${X[1]}
	paddd	${t0},${e}				# e+=Maj(b,d,c)

	psrld	$2,${b}
	paddd	${t2},${e}				# e+=rol(a,5)
	 por	${tx},${X[1]}			# rol(@X[1],1)
	por	${t1},${b}				# b=rol(b,30)
`;
  rotXiLeft(X);
}

// ---------------------------------------------------------------------------
// SSSE3 body of sha1_multi_block
// ---------------------------------------------------------------------------
function genSsse3(): void {
  code += `.text

.globl	sha1_multi_block
.type	sha1_multi_block,@function,3
.align	32
sha1_multi_block:
.cfi_startproc
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbx
	sub	$${REG_SZ * 18},%rsp
	and	$-256,%rsp
	mov	%rax,${REG_SZ * 17}(%rsp)		# original %rsp
.cfi_cfa_expression	%rsp+${REG_SZ * 17},deref,+8
${L_body}:
	lea	${K_TBL}(%rip),${Tbl}
	lea	${REG_SZ * 16}(%rsp),%rbx

${L_loop_grande}:
	mov	${num},${REG_SZ * 17 + 8}(%rsp)	# original ${num}
	xor	${num},${num}
`;
  for (let i = 0; i < 4; i++) {
    code += `	# input pointer
	mov	${inp_elm_size * i + 0}(${inp}),${ptr[i]}
	# number of blocks
	mov	${inp_elm_size * i + 8}(${inp}),%ecx
	cmp	${num},%ecx
	cmovg	%ecx,${num}			# find maximum
	test	%ecx,%ecx
	mov	%ecx,${4 * i}(%rbx)		# initialize counters
	cmovle	${Tbl},${ptr[i]}			# cancel input
`;
  }
  code += `	test	${num},${num}
	jz	${L_done}

	movdqu	0x00(${ctx}),${Vreg[0]}			# load context
	 lea	128(%rsp),%rax
	movdqu	0x20(${ctx}),${Vreg[1]}
	movdqu	0x40(${ctx}),${Vreg[2]}
	movdqu	0x60(${ctx}),${Vreg[3]}
	movdqu	0x80(${ctx}),${Vreg[4]}
	movdqa	0x60(${Tbl}),${tx}			# pbswap_mask
	movdqa	-0x20(${Tbl}),${K}			# K_00_19
	jmp	${L_loop}

.align	32
${L_loop}:
`;

  // The 80-round unrolled body.  The state lives in V (xmm10-14) and
  // the message-schedule window in X (xmm0-4); both arrays rotate each
  // round and return to their initial ordering after 80 iterations.
  const V = [...Vreg];
  const X = [...XiReg];

  let i = 0;
  for (; i < 20; i++) {
    emitBody00_19(i, V, X);
    rotVRight(V);
  }
  code += `	movdqa	0x00(${Tbl}),${K}\n`;
  for (; i < 40; i++) {
    emitBody20_39(i, V, X);
    rotVRight(V);
  }
  code += `	movdqa	0x20(${Tbl}),${K}\n`;
  for (; i < 60; i++) {
    emitBody40_59(i, V, X);
    rotVRight(V);
  }
  code += `	movdqa	0x40(${Tbl}),${K}\n`;
  for (; i < 80; i++) {
    emitBody20_39(i, V, X);
    rotVRight(V);
  }

  // After 80 rounds V is back to (xmm10..xmm14) and X to (xmm0..xmm4).
  // Counters/mask live in X[0]/X[1]; the hash state is in V[0..4].
  code += `	movdqa	(%rbx),${X[0]}			# pull counters
	mov	$1,%ecx
	cmp	4*0(%rbx),%ecx			# examine counters
	pxor	${t2},${t2}
	cmovge	${Tbl},${ptr[0]}			# cancel input
	cmp	4*1(%rbx),%ecx
	movdqa	${X[0]},${X[1]}
	cmovge	${Tbl},${ptr[1]}
	cmp	4*2(%rbx),%ecx
	pcmpgtd	${t2},${X[1]}			# mask value
	cmovge	${Tbl},${ptr[2]}
	cmp	4*3(%rbx),%ecx
	paddd	${X[1]},${X[0]}			# counters--
	cmovge	${Tbl},${ptr[3]}

	movdqu	0x00(${ctx}),${t0}
	pand	${X[1]},${V[0]}
	movdqu	0x20(${ctx}),${t1}
	pand	${X[1]},${V[1]}
	paddd	${t0},${V[0]}
	movdqu	0x40(${ctx}),${t2}
	pand	${X[1]},${V[2]}
	paddd	${t1},${V[1]}
	movdqu	0x60(${ctx}),${t3}
	pand	${X[1]},${V[3]}
	paddd	${t2},${V[2]}
	movdqu	0x80(${ctx}),${tx}
	pand	${X[1]},${V[4]}
	movdqu	${V[0]},0x00(${ctx})
	paddd	${t3},${V[3]}
	movdqu	${V[1]},0x20(${ctx})
	paddd	${tx},${V[4]}
	movdqu	${V[2]},0x40(${ctx})
	movdqu	${V[3]},0x60(${ctx})
	movdqu	${V[4]},0x80(${ctx})

	movdqa	${X[0]},(%rbx)			# save counters
	movdqa	0x60(${Tbl}),${tx}			# pbswap_mask
	movdqa	-0x20(${Tbl}),${K}			# K_00_19
	dec	${num}
	jnz	${L_loop}

	mov	${REG_SZ * 17 + 8}(%rsp),${num}
	lea	${REG_SZ}(${ctx}),${ctx}
	lea	${inp_elm_size * (REG_SZ / 4)}(${inp}),${inp}
	dec	${num}
	jnz	${L_loop_grande}

${L_done}:
	mov	${REG_SZ * 17}(%rsp),%rax		# original %rsp
.cfi_def_cfa	%rax,8
	mov	-16(%rax),%rbp
.cfi_restore	%rbp
	mov	-8(%rax),%rbx
.cfi_restore	%rbx
	lea	(%rax),%rsp
.cfi_def_cfa_register	%rsp
${L_epilogue}:
	ret
.cfi_endproc
.size	sha1_multi_block,.-sha1_multi_block
`;
}

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------
function genData(): void {
  code += `.section .rodata align=256
.align	256
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999	# K_00_19
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999	# K_00_19
${K_TBL}:
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1	# K_20_39
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1	# K_20_39
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc	# K_40_59
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc	# K_40_59
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6	# K_60_79
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6	# K_60_79
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap
	.byte	0xf,0xe,0xd,0xc,0xb,0xa,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0
	.asciz	"SHA1 multi-block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
.previous
`;
}

genSsse3();
genData();

export default translateAssembly(code);
