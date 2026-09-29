/**
 * sha256_multi_block (multi-buffer SHA-256) for x86_64 — SSSE3 4-way.
 *
 * TypeScript port of OpenSSL crypto/sha/asm/sha256-mb-x86_64.pl.
 * Written by Andy Polyakov, @dot-asm.
 * Copyright 2013-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Only the SSSE3 4-lane body of `sha256_multi_block` is emitted.
 * The shaext / avx / avx2 tiers are deferred — see NOTES.md.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

function isNumericLiteral(arg: string): boolean {
  return /^-?[0-9]+$/.test(arg);
}

function AUTOLOAD(opcode: string, ...args: string[]): void {
  let arg = args.pop() as string;
  if (isNumericLiteral(arg)) arg = '$' + arg;
  const rest = [...args].reverse();
  code += `\t${opcode}\t${[arg, ...rest].join(',')}\n`;
}

// ---------------------------------------------------------------------------
// Registers (after the perl assignments)
// ---------------------------------------------------------------------------
const ctx = '%rdi';
const inp = '%rsi';
const num = '%edx';
const ptr = ['%r8', '%r9', '%r10', '%r11'];
const Tbl = '%rbp';

// @V = ($A..$H) = xmm8..xmm15
const Vreg = [
  '%xmm8',
  '%xmm9',
  '%xmm10',
  '%xmm11',
  '%xmm12',
  '%xmm13',
  '%xmm14',
  '%xmm15',
];
// ($t1,$t2,$t3,$axb,$bxc,$Xi,$Xn,$sigma) = xmm0..xmm7
const t1 = '%xmm0';
const t2 = '%xmm1';
const t3 = '%xmm2';
let axb = '%xmm3';
let bxc = '%xmm4';
let Xi = '%xmm5';
let Xn = '%xmm6';
const sigma = '%xmm7';

const REG_SZ = 16;
const inp_elm_size = 16;

const L_body = '.Lsha256mb_body';
const L_loop_grande = '.Lsha256mb_loop_grande';
const L_loop = '.Lsha256mb_loop';
const L_loop_16_xx = '.Lsha256mb_loop_16_xx';
const L_done = '.Lsha256mb_done';
const L_epilogue = '.Lsha256mb_epilogue';
const K_TBL = 'sha256mb_K256';
const L_pbswap = '.Lsha256mb_pbswap';

function Xi_off(off: number): string {
  const o = (off % 16) * REG_SZ;
  return o < 256 ? `${o}-128(%rax)` : `${o - 256 - 128}(%rbx)`;
}

function rotVRight(V: string[]): void {
  const last = V.pop() as string;
  V.unshift(last);
}

function swapAxgBxc(): void {
  [axb, bxc] = [bxc, axb];
}

function swapXiXn(): void {
  [Xi, Xn] = [Xn, Xi];
}

// ---------------------------------------------------------------------------
// ROUND_00_15
// ---------------------------------------------------------------------------
function emitRound00_15(i: number, V: string[]): void {
  const a = V[0],
    b = V[1],
    c = V[2],
    d = V[3],
    e = V[4],
    f = V[5],
    g = V[6],
    h = V[7];

  // Load input words (i<15: plain; i==15: also advance pointers)
  if (i < 15) {
    code += `	movd		${4 * i}(${ptr[0]}),${Xi}
	movd		${4 * i}(${ptr[1]}),${t1}
	movd		${4 * i}(${ptr[2]}),${t2}
	movd		${4 * i}(${ptr[3]}),${t3}
	punpckldq	${t2},${Xi}
	punpckldq	${t3},${t1}
	punpckldq	${t1},${Xi}
`;
  }
  if (i === 15) {
    code += `	movd		${4 * i}(${ptr[0]}),${Xi}
	 lea		${16 * 4}(${ptr[0]}),${ptr[0]}
	movd		${4 * i}(${ptr[1]}),${t1}
	 lea		${16 * 4}(${ptr[1]}),${ptr[1]}
	movd		${4 * i}(${ptr[2]}),${t2}
	 lea		${16 * 4}(${ptr[2]}),${ptr[2]}
	movd		${4 * i}(${ptr[3]}),${t3}
	 lea		${16 * 4}(${ptr[3]}),${ptr[3]}
	punpckldq	${t2},${Xi}
	punpckldq	${t3},${t1}
	punpckldq	${t1},${Xi}
`;
  }

  // Sigma1(e) + Ch(e,f,g) + Maj + schedule
  // The pshufb is emitted conditionally: even i after sigma=e, odd i after t3=e.
  const pshufbEven = i <= 15 && (i & 1) === 0;
  const pshufbOdd = i <= 15 && (i & 1) === 1;

  code += `	movdqa	${e},${sigma}
`;
  if (pshufbEven) {
    code += `	pshufb	${Xn},${Xi}
`;
  } else {
    code += `\t
`;
  }
  code += `	movdqa	${e},${t3}
`;
  if (pshufbOdd) {
    code += `	pshufb	${Xn},${Xi}
`;
  } else {
    code += `\t
`;
  }
  code += `	psrld	$6,${sigma}
	movdqa	${e},${t2}
	pslld	$7,${t3}
	movdqa	${Xi},${Xi_off(i)}
	 paddd	${h},${Xi}				# Xi+=h

	psrld	$11,${t2}
	pxor	${t3},${sigma}
	pslld	$21-7,${t3}
	 paddd	${32 * (i % 8) - 128}(${Tbl}),${Xi}	# Xi+=K[round]
	pxor	${t2},${sigma}

	psrld	$25-11,${t2}
	 movdqa	${e},${t1}
`;
  // prefetcht0 lines (i==15 only)
  if (i === 15) {
    code += `	 prefetcht0	63(${ptr[0]})
`;
  } else {
    code += `\t
`;
  }
  code += `	pxor	${t3},${sigma}
	 movdqa	${e},${axb}				# borrow ${axb}
	pslld	$26-21,${t3}
	 pandn	${g},${t1}
	 pand	${f},${axb}
	pxor	${t2},${sigma}

`;
  if (i === 15) {
    code += `	 prefetcht0	63(${ptr[1]})
`;
  } else {
    code += `\t
`;
  }
  code += `	movdqa	${a},${t2}
	pxor	${t3},${sigma}			# Sigma1(e)
	movdqa	${a},${t3}
	psrld	$2,${t2}
	paddd	${sigma},${Xi}			# Xi+=Sigma1(e)
	 pxor	${axb},${t1}			# Ch(e,f,g)
	 movdqa	${b},${axb}
	movdqa	${a},${sigma}
	pslld	$10,${t3}
	 pxor	${a},${axb}				# a^b, b^c in next round

`;
  if (i === 15) {
    code += `	 prefetcht0	63(${ptr[2]})
`;
  } else {
    code += `\t
`;
  }
  code += `	psrld	$13,${sigma}
	pxor	${t3},${t2}
	 paddd	${t1},${Xi}				# Xi+=Ch(e,f,g)
	pslld	$19-10,${t3}
	 pand	${axb},${bxc}
	pxor	${sigma},${t2}

`;
  if (i === 15) {
    code += `	 prefetcht0	63(${ptr[3]})
`;
  } else {
    code += `\t
`;
  }
  code += `	psrld	$22-13,${sigma}
	pxor	${t3},${t2}
	 movdqa	${b},${h}
	pslld	$30-19,${t3}
	pxor	${t2},${sigma}
	 pxor	${bxc},${h}				# h=Maj(a,b,c)=Ch(a^b,c,b)
	 paddd	${Xi},${d}				# d+=Xi
	pxor	${t3},${sigma}			# Sigma0(a)

	paddd	${Xi},${h}				# h+=Xi
	paddd	${sigma},${h}			# h+=Sigma0(a)
`;
  // Advance Tbl every 8 rounds
  if (i % 8 === 7) {
    code += `	lea	${32 * 8}(${Tbl}),${Tbl}
`;
  }
  swapAxgBxc();
}

// ---------------------------------------------------------------------------
// ROUND_16_XX — message schedule expansion + ROUND_00_15
// ---------------------------------------------------------------------------
function emitRound16_XX(i: number, V: string[]): void {
  code += `	movdqa	${Xi_off(i + 1)},${Xn}
	paddd	${Xi_off(i + 9)},${Xi}		# Xi+=X[i+9]

	movdqa	${Xn},${sigma}
	movdqa	${Xn},${t2}
	psrld	$3,${sigma}
	movdqa	${Xn},${t3}

	psrld	$7,${t2}
	movdqa	${Xi_off(i + 14)},${t1}
	pslld	$14,${t3}
	pxor	${t2},${sigma}
	psrld	$18-7,${t2}
	movdqa	${t1},${axb}			# borrow ${axb}
	pxor	${t3},${sigma}
	pslld	$25-14,${t3}
	pxor	${t2},${sigma}
	psrld	$10,${t1}
	movdqa	${axb},${t2}

	psrld	$17,${axb}
	pxor	${t3},${sigma}			# sigma0(X[i+1])
	pslld	$13,${t2}
	 paddd	${sigma},${Xi}			# Xi+=sigma0(e)
	pxor	${axb},${t1}
	psrld	$19-17,${axb}
	pxor	${t2},${t1}
	pslld	$15-13,${t2}
	pxor	${axb},${t1}
	pxor	${t2},${t1}				# sigma0(X[i+14])
	paddd	${t1},${Xi}				# Xi+=sigma1(X[i+14])
`;
  emitRound00_15(i, V);
  swapXiXn();
}

// ---------------------------------------------------------------------------
// SSSE3 body
// ---------------------------------------------------------------------------
function genSsse3(): void {
  code += `.text

.globl	sha256_multi_block
.type	sha256_multi_block,@function,3
.align	32
sha256_multi_block:
.cfi_startproc
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	sub	$${REG_SZ * 18}, %rsp
	and	$-256,%rsp
	mov	%rax,${REG_SZ * 17}(%rsp)		# original %rsp
.cfi_cfa_expression	%rsp+${REG_SZ * 17},deref,+8
${L_body}:
	lea	${K_TBL}+128(%rip),${Tbl}
	lea	${REG_SZ * 16}(%rsp),%rbx
	lea	0x80(${ctx}),${ctx}			# size optimization

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

	movdqu	0x00-0x80(${ctx}),${Vreg[0]}		# load context
	 lea	128(%rsp),%rax
	movdqu	0x20-0x80(${ctx}),${Vreg[1]}
	movdqu	0x40-0x80(${ctx}),${Vreg[2]}
	movdqu	0x60-0x80(${ctx}),${Vreg[3]}
	movdqu	0x80-0x80(${ctx}),${Vreg[4]}
	movdqu	0xa0-0x80(${ctx}),${Vreg[5]}
	movdqu	0xc0-0x80(${ctx}),${Vreg[6]}
	movdqu	0xe0-0x80(${ctx}),${Vreg[7]}
	movdqu	${L_pbswap}(%rip),${Xn}
	jmp	${L_loop}

.align	32
${L_loop}:
	movdqa	${Vreg[2]},${bxc}
	pxor	${Vreg[1]},${bxc}				# magic seed
`;

  // 64 rounds
  const V = [...Vreg];
  let i = 0;
  for (; i < 16; i++) {
    emitRound00_15(i, V);
    rotVRight(V);
  }
  code += `	movdqu	${Xi_off(i)},${Xi}
	mov	$3,%ecx
	jmp	${L_loop_16_xx}
.align	32
${L_loop_16_xx}:
`;
  for (; i < 32; i++) {
    emitRound16_XX(i, V);
    rotVRight(V);
  }
  code += `	dec	%ecx
	jnz	${L_loop_16_xx}

	mov	$1,%ecx
	lea	${K_TBL}+128(%rip),${Tbl}

	movdqa	(%rbx),${sigma}			# pull counters
	cmp	4*0(%rbx),%ecx			# examine counters
	pxor	${t1},${t1}
	cmovge	${Tbl},${ptr[0]}			# cancel input
	cmp	4*1(%rbx),%ecx
	movdqa	${sigma},${Xn}
	cmovge	${Tbl},${ptr[1]}
	cmp	4*2(%rbx),%ecx
	pcmpgtd	${t1},${Xn}				# mask value
	cmovge	${Tbl},${ptr[2]}
	cmp	4*3(%rbx),%ecx
	paddd	${Xn},${sigma}			# counters--
	cmovge	${Tbl},${ptr[3]}

	movdqu	0x00-0x80(${ctx}),${t1}
	pand	${Xn},${V[0]}
	movdqu	0x20-0x80(${ctx}),${t2}
	pand	${Xn},${V[1]}
	movdqu	0x40-0x80(${ctx}),${t3}
	pand	${Xn},${V[2]}
	movdqu	0x60-0x80(${ctx}),${Xi}
	pand	${Xn},${V[3]}
	paddd	${t1},${V[0]}
	movdqu	0x80-0x80(${ctx}),${t1}
	pand	${Xn},${V[4]}
	paddd	${t2},${V[1]}
	movdqu	0xa0-0x80(${ctx}),${t2}
	pand	${Xn},${V[5]}
	paddd	${t3},${V[2]}
	movdqu	0xc0-0x80(${ctx}),${t3}
	pand	${Xn},${V[6]}
	paddd	${Xi},${V[3]}
	movdqu	0xe0-0x80(${ctx}),${Xi}
	pand	${Xn},${V[7]}
	paddd	${t1},${V[4]}
	paddd	${t2},${V[5]}
	movdqu	${V[0]},0x00-0x80(${ctx})
	paddd	${t3},${V[6]}
	movdqu	${V[1]},0x20-0x80(${ctx})
	paddd	${Xi},${V[7]}
	movdqu	${V[2]},0x40-0x80(${ctx})
	movdqu	${V[3]},0x60-0x80(${ctx})
	movdqu	${V[4]},0x80-0x80(${ctx})
	movdqu	${V[5]},0xa0-0x80(${ctx})
	movdqu	${V[6]},0xc0-0x80(${ctx})
	movdqu	${V[7]},0xe0-0x80(${ctx})

	movdqa	${sigma},(%rbx)			# save counters
	movdqa	${L_pbswap}(%rip),${Xn}
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
.size	sha256_multi_block,.-sha256_multi_block
`;
}

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------
// SHA-256 K constants (FIPS 180-4), each broadcast 8× for the SIMD layout.
const K256_CONSTANTS = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function genData(): void {
  code += `.section .rodata align=256
.align	256
${K_TBL}:
`;
  for (const k of K256_CONSTANTS) {
    code += `	.long	${k},${k},${k},${k}
	.long	${k},${k},${k},${k}
`;
  }
  code += `${L_pbswap}:
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f	# pbswap
${K_TBL}_shaext:
`;
  for (let i = 0; i < K256_CONSTANTS.length; i += 4) {
    const row = K256_CONSTANTS.slice(i, i + 4)
      .map(k => '0x' + k.toString(16).padStart(8, '0'))
      .join(',');
    code += `	.long	${row}
`;
  }
  code += `	.asciz	"SHA256 multi-block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
.previous
`;
}

genSsse3();
genData();

export default translateAssembly(code);
