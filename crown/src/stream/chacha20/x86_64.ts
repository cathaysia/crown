/**
 * ChaCha20 for x86_64.
 *
 * TypeScript port of OpenSSL crypto/chacha/asm/chacha-x86_64.pl.
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $avx=0 (emits the ialu, ssse3,
 * 128 and 4x code paths).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// input parameter block
const out = '%rdi';
const inp = '%rsi';
const len = '%rdx';
const key = '%rcx';
const counter = '%r8';

// perl AUTOLOAD thunk
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

// perl backtick evaluation pass over the final code
function evaluateBackticks(): void {
  code = code.replace(/`([^`]*)`/g, (_, expr) => String(eval(expr)));
}

code += `.text

.extern OPENSSL_ia32cap_P

.section .rodata align=64
.align	64
.Lzero:
.long	0,0,0,0
.Lone:
.long	1,0,0,0
.Linc:
.long	0,1,2,3
.Lfour:
.long	4,4,4,4
.Lincy:
.long	0,2,4,6,1,3,5,7
.Leight:
.long	8,8,8,8,8,8,8,8
.Lrot16:
.byte	0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd
.Lrot24:
.byte	0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe
.Ltwoy:
.long	2,0,0,0, 2,0,0,0
.align	64
.Lzeroz:
.long	0,0,0,0, 1,0,0,0, 2,0,0,0, 3,0,0,0
.Lfourz:
.long	4,0,0,0, 4,0,0,0, 4,0,0,0, 4,0,0,0
.Lincz:
.long	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
.Lsixteen:
.long	16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16
.Lsigma:
.asciz	"expand 32-byte k"
.asciz	"ChaCha20 for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.previous
`;

// ---------------------------------------------------------------------------
// ialu round: critical path is 24 cycles per round
// ---------------------------------------------------------------------------
const x = [
  '%eax', '%ebx', '%ecx', '%edx', '%r8d', '%r9d', '%r10d', '%r11d',
  'nox', 'nox', 'nox', 'nox', '%r12d', '%r13d', '%r14d', '%r15d',
];
const t = ['%esi', '%edi'];

function ROUND(a0: number, b0: number, c0: number, d0: number): void {
  const lane = (v: number) => (v & ~3) + ((v + 1) & 3);
  const a1 = lane(a0), b1 = lane(b0), c1 = lane(c0), d1 = lane(d0);
  const a2 = lane(a1), b2 = lane(b1), c2 = lane(c1), d2 = lane(d1);
  const a3 = lane(a2), b3 = lane(b2), c3 = lane(c2), d3 = lane(d2);
  const xc = t[0];
  const xc_ = t[1];

  AUTOLOAD('add', x[a0], x[b0]); // Q1
  AUTOLOAD('xor', x[d0], x[a0]);
  AUTOLOAD('rol', x[d0], '16');
  AUTOLOAD('add', x[a1], x[b1]); // Q2
  AUTOLOAD('xor', x[d1], x[a1]);
  AUTOLOAD('rol', x[d1], '16');

  AUTOLOAD('add', xc, x[d0]);
  AUTOLOAD('xor', x[b0], xc);
  AUTOLOAD('rol', x[b0], '12');
  AUTOLOAD('add', xc_, x[d1]);
  AUTOLOAD('xor', x[b1], xc_);
  AUTOLOAD('rol', x[b1], '12');

  AUTOLOAD('add', x[a0], x[b0]);
  AUTOLOAD('xor', x[d0], x[a0]);
  AUTOLOAD('rol', x[d0], '8');
  AUTOLOAD('add', x[a1], x[b1]);
  AUTOLOAD('xor', x[d1], x[a1]);
  AUTOLOAD('rol', x[d1], '8');

  AUTOLOAD('add', xc, x[d0]);
  AUTOLOAD('xor', x[b0], xc);
  AUTOLOAD('rol', x[b0], '7');
  AUTOLOAD('add', xc_, x[d1]);
  AUTOLOAD('xor', x[b1], xc_);
  AUTOLOAD('rol', x[b1], '7');

  AUTOLOAD('mov', `4*${c0}(%rsp)`, xc); // reload pair of 'c's
  AUTOLOAD('mov', `4*${c1}(%rsp)`, xc_);
  AUTOLOAD('mov', xc, `4*${c2}(%rsp)`);
  AUTOLOAD('mov', xc_, `4*${c3}(%rsp)`);

  AUTOLOAD('add', x[a2], x[b2]); // Q3
  AUTOLOAD('xor', x[d2], x[a2]);
  AUTOLOAD('rol', x[d2], '16');
  AUTOLOAD('add', x[a3], x[b3]); // Q4
  AUTOLOAD('xor', x[d3], x[a3]);
  AUTOLOAD('rol', x[d3], '16');

  AUTOLOAD('add', xc, x[d2]);
  AUTOLOAD('xor', x[b2], xc);
  AUTOLOAD('rol', x[b2], '12');
  AUTOLOAD('add', xc_, x[d3]);
  AUTOLOAD('xor', x[b3], xc_);
  AUTOLOAD('rol', x[b3], '12');

  AUTOLOAD('add', x[a2], x[b2]);
  AUTOLOAD('xor', x[d2], x[a2]);
  AUTOLOAD('rol', x[d2], '8');
  AUTOLOAD('add', x[a3], x[b3]);
  AUTOLOAD('xor', x[d3], x[a3]);
  AUTOLOAD('rol', x[d3], '8');

  AUTOLOAD('add', xc, x[d2]);
  AUTOLOAD('xor', x[b2], xc);
  AUTOLOAD('rol', x[b2], '7');
  AUTOLOAD('add', xc_, x[d3]);
  AUTOLOAD('xor', x[b3], xc_);
  AUTOLOAD('rol', x[b3], '7');
}

function genCtr32(): void {
  code += `.globl	ChaCha20_ctr32
.type	ChaCha20_ctr32,@function,5
.align	64
ChaCha20_ctr32:
.cfi_startproc
	cmp	$0,${len}
	je	.Lno_data
	mov	OPENSSL_ia32cap_P+4(%rip),%r10
	test	$${1 << (41 - 32)},%r10d
	jnz	.LChaCha20_ssse3

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
	sub	$64+24,%rsp
.cfi_adjust_cfa_offset	64+24
.Lctr32_body:

	#movdqa	.Lsigma(%rip),%xmm0
	movdqu	(${key}),%xmm1
	movdqu	16(${key}),%xmm2
	movdqu	(${counter}),%xmm3
	movdqa	.Lone(%rip),%xmm4

	#movdqa	%xmm0,4*0(%rsp)		# key[0]
	movdqa	%xmm1,4*4(%rsp)		# key[1]
	movdqa	%xmm2,4*8(%rsp)		# key[2]
	movdqa	%xmm3,4*12(%rsp)	# key[3]
	mov	${len},%rbp		# reassign ${len}
	jmp	.Loop_outer

.align	32
.Loop_outer:
	mov	$0x61707865,${x[0]}      # 'expa'
	mov	$0x3320646e,${x[1]}      # 'nd 3'
	mov	$0x79622d32,${x[2]}      # '2-by'
	mov	$0x6b206574,${x[3]}      # 'te k'
	mov	4*4(%rsp),${x[4]}
	mov	4*5(%rsp),${x[5]}
	mov	4*6(%rsp),${x[6]}
	mov	4*7(%rsp),${x[7]}
	movd	%xmm3,${x[12]}
	mov	4*13(%rsp),${x[13]}
	mov	4*14(%rsp),${x[14]}
	mov	4*15(%rsp),${x[15]}

	mov	%rbp,64+0(%rsp)		# save len
	mov	$10,%ebp
	mov	${inp},64+8(%rsp)		# save inp
	movq	%xmm2,%rsi		# "@x[8]"
	mov	${out},64+16(%rsp)	# save out
	mov	%rsi,%rdi
	shr	$32,%rdi		# "@x[9]"
	jmp	.Loop

.align	32
.Loop:
`;
  ROUND(0, 4, 8, 12);
  ROUND(0, 5, 10, 15);
  AUTOLOAD('dec', '%ebp');
  AUTOLOAD('jnz', '.Loop');

  code += `	mov	${t[1]},4*9(%rsp)		# modulo-scheduled
	mov	${t[0]},4*8(%rsp)
	mov	64(%rsp),%rbp		# load len
	movdqa	%xmm2,%xmm1
	mov	64+8(%rsp),${inp}		# load inp
	paddd	%xmm4,%xmm3		# increment counter
	mov	64+16(%rsp),${out}	# load out

	add	$0x61707865,${x[0]}      # 'expa'
	add	$0x3320646e,${x[1]}      # 'nd 3'
	add	$0x79622d32,${x[2]}      # '2-by'
	add	$0x6b206574,${x[3]}      # 'te k'
	add	4*4(%rsp),${x[4]}
	add	4*5(%rsp),${x[5]}
	add	4*6(%rsp),${x[6]}
	add	4*7(%rsp),${x[7]}
	add	4*12(%rsp),${x[12]}
	add	4*13(%rsp),${x[13]}
	add	4*14(%rsp),${x[14]}
	add	4*15(%rsp),${x[15]}
	paddd	4*8(%rsp),%xmm1

	cmp	$64,%rbp
	jb	.Ltail

	xor	4*0(${inp}),${x[0]}		# xor with input
	xor	4*1(${inp}),${x[1]}
	xor	4*2(${inp}),${x[2]}
	xor	4*3(${inp}),${x[3]}
	xor	4*4(${inp}),${x[4]}
	xor	4*5(${inp}),${x[5]}
	xor	4*6(${inp}),${x[6]}
	xor	4*7(${inp}),${x[7]}
	movdqu	4*8(${inp}),%xmm0
	xor	4*12(${inp}),${x[12]}
	xor	4*13(${inp}),${x[13]}
	xor	4*14(${inp}),${x[14]}
	xor	4*15(${inp}),${x[15]}
	lea	4*16(${inp}),${inp}		# inp+=64
	pxor	%xmm1,%xmm0

	movdqa	%xmm2,4*8(%rsp)
	movd	%xmm3,4*12(%rsp)

	mov	${x[0]},4*0(${out})		# write output
	mov	${x[1]},4*1(${out})
	mov	${x[2]},4*2(${out})
	mov	${x[3]},4*3(${out})
	mov	${x[4]},4*4(${out})
	mov	${x[5]},4*5(${out})
	mov	${x[6]},4*6(${out})
	mov	${x[7]},4*7(${out})
	movdqu	%xmm0,4*8(${out})
	mov	${x[12]},4*12(${out})
	mov	${x[13]},4*13(${out})
	mov	${x[14]},4*14(${out})
	mov	${x[15]},4*15(${out})
	lea	4*16(${out}),${out}		# out+=64

	sub	$64,%rbp
	jnz	.Loop_outer

	jmp	.Ldone

.align	16
.Ltail:
	mov	${x[0]},4*0(%rsp)
	mov	${x[1]},4*1(%rsp)
	xor	%rbx,%rbx
	mov	${x[2]},4*2(%rsp)
	mov	${x[3]},4*3(%rsp)
	mov	${x[4]},4*4(%rsp)
	mov	${x[5]},4*5(%rsp)
	mov	${x[6]},4*6(%rsp)
	mov	${x[7]},4*7(%rsp)
	movdqa	%xmm1,4*8(%rsp)
	mov	${x[12]},4*12(%rsp)
	mov	${x[13]},4*13(%rsp)
	mov	${x[14]},4*14(%rsp)
	mov	${x[15]},4*15(%rsp)

.Loop_tail:
	movzb	(${inp},%rbx),%eax
	movzb	(%rsp,%rbx),%edx
	lea	1(%rbx),%rbx
	xor	%edx,%eax
	mov	%al,-1(${out},%rbx)
	dec	%rbp
	jnz	.Loop_tail

.Ldone:
	lea	64+24+48(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	mov	-48(%rsi),%r15
.cfi_restore	%r15
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
.Lno_data:
	ret
.cfi_endproc
.size	ChaCha20_ctr32,.-ChaCha20_ctr32
`;
}

// ---------------------------------------------------------------------------
// SSSE3 code path that handles shorter lengths
// ---------------------------------------------------------------------------
function SSSE3ROUND(
  a: string, b: string, c: string, d: string,
  t0: string, t1: string, rot16: string, rot24: string,
): void {
  AUTOLOAD('paddd', a, b);
  AUTOLOAD('pxor', d, a);
  AUTOLOAD('pshufb', d, rot16);

  AUTOLOAD('paddd', c, d);
  AUTOLOAD('pxor', b, c);
  AUTOLOAD('movdqa', t0, b);
  AUTOLOAD('psrld', b, '20');
  AUTOLOAD('pslld', t0, '12');
  AUTOLOAD('por', b, t0);

  AUTOLOAD('paddd', a, b);
  AUTOLOAD('pxor', d, a);
  AUTOLOAD('pshufb', d, rot24);

  AUTOLOAD('paddd', c, d);
  AUTOLOAD('pxor', b, c);
  AUTOLOAD('movdqa', t0, b);
  AUTOLOAD('psrld', b, '25');
  AUTOLOAD('pslld', t0, '7');
  AUTOLOAD('por', b, t0);
}

function genSsse3(): void {
  const a = '%xmm0', b = '%xmm1', c = '%xmm2', d = '%xmm3';
  const t0 = '%xmm4', t1 = '%xmm5', rot16 = '%xmm6', rot24 = '%xmm7';
  const xframe = 8; // win64 ? 160+8 : 8

  code += `.type	ChaCha20_ssse3,@function,5
.align	32
ChaCha20_ssse3:
.cfi_startproc
.LChaCha20_ssse3:
	mov	%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
	cmp	$128,${len}		# we might throw away some data,
	je	.LChaCha20_128
	ja	.LChaCha20_4x		# but overall it won't be slower

.Ldo_sse3_after_all:
	sub	$64+${xframe},%rsp
	movdqa	.Lsigma(%rip),${a}
	movdqu	(${key}),${b}
	movdqu	16(${key}),${c}
	movdqu	(${counter}),${d}
	movdqa	.Lrot16(%rip),${rot16}
	movdqa	.Lrot24(%rip),${rot24}

	movdqa	${a},0x00(%rsp)
	movdqa	${b},0x10(%rsp)
	movdqa	${c},0x20(%rsp)
	movdqa	${d},0x30(%rsp)
	mov	$10,${counter}		# reuse ${counter}
	jmp	.Loop_ssse3

.align	32
.Loop_outer_ssse3:
	movdqa	.Lone(%rip),${d}
	movdqa	0x00(%rsp),${a}
	movdqa	0x10(%rsp),${b}
	movdqa	0x20(%rsp),${c}
	paddd	0x30(%rsp),${d}
	mov	$10,${counter}
	movdqa	${d},0x30(%rsp)
	jmp	.Loop_ssse3

.align	32
.Loop_ssse3:
`;
  SSSE3ROUND(a, b, c, d, t0, t1, rot16, rot24);
  AUTOLOAD('pshufd', c, c, '78');
  AUTOLOAD('pshufd', b, b, '57');
  AUTOLOAD('pshufd', d, d, '147');
  AUTOLOAD('nop');

  SSSE3ROUND(a, b, c, d, t0, t1, rot16, rot24);
  AUTOLOAD('pshufd', c, c, '78');
  AUTOLOAD('pshufd', b, b, '147');
  AUTOLOAD('pshufd', d, d, '57');

  AUTOLOAD('dec', counter);
  AUTOLOAD('jnz', '.Loop_ssse3');

  code += `	paddd	0x00(%rsp),${a}
	paddd	0x10(%rsp),${b}
	paddd	0x20(%rsp),${c}
	paddd	0x30(%rsp),${d}

	cmp	$64,${len}
	jb	.Ltail_ssse3

	movdqu	0x00(${inp}),${t0}
	movdqu	0x10(${inp}),${t1}
	pxor	${t0},${a}			# xor with input
	movdqu	0x20(${inp}),${t0}
	pxor	${t1},${b}
	movdqu	0x30(${inp}),${t1}
	lea	0x40(${inp}),${inp}		# inp+=64
	pxor	${t0},${c}
	pxor	${t1},${d}

	movdqu	${a},0x00(${out})		# write output
	movdqu	${b},0x10(${out})
	movdqu	${c},0x20(${out})
	movdqu	${d},0x30(${out})
	lea	0x40(${out}),${out}		# out+=64

	sub	$64,${len}
	jnz	.Loop_outer_ssse3

	jmp	.Ldone_ssse3

.align	16
.Ltail_ssse3:
	movdqa	${a},0x00(%rsp)
	movdqa	${b},0x10(%rsp)
	movdqa	${c},0x20(%rsp)
	movdqa	${d},0x30(%rsp)
	xor	${counter},${counter}

.Loop_tail_ssse3:
	movzb	(${inp},${counter}),%eax
	movzb	(%rsp,${counter}),%ecx
	lea	1(${counter}),${counter}
	xor	%ecx,%eax
	mov	%al,-1(${out},${counter})
	dec	${len}
	jnz	.Loop_tail_ssse3

.Ldone_ssse3:
	lea	(%r9),%rsp
.cfi_def_cfa_register	%rsp
.Lssse3_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_ssse3,.-ChaCha20_ssse3
`;
}

// ---------------------------------------------------------------------------
// SSSE3 code path that handles 128-byte inputs
// ---------------------------------------------------------------------------
function SSSE3ROUND_2x(
  a: string, b: string, c: string, d: string,
  t0: string, t1: string, rot16: string, rot24: string,
  a1: string, b1: string, c1: string, d1: string,
): void {
  AUTOLOAD('paddd', a, b);
  AUTOLOAD('pxor', d, a);
  AUTOLOAD('paddd', a1, b1);
  AUTOLOAD('pxor', d1, a1);
  AUTOLOAD('pshufb', d, rot16);
  AUTOLOAD('pshufb', d1, rot16);

  AUTOLOAD('paddd', c, d);
  AUTOLOAD('paddd', c1, d1);
  AUTOLOAD('pxor', b, c);
  AUTOLOAD('pxor', b1, c1);
  AUTOLOAD('movdqa', t0, b);
  AUTOLOAD('psrld', b, '20');
  AUTOLOAD('movdqa', t1, b1);
  AUTOLOAD('pslld', t0, '12');
  AUTOLOAD('psrld', b1, '20');
  AUTOLOAD('por', b, t0);
  AUTOLOAD('pslld', t1, '12');
  AUTOLOAD('por', b1, t1);

  AUTOLOAD('paddd', a, b);
  AUTOLOAD('pxor', d, a);
  AUTOLOAD('paddd', a1, b1);
  AUTOLOAD('pxor', d1, a1);
  AUTOLOAD('pshufb', d, rot24);
  AUTOLOAD('pshufb', d1, rot24);

  AUTOLOAD('paddd', c, d);
  AUTOLOAD('paddd', c1, d1);
  AUTOLOAD('pxor', b, c);
  AUTOLOAD('pxor', b1, c1);
  AUTOLOAD('movdqa', t0, b);
  AUTOLOAD('psrld', b, '25');
  AUTOLOAD('movdqa', t1, b1);
  AUTOLOAD('pslld', t0, '7');
  AUTOLOAD('psrld', b1, '25');
  AUTOLOAD('por', b, t0);
  AUTOLOAD('pslld', t1, '7');
  AUTOLOAD('por', b1, t1);
}

function gen128(): void {
  const a = '%xmm8', b = '%xmm9', c = '%xmm2', d = '%xmm3';
  const t0 = '%xmm4', t1 = '%xmm5', rot16 = '%xmm6', rot24 = '%xmm7';
  const a1 = '%xmm10', b1 = '%xmm11', c1 = '%xmm0', d1 = '%xmm1';
  const xframe = 8; // win64 ? 0x68 : 8

  code += `.type	ChaCha20_128,@function,5
.align	32
ChaCha20_128:
.cfi_startproc
.LChaCha20_128:
	mov	%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
	sub	$64+${xframe},%rsp
	movdqa	.Lsigma(%rip),${a}
	movdqu	(${key}),${b}
	movdqu	16(${key}),${c}
	movdqu	(${counter}),${d}
	movdqa	.Lone(%rip),${d1}
	movdqa	.Lrot16(%rip),${rot16}
	movdqa	.Lrot24(%rip),${rot24}

	movdqa	${a},${a1}
	movdqa	${a},0x00(%rsp)
	movdqa	${b},${b1}
	movdqa	${b},0x10(%rsp)
	movdqa	${c},${c1}
	movdqa	${c},0x20(%rsp)
	paddd	${d},${d1}
	movdqa	${d},0x30(%rsp)
	mov	$10,${counter}		# reuse ${counter}
	jmp	.Loop_128

.align	32
.Loop_128:
`;
  SSSE3ROUND_2x(a, b, c, d, t0, t1, rot16, rot24, a1, b1, c1, d1);
  AUTOLOAD('pshufd', c, c, '78');
  AUTOLOAD('pshufd', b, b, '57');
  AUTOLOAD('pshufd', d, d, '147');
  AUTOLOAD('pshufd', c1, c1, '78');
  AUTOLOAD('pshufd', b1, b1, '57');
  AUTOLOAD('pshufd', d1, d1, '147');

  SSSE3ROUND_2x(a, b, c, d, t0, t1, rot16, rot24, a1, b1, c1, d1);
  AUTOLOAD('pshufd', c, c, '78');
  AUTOLOAD('pshufd', b, b, '147');
  AUTOLOAD('pshufd', d, d, '57');
  AUTOLOAD('pshufd', c1, c1, '78');
  AUTOLOAD('pshufd', b1, b1, '147');
  AUTOLOAD('pshufd', d1, d1, '57');

  AUTOLOAD('dec', counter);
  AUTOLOAD('jnz', '.Loop_128');

  code += `	paddd	0x00(%rsp),${a}
	paddd	0x10(%rsp),${b}
	paddd	0x20(%rsp),${c}
	paddd	0x30(%rsp),${d}
	paddd	.Lone(%rip),${d1}
	paddd	0x00(%rsp),${a1}
	paddd	0x10(%rsp),${b1}
	paddd	0x20(%rsp),${c1}
	paddd	0x30(%rsp),${d1}

	movdqu	0x00(${inp}),${t0}
	movdqu	0x10(${inp}),${t1}
	pxor	${t0},${a}			# xor with input
	movdqu	0x20(${inp}),${t0}
	pxor	${t1},${b}
	movdqu	0x30(${inp}),${t1}
	pxor	${t0},${c}
	movdqu	0x40(${inp}),${t0}
	pxor	${t1},${d}
	movdqu	0x50(${inp}),${t1}
	pxor	${t0},${a1}
	movdqu	0x60(${inp}),${t0}
	pxor	${t1},${b1}
	movdqu	0x70(${inp}),${t1}
	pxor	${t0},${c1}
	pxor	${t1},${d1}

	movdqu	${a},0x00(${out})		# write output
	movdqu	${b},0x10(${out})
	movdqu	${c},0x20(${out})
	movdqu	${d},0x30(${out})
	movdqu	${a1},0x40(${out})
	movdqu	${b1},0x50(${out})
	movdqu	${c1},0x60(${out})
	movdqu	${d1},0x70(${out})
	lea	(%r9),%rsp
.cfi_def_cfa_register	%rsp
.L128_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_128,.-ChaCha20_128
`;
}

function gen4x(): void {
  // assign variables to favor Atom front-end
  let xd0 = '%xmm0', xd1 = '%xmm1', xd2 = '%xmm2', xd3 = '%xmm3';
  let xt0 = '%xmm4', xt1 = '%xmm5', xt2 = '%xmm6', xt3 = '%xmm7';
  let xa0 = '%xmm8', xa1 = '%xmm9', xa2 = '%xmm10', xa3 = '%xmm11';
  let xb0 = '%xmm12', xb1 = '%xmm13', xb2 = '%xmm14', xb3 = '%xmm15';
  const xx = [
    xa0, xa1, xa2, xa3, xb0, xb1, xb2, xb3,
    'nox', 'nox', 'nox', 'nox', xd0, xd1, xd2, xd3,
  ];

  function laneROUND(a0: number, b0: number, c0: number, d0: number): void {
    const lane = (v: number) => (v & ~3) + ((v + 1) & 3);
    const a1 = lane(a0), b1 = lane(b0), c1 = lane(c0), d1 = lane(d0);
    const a2 = lane(a1), b2 = lane(b1), c2 = lane(c1), d2 = lane(d1);
    const a3 = lane(a2), b3 = lane(b2), c3 = lane(c2), d3 = lane(d2);
    const xc = xt0, xc_ = xt1, t0 = xt2, t1 = xt3;

    AUTOLOAD('paddd', xx[a0], xx[b0]); // Q1
    AUTOLOAD('paddd', xx[a1], xx[b1]); // Q2
    AUTOLOAD('pxor', xx[d0], xx[a0]);
    AUTOLOAD('pxor', xx[d1], xx[a1]);
    AUTOLOAD('pshufb', xx[d0], t1);
    AUTOLOAD('pshufb', xx[d1], t1);

    AUTOLOAD('paddd', xc, xx[d0]);
    AUTOLOAD('paddd', xc_, xx[d1]);
    AUTOLOAD('pxor', xx[b0], xc);
    AUTOLOAD('pxor', xx[b1], xc_);
    AUTOLOAD('movdqa', t0, xx[b0]);
    AUTOLOAD('pslld', xx[b0], '12');
    AUTOLOAD('psrld', t0, '20');
    AUTOLOAD('movdqa', t1, xx[b1]);
    AUTOLOAD('pslld', xx[b1], '12');
    AUTOLOAD('por', xx[b0], t0);
    AUTOLOAD('psrld', t1, '20');
    AUTOLOAD('movdqa', t0, '(%r11)'); // .Lrot24(%rip)
    AUTOLOAD('por', xx[b1], t1);

    AUTOLOAD('paddd', xx[a0], xx[b0]);
    AUTOLOAD('paddd', xx[a1], xx[b1]);
    AUTOLOAD('pxor', xx[d0], xx[a0]);
    AUTOLOAD('pxor', xx[d1], xx[a1]);
    AUTOLOAD('pshufb', xx[d0], t0);
    AUTOLOAD('pshufb', xx[d1], t0);

    AUTOLOAD('paddd', xc, xx[d0]);
    AUTOLOAD('paddd', xc_, xx[d1]);
    AUTOLOAD('pxor', xx[b0], xc);
    AUTOLOAD('pxor', xx[b1], xc_);
    AUTOLOAD('movdqa', t1, xx[b0]);
    AUTOLOAD('pslld', xx[b0], '7');
    AUTOLOAD('psrld', t1, '25');
    AUTOLOAD('movdqa', t0, xx[b1]);
    AUTOLOAD('pslld', xx[b1], '7');
    AUTOLOAD('por', xx[b0], t1);
    AUTOLOAD('psrld', t0, '25');
    AUTOLOAD('movdqa', t1, '(%r10)'); // .Lrot16(%rip)
    AUTOLOAD('por', xx[b1], t0);

    AUTOLOAD('movdqa', `\`16*(${c0}-8)\`(%rsp)`, xc); // reload pair of 'c's
    AUTOLOAD('movdqa', `\`16*(${c1}-8)\`(%rsp)`, xc_);
    AUTOLOAD('movdqa', xc, `\`16*(${c2}-8)\`(%rsp)`);
    AUTOLOAD('movdqa', xc_, `\`16*(${c3}-8)\`(%rsp)`);

    AUTOLOAD('paddd', xx[a2], xx[b2]); // Q3
    AUTOLOAD('paddd', xx[a3], xx[b3]); // Q4
    AUTOLOAD('pxor', xx[d2], xx[a2]);
    AUTOLOAD('pxor', xx[d3], xx[a3]);
    AUTOLOAD('pshufb', xx[d2], t1);
    AUTOLOAD('pshufb', xx[d3], t1);

    AUTOLOAD('paddd', xc, xx[d2]);
    AUTOLOAD('paddd', xc_, xx[d3]);
    AUTOLOAD('pxor', xx[b2], xc);
    AUTOLOAD('pxor', xx[b3], xc_);
    AUTOLOAD('movdqa', t0, xx[b2]);
    AUTOLOAD('pslld', xx[b2], '12');
    AUTOLOAD('psrld', t0, '20');
    AUTOLOAD('movdqa', t1, xx[b3]);
    AUTOLOAD('pslld', xx[b3], '12');
    AUTOLOAD('por', xx[b2], t0);
    AUTOLOAD('psrld', t1, '20');
    AUTOLOAD('movdqa', t0, '(%r11)'); // .Lrot24(%rip)
    AUTOLOAD('por', xx[b3], t1);

    AUTOLOAD('paddd', xx[a2], xx[b2]);
    AUTOLOAD('paddd', xx[a3], xx[b3]);
    AUTOLOAD('pxor', xx[d2], xx[a2]);
    AUTOLOAD('pxor', xx[d3], xx[a3]);
    AUTOLOAD('pshufb', xx[d2], t0);
    AUTOLOAD('pshufb', xx[d3], t0);

    AUTOLOAD('paddd', xc, xx[d2]);
    AUTOLOAD('paddd', xc_, xx[d3]);
    AUTOLOAD('pxor', xx[b2], xc);
    AUTOLOAD('pxor', xx[b3], xc_);
    AUTOLOAD('movdqa', t1, xx[b2]);
    AUTOLOAD('pslld', xx[b2], '7');
    AUTOLOAD('psrld', t1, '25');
    AUTOLOAD('movdqa', t0, xx[b3]);
    AUTOLOAD('pslld', xx[b3], '7');
    AUTOLOAD('por', xx[b2], t1);
    AUTOLOAD('psrld', t0, '25');
    AUTOLOAD('movdqa', t1, '(%r10)'); // .Lrot16(%rip)
    AUTOLOAD('por', xx[b3], t0);
  }

  const xframe = 8; // win64 ? 0xa8 : 8

  code += `.type	ChaCha20_4x,@function,5
.align	32
ChaCha20_4x:
.cfi_startproc
.LChaCha20_4x:
	mov		%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
	mov		%r10,%r11
	cmp		$192,${len}
	ja		.Lproceed4x

	and		$${(1 << 26) | (1 << 22)},%r11	# isolate XSAVE+MOVBE
	cmp		$${1 << 22},%r11		# check for MOVBE without XSAVE
	je		.Ldo_sse3_after_all	# to detect Atom

.Lproceed4x:
	sub		$0x140+${xframe},%rsp
	movdqa		.Lsigma(%rip),${xa3}	# key[0]
	movdqu		(${key}),${xb3}		# key[1]
	movdqu		16(${key}),${xt3}		# key[2]
	movdqu		(${counter}),${xd3}		# key[3]
	lea		0x100(%rsp),%rcx	# size optimization
	lea		.Lrot16(%rip),%r10
	lea		.Lrot24(%rip),%r11

	pshufd		$0x00,${xa3},${xa0}	# smash key by lanes...
	pshufd		$0x55,${xa3},${xa1}
	movdqa		${xa0},0x40(%rsp)		# ... and offload
	pshufd		$0xaa,${xa3},${xa2}
	movdqa		${xa1},0x50(%rsp)
	pshufd		$0xff,${xa3},${xa3}
	movdqa		${xa2},0x60(%rsp)
	movdqa		${xa3},0x70(%rsp)

	pshufd		$0x00,${xb3},${xb0}
	pshufd		$0x55,${xb3},${xb1}
	movdqa		${xb0},0x80-0x100(%rcx)
	pshufd		$0xaa,${xb3},${xb2}
	movdqa		${xb1},0x90-0x100(%rcx)
	pshufd		$0xff,${xb3},${xb3}
	movdqa		${xb2},0xa0-0x100(%rcx)
	movdqa		${xb3},0xb0-0x100(%rcx)

	pshufd		$0x00,${xt3},${xt0}	# "xc0"
	pshufd		$0x55,${xt3},${xt1}	# "xc1"
	movdqa		${xt0},0xc0-0x100(%rcx)
	pshufd		$0xaa,${xt3},${xt2}	# "xc2"
	movdqa		${xt1},0xd0-0x100(%rcx)
	pshufd		$0xff,${xt3},${xt3}	# "xc3"
	movdqa		${xt2},0xe0-0x100(%rcx)
	movdqa		${xt3},0xf0-0x100(%rcx)

	pshufd		$0x00,${xd3},${xd0}
	pshufd		$0x55,${xd3},${xd1}
	paddd		.Linc(%rip),${xd0}	# don't save counters yet
	pshufd		$0xaa,${xd3},${xd2}
	movdqa		${xd1},0x110-0x100(%rcx)
	pshufd		$0xff,${xd3},${xd3}
	movdqa		${xd2},0x120-0x100(%rcx)
	movdqa		${xd3},0x130-0x100(%rcx)

	jmp		.Loop_enter4x

.align	32
.Loop_outer4x:
	movdqa		0x40(%rsp),${xa0}		# re-load smashed key
	movdqa		0x50(%rsp),${xa1}
	movdqa		0x60(%rsp),${xa2}
	movdqa		0x70(%rsp),${xa3}
	movdqa		0x80-0x100(%rcx),${xb0}
	movdqa		0x90-0x100(%rcx),${xb1}
	movdqa		0xa0-0x100(%rcx),${xb2}
	movdqa		0xb0-0x100(%rcx),${xb3}
	movdqa		0xc0-0x100(%rcx),${xt0}	# "xc0"
	movdqa		0xd0-0x100(%rcx),${xt1}	# "xc1"
	movdqa		0xe0-0x100(%rcx),${xt2}	# "xc2"
	movdqa		0xf0-0x100(%rcx),${xt3}	# "xc3"
	movdqa		0x100-0x100(%rcx),${xd0}
	movdqa		0x110-0x100(%rcx),${xd1}
	movdqa		0x120-0x100(%rcx),${xd2}
	movdqa		0x130-0x100(%rcx),${xd3}
	paddd		.Lfour(%rip),${xd0}	# next SIMD counters

.Loop_enter4x:
	movdqa		${xt2},0x20(%rsp)		# SIMD equivalent of "@x[10]"
	movdqa		${xt3},0x30(%rsp)		# SIMD equivalent of "@x[11]"
	movdqa		(%r10),${xt3}		# .Lrot16(%rip)
	mov		$10,%eax
	movdqa		${xd0},0x100-0x100(%rcx)	# save SIMD counters
	jmp		.Loop4x

.align	32
.Loop4x:
`;
  laneROUND(0, 4, 8, 12);
  laneROUND(0, 5, 10, 15);
  code += `	dec		%eax
	jnz		.Loop4x

	paddd		0x40(%rsp),${xa0}		# accumulate key material
	paddd		0x50(%rsp),${xa1}
	paddd		0x60(%rsp),${xa2}
	paddd		0x70(%rsp),${xa3}

	movdqa		${xa0},${xt2}		# "de-interlace" data
	punpckldq	${xa1},${xa0}
	movdqa		${xa2},${xt3}
	punpckldq	${xa3},${xa2}
	punpckhdq	${xa1},${xt2}
	punpckhdq	${xa3},${xt3}
	movdqa		${xa0},${xa1}
	punpcklqdq	${xa2},${xa0}		# "a0"
	movdqa		${xt2},${xa3}
	punpcklqdq	${xt3},${xt2}		# "a2"
	punpckhqdq	${xa2},${xa1}		# "a1"
	punpckhqdq	${xt3},${xa3}		# "a3"
`;
  // perl: ($xa2,$xt2)=($xt2,$xa2);
  [xa2, xt2] = [xt2, xa2];
  code += `	paddd		0x80-0x100(%rcx),${xb0}
	paddd		0x90-0x100(%rcx),${xb1}
	paddd		0xa0-0x100(%rcx),${xb2}
	paddd		0xb0-0x100(%rcx),${xb3}

	movdqa		${xa0},0x00(%rsp)		# offload xaN
	movdqa		${xa1},0x10(%rsp)
	movdqa		0x20(%rsp),${xa0}		# "xc2"
	movdqa		0x30(%rsp),${xa1}		# "xc3"

	movdqa		${xb0},${xt2}
	punpckldq	${xb1},${xb0}
	movdqa		${xb2},${xt3}
	punpckldq	${xb3},${xb2}
	punpckhdq	${xb1},${xt2}
	punpckhdq	${xb3},${xt3}
	movdqa		${xb0},${xb1}
	punpcklqdq	${xb2},${xb0}		# "b0"
	movdqa		${xt2},${xb3}
	punpcklqdq	${xt3},${xt2}		# "b2"
	punpckhqdq	${xb2},${xb1}		# "b1"
	punpckhqdq	${xt3},${xb3}		# "b3"
`;
  // perl: ($xb2,$xt2)=($xt2,$xb2);
  [xb2, xt2] = [xt2, xb2];
  // perl: my ($xc0,$xc1,$xc2,$xc3)=($xt0,$xt1,$xa0,$xa1);
  let xc0 = xt0, xc1 = xt1, xc2 = xa0, xc3 = xa1;
  code += `	paddd		0xc0-0x100(%rcx),${xc0}
	paddd		0xd0-0x100(%rcx),${xc1}
	paddd		0xe0-0x100(%rcx),${xc2}
	paddd		0xf0-0x100(%rcx),${xc3}

	movdqa		${xa2},0x20(%rsp)		# keep offloading xaN
	movdqa		${xa3},0x30(%rsp)

	movdqa		${xc0},${xt2}
	punpckldq	${xc1},${xc0}
	movdqa		${xc2},${xt3}
	punpckldq	${xc3},${xc2}
	punpckhdq	${xc1},${xt2}
	punpckhdq	${xc3},${xt3}
	movdqa		${xc0},${xc1}
	punpcklqdq	${xc2},${xc0}		# "c0"
	movdqa		${xt2},${xc3}
	punpcklqdq	${xt3},${xt2}		# "c2"
	punpckhqdq	${xc2},${xc1}		# "c1"
	punpckhqdq	${xt3},${xc3}		# "c3"
`;
  // perl: ($xc2,$xt2)=($xt2,$xc2);
  [xc2, xt2] = [xt2, xc2];
  // perl: ($xt0,$xt1)=($xa2,$xa3); use xaN registers as temporary
  [xt0, xt1] = [xa2, xa3];
  code += `	paddd		0x100-0x100(%rcx),${xd0}
	paddd		0x110-0x100(%rcx),${xd1}
	paddd		0x120-0x100(%rcx),${xd2}
	paddd		0x130-0x100(%rcx),${xd3}

	movdqa		${xd0},${xt2}
	punpckldq	${xd1},${xd0}
	movdqa		${xd2},${xt3}
	punpckldq	${xd3},${xd2}
	punpckhdq	${xd1},${xt2}
	punpckhdq	${xd3},${xt3}
	movdqa		${xd0},${xd1}
	punpcklqdq	${xd2},${xd0}		# "d0"
	movdqa		${xt2},${xd3}
	punpcklqdq	${xt3},${xt2}		# "d2"
	punpckhqdq	${xd2},${xd1}		# "d1"
	punpckhqdq	${xt3},${xd3}		# "d3"
`;
  // perl: ($xd2,$xt2)=($xt2,$xd2);
  [xd2, xt2] = [xt2, xd2];
  code += `	cmp		$64*4,${len}
	jb		.Ltail4x

	movdqu		0x00(${inp}),${xt0}		# xor with input
	movdqu		0x10(${inp}),${xt1}
	movdqu		0x20(${inp}),${xt2}
	movdqu		0x30(${inp}),${xt3}
	pxor		0x00(%rsp),${xt0}		# xaN is offloaded, remember?
	pxor		${xb0},${xt1}
	pxor		${xc0},${xt2}
	pxor		${xd0},${xt3}

	 movdqu		${xt0},0x00(${out})
	movdqu		0x40(${inp}),${xt0}
	 movdqu		${xt1},0x10(${out})
	movdqu		0x50(${inp}),${xt1}
	 movdqu		${xt2},0x20(${out})
	movdqu		0x60(${inp}),${xt2}
	 movdqu		${xt3},0x30(${out})
	movdqu		0x70(${inp}),${xt3}
	lea		0x80(${inp}),${inp}		# size optimization
	pxor		0x10(%rsp),${xt0}
	pxor		${xb1},${xt1}
	pxor		${xc1},${xt2}
	pxor		${xd1},${xt3}

	 movdqu		${xt0},0x40(${out})
	movdqu		0x00(${inp}),${xt0}
	 movdqu		${xt1},0x50(${out})
	movdqu		0x10(${inp}),${xt1}
	 movdqu		${xt2},0x60(${out})
	movdqu		0x20(${inp}),${xt2}
	 movdqu		${xt3},0x70(${out})
	 lea		0x80(${out}),${out}		# size optimization
	movdqu		0x30(${inp}),${xt3}
	pxor		0x20(%rsp),${xt0}
	pxor		${xb2},${xt1}
	pxor		${xc2},${xt2}
	pxor		${xd2},${xt3}

	 movdqu		${xt0},0x00(${out})
	movdqu		0x40(${inp}),${xt0}
	 movdqu		${xt1},0x10(${out})
	movdqu		0x50(${inp}),${xt1}
	 movdqu		${xt2},0x20(${out})
	movdqu		0x60(${inp}),${xt2}
	 movdqu		${xt3},0x30(${out})
	movdqu		0x70(${inp}),${xt3}
	lea		0x80(${inp}),${inp}		# inp+=64*4
	pxor		0x30(%rsp),${xt0}
	pxor		${xb3},${xt1}
	pxor		${xc3},${xt2}
	pxor		${xd3},${xt3}
	movdqu		${xt0},0x40(${out})
	movdqu		${xt1},0x50(${out})
	movdqu		${xt2},0x60(${out})
	movdqu		${xt3},0x70(${out})
	lea		0x80(${out}),${out}		# out+=64*4

	sub		$64*4,${len}
	jnz		.Loop_outer4x

	jmp		.Ldone4x

.Ltail4x:
	cmp		$192,${len}
	jae		.L192_or_more4x
	cmp		$128,${len}
	jae		.L128_or_more4x
	cmp		$64,${len}
	jae		.L64_or_more4x

	#movdqa		0x00(%rsp),${xt0}		# xaN is offloaded, remember?
	xor		%r10,%r10
	#movdqa		${xt0},0x00(%rsp)
	movdqa		${xb0},0x10(%rsp)
	movdqa		${xc0},0x20(%rsp)
	movdqa		${xd0},0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L64_or_more4x:
	movdqu		0x00(${inp}),${xt0}		# xor with input
	movdqu		0x10(${inp}),${xt1}
	movdqu		0x20(${inp}),${xt2}
	movdqu		0x30(${inp}),${xt3}
	pxor		0x00(%rsp),${xt0}		# xaxN is offloaded, remember?
	pxor		${xb0},${xt1}
	pxor		${xc0},${xt2}
	pxor		${xd0},${xt3}
	movdqu		${xt0},0x00(${out})
	movdqu		${xt1},0x10(${out})
	movdqu		${xt2},0x20(${out})
	movdqu		${xt3},0x30(${out})
	je		.Ldone4x

	movdqa		0x10(%rsp),${xt0}		# xaN is offloaded, remember?
	lea		0x40(${inp}),${inp}		# inp+=64*1
	xor		%r10,%r10
	movdqa		${xt0},0x00(%rsp)
	movdqa		${xb1},0x10(%rsp)
	lea		0x40(${out}),${out}		# out+=64*1
	movdqa		${xc1},0x20(%rsp)
	sub		$64,${len}		# len-=64*1
	movdqa		${xd1},0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L128_or_more4x:
	movdqu		0x00(${inp}),${xt0}		# xor with input
	movdqu		0x10(${inp}),${xt1}
	movdqu		0x20(${inp}),${xt2}
	movdqu		0x30(${inp}),${xt3}
	pxor		0x00(%rsp),${xt0}		# xaN is offloaded, remember?
	pxor		${xb0},${xt1}
	pxor		${xc0},${xt2}
	pxor		${xd0},${xt3}

	 movdqu		${xt0},0x00(${out})
	movdqu		0x40(${inp}),${xt0}
	 movdqu		${xt1},0x10(${out})
	movdqu		0x50(${inp}),${xt1}
	 movdqu		${xt2},0x20(${out})
	movdqu		0x60(${inp}),${xt2}
	 movdqu		${xt3},0x30(${out})
	movdqu		0x70(${inp}),${xt3}
	pxor		0x10(%rsp),${xt0}
	pxor		${xb1},${xt1}
	pxor		${xc1},${xt2}
	pxor		${xd1},${xt3}
	movdqu		${xt0},0x40(${out})
	movdqu		${xt1},0x50(${out})
	movdqu		${xt2},0x60(${out})
	movdqu		${xt3},0x70(${out})
	je		.Ldone4x

	movdqa		0x20(%rsp),${xt0}		# xaN is offloaded, remember?
	lea		0x80(${inp}),${inp}		# inp+=64*2
	xor		%r10,%r10
	movdqa		${xt0},0x00(%rsp)
	movdqa		${xb2},0x10(%rsp)
	lea		0x80(${out}),${out}		# out+=64*2
	movdqa		${xc2},0x20(%rsp)
	sub		$128,${len}		# len-=64*2
	movdqa		${xd2},0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L192_or_more4x:
	movdqu		0x00(${inp}),${xt0}		# xor with input
	movdqu		0x10(${inp}),${xt1}
	movdqu		0x20(${inp}),${xt2}
	movdqu		0x30(${inp}),${xt3}
	pxor		0x00(%rsp),${xt0}		# xaN is offloaded, remember?
	pxor		${xb0},${xt1}
	pxor		${xc0},${xt2}
	pxor		${xd0},${xt3}

	 movdqu		${xt0},0x00(${out})
	movdqu		0x40(${inp}),${xt0}
	 movdqu		${xt1},0x10(${out})
	movdqu		0x50(${inp}),${xt1}
	 movdqu		${xt2},0x20(${out})
	movdqu		0x60(${inp}),${xt2}
	 movdqu		${xt3},0x30(${out})
	movdqu		0x70(${inp}),${xt3}
	lea		0x80(${inp}),${inp}		# size optimization
	pxor		0x10(%rsp),${xt0}
	pxor		${xb1},${xt1}
	pxor		${xc1},${xt2}
	pxor		${xd1},${xt3}

	 movdqu		${xt0},0x40(${out})
	movdqu		0x00(${inp}),${xt0}
	 movdqu		${xt1},0x50(${out})
	movdqu		0x10(${inp}),${xt1}
	 movdqu		${xt2},0x60(${out})
	movdqu		0x20(${inp}),${xt2}
	 movdqu		${xt3},0x70(${out})
	 lea		0x80(${out}),${out}		# size optimization
	movdqu		0x30(${inp}),${xt3}
	pxor		0x20(%rsp),${xt0}
	pxor		${xb2},${xt1}
	pxor		${xc2},${xt2}
	pxor		${xd2},${xt3}
	movdqu		${xt0},0x00(${out})
	movdqu		${xt1},0x10(${out})
	movdqu		${xt2},0x20(${out})
	movdqu		${xt3},0x30(${out})
	je		.Ldone4x

	movdqa		0x30(%rsp),${xt0}		# xaN is offloaded, remember?
	lea		0x40(${inp}),${inp}		# inp+=64*3
	xor		%r10,%r10
	movdqa		${xt0},0x00(%rsp)
	movdqa		${xb3},0x10(%rsp)
	lea		0x40(${out}),${out}		# out+=64*3
	movdqa		${xc3},0x20(%rsp)
	sub		$192,${len}		# len-=64*3
	movdqa		${xd3},0x30(%rsp)

.Loop_tail4x:
	movzb		(${inp},%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1(${out},%r10)
	dec		${len}
	jnz		.Loop_tail4x

.Ldone4x:
	lea		(%r9),%rsp
.cfi_def_cfa_register	%rsp
.L4x_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_4x,.-ChaCha20_4x
`;
}

genCtr32();
genSsse3();
gen128();
gen4x();
evaluateBackticks();

export default translateAssembly(code);
