/**
 * bn_GF2m_mul_2x2 for x86_64.
 *
 * TypeScript port of OpenSSL crypto/bn/asm/x86_64-gf2m.pl.
 * Written by Andy Polyakov, @dot-asm.
 * Copyright 2011-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $win64=0 (unix SysV ABI; the
 * Win64 SEH blocks and .pdata/.xdata are dropped). The script has no
 * assembler probes; the PCLMULQDQ path is selected at runtime via
 * OPENSSL_ia32cap_P bit 33.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// ---------------------------------------------------------------------------
// _mul_1x1 register map (perl: ($lo,$hi)=("%rax","%rdx"); $a=$lo; ...)
// ---------------------------------------------------------------------------
const lo = '%rax';
const hi = '%rdx';
const a = lo; // same register as $lo
const i0 = '%rsi';
const i1 = '%rdi';
const t0 = '%rbx';
const t1 = '%rcx';
const b = '%rbp';
const mask = '%r8';
const a1m = '%r9'; // $a1 inside _mul_1x1 (renamed: mul_2x2 reassigns $a1)
const a2m = '%r10';
const a4m = '%r11';
const a8m = '%r12';
const a12m = '%r13';
const a48m = '%r14';
const R = '%xmm0';
const Tx = '%xmm1';

// ---------------------------------------------------------------------------
// bn_GF2m_mul_2x2 argument registers (unix SysV; perl reassigns $a1..$b0)
// ---------------------------------------------------------------------------
const rp = '%rdi';
const a1 = '%rsi';
const a0 = '%rdx';
const b1 = '%rcx';
const b0 = '%r8';
// @r = ("%rbx","%rcx","%rdi","%rsi") — used after the third _mul_1x1 call
const r0 = '%rbx';
const r1 = '%rcx';
const r2 = '%rdi';
const r3 = '%rsi';

function genMul1x1(): void {
  code += `.text

.type	_mul_1x1,@abi-omnipotent
.align	16
_mul_1x1:
.cfi_startproc
	sub	$128+8,%rsp
.cfi_adjust_cfa_offset	128+8
	mov	$-1,${a1m}
	lea	(${a},${a}),${i0}
	shr	$3,${a1m}
	lea	(,${a},4),${i1}
	and	${a},${a1m}			# a1=a&0x1fffffffffffffff
	lea	(,${a},8),${a8m}
	sar	$63,${a}			# broadcast 63rd bit
	lea	(${a1m},${a1m}),${a2m}
	sar	$63,${i0}		# broadcast 62nd bit
	lea	(,${a1m},4),${a4m}
	and	${b},${a}
	sar	$63,${i1}		# broadcast 61st bit
	mov	${a},${hi}			# ${a} is ${lo}
	shl	$63,${lo}
	and	${b},${i0}
	shr	$1,${hi}
	mov	${i0},${t1}
	shl	$62,${i0}
	and	${b},${i1}
	shr	$2,${t1}
	xor	${i0},${lo}
	mov	${i1},${t0}
	shl	$61,${i1}
	xor	${t1},${hi}
	shr	$3,${t0}
	xor	${i1},${lo}
	xor	${t0},${hi}

	mov	${a1m},${a12m}
	movq	$0,0(%rsp)		# tab[0]=0
	xor	${a2m},${a12m}		# a1^a2
	mov	${a1m},8(%rsp)		# tab[1]=a1
	 mov	${a4m},${a48m}
	mov	${a2m},16(%rsp)		# tab[2]=a2
	 xor	${a8m},${a48m}		# a4^a8
	mov	${a12m},24(%rsp)		# tab[3]=a1^a2

	xor	${a4m},${a1m}
	mov	${a4m},32(%rsp)		# tab[4]=a4
	xor	${a4m},${a2m}
	mov	${a1m},40(%rsp)		# tab[5]=a1^a4
	xor	${a4m},${a12m}
	mov	${a2m},48(%rsp)		# tab[6]=a2^a4
	 xor	${a48m},${a1m}		# a1^a4^a4^a8=a1^a8
	mov	${a12m},56(%rsp)		# tab[7]=a1^a2^a4
	 xor	${a48m},${a2m}		# a2^a4^a4^a8=a1^a8

	mov	${a8m},64(%rsp)		# tab[8]=a8
	xor	${a48m},${a12m}		# a1^a2^a4^a4^a8=a1^a2^a8
	mov	${a1m},72(%rsp)		# tab[9]=a1^a8
	 xor	${a4m},${a1m}		# a1^a8^a4
	mov	${a2m},80(%rsp)		# tab[10]=a2^a8
	 xor	${a4m},${a2m}		# a2^a8^a4
	mov	${a12m},88(%rsp)		# tab[11]=a1^a2^a8

	xor	${a4m},${a12m}		# a1^a2^a8^a4
	mov	${a48m},96(%rsp)		# tab[12]=a4^a8
	 mov	${mask},${i0}
	mov	${a1m},104(%rsp)		# tab[13]=a1^a4^a8
	 and	${b},${i0}
	mov	${a2m},112(%rsp)		# tab[14]=a2^a4^a8
	 shr	$4,${b}
	mov	${a12m},120(%rsp)		# tab[15]=a1^a2^a4^a8
	 mov	${mask},${i1}
	 and	${b},${i1}
	 shr	$4,${b}

	movq	(%rsp,${i0},8),${R}		# half of calculations is done in SSE2
	mov	${mask},${i0}
	and	${b},${i0}
	shr	$4,${b}
`;
  for (let n = 1; n < 8; n++) {
    code += `	mov	(%rsp,${i1},8),${t1}
	mov	${mask},${i1}
	mov	${t1},${t0}
	shl	$${8 * n - 4},${t1}
	and	${b},${i1}
	 movq	(%rsp,${i0},8),${Tx}
	shr	$${64 - (8 * n - 4)},${t0}
	xor	${t1},${lo}
	 pslldq	$${n},${Tx}
	 mov	${mask},${i0}
	shr	$4,${b}
	xor	${t0},${hi}
	 and	${b},${i0}
	 shr	$4,${b}
	 pxor	${Tx},${R}
`;
  }
  // after the loop $n == 8 (perl leaves the loop variable at its exit value)
  const n = 8;
  code += `	mov	(%rsp,${i1},8),${t1}
	mov	${t1},${t0}
	shl	$${8 * n - 4},${t1}
	movq	${R},${i0}
	shr	$${64 - (8 * n - 4)},${t0}
	xor	${t1},${lo}
	psrldq	$8,${R}
	xor	${t0},${hi}
	movq	${R},${i1}
	xor	${i0},${lo}
	xor	${i1},${hi}

	add	$128+8,%rsp
.cfi_adjust_cfa_offset	-128-8
	ret
.Lend_mul_1x1:
.cfi_endproc
.size	_mul_1x1,.-_mul_1x1
`;
}

function genMul2x2(): void {
  code += `.extern	OPENSSL_ia32cap_P
.globl	bn_GF2m_mul_2x2
.type	bn_GF2m_mul_2x2,@abi-omnipotent
.align	16
bn_GF2m_mul_2x2:
.cfi_startproc
	mov	%rsp,%rax
	mov	OPENSSL_ia32cap_P(%rip),%r10
	bt	$33,%r10
	jnc	.Lvanilla_mul_2x2

	movq		${a1},${R}
	movq		${b1},${Tx}
	movq		${a0},%xmm2
	movq		${b0},%xmm3
	movdqa		${R},%xmm4
	movdqa		${Tx},%xmm5
	pclmulqdq	$0,${Tx},${R}	# a1·b1
	pxor		%xmm2,%xmm4
	pxor		%xmm3,%xmm5
	pclmulqdq	$0,%xmm3,%xmm2	# a0·b0
	pclmulqdq	$0,%xmm5,%xmm4	# (a0+a1)·(b0+b1)
	xorps		${R},%xmm4
	xorps		%xmm2,%xmm4	# (a0+a1)·(b0+b1)-a0·b0-a1·b1
	movdqa		%xmm4,%xmm5
	pslldq		$8,%xmm4
	psrldq		$8,%xmm5
	pxor		%xmm4,%xmm2
	pxor		%xmm5,${R}
	movdqu		%xmm2,0(${rp})
	movdqu		${R},16(${rp})
	ret

.align	16
.Lvanilla_mul_2x2:
	lea	-8*17(%rsp),%rsp
.cfi_adjust_cfa_offset	8*17
	mov	%r14,8*10(%rsp)
.cfi_rel_offset	%r14,8*10
	mov	%r13,8*11(%rsp)
.cfi_rel_offset	%r13,8*11
	mov	%r12,8*12(%rsp)
.cfi_rel_offset	%r12,8*12
	mov	%rbp,8*13(%rsp)
.cfi_rel_offset	%rbp,8*13
	mov	%rbx,8*14(%rsp)
.cfi_rel_offset	%rbx,8*14
.Lbody_mul_2x2:
	mov	${rp},32(%rsp)		# save the arguments
	mov	${a1},40(%rsp)
	mov	${a0},48(%rsp)
	mov	${b1},56(%rsp)
	mov	${b0},64(%rsp)

	mov	$0xf,${mask}
	mov	${a1},${a}
	mov	${b1},${b}
	call	_mul_1x1		# a1·b1
	mov	${lo},16(%rsp)
	mov	${hi},24(%rsp)

	mov	48(%rsp),${a}
	mov	64(%rsp),${b}
	call	_mul_1x1		# a0·b0
	mov	${lo},0(%rsp)
	mov	${hi},8(%rsp)

	mov	40(%rsp),${a}
	mov	56(%rsp),${b}
	xor	48(%rsp),${a}
	xor	64(%rsp),${b}
	call	_mul_1x1		# (a0+a1)·(b0+b1)
	mov	0(%rsp),${r0}
	mov	8(%rsp),${r1}
	mov	16(%rsp),${r2}
	mov	24(%rsp),${r3}
	mov	32(%rsp),%rbp

	xor	${hi},${lo}
	xor	${r1},${hi}
	xor	${r0},${lo}
	mov	${r0},0(%rbp)
	xor	${r2},${hi}
	mov	${r3},24(%rbp)
	xor	${r3},${lo}
	xor	${r3},${hi}
	xor	${hi},${lo}
	mov	${hi},16(%rbp)
	mov	${lo},8(%rbp)

	mov	8*10(%rsp),%r14
.cfi_restore	%r14
	mov	8*11(%rsp),%r13
.cfi_restore	%r13
	mov	8*12(%rsp),%r12
.cfi_restore	%r12
	mov	8*13(%rsp),%rbp
.cfi_restore	%rbp
	mov	8*14(%rsp),%rbx
.cfi_restore	%rbx
	lea	8*17(%rsp),%rsp
.cfi_adjust_cfa_offset	-8*17
.Lepilogue_mul_2x2:
	ret
.Lend_mul_2x2:
.cfi_endproc
.size	bn_GF2m_mul_2x2,.-bn_GF2m_mul_2x2
.asciz	"GF(2^m) Multiplication for x86_64, CRYPTOGAMS by <appro@openssl.org>"
.align	16
`;
}

genMul1x1();
genMul2x2();

export default translateAssembly(code);
