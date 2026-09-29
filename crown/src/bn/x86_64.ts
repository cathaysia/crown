/**
 * bn_mul_mont for x86_64.
 *
 * TypeScript port of OpenSSL crypto/bn/asm/x86_64-mont.pl.
 * Copyright 2005-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 Reference configuration: default `elf` output. `bn_mul_mont` dispatches
 on the operand count in-register (4 limbs takes the special BMI2/ADX-free
 path; 6/8/12.../64 take the unrolled paths; other counts take the
 variable-length loop) and consults OPENSSL_ia32cap_P for the mont5
 gather5 shortcuts, which this build links against
 utils/cpuid's OPENSSL_ia32cap_P.
 Register map: rp=%rdi ap=%rsi bp=%rdx np=%rcx n0p=%r8 num=%r9d;
 %rbx/%rbp/%r12-%r15 callee-saved; %r10-%r11 scratch.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

/**
 * bn_mul_mont for x86_64.
 *
 * TypeScript port of OpenSSL crypto/bn/asm/x86_64-mont.pl.
 * Copyright 2005-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Reference configuration: default `elf` output with the perl's
 * `$ENV{CC}` assembler probe succeeding (`$addx=1`; ADX/BMI2 forms).
 * `bn_mul_mont` dispatches on the operand count in-register (4 limbs
 * takes the special path; 6/8/12.../64 take unrolled paths; other counts
 * take the variable-length loop) and consults OPENSSL_ia32cap_P (linked
 * from utils/cpuid) for the mont5 gather5 shortcuts.
 * Register map: rp=%rdi ap=%rsi bp=%rdx np=%rcx n0p=%r8 num=%r9d;
 * %rbx/%rbp/%r12-%r15 callee-saved; %r10-%r11 scratch.
 */

const code = `.text



.globl	bn_mul_mont
.type	bn_mul_mont,@function
.align	16
bn_mul_mont:
.cfi_startproc
	movl	%r9d,%r9d
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
	testl	$3,%r9d
	jnz	.Lmul_enter
	cmpl	$8,%r9d
	jb	.Lmul_enter
	movl	OPENSSL_ia32cap_P+8(%rip),%r11d
	cmp	%rsi,%rdx
	jne	.Lmul4x_enter
	testl	$7,%r9d
	jz	.Lsqr8x_enter
	jmp	.Lmul4x_enter

.align	16
.Lmul_enter:
	pushq	%rbx
.cfi_offset	%rbx,-16
	pushq	%rbp
.cfi_offset	%rbp,-24
	pushq	%r12
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_offset	%r15,-56

	negq	%r9
	mov	%rsp,%r11
	lea	-16(%rsp,%r9,8),%r10
	negq	%r9
	and	$-1024,%r10









	sub	%r10,%r11
	and	$-4096,%r11
	lea	(%r10,%r11,1),%rsp
	mov	(%rsp),%r11
	cmp	%r10,%rsp
	ja	.Lmul_page_walk
	jmp	.Lmul_page_walk_done

.align	16
.Lmul_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r11
	cmp	%r10,%rsp
	ja	.Lmul_page_walk
.Lmul_page_walk_done:

	mov	%rax,8(%rsp,%r9,8)
.cfi_escape	0x0f,0x0a,0x77,0x08,0x79,0x00,0x38,0x1e,0x22,0x06,0x23,0x08
.Lmul_body:
	mov	%rdx,%r12
	mov	(%r8),%r8
	mov	(%r12),%rbx
	mov	(%rsi),%rax

	xor	%r14,%r14
	xor	%r15,%r15

	mov	%r8,%rbp
	mulq	%rbx
	mov	%rax,%r10
	mov	(%rcx),%rax

	imul	%r10,%rbp
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r10
	mov	8(%rsi),%rax
	adc	$0,%rdx
	mov	%rdx,%r13

	lea	1(%r15),%r15
	jmp	.L1st_enter

.align	16
.L1st:
	add	%rax,%r13
	mov	(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r11,%r13
	mov	%r10,%r11
	adc	$0,%rdx
	mov	%r13,-16(%rsp,%r15,8)
	mov	%rdx,%r13

.L1st_enter:
	mulq	%rbx
	add	%rax,%r11
	mov	(%rcx,%r15,8),%rax
	adc	$0,%rdx
	lea	1(%r15),%r15
	mov	%rdx,%r10

	mulq	%rbp
	cmp	%r9,%r15
	jne	.L1st

	add	%rax,%r13
	mov	(%rsi),%rax
	adc	$0,%rdx
	add	%r11,%r13
	adc	$0,%rdx
	mov	%r13,-16(%rsp,%r15,8)
	mov	%rdx,%r13
	mov	%r10,%r11

	xor	%rdx,%rdx
	add	%r11,%r13
	adc	$0,%rdx
	mov	%r13,-8(%rsp,%r9,8)
	mov	%rdx,(%rsp,%r9,8)

	lea	1(%r14),%r14
	jmp	.Louter
.align	16
.Louter:
	mov	(%r12,%r14,8),%rbx
	xor	%r15,%r15
	mov	%r8,%rbp
	mov	(%rsp),%r10
	mulq	%rbx
	add	%rax,%r10
	mov	(%rcx),%rax
	adc	$0,%rdx

	imul	%r10,%rbp
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r10
	mov	8(%rsi),%rax
	adc	$0,%rdx
	mov	8(%rsp),%r10
	mov	%rdx,%r13

	lea	1(%r15),%r15
	jmp	.Linner_enter

.align	16
.Linner:
	add	%rax,%r13
	mov	(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r10,%r13
	mov	(%rsp,%r15,8),%r10
	adc	$0,%rdx
	mov	%r13,-16(%rsp,%r15,8)
	mov	%rdx,%r13

.Linner_enter:
	mulq	%rbx
	add	%rax,%r11
	mov	(%rcx,%r15,8),%rax
	adc	$0,%rdx
	add	%r11,%r10
	mov	%rdx,%r11
	adc	$0,%r11
	lea	1(%r15),%r15

	mulq	%rbp
	cmp	%r9,%r15
	jne	.Linner

	add	%rax,%r13
	mov	(%rsi),%rax
	adc	$0,%rdx
	add	%r10,%r13
	mov	(%rsp,%r15,8),%r10
	adc	$0,%rdx
	mov	%r13,-16(%rsp,%r15,8)
	mov	%rdx,%r13

	xor	%rdx,%rdx
	add	%r11,%r13
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-8(%rsp,%r9,8)
	mov	%rdx,(%rsp,%r9,8)

	lea	1(%r14),%r14
	cmp	%r9,%r14
	jb	.Louter

	xor	%r14,%r14
	mov	(%rsp),%rax
	mov	%r9,%r15

.align	16
.Lsub:	sbbq	(%rcx,%r14,8),%rax
	mov	%rax,(%rdi,%r14,8)
	mov	8(%rsp,%r14,8),%rax
	lea	1(%r14),%r14
	decq	%r15
	jnz	.Lsub

	sbb	$0,%rax
	mov	$-1,%rbx
	xor	%rax,%rbx
	xor	%r14,%r14
	mov	%r9,%r15

.Lcopy:
	mov	(%rdi,%r14,8),%rcx
	mov	(%rsp,%r14,8),%rdx
	and	%rbx,%rcx
	and	%rax,%rdx
	mov	%r9,(%rsp,%r14,8)
	or	%rcx,%rdx
	mov	%rdx,(%rdi,%r14,8)
	lea	1(%r14),%r14
	sub	$1,%r15
	jnz	.Lcopy

	mov	8(%rsp,%r9,8),%rsi
.cfi_def_cfa	%rsi,8
	mov	$1,%rax
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
.Lmul_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	bn_mul_mont,.-bn_mul_mont
.type	bn_mul4x_mont,@function
.align	16
bn_mul4x_mont:
.cfi_startproc
	movl	%r9d,%r9d
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
.Lmul4x_enter:
	andl	$0x80100,%r11d
	cmpl	$0x80100,%r11d
	je	.Lmulx4x_enter
	pushq	%rbx
.cfi_offset	%rbx,-16
	pushq	%rbp
.cfi_offset	%rbp,-24
	pushq	%r12
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_offset	%r15,-56

	negq	%r9
	mov	%rsp,%r11
	lea	-32(%rsp,%r9,8),%r10
	negq	%r9
	and	$-1024,%r10

	sub	%r10,%r11
	and	$-4096,%r11
	lea	(%r10,%r11,1),%rsp
	mov	(%rsp),%r11
	cmp	%r10,%rsp
	ja	.Lmul4x_page_walk
	jmp	.Lmul4x_page_walk_done

.Lmul4x_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r11
	cmp	%r10,%rsp
	ja	.Lmul4x_page_walk
.Lmul4x_page_walk_done:

	mov	%rax,8(%rsp,%r9,8)
.cfi_escape	0x0f,0x0a,0x77,0x08,0x79,0x00,0x38,0x1e,0x22,0x06,0x23,0x08
.Lmul4x_body:
	mov	%rdi,16(%rsp,%r9,8)
	mov	%rdx,%r12
	mov	(%r8),%r8
	mov	(%r12),%rbx
	mov	(%rsi),%rax

	xor	%r14,%r14
	xor	%r15,%r15

	mov	%r8,%rbp
	mulq	%rbx
	mov	%rax,%r10
	mov	(%rcx),%rax

	imul	%r10,%rbp
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r10
	mov	8(%rsi),%rax
	adc	$0,%rdx
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	8(%rcx),%rax
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	16(%rsi),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	lea	4(%r15),%r15
	adc	$0,%rdx
	mov	%rdi,(%rsp)
	mov	%rdx,%r13
	jmp	.L1st4x
.align	16
.L1st4x:
	mulq	%rbx
	add	%rax,%r10
	mov	-16(%rcx,%r15,8),%rax
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	-8(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-24(%rsp,%r15,8)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	-8(%rcx,%r15,8),%rax
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%rdi,-16(%rsp,%r15,8)
	mov	%rdx,%r13

	mulq	%rbx
	add	%rax,%r10
	mov	(%rcx,%r15,8),%rax
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	8(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-8(%rsp,%r15,8)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	8(%rcx,%r15,8),%rax
	adc	$0,%rdx
	lea	4(%r15),%r15
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	-16(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%rdi,-32(%rsp,%r15,8)
	mov	%rdx,%r13
	cmp	%r9,%r15
	jb	.L1st4x

	mulq	%rbx
	add	%rax,%r10
	mov	-16(%rcx,%r15,8),%rax
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	-8(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-24(%rsp,%r15,8)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	-8(%rcx,%r15,8),%rax
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	(%rsi),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%rdi,-16(%rsp,%r15,8)
	mov	%rdx,%r13

	xor	%rdi,%rdi
	add	%r10,%r13
	adc	$0,%rdi
	mov	%r13,-8(%rsp,%r15,8)
	mov	%rdi,(%rsp,%r15,8)

	lea	1(%r14),%r14
.align	4
.Louter4x:
	mov	(%r12,%r14,8),%rbx
	xor	%r15,%r15
	mov	(%rsp),%r10
	mov	%r8,%rbp
	mulq	%rbx
	add	%rax,%r10
	mov	(%rcx),%rax
	adc	$0,%rdx

	imul	%r10,%rbp
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r10
	mov	8(%rsi),%rax
	adc	$0,%rdx
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	8(%rcx),%rax
	adc	$0,%rdx
	add	8(%rsp),%r11
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	16(%rsi),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	lea	4(%r15),%r15
	adc	$0,%rdx
	mov	%rdi,(%rsp)
	mov	%rdx,%r13
	jmp	.Linner4x
.align	16
.Linner4x:
	mulq	%rbx
	add	%rax,%r10
	mov	-16(%rcx,%r15,8),%rax
	adc	$0,%rdx
	add	-16(%rsp,%r15,8),%r10
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	-8(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-24(%rsp,%r15,8)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	-8(%rcx,%r15,8),%rax
	adc	$0,%rdx
	add	-8(%rsp,%r15,8),%r11
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%rdi,-16(%rsp,%r15,8)
	mov	%rdx,%r13

	mulq	%rbx
	add	%rax,%r10
	mov	(%rcx,%r15,8),%rax
	adc	$0,%rdx
	add	(%rsp,%r15,8),%r10
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	8(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-8(%rsp,%r15,8)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	8(%rcx,%r15,8),%rax
	adc	$0,%rdx
	add	8(%rsp,%r15,8),%r11
	adc	$0,%rdx
	lea	4(%r15),%r15
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	-16(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%rdi,-32(%rsp,%r15,8)
	mov	%rdx,%r13
	cmp	%r9,%r15
	jb	.Linner4x

	mulq	%rbx
	add	%rax,%r10
	mov	-16(%rcx,%r15,8),%rax
	adc	$0,%rdx
	add	-16(%rsp,%r15,8),%r10
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	-8(%rsi,%r15,8),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-24(%rsp,%r15,8)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	-8(%rcx,%r15,8),%rax
	adc	$0,%rdx
	add	-8(%rsp,%r15,8),%r11
	adc	$0,%rdx
	lea	1(%r14),%r14
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	(%rsi),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%rdi,-16(%rsp,%r15,8)
	mov	%rdx,%r13

	xor	%rdi,%rdi
	add	%r10,%r13
	adc	$0,%rdi
	add	(%rsp,%r9,8),%r13
	adc	$0,%rdi
	mov	%r13,-8(%rsp,%r15,8)
	mov	%rdi,(%rsp,%r15,8)

	cmp	%r9,%r14
	jb	.Louter4x
	mov	16(%rsp,%r9,8),%rdi
	lea	-4(%r9),%r15
	mov	0(%rsp),%rax
	mov	8(%rsp),%rdx
	shrq	$2,%r15
	lea	(%rsp),%rsi
	xor	%r14,%r14

	sub	0(%rcx),%rax
	mov	16(%rsi),%rbx
	mov	24(%rsi),%rbp
	sbb	8(%rcx),%rdx

.Lsub4x:
	mov	%rax,0(%rdi,%r14,8)
	mov	%rdx,8(%rdi,%r14,8)
	sbb	16(%rcx,%r14,8),%rbx
	mov	32(%rsi,%r14,8),%rax
	mov	40(%rsi,%r14,8),%rdx
	sbb	24(%rcx,%r14,8),%rbp
	mov	%rbx,16(%rdi,%r14,8)
	mov	%rbp,24(%rdi,%r14,8)
	sbb	32(%rcx,%r14,8),%rax
	mov	48(%rsi,%r14,8),%rbx
	mov	56(%rsi,%r14,8),%rbp
	sbb	40(%rcx,%r14,8),%rdx
	lea	4(%r14),%r14
	decq	%r15
	jnz	.Lsub4x

	mov	%rax,0(%rdi,%r14,8)
	mov	32(%rsi,%r14,8),%rax
	sbb	16(%rcx,%r14,8),%rbx
	mov	%rdx,8(%rdi,%r14,8)
	sbb	24(%rcx,%r14,8),%rbp
	mov	%rbx,16(%rdi,%r14,8)

	sbb	$0,%rax
	mov	%rbp,24(%rdi,%r14,8)
	pxor	%xmm0,%xmm0
.byte	102,72,15,110,224
	pcmpeqd	%xmm5,%xmm5
	pshufd	$0,%xmm4,%xmm4
	mov	%r9,%r15
	pxor	%xmm4,%xmm5
	shrq	$2,%r15
	xor	%eax,%eax

	jmp	.Lcopy4x
.align	16
.Lcopy4x:
	movdqa	(%rsp,%rax,1),%xmm1
	movdqu	(%rdi,%rax,1),%xmm2
	pand	%xmm4,%xmm1
	pand	%xmm5,%xmm2
	movdqa	16(%rsp,%rax,1),%xmm3
	movdqa	%xmm0,(%rsp,%rax,1)
	por	%xmm2,%xmm1
	movdqu	16(%rdi,%rax,1),%xmm2
	movdqu	%xmm1,(%rdi,%rax,1)
	pand	%xmm4,%xmm3
	pand	%xmm5,%xmm2
	movdqa	%xmm0,16(%rsp,%rax,1)
	por	%xmm2,%xmm3
	movdqu	%xmm3,16(%rdi,%rax,1)
	lea	32(%rax),%rax
	decq	%r15
	jnz	.Lcopy4x
	mov	8(%rsp,%r9,8),%rsi
.cfi_def_cfa	%rsi, 8
	mov	$1,%rax
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
.Lmul4x_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	bn_mul4x_mont,.-bn_mul4x_mont



.type	bn_sqr8x_mont,@function
.align	32
bn_sqr8x_mont:
.cfi_startproc
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
.Lsqr8x_enter:
	pushq	%rbx
.cfi_offset	%rbx,-16
	pushq	%rbp
.cfi_offset	%rbp,-24
	pushq	%r12
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_offset	%r15,-56
.Lsqr8x_prologue:

	movl	%r9d,%r10d
	shll	$3,%r9d
	shlq	$3+2,%r10
	negq	%r9






	lea	-64(%rsp,%r9,2),%r11
	mov	%rsp,%rbp
	mov	(%r8),%r8
	sub	%rsi,%r11
	and	$4095,%r11
	cmp	%r11,%r10
	jb	.Lsqr8x_sp_alt
	sub	%r11,%rbp
	lea	-64(%rbp,%r9,2),%rbp
	jmp	.Lsqr8x_sp_done

.align	32
.Lsqr8x_sp_alt:
	lea	4096-64(,%r9,2),%r10
	lea	-64(%rbp,%r9,2),%rbp
	sub	%r10,%r11
	mov	$0,%r10
	cmovc	%r10,%r11
	sub	%r11,%rbp
.Lsqr8x_sp_done:
	and	$-64,%rbp
	mov	%rsp,%r11
	sub	%rbp,%r11
	and	$-4096,%r11
	lea	(%r11,%rbp,1),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lsqr8x_page_walk
	jmp	.Lsqr8x_page_walk_done

.align	16
.Lsqr8x_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lsqr8x_page_walk
.Lsqr8x_page_walk_done:

	mov	%r9,%r10
	negq	%r9

	mov	%r8,32(%rsp)
	mov	%rax,40(%rsp)
.cfi_escape	0x0f,0x05,0x77,0x28,0x06,0x23,0x08
.Lsqr8x_body:

.byte	102,72,15,110,209
	pxor	%xmm0,%xmm0
.byte	102,72,15,110,207
.byte	102,73,15,110,218
	mov	OPENSSL_ia32cap_P+8(%rip),%eax
	and	$0x80100,%eax
	cmp	$0x80100,%eax
	jne	.Lsqr8x_nox

	call	bn_sqrx8x_internal




	lea	(%r8,%rcx,1),%rbx
	mov	%rcx,%r9
	mov	%rcx,%rdx
.byte	102,72,15,126,207
	sarq	$3+2,%rcx
	jmp	.Lsqr8x_sub

.align	32
.Lsqr8x_nox:
	call	bn_sqr8x_internal




	lea	(%rdi,%r9,1),%rbx
	mov	%r9,%rcx
	mov	%r9,%rdx
.byte	102,72,15,126,207
	sarq	$3+2,%rcx
	jmp	.Lsqr8x_sub

.align	32
.Lsqr8x_sub:
	mov	0(%rbx),%r12
	mov	8(%rbx),%r13
	mov	16(%rbx),%r14
	mov	24(%rbx),%r15
	lea	32(%rbx),%rbx
	sbb	0(%rbp),%r12
	sbb	8(%rbp),%r13
	sbb	16(%rbp),%r14
	sbb	24(%rbp),%r15
	lea	32(%rbp),%rbp
	mov	%r12,0(%rdi)
	mov	%r13,8(%rdi)
	mov	%r14,16(%rdi)
	mov	%r15,24(%rdi)
	lea	32(%rdi),%rdi
	incq	%rcx
	jnz	.Lsqr8x_sub

	sbb	$0,%rax
	lea	(%rbx,%r9,1),%rbx
	lea	(%rdi,%r9,1),%rdi

.byte	102,72,15,110,200
	pxor	%xmm0,%xmm0
	pshufd	$0,%xmm1,%xmm1
	mov	40(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	jmp	.Lsqr8x_cond_copy

.align	32
.Lsqr8x_cond_copy:
	movdqa	0(%rbx),%xmm2
	movdqa	16(%rbx),%xmm3
	lea	32(%rbx),%rbx
	movdqu	0(%rdi),%xmm4
	movdqu	16(%rdi),%xmm5
	lea	32(%rdi),%rdi
	movdqa	%xmm0,-32(%rbx)
	movdqa	%xmm0,-16(%rbx)
	movdqa	%xmm0,-32(%rbx,%rdx,1)
	movdqa	%xmm0,-16(%rbx,%rdx,1)
	pcmpeqd	%xmm1,%xmm0
	pand	%xmm1,%xmm2
	pand	%xmm1,%xmm3
	pand	%xmm0,%xmm4
	pand	%xmm0,%xmm5
	pxor	%xmm0,%xmm0
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqu	%xmm4,-32(%rdi)
	movdqu	%xmm5,-16(%rdi)
	add	$32,%r9
	jnz	.Lsqr8x_cond_copy

	mov	$1,%rax
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
.Lsqr8x_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	bn_sqr8x_mont,.-bn_sqr8x_mont
.type	bn_mulx4x_mont,@function
.align	32
bn_mulx4x_mont:
.cfi_startproc
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
.Lmulx4x_enter:
	pushq	%rbx
.cfi_offset	%rbx,-16
	pushq	%rbp
.cfi_offset	%rbp,-24
	pushq	%r12
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_offset	%r15,-56
.Lmulx4x_prologue:

	shll	$3,%r9d
	xor	%r10,%r10
	sub	%r9,%r10
	mov	(%r8),%r8
	lea	-72(%rsp,%r10,1),%rbp
	and	$-128,%rbp
	mov	%rsp,%r11
	sub	%rbp,%r11
	and	$-4096,%r11
	lea	(%r11,%rbp,1),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lmulx4x_page_walk
	jmp	.Lmulx4x_page_walk_done

.align	16
.Lmulx4x_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lmulx4x_page_walk
.Lmulx4x_page_walk_done:

	lea	(%rdx,%r9,1),%r10












	mov	%r9,0(%rsp)
	shrq	$5,%r9
	mov	%r10,16(%rsp)
	sub	$1,%r9
	mov	%r8,24(%rsp)
	mov	%rdi,32(%rsp)
	mov	%rax,40(%rsp)
.cfi_escape	0x0f,0x05,0x77,0x28,0x06,0x23,0x08
	mov	%r9,48(%rsp)
	jmp	.Lmulx4x_body

.align	32
.Lmulx4x_body:
	lea	8(%rdx),%rdi
	mov	(%rdx),%rdx
	lea	64+32(%rsp),%rbx
	mov	%rdx,%r9

	mulxq	0(%rsi),%r8,%rax
	mulxq	8(%rsi),%r11,%r14
	add	%rax,%r11
	mov	%rdi,8(%rsp)
	mulxq	16(%rsi),%r12,%r13
	adc	%r14,%r12
	adc	$0,%r13

	mov	%r8,%rdi
	imul	24(%rsp),%r8
	xor	%rbp,%rbp

	mulxq	24(%rsi),%rax,%r14
	mov	%r8,%rdx
	lea	32(%rsi),%rsi
	adcxq	%rax,%r13
	adcxq	%rbp,%r14

	mulxq	0(%rcx),%rax,%r10
	adcxq	%rax,%rdi
	adoxq	%r11,%r10
	mulxq	8(%rcx),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11
.byte	0xc4,0x62,0xfb,0xf6,0xa1,0x10,0x00,0x00,0x00
	mov	48(%rsp),%rdi
	mov	%r10,-32(%rbx)
	adcxq	%rax,%r11
	adoxq	%r13,%r12
	mulxq	24(%rcx),%rax,%r15
	mov	%r9,%rdx
	mov	%r11,-24(%rbx)
	adcxq	%rax,%r12
	adoxq	%rbp,%r15
	lea	32(%rcx),%rcx
	mov	%r12,-16(%rbx)

	jmp	.Lmulx4x_1st

.align	32
.Lmulx4x_1st:
	adcxq	%rbp,%r15
	mulxq	0(%rsi),%r10,%rax
	adcxq	%r14,%r10
	mulxq	8(%rsi),%r11,%r14
	adcxq	%rax,%r11
	mulxq	16(%rsi),%r12,%rax
	adcxq	%r14,%r12
	mulxq	24(%rsi),%r13,%r14
.byte	0x67,0x67
	mov	%r8,%rdx
	adcxq	%rax,%r13
	adcxq	%rbp,%r14
	lea	32(%rsi),%rsi
	lea	32(%rbx),%rbx

	adoxq	%r15,%r10
	mulxq	0(%rcx),%rax,%r15
	adcxq	%rax,%r10
	adoxq	%r15,%r11
	mulxq	8(%rcx),%rax,%r15
	adcxq	%rax,%r11
	adoxq	%r15,%r12
	mulxq	16(%rcx),%rax,%r15
	mov	%r10,-40(%rbx)
	adcxq	%rax,%r12
	mov	%r11,-32(%rbx)
	adoxq	%r15,%r13
	mulxq	24(%rcx),%rax,%r15
	mov	%r9,%rdx
	mov	%r12,-24(%rbx)
	adcxq	%rax,%r13
	adoxq	%rbp,%r15
	lea	32(%rcx),%rcx
	mov	%r13,-16(%rbx)

	decq	%rdi
	jnz	.Lmulx4x_1st

	mov	0(%rsp),%rax
	mov	8(%rsp),%rdi
	adc	%rbp,%r15
	add	%r15,%r14
	sbb	%r15,%r15
	mov	%r14,-8(%rbx)
	jmp	.Lmulx4x_outer

.align	32
.Lmulx4x_outer:
	mov	(%rdi),%rdx
	lea	8(%rdi),%rdi
	sub	%rax,%rsi
	mov	%r15,(%rbx)
	lea	64+32(%rsp),%rbx
	sub	%rax,%rcx

	mulxq	0(%rsi),%r8,%r11
	xor	%ebp,%ebp
	mov	%rdx,%r9
	mulxq	8(%rsi),%r14,%r12
	adoxq	-32(%rbx),%r8
	adcxq	%r14,%r11
	mulxq	16(%rsi),%r15,%r13
	adoxq	-24(%rbx),%r11
	adcxq	%r15,%r12
	adoxq	-16(%rbx),%r12
	adcxq	%rbp,%r13
	adoxq	%rbp,%r13

	mov	%rdi,8(%rsp)
	mov	%r8,%r15
	imul	24(%rsp),%r8
	xor	%ebp,%ebp

	mulxq	24(%rsi),%rax,%r14
	mov	%r8,%rdx
	adcxq	%rax,%r13
	adoxq	-8(%rbx),%r13
	adcxq	%rbp,%r14
	lea	32(%rsi),%rsi
	adoxq	%rbp,%r14

	mulxq	0(%rcx),%rax,%r10
	adcxq	%rax,%r15
	adoxq	%r11,%r10
	mulxq	8(%rcx),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11
	mulxq	16(%rcx),%rax,%r12
	mov	%r10,-32(%rbx)
	adcxq	%rax,%r11
	adoxq	%r13,%r12
	mulxq	24(%rcx),%rax,%r15
	mov	%r9,%rdx
	mov	%r11,-24(%rbx)
	lea	32(%rcx),%rcx
	adcxq	%rax,%r12
	adoxq	%rbp,%r15
	mov	48(%rsp),%rdi
	mov	%r12,-16(%rbx)

	jmp	.Lmulx4x_inner

.align	32
.Lmulx4x_inner:
	mulxq	0(%rsi),%r10,%rax
	adcxq	%rbp,%r15
	adoxq	%r14,%r10
	mulxq	8(%rsi),%r11,%r14
	adcxq	0(%rbx),%r10
	adoxq	%rax,%r11
	mulxq	16(%rsi),%r12,%rax
	adcxq	8(%rbx),%r11
	adoxq	%r14,%r12
	mulxq	24(%rsi),%r13,%r14
	mov	%r8,%rdx
	adcxq	16(%rbx),%r12
	adoxq	%rax,%r13
	adcxq	24(%rbx),%r13
	adoxq	%rbp,%r14
	lea	32(%rsi),%rsi
	lea	32(%rbx),%rbx
	adcxq	%rbp,%r14

	adoxq	%r15,%r10
	mulxq	0(%rcx),%rax,%r15
	adcxq	%rax,%r10
	adoxq	%r15,%r11
	mulxq	8(%rcx),%rax,%r15
	adcxq	%rax,%r11
	adoxq	%r15,%r12
	mulxq	16(%rcx),%rax,%r15
	mov	%r10,-40(%rbx)
	adcxq	%rax,%r12
	adoxq	%r15,%r13
	mulxq	24(%rcx),%rax,%r15
	mov	%r9,%rdx
	mov	%r11,-32(%rbx)
	mov	%r12,-24(%rbx)
	adcxq	%rax,%r13
	adoxq	%rbp,%r15
	lea	32(%rcx),%rcx
	mov	%r13,-16(%rbx)

	decq	%rdi
	jnz	.Lmulx4x_inner

	mov	0(%rsp),%rax
	mov	8(%rsp),%rdi
	adc	%rbp,%r15
	sub	0(%rbx),%rbp
	adc	%r15,%r14
	sbb	%r15,%r15
	mov	%r14,-8(%rbx)

	cmp	16(%rsp),%rdi
	jne	.Lmulx4x_outer

	lea	64(%rsp),%rbx
	sub	%rax,%rcx
	negq	%r15
	mov	%rax,%rdx
	shrq	$3+2,%rax
	mov	32(%rsp),%rdi
	jmp	.Lmulx4x_sub

.align	32
.Lmulx4x_sub:
	mov	0(%rbx),%r11
	mov	8(%rbx),%r12
	mov	16(%rbx),%r13
	mov	24(%rbx),%r14
	lea	32(%rbx),%rbx
	sbb	0(%rcx),%r11
	sbb	8(%rcx),%r12
	sbb	16(%rcx),%r13
	sbb	24(%rcx),%r14
	lea	32(%rcx),%rcx
	mov	%r11,0(%rdi)
	mov	%r12,8(%rdi)
	mov	%r13,16(%rdi)
	mov	%r14,24(%rdi)
	lea	32(%rdi),%rdi
	decq	%rax
	jnz	.Lmulx4x_sub

	sbb	$0,%r15
	lea	64(%rsp),%rbx
	sub	%rdx,%rdi

.byte	102,73,15,110,207
	pxor	%xmm0,%xmm0
	pshufd	$0,%xmm1,%xmm1
	mov	40(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	jmp	.Lmulx4x_cond_copy

.align	32
.Lmulx4x_cond_copy:
	movdqa	0(%rbx),%xmm2
	movdqa	16(%rbx),%xmm3
	lea	32(%rbx),%rbx
	movdqu	0(%rdi),%xmm4
	movdqu	16(%rdi),%xmm5
	lea	32(%rdi),%rdi
	movdqa	%xmm0,-32(%rbx)
	movdqa	%xmm0,-16(%rbx)
	pcmpeqd	%xmm1,%xmm0
	pand	%xmm1,%xmm2
	pand	%xmm1,%xmm3
	pand	%xmm0,%xmm4
	pand	%xmm0,%xmm5
	pxor	%xmm0,%xmm0
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqu	%xmm4,-32(%rdi)
	movdqu	%xmm5,-16(%rdi)
	sub	$32,%rdx
	jnz	.Lmulx4x_cond_copy

	mov	%rdx,(%rbx)

	mov	$1,%rax
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
.Lmulx4x_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	bn_mulx4x_mont,.-bn_mulx4x_mont
.byte	77,111,110,116,103,111,109,101,114,121,32,77,117,108,116,105,112,108,105,99,97,116,105,111,110,32,102,111,114,32,120,56,54,95,54,52,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,104,116,116,112,115,58,47,47,103,105,116,104,117,98,46,99,111,109,47,100,111,116,45,97,115,109,62,0
.align	16
	.section ".note.gnu.property", "a"
	.p2align 3
	.long 1f - 0f
	.long 4f - 1f
	.long 5
0:
	# "GNU" encoded with .byte, since .asciz isn't supported
	# on Solaris.
	.byte 0x47
	.byte 0x4e
	.byte 0x55
	.byte 0
1:
	.p2align 3
	.long 0xc0000002
	.long 3f - 2f
2:
	.long 3
3:
	.p2align 3
4:
`;

export default translateAssembly(code);
