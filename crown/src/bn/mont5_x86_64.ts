/**
 * bn_mul_mont_gather5 / bn_power5 for x86_64 (RSA modexp).
 *
 * TypeScript port of OpenSSL crypto/bn/asm/x86_64-mont5.pl.
 * Copyright 2011-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Reference configuration: default `elf` output with the perl's
 * assembler probe succeeding (`$addx=1`). Also provides
 * `bn_sqr8x_internal`/`bn_sqrx8x_internal`, the internal continuations
 * referenced by x86_64-mont.pl's `bn_sqr8x_mont` (the two modules are
 * separate translation units in OpenSSL, so the `.L` label namespaces
 * don't collide; this file is compiled through its own `global_asm!`).
 *
 * Register map: rp=%rdi ap=%rsi bp=%rdx np=%rcx n0p=%r8 num=%r9d
 * (bn_power5 consumes the power table built by bn_scatter5/bn_gather5).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text	



.globl	bn_mul_mont_gather5
.type	bn_mul_mont_gather5,@function
.align	64
bn_mul_mont_gather5:
.cfi_startproc	
	movl	%r9d,%r9d
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
	testl	$7,%r9d
	jnz	.Lmul_enter
	movl	OPENSSL_ia32cap_P+8(%rip),%r11d
	jmp	.Lmul4x_enter

.align	16
.Lmul_enter:
	movd	8(%rsp),%xmm5
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
	lea	-280(%rsp,%r9,8),%r10
	negq	%r9
	and	$-1024,%r10









	sub	%r10,%r11
	and	$-4096,%r11
	lea	(%r10,%r11,1),%rsp
	mov	(%rsp),%r11
	cmp	%r10,%rsp
	ja	.Lmul_page_walk
	jmp	.Lmul_page_walk_done

.Lmul_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r11
	cmp	%r10,%rsp
	ja	.Lmul_page_walk
.Lmul_page_walk_done:

	lea	.Linc(%rip),%r10
	mov	%rax,8(%rsp,%r9,8)
.cfi_escape	0x0f,0x0a,0x77,0x08,0x79,0x00,0x38,0x1e,0x22,0x06,0x23,0x08
.Lmul_body:

	lea	128(%rdx),%r12
	movdqa	0(%r10),%xmm0
	movdqa	16(%r10),%xmm1
	lea	24-112(%rsp,%r9,8),%r10
	and	$-16,%r10

	pshufd	$0,%xmm5,%xmm5
	movdqa	%xmm1,%xmm4
	movdqa	%xmm1,%xmm2
	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
.byte	0x67
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,112(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,128(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,144(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,160(%r10)
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,176(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,192(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,208(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,224(%r10)
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,240(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,256(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,272(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,288(%r10)
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,304(%r10)

	paddd	%xmm2,%xmm3
.byte	0x67
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,320(%r10)

	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,336(%r10)
	pand	64(%r12),%xmm0

	pand	80(%r12),%xmm1
	pand	96(%r12),%xmm2
	movdqa	%xmm3,352(%r10)
	pand	112(%r12),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	-128(%r12),%xmm4
	movdqa	-112(%r12),%xmm5
	movdqa	-96(%r12),%xmm2
	pand	112(%r10),%xmm4
	movdqa	-80(%r12),%xmm3
	pand	128(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	144(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	160(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	-64(%r12),%xmm4
	movdqa	-48(%r12),%xmm5
	movdqa	-32(%r12),%xmm2
	pand	176(%r10),%xmm4
	movdqa	-16(%r12),%xmm3
	pand	192(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	208(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	224(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	0(%r12),%xmm4
	movdqa	16(%r12),%xmm5
	movdqa	32(%r12),%xmm2
	pand	240(%r10),%xmm4
	movdqa	48(%r12),%xmm3
	pand	256(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	272(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	288(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	por	%xmm1,%xmm0
	pshufd	$0x4e,%xmm0,%xmm1
	por	%xmm1,%xmm0
	lea	256(%r12),%r12
.byte	102,72,15,126,195

	mov	(%r8),%r8
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
	adc	$0,%rdx
	add	%r11,%r13
	adc	$0,%rdx
	mov	%r13,-16(%rsp,%r9,8)
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
	lea	24+128(%rsp,%r9,8),%rdx
	and	$-16,%rdx
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	movdqa	-128(%r12),%xmm0
	movdqa	-112(%r12),%xmm1
	movdqa	-96(%r12),%xmm2
	movdqa	-80(%r12),%xmm3
	pand	-128(%rdx),%xmm0
	pand	-112(%rdx),%xmm1
	por	%xmm0,%xmm4
	pand	-96(%rdx),%xmm2
	por	%xmm1,%xmm5
	pand	-80(%rdx),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	-64(%r12),%xmm0
	movdqa	-48(%r12),%xmm1
	movdqa	-32(%r12),%xmm2
	movdqa	-16(%r12),%xmm3
	pand	-64(%rdx),%xmm0
	pand	-48(%rdx),%xmm1
	por	%xmm0,%xmm4
	pand	-32(%rdx),%xmm2
	por	%xmm1,%xmm5
	pand	-16(%rdx),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	0(%r12),%xmm0
	movdqa	16(%r12),%xmm1
	movdqa	32(%r12),%xmm2
	movdqa	48(%r12),%xmm3
	pand	0(%rdx),%xmm0
	pand	16(%rdx),%xmm1
	por	%xmm0,%xmm4
	pand	32(%rdx),%xmm2
	por	%xmm1,%xmm5
	pand	48(%rdx),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	64(%r12),%xmm0
	movdqa	80(%r12),%xmm1
	movdqa	96(%r12),%xmm2
	movdqa	112(%r12),%xmm3
	pand	64(%rdx),%xmm0
	pand	80(%rdx),%xmm1
	por	%xmm0,%xmm4
	pand	96(%rdx),%xmm2
	por	%xmm1,%xmm5
	pand	112(%rdx),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	por	%xmm5,%xmm4
	pshufd	$0x4e,%xmm4,%xmm0
	por	%xmm4,%xmm0
	lea	256(%r12),%r12

	mov	(%rsi),%rax
.byte	102,72,15,126,195

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
	adc	$0,%rdx
	add	%r10,%r13
	mov	(%rsp,%r9,8),%r10
	adc	$0,%rdx
	mov	%r13,-16(%rsp,%r9,8)
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
	lea	(%rsp),%rsi
	mov	%r9,%r15
	jmp	.Lsub
.align	16
.Lsub:	sbbq	(%rcx,%r14,8),%rax
	mov	%rax,(%rdi,%r14,8)
	mov	8(%rsi,%r14,8),%rax
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
	mov	%r14,(%rsp,%r14,8)
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
.size	bn_mul_mont_gather5,.-bn_mul_mont_gather5
.type	bn_mul4x_mont_gather5,@function
.align	32
bn_mul4x_mont_gather5:
.cfi_startproc	
.byte	0x67
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
.Lmul4x_enter:
	andl	$0x80108,%r11d
	cmpl	$0x80108,%r11d
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
.Lmul4x_prologue:

.byte	0x67
	shll	$3,%r9d
	lea	(%r9,%r9,2),%r10
	negq	%r9










	lea	-320(%rsp,%r9,2),%r11
	mov	%rsp,%rbp
	sub	%rdi,%r11
	and	$4095,%r11
	cmp	%r11,%r10
	jb	.Lmul4xsp_alt
	sub	%r11,%rbp
	lea	-320(%rbp,%r9,2),%rbp
	jmp	.Lmul4xsp_done

.align	32
.Lmul4xsp_alt:
	lea	4096-320(,%r9,2),%r10
	lea	-320(%rbp,%r9,2),%rbp
	sub	%r10,%r11
	mov	$0,%r10
	cmovc	%r10,%r11
	sub	%r11,%rbp
.Lmul4xsp_done:
	and	$-64,%rbp
	mov	%rsp,%r11
	sub	%rbp,%r11
	and	$-4096,%r11
	lea	(%r11,%rbp,1),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lmul4x_page_walk
	jmp	.Lmul4x_page_walk_done

.Lmul4x_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lmul4x_page_walk
.Lmul4x_page_walk_done:

	negq	%r9

	mov	%rax,40(%rsp)
.cfi_escape	0x0f,0x05,0x77,0x28,0x06,0x23,0x08
.Lmul4x_body:

	call	mul4x_internal

	mov	40(%rsp),%rsi
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
.Lmul4x_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc	
.size	bn_mul4x_mont_gather5,.-bn_mul4x_mont_gather5

.type	mul4x_internal,@function
.align	32
mul4x_internal:
.cfi_startproc	
	shlq	$5,%r9
	movd	8(%rax),%xmm5
	lea	.Linc(%rip),%rax
	lea	128(%rdx,%r9,1),%r13
	shrq	$5,%r9
	movdqa	0(%rax),%xmm0
	movdqa	16(%rax),%xmm1
	lea	88-112(%rsp,%r9,1),%r10
	lea	128(%rdx),%r12

	pshufd	$0,%xmm5,%xmm5
	movdqa	%xmm1,%xmm4
.byte	0x67,0x67
	movdqa	%xmm1,%xmm2
	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
.byte	0x67
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,112(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,128(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,144(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,160(%r10)
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,176(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,192(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,208(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,224(%r10)
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,240(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,256(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,272(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,288(%r10)
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,304(%r10)

	paddd	%xmm2,%xmm3
.byte	0x67
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,320(%r10)

	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,336(%r10)
	pand	64(%r12),%xmm0

	pand	80(%r12),%xmm1
	pand	96(%r12),%xmm2
	movdqa	%xmm3,352(%r10)
	pand	112(%r12),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	-128(%r12),%xmm4
	movdqa	-112(%r12),%xmm5
	movdqa	-96(%r12),%xmm2
	pand	112(%r10),%xmm4
	movdqa	-80(%r12),%xmm3
	pand	128(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	144(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	160(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	-64(%r12),%xmm4
	movdqa	-48(%r12),%xmm5
	movdqa	-32(%r12),%xmm2
	pand	176(%r10),%xmm4
	movdqa	-16(%r12),%xmm3
	pand	192(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	208(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	224(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	0(%r12),%xmm4
	movdqa	16(%r12),%xmm5
	movdqa	32(%r12),%xmm2
	pand	240(%r10),%xmm4
	movdqa	48(%r12),%xmm3
	pand	256(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	272(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	288(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	por	%xmm1,%xmm0
	pshufd	$0x4e,%xmm0,%xmm1
	por	%xmm1,%xmm0
	lea	256(%r12),%r12
.byte	102,72,15,126,195

	mov	%r13,16+8(%rsp)
	mov	%rdi,56+8(%rsp)

	mov	(%r8),%r8
	mov	(%rsi),%rax
	lea	(%rsi,%r9,1),%rsi
	negq	%r9

	mov	%r8,%rbp
	mulq	%rbx
	mov	%rax,%r10
	mov	(%rcx),%rax

	imul	%r10,%rbp
	lea	64+8(%rsp),%r14
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r10
	mov	8(%rsi,%r9,1),%rax
	adc	$0,%rdx
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	8(%rcx),%rax
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	16(%rsi,%r9,1),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	lea	32(%r9),%r15
	lea	32(%rcx),%rcx
	adc	$0,%rdx
	mov	%rdi,(%r14)
	mov	%rdx,%r13
	jmp	.L1st4x

.align	32
.L1st4x:
	mulq	%rbx
	add	%rax,%r10
	mov	-16(%rcx),%rax
	lea	32(%r14),%r14
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	-8(%rsi,%r15,1),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-24(%r14)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	-8(%rcx),%rax
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	(%rsi,%r15,1),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%rdi,-16(%r14)
	mov	%rdx,%r13

	mulq	%rbx
	add	%rax,%r10
	mov	0(%rcx),%rax
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	8(%rsi,%r15,1),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-8(%r14)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	8(%rcx),%rax
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	16(%rsi,%r15,1),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	lea	32(%rcx),%rcx
	adc	$0,%rdx
	mov	%rdi,(%r14)
	mov	%rdx,%r13

	add	$32,%r15
	jnz	.L1st4x

	mulq	%rbx
	add	%rax,%r10
	mov	-16(%rcx),%rax
	lea	32(%r14),%r14
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	-8(%rsi),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%r13,-24(%r14)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	-8(%rcx),%rax
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	(%rsi,%r9,1),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%rdi,-16(%r14)
	mov	%rdx,%r13

	lea	(%rcx,%r9,1),%rcx

	xor	%rdi,%rdi
	add	%r10,%r13
	adc	$0,%rdi
	mov	%r13,-8(%r14)

	jmp	.Louter4x

.align	32
.Louter4x:
	lea	16+128(%r14),%rdx
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	movdqa	-128(%r12),%xmm0
	movdqa	-112(%r12),%xmm1
	movdqa	-96(%r12),%xmm2
	movdqa	-80(%r12),%xmm3
	pand	-128(%rdx),%xmm0
	pand	-112(%rdx),%xmm1
	por	%xmm0,%xmm4
	pand	-96(%rdx),%xmm2
	por	%xmm1,%xmm5
	pand	-80(%rdx),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	-64(%r12),%xmm0
	movdqa	-48(%r12),%xmm1
	movdqa	-32(%r12),%xmm2
	movdqa	-16(%r12),%xmm3
	pand	-64(%rdx),%xmm0
	pand	-48(%rdx),%xmm1
	por	%xmm0,%xmm4
	pand	-32(%rdx),%xmm2
	por	%xmm1,%xmm5
	pand	-16(%rdx),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	0(%r12),%xmm0
	movdqa	16(%r12),%xmm1
	movdqa	32(%r12),%xmm2
	movdqa	48(%r12),%xmm3
	pand	0(%rdx),%xmm0
	pand	16(%rdx),%xmm1
	por	%xmm0,%xmm4
	pand	32(%rdx),%xmm2
	por	%xmm1,%xmm5
	pand	48(%rdx),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	64(%r12),%xmm0
	movdqa	80(%r12),%xmm1
	movdqa	96(%r12),%xmm2
	movdqa	112(%r12),%xmm3
	pand	64(%rdx),%xmm0
	pand	80(%rdx),%xmm1
	por	%xmm0,%xmm4
	pand	96(%rdx),%xmm2
	por	%xmm1,%xmm5
	pand	112(%rdx),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	por	%xmm5,%xmm4
	pshufd	$0x4e,%xmm4,%xmm0
	por	%xmm4,%xmm0
	lea	256(%r12),%r12
.byte	102,72,15,126,195

	mov	(%r14,%r9,1),%r10
	mov	%r8,%rbp
	mulq	%rbx
	add	%rax,%r10
	mov	(%rcx),%rax
	adc	$0,%rdx

	imul	%r10,%rbp
	mov	%rdx,%r11
	mov	%rdi,(%r14)

	lea	(%r14,%r9,1),%r14

	mulq	%rbp
	add	%rax,%r10
	mov	8(%rsi,%r9,1),%rax
	adc	$0,%rdx
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	8(%rcx),%rax
	adc	$0,%rdx
	add	8(%r14),%r11
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	16(%rsi,%r9,1),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	lea	32(%r9),%r15
	lea	32(%rcx),%rcx
	adc	$0,%rdx
	mov	%rdx,%r13
	jmp	.Linner4x

.align	32
.Linner4x:
	mulq	%rbx
	add	%rax,%r10
	mov	-16(%rcx),%rax
	adc	$0,%rdx
	add	16(%r14),%r10
	lea	32(%r14),%r14
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	-8(%rsi,%r15,1),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%rdi,-32(%r14)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	-8(%rcx),%rax
	adc	$0,%rdx
	add	-8(%r14),%r11
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	(%rsi,%r15,1),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%r13,-24(%r14)
	mov	%rdx,%r13

	mulq	%rbx
	add	%rax,%r10
	mov	0(%rcx),%rax
	adc	$0,%rdx
	add	(%r14),%r10
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	8(%rsi,%r15,1),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%rdi,-16(%r14)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	8(%rcx),%rax
	adc	$0,%rdx
	add	8(%r14),%r11
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	16(%rsi,%r15,1),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	lea	32(%rcx),%rcx
	adc	$0,%rdx
	mov	%r13,-8(%r14)
	mov	%rdx,%r13

	add	$32,%r15
	jnz	.Linner4x

	mulq	%rbx
	add	%rax,%r10
	mov	-16(%rcx),%rax
	adc	$0,%rdx
	add	16(%r14),%r10
	lea	32(%r14),%r14
	adc	$0,%rdx
	mov	%rdx,%r11

	mulq	%rbp
	add	%rax,%r13
	mov	-8(%rsi),%rax
	adc	$0,%rdx
	add	%r10,%r13
	adc	$0,%rdx
	mov	%rdi,-32(%r14)
	mov	%rdx,%rdi

	mulq	%rbx
	add	%rax,%r11
	mov	%rbp,%rax
	mov	-8(%rcx),%rbp
	adc	$0,%rdx
	add	-8(%r14),%r11
	adc	$0,%rdx
	mov	%rdx,%r10

	mulq	%rbp
	add	%rax,%rdi
	mov	(%rsi,%r9,1),%rax
	adc	$0,%rdx
	add	%r11,%rdi
	adc	$0,%rdx
	mov	%r13,-24(%r14)
	mov	%rdx,%r13

	mov	%rdi,-16(%r14)
	lea	(%rcx,%r9,1),%rcx

	xor	%rdi,%rdi
	add	%r10,%r13
	adc	$0,%rdi
	add	(%r14),%r13
	adc	$0,%rdi
	mov	%r13,-8(%r14)

	cmp	16+8(%rsp),%r12
	jb	.Louter4x
	xor	%rax,%rax
	sub	%r13,%rbp
	adc	%r15,%r15
	or	%r15,%rdi
	sub	%rdi,%rax
	lea	(%r14,%r9,1),%rbx
	mov	(%rcx),%r12
	lea	(%rcx),%rbp
	mov	%r9,%rcx
	sarq	$3+2,%rcx
	mov	56+8(%rsp),%rdi
	decq	%r12
	xor	%r10,%r10
	mov	8(%rbp),%r13
	mov	16(%rbp),%r14
	mov	24(%rbp),%r15
	jmp	.Lsqr4x_sub_entry
.cfi_endproc	
.size	mul4x_internal,.-mul4x_internal
.globl	bn_power5
.type	bn_power5,@function
.align	32
bn_power5:
.cfi_startproc	
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
	movl	OPENSSL_ia32cap_P+8(%rip),%r11d
	andl	$0x80108,%r11d
	cmpl	$0x80108,%r11d
	je	.Lpowerx5_enter
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
.Lpower5_prologue:

	shll	$3,%r9d
	leal	(%r9,%r9,2),%r10d
	negq	%r9
	mov	(%r8),%r8








	lea	-320(%rsp,%r9,2),%r11
	mov	%rsp,%rbp
	sub	%rdi,%r11
	and	$4095,%r11
	cmp	%r11,%r10
	jb	.Lpwr_sp_alt
	sub	%r11,%rbp
	lea	-320(%rbp,%r9,2),%rbp
	jmp	.Lpwr_sp_done

.align	32
.Lpwr_sp_alt:
	lea	4096-320(,%r9,2),%r10
	lea	-320(%rbp,%r9,2),%rbp
	sub	%r10,%r11
	mov	$0,%r10
	cmovc	%r10,%r11
	sub	%r11,%rbp
.Lpwr_sp_done:
	and	$-64,%rbp
	mov	%rsp,%r11
	sub	%rbp,%r11
	and	$-4096,%r11
	lea	(%r11,%rbp,1),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lpwr_page_walk
	jmp	.Lpwr_page_walk_done

.Lpwr_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lpwr_page_walk
.Lpwr_page_walk_done:

	mov	%r9,%r10
	negq	%r9










	mov	%r8,32(%rsp)
	mov	%rax,40(%rsp)
.cfi_escape	0x0f,0x05,0x77,0x28,0x06,0x23,0x08
.Lpower5_body:
.byte	102,72,15,110,207
.byte	102,72,15,110,209
.byte	102,73,15,110,218
.byte	102,72,15,110,226

	call	__bn_sqr8x_internal
	call	__bn_post4x_internal
	call	__bn_sqr8x_internal
	call	__bn_post4x_internal
	call	__bn_sqr8x_internal
	call	__bn_post4x_internal
	call	__bn_sqr8x_internal
	call	__bn_post4x_internal
	call	__bn_sqr8x_internal
	call	__bn_post4x_internal

.byte	102,72,15,126,209
.byte	102,72,15,126,226
	mov	%rsi,%rdi
	mov	40(%rsp),%rax
	lea	32(%rsp),%r8

	call	mul4x_internal

	mov	40(%rsp),%rsi
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
.Lpower5_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc	
.size	bn_power5,.-bn_power5

.globl	bn_sqr8x_internal
.hidden	bn_sqr8x_internal
.type	bn_sqr8x_internal,@function
.align	32
bn_sqr8x_internal:
__bn_sqr8x_internal:
.cfi_startproc	









































































	lea	32(%r10),%rbp
	lea	(%rsi,%r9,1),%rsi

	mov	%r9,%rcx


	mov	-32(%rsi,%rbp,1),%r14
	lea	48+8(%rsp,%r9,2),%rdi
	mov	-24(%rsi,%rbp,1),%rax
	lea	-32(%rdi,%rbp,1),%rdi
	mov	-16(%rsi,%rbp,1),%rbx
	mov	%rax,%r15

	mulq	%r14
	mov	%rax,%r10
	mov	%rbx,%rax
	mov	%rdx,%r11
	mov	%r10,-24(%rdi,%rbp,1)

	mulq	%r14
	add	%rax,%r11
	mov	%rbx,%rax
	adc	$0,%rdx
	mov	%r11,-16(%rdi,%rbp,1)
	mov	%rdx,%r10


	mov	-8(%rsi,%rbp,1),%rbx
	mulq	%r15
	mov	%rax,%r12
	mov	%rbx,%rax
	mov	%rdx,%r13

	lea	(%rbp),%rcx
	mulq	%r14
	add	%rax,%r10
	mov	%rbx,%rax
	mov	%rdx,%r11
	adc	$0,%r11
	add	%r12,%r10
	adc	$0,%r11
	mov	%r10,-8(%rdi,%rcx,1)
	jmp	.Lsqr4x_1st

.align	32
.Lsqr4x_1st:
	mov	(%rsi,%rcx,1),%rbx
	mulq	%r15
	add	%rax,%r13
	mov	%rbx,%rax
	mov	%rdx,%r12
	adc	$0,%r12

	mulq	%r14
	add	%rax,%r11
	mov	%rbx,%rax
	mov	8(%rsi,%rcx,1),%rbx
	mov	%rdx,%r10
	adc	$0,%r10
	add	%r13,%r11
	adc	$0,%r10


	mulq	%r15
	add	%rax,%r12
	mov	%rbx,%rax
	mov	%r11,(%rdi,%rcx,1)
	mov	%rdx,%r13
	adc	$0,%r13

	mulq	%r14
	add	%rax,%r10
	mov	%rbx,%rax
	mov	16(%rsi,%rcx,1),%rbx
	mov	%rdx,%r11
	adc	$0,%r11
	add	%r12,%r10
	adc	$0,%r11

	mulq	%r15
	add	%rax,%r13
	mov	%rbx,%rax
	mov	%r10,8(%rdi,%rcx,1)
	mov	%rdx,%r12
	adc	$0,%r12

	mulq	%r14
	add	%rax,%r11
	mov	%rbx,%rax
	mov	24(%rsi,%rcx,1),%rbx
	mov	%rdx,%r10
	adc	$0,%r10
	add	%r13,%r11
	adc	$0,%r10


	mulq	%r15
	add	%rax,%r12
	mov	%rbx,%rax
	mov	%r11,16(%rdi,%rcx,1)
	mov	%rdx,%r13
	adc	$0,%r13
	lea	32(%rcx),%rcx

	mulq	%r14
	add	%rax,%r10
	mov	%rbx,%rax
	mov	%rdx,%r11
	adc	$0,%r11
	add	%r12,%r10
	adc	$0,%r11
	mov	%r10,-8(%rdi,%rcx,1)

	cmp	$0,%rcx
	jne	.Lsqr4x_1st

	mulq	%r15
	add	%rax,%r13
	lea	16(%rbp),%rbp
	adc	$0,%rdx
	add	%r11,%r13
	adc	$0,%rdx

	mov	%r13,(%rdi)
	mov	%rdx,%r12
	mov	%rdx,8(%rdi)
	jmp	.Lsqr4x_outer

.align	32
.Lsqr4x_outer:
	mov	-32(%rsi,%rbp,1),%r14
	lea	48+8(%rsp,%r9,2),%rdi
	mov	-24(%rsi,%rbp,1),%rax
	lea	-32(%rdi,%rbp,1),%rdi
	mov	-16(%rsi,%rbp,1),%rbx
	mov	%rax,%r15

	mulq	%r14
	mov	-24(%rdi,%rbp,1),%r10
	add	%rax,%r10
	mov	%rbx,%rax
	adc	$0,%rdx
	mov	%r10,-24(%rdi,%rbp,1)
	mov	%rdx,%r11

	mulq	%r14
	add	%rax,%r11
	mov	%rbx,%rax
	adc	$0,%rdx
	add	-16(%rdi,%rbp,1),%r11
	mov	%rdx,%r10
	adc	$0,%r10
	mov	%r11,-16(%rdi,%rbp,1)

	xor	%r12,%r12

	mov	-8(%rsi,%rbp,1),%rbx
	mulq	%r15
	add	%rax,%r12
	mov	%rbx,%rax
	adc	$0,%rdx
	add	-8(%rdi,%rbp,1),%r12
	mov	%rdx,%r13
	adc	$0,%r13

	mulq	%r14
	add	%rax,%r10
	mov	%rbx,%rax
	adc	$0,%rdx
	add	%r12,%r10
	mov	%rdx,%r11
	adc	$0,%r11
	mov	%r10,-8(%rdi,%rbp,1)

	lea	(%rbp),%rcx
	jmp	.Lsqr4x_inner

.align	32
.Lsqr4x_inner:
	mov	(%rsi,%rcx,1),%rbx
	mulq	%r15
	add	%rax,%r13
	mov	%rbx,%rax
	mov	%rdx,%r12
	adc	$0,%r12
	add	(%rdi,%rcx,1),%r13
	adc	$0,%r12

.byte	0x67
	mulq	%r14
	add	%rax,%r11
	mov	%rbx,%rax
	mov	8(%rsi,%rcx,1),%rbx
	mov	%rdx,%r10
	adc	$0,%r10
	add	%r13,%r11
	adc	$0,%r10

	mulq	%r15
	add	%rax,%r12
	mov	%r11,(%rdi,%rcx,1)
	mov	%rbx,%rax
	mov	%rdx,%r13
	adc	$0,%r13
	add	8(%rdi,%rcx,1),%r12
	lea	16(%rcx),%rcx
	adc	$0,%r13

	mulq	%r14
	add	%rax,%r10
	mov	%rbx,%rax
	adc	$0,%rdx
	add	%r12,%r10
	mov	%rdx,%r11
	adc	$0,%r11
	mov	%r10,-8(%rdi,%rcx,1)

	cmp	$0,%rcx
	jne	.Lsqr4x_inner

.byte	0x67
	mulq	%r15
	add	%rax,%r13
	adc	$0,%rdx
	add	%r11,%r13
	adc	$0,%rdx

	mov	%r13,(%rdi)
	mov	%rdx,%r12
	mov	%rdx,8(%rdi)

	add	$16,%rbp
	jnz	.Lsqr4x_outer


	mov	-32(%rsi),%r14
	lea	48+8(%rsp,%r9,2),%rdi
	mov	-24(%rsi),%rax
	lea	-32(%rdi,%rbp,1),%rdi
	mov	-16(%rsi),%rbx
	mov	%rax,%r15

	mulq	%r14
	add	%rax,%r10
	mov	%rbx,%rax
	mov	%rdx,%r11
	adc	$0,%r11

	mulq	%r14
	add	%rax,%r11
	mov	%rbx,%rax
	mov	%r10,-24(%rdi)
	mov	%rdx,%r10
	adc	$0,%r10
	add	%r13,%r11
	mov	-8(%rsi),%rbx
	adc	$0,%r10

	mulq	%r15
	add	%rax,%r12
	mov	%rbx,%rax
	mov	%r11,-16(%rdi)
	mov	%rdx,%r13
	adc	$0,%r13

	mulq	%r14
	add	%rax,%r10
	mov	%rbx,%rax
	mov	%rdx,%r11
	adc	$0,%r11
	add	%r12,%r10
	adc	$0,%r11
	mov	%r10,-8(%rdi)

	mulq	%r15
	add	%rax,%r13
	mov	-16(%rsi),%rax
	adc	$0,%rdx
	add	%r11,%r13
	adc	$0,%rdx

	mov	%r13,(%rdi)
	mov	%rdx,%r12
	mov	%rdx,8(%rdi)

	mulq	%rbx
	add	$16,%rbp
	xor	%r14,%r14
	sub	%r9,%rbp
	xor	%r15,%r15

	add	%r12,%rax
	adc	$0,%rdx
	mov	%rax,8(%rdi)
	mov	%rdx,16(%rdi)
	mov	%r15,24(%rdi)

	mov	-16(%rsi,%rbp,1),%rax
	lea	48+8(%rsp),%rdi
	xor	%r10,%r10
	mov	8(%rdi),%r11

	lea	(%r14,%r10,2),%r12
	shrq	$63,%r10
	lea	(%rcx,%r11,2),%r13
	shrq	$63,%r11
	or	%r10,%r13
	mov	16(%rdi),%r10
	mov	%r11,%r14
	mulq	%rax
	negq	%r15
	mov	24(%rdi),%r11
	adc	%rax,%r12
	mov	-8(%rsi,%rbp,1),%rax
	mov	%r12,(%rdi)
	adc	%rdx,%r13

	lea	(%r14,%r10,2),%rbx
	mov	%r13,8(%rdi)
	sbb	%r15,%r15
	shrq	$63,%r10
	lea	(%rcx,%r11,2),%r8
	shrq	$63,%r11
	or	%r10,%r8
	mov	32(%rdi),%r10
	mov	%r11,%r14
	mulq	%rax
	negq	%r15
	mov	40(%rdi),%r11
	adc	%rax,%rbx
	mov	0(%rsi,%rbp,1),%rax
	mov	%rbx,16(%rdi)
	adc	%rdx,%r8
	lea	16(%rbp),%rbp
	mov	%r8,24(%rdi)
	sbb	%r15,%r15
	lea	64(%rdi),%rdi
	jmp	.Lsqr4x_shift_n_add

.align	32
.Lsqr4x_shift_n_add:
	lea	(%r14,%r10,2),%r12
	shrq	$63,%r10
	lea	(%rcx,%r11,2),%r13
	shrq	$63,%r11
	or	%r10,%r13
	mov	-16(%rdi),%r10
	mov	%r11,%r14
	mulq	%rax
	negq	%r15
	mov	-8(%rdi),%r11
	adc	%rax,%r12
	mov	-8(%rsi,%rbp,1),%rax
	mov	%r12,-32(%rdi)
	adc	%rdx,%r13

	lea	(%r14,%r10,2),%rbx
	mov	%r13,-24(%rdi)
	sbb	%r15,%r15
	shrq	$63,%r10
	lea	(%rcx,%r11,2),%r8
	shrq	$63,%r11
	or	%r10,%r8
	mov	0(%rdi),%r10
	mov	%r11,%r14
	mulq	%rax
	negq	%r15
	mov	8(%rdi),%r11
	adc	%rax,%rbx
	mov	0(%rsi,%rbp,1),%rax
	mov	%rbx,-16(%rdi)
	adc	%rdx,%r8

	lea	(%r14,%r10,2),%r12
	mov	%r8,-8(%rdi)
	sbb	%r15,%r15
	shrq	$63,%r10
	lea	(%rcx,%r11,2),%r13
	shrq	$63,%r11
	or	%r10,%r13
	mov	16(%rdi),%r10
	mov	%r11,%r14
	mulq	%rax
	negq	%r15
	mov	24(%rdi),%r11
	adc	%rax,%r12
	mov	8(%rsi,%rbp,1),%rax
	mov	%r12,0(%rdi)
	adc	%rdx,%r13

	lea	(%r14,%r10,2),%rbx
	mov	%r13,8(%rdi)
	sbb	%r15,%r15
	shrq	$63,%r10
	lea	(%rcx,%r11,2),%r8
	shrq	$63,%r11
	or	%r10,%r8
	mov	32(%rdi),%r10
	mov	%r11,%r14
	mulq	%rax
	negq	%r15
	mov	40(%rdi),%r11
	adc	%rax,%rbx
	mov	16(%rsi,%rbp,1),%rax
	mov	%rbx,16(%rdi)
	adc	%rdx,%r8
	mov	%r8,24(%rdi)
	sbb	%r15,%r15
	lea	64(%rdi),%rdi
	add	$32,%rbp
	jnz	.Lsqr4x_shift_n_add

	lea	(%r14,%r10,2),%r12
.byte	0x67
	shrq	$63,%r10
	lea	(%rcx,%r11,2),%r13
	shrq	$63,%r11
	or	%r10,%r13
	mov	-16(%rdi),%r10
	mov	%r11,%r14
	mulq	%rax
	negq	%r15
	mov	-8(%rdi),%r11
	adc	%rax,%r12
	mov	-8(%rsi),%rax
	mov	%r12,-32(%rdi)
	adc	%rdx,%r13

	lea	(%r14,%r10,2),%rbx
	mov	%r13,-24(%rdi)
	sbb	%r15,%r15
	shrq	$63,%r10
	lea	(%rcx,%r11,2),%r8
	shrq	$63,%r11
	or	%r10,%r8
	mulq	%rax
	negq	%r15
	adc	%rax,%rbx
	adc	%rdx,%r8
	mov	%rbx,-16(%rdi)
	mov	%r8,-8(%rdi)
.byte	102,72,15,126,213
__bn_sqr8x_reduction:
	xor	%rax,%rax
	lea	(%r9,%rbp,1),%rcx
	lea	48+8(%rsp,%r9,2),%rdx
	mov	%rcx,0+8(%rsp)
	lea	48+8(%rsp,%r9,1),%rdi
	mov	%rdx,8+8(%rsp)
	negq	%r9
	jmp	.L8x_reduction_loop

.align	32
.L8x_reduction_loop:
	lea	(%rdi,%r9,1),%rdi
.byte	0x66
	mov	0(%rdi),%rbx
	mov	8(%rdi),%r9
	mov	16(%rdi),%r10
	mov	24(%rdi),%r11
	mov	32(%rdi),%r12
	mov	40(%rdi),%r13
	mov	48(%rdi),%r14
	mov	56(%rdi),%r15
	mov	%rax,(%rdx)
	lea	64(%rdi),%rdi

.byte	0x67
	mov	%rbx,%r8
	imul	32+8(%rsp),%rbx
	mov	0(%rbp),%rax
	mov	$8,%ecx
	jmp	.L8x_reduce

.align	32
.L8x_reduce:
	mulq	%rbx
	mov	8(%rbp),%rax
	negq	%r8
	mov	%rdx,%r8
	adc	$0,%r8

	mulq	%rbx
	add	%rax,%r9
	mov	16(%rbp),%rax
	adc	$0,%rdx
	add	%r9,%r8
	mov	%rbx,48-8+8(%rsp,%rcx,8)
	mov	%rdx,%r9
	adc	$0,%r9

	mulq	%rbx
	add	%rax,%r10
	mov	24(%rbp),%rax
	adc	$0,%rdx
	add	%r10,%r9
	mov	32+8(%rsp),%rsi
	mov	%rdx,%r10
	adc	$0,%r10

	mulq	%rbx
	add	%rax,%r11
	mov	32(%rbp),%rax
	adc	$0,%rdx
	imul	%r8,%rsi
	add	%r11,%r10
	mov	%rdx,%r11
	adc	$0,%r11

	mulq	%rbx
	add	%rax,%r12
	mov	40(%rbp),%rax
	adc	$0,%rdx
	add	%r12,%r11
	mov	%rdx,%r12
	adc	$0,%r12

	mulq	%rbx
	add	%rax,%r13
	mov	48(%rbp),%rax
	adc	$0,%rdx
	add	%r13,%r12
	mov	%rdx,%r13
	adc	$0,%r13

	mulq	%rbx
	add	%rax,%r14
	mov	56(%rbp),%rax
	adc	$0,%rdx
	add	%r14,%r13
	mov	%rdx,%r14
	adc	$0,%r14

	mulq	%rbx
	mov	%rsi,%rbx
	add	%rax,%r15
	mov	0(%rbp),%rax
	adc	$0,%rdx
	add	%r15,%r14
	mov	%rdx,%r15
	adc	$0,%r15

	decl	%ecx
	jnz	.L8x_reduce

	lea	64(%rbp),%rbp
	xor	%rax,%rax
	mov	8+8(%rsp),%rdx
	cmp	0+8(%rsp),%rbp
	jae	.L8x_no_tail

.byte	0x66
	add	0(%rdi),%r8
	adc	8(%rdi),%r9
	adc	16(%rdi),%r10
	adc	24(%rdi),%r11
	adc	32(%rdi),%r12
	adc	40(%rdi),%r13
	adc	48(%rdi),%r14
	adc	56(%rdi),%r15
	sbb	%rsi,%rsi

	mov	48+56+8(%rsp),%rbx
	mov	$8,%ecx
	mov	0(%rbp),%rax
	jmp	.L8x_tail

.align	32
.L8x_tail:
	mulq	%rbx
	add	%rax,%r8
	mov	8(%rbp),%rax
	mov	%r8,(%rdi)
	mov	%rdx,%r8
	adc	$0,%r8

	mulq	%rbx
	add	%rax,%r9
	mov	16(%rbp),%rax
	adc	$0,%rdx
	add	%r9,%r8
	lea	8(%rdi),%rdi
	mov	%rdx,%r9
	adc	$0,%r9

	mulq	%rbx
	add	%rax,%r10
	mov	24(%rbp),%rax
	adc	$0,%rdx
	add	%r10,%r9
	mov	%rdx,%r10
	adc	$0,%r10

	mulq	%rbx
	add	%rax,%r11
	mov	32(%rbp),%rax
	adc	$0,%rdx
	add	%r11,%r10
	mov	%rdx,%r11
	adc	$0,%r11

	mulq	%rbx
	add	%rax,%r12
	mov	40(%rbp),%rax
	adc	$0,%rdx
	add	%r12,%r11
	mov	%rdx,%r12
	adc	$0,%r12

	mulq	%rbx
	add	%rax,%r13
	mov	48(%rbp),%rax
	adc	$0,%rdx
	add	%r13,%r12
	mov	%rdx,%r13
	adc	$0,%r13

	mulq	%rbx
	add	%rax,%r14
	mov	56(%rbp),%rax
	adc	$0,%rdx
	add	%r14,%r13
	mov	%rdx,%r14
	adc	$0,%r14

	mulq	%rbx
	mov	48-16+8(%rsp,%rcx,8),%rbx
	add	%rax,%r15
	adc	$0,%rdx
	add	%r15,%r14
	mov	0(%rbp),%rax
	mov	%rdx,%r15
	adc	$0,%r15

	decl	%ecx
	jnz	.L8x_tail

	lea	64(%rbp),%rbp
	mov	8+8(%rsp),%rdx
	cmp	0+8(%rsp),%rbp
	jae	.L8x_tail_done

	mov	48+56+8(%rsp),%rbx
	negq	%rsi
	mov	0(%rbp),%rax
	adc	0(%rdi),%r8
	adc	8(%rdi),%r9
	adc	16(%rdi),%r10
	adc	24(%rdi),%r11
	adc	32(%rdi),%r12
	adc	40(%rdi),%r13
	adc	48(%rdi),%r14
	adc	56(%rdi),%r15
	sbb	%rsi,%rsi

	mov	$8,%ecx
	jmp	.L8x_tail

.align	32
.L8x_tail_done:
	xor	%rax,%rax
	add	(%rdx),%r8
	adc	$0,%r9
	adc	$0,%r10
	adc	$0,%r11
	adc	$0,%r12
	adc	$0,%r13
	adc	$0,%r14
	adc	$0,%r15
	adc	$0,%rax

	negq	%rsi
.L8x_no_tail:
	adc	0(%rdi),%r8
	adc	8(%rdi),%r9
	adc	16(%rdi),%r10
	adc	24(%rdi),%r11
	adc	32(%rdi),%r12
	adc	40(%rdi),%r13
	adc	48(%rdi),%r14
	adc	56(%rdi),%r15
	adc	$0,%rax
	mov	-8(%rbp),%rcx
	xor	%rsi,%rsi

.byte	102,72,15,126,213

	mov	%r8,0(%rdi)
	mov	%r9,8(%rdi)
.byte	102,73,15,126,217
	mov	%r10,16(%rdi)
	mov	%r11,24(%rdi)
	mov	%r12,32(%rdi)
	mov	%r13,40(%rdi)
	mov	%r14,48(%rdi)
	mov	%r15,56(%rdi)
	lea	64(%rdi),%rdi

	cmp	%rdx,%rdi
	jb	.L8x_reduction_loop
	.byte	0xf3,0xc3
.cfi_endproc	
.size	bn_sqr8x_internal,.-bn_sqr8x_internal
.type	__bn_post4x_internal,@function
.align	32
__bn_post4x_internal:
.cfi_startproc	
	mov	0(%rbp),%r12
	lea	(%rdi,%r9,1),%rbx
	mov	%r9,%rcx
.byte	102,72,15,126,207
	negq	%rax
.byte	102,72,15,126,206
	sarq	$3+2,%rcx
	decq	%r12
	xor	%r10,%r10
	mov	8(%rbp),%r13
	mov	16(%rbp),%r14
	mov	24(%rbp),%r15
	jmp	.Lsqr4x_sub_entry

.align	16
.Lsqr4x_sub:
	mov	0(%rbp),%r12
	mov	8(%rbp),%r13
	mov	16(%rbp),%r14
	mov	24(%rbp),%r15
.Lsqr4x_sub_entry:
	lea	32(%rbp),%rbp
	notq	%r12
	notq	%r13
	notq	%r14
	notq	%r15
	and	%rax,%r12
	and	%rax,%r13
	and	%rax,%r14
	and	%rax,%r15

	negq	%r10
	adc	0(%rbx),%r12
	adc	8(%rbx),%r13
	adc	16(%rbx),%r14
	adc	24(%rbx),%r15
	mov	%r12,0(%rdi)
	lea	32(%rbx),%rbx
	mov	%r13,8(%rdi)
	sbb	%r10,%r10
	mov	%r14,16(%rdi)
	mov	%r15,24(%rdi)
	lea	32(%rdi),%rdi

	incq	%rcx
	jnz	.Lsqr4x_sub

	mov	%r9,%r10
	negq	%r9
	.byte	0xf3,0xc3
.cfi_endproc	
.size	__bn_post4x_internal,.-__bn_post4x_internal
.type	bn_mulx4x_mont_gather5,@function
.align	32
bn_mulx4x_mont_gather5:
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
	lea	(%r9,%r9,2),%r10
	negq	%r9
	mov	(%r8),%r8










	lea	-320(%rsp,%r9,2),%r11
	mov	%rsp,%rbp
	sub	%rdi,%r11
	and	$4095,%r11
	cmp	%r11,%r10
	jb	.Lmulx4xsp_alt
	sub	%r11,%rbp
	lea	-320(%rbp,%r9,2),%rbp
	jmp	.Lmulx4xsp_done

.Lmulx4xsp_alt:
	lea	4096-320(,%r9,2),%r10
	lea	-320(%rbp,%r9,2),%rbp
	sub	%r10,%r11
	mov	$0,%r10
	cmovc	%r10,%r11
	sub	%r11,%rbp
.Lmulx4xsp_done:
	and	$-64,%rbp
	mov	%rsp,%r11
	sub	%rbp,%r11
	and	$-4096,%r11
	lea	(%r11,%rbp,1),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lmulx4x_page_walk
	jmp	.Lmulx4x_page_walk_done

.Lmulx4x_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lmulx4x_page_walk
.Lmulx4x_page_walk_done:













	mov	%r8,32(%rsp)
	mov	%rax,40(%rsp)
.cfi_escape	0x0f,0x05,0x77,0x28,0x06,0x23,0x08
.Lmulx4x_body:
	call	mulx4x_internal

	mov	40(%rsp),%rsi
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
.Lmulx4x_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc	
.size	bn_mulx4x_mont_gather5,.-bn_mulx4x_mont_gather5

.type	mulx4x_internal,@function
.align	32
mulx4x_internal:
.cfi_startproc	
	mov	%r9,8(%rsp)
	mov	%r9,%r10
	negq	%r9
	shlq	$5,%r9
	negq	%r10
	lea	128(%rdx,%r9,1),%r13
	shrq	$5+5,%r9
	movd	8(%rax),%xmm5
	sub	$1,%r9
	lea	.Linc(%rip),%rax
	mov	%r13,16+8(%rsp)
	mov	%r9,24+8(%rsp)
	mov	%rdi,56+8(%rsp)
	movdqa	0(%rax),%xmm0
	movdqa	16(%rax),%xmm1
	lea	88-112(%rsp,%r10,1),%r10
	lea	128(%rdx),%rdi

	pshufd	$0,%xmm5,%xmm5
	movdqa	%xmm1,%xmm4
.byte	0x67
	movdqa	%xmm1,%xmm2
.byte	0x67
	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,112(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,128(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,144(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,160(%r10)
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,176(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,192(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,208(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,224(%r10)
	movdqa	%xmm4,%xmm3
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,240(%r10)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,256(%r10)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,272(%r10)
	movdqa	%xmm4,%xmm2

	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,288(%r10)
	movdqa	%xmm4,%xmm3
.byte	0x67
	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,304(%r10)

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,320(%r10)

	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,336(%r10)

	pand	64(%rdi),%xmm0
	pand	80(%rdi),%xmm1
	pand	96(%rdi),%xmm2
	movdqa	%xmm3,352(%r10)
	pand	112(%rdi),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	-128(%rdi),%xmm4
	movdqa	-112(%rdi),%xmm5
	movdqa	-96(%rdi),%xmm2
	pand	112(%r10),%xmm4
	movdqa	-80(%rdi),%xmm3
	pand	128(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	144(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	160(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	-64(%rdi),%xmm4
	movdqa	-48(%rdi),%xmm5
	movdqa	-32(%rdi),%xmm2
	pand	176(%r10),%xmm4
	movdqa	-16(%rdi),%xmm3
	pand	192(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	208(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	224(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	movdqa	0(%rdi),%xmm4
	movdqa	16(%rdi),%xmm5
	movdqa	32(%rdi),%xmm2
	pand	240(%r10),%xmm4
	movdqa	48(%rdi),%xmm3
	pand	256(%r10),%xmm5
	por	%xmm4,%xmm0
	pand	272(%r10),%xmm2
	por	%xmm5,%xmm1
	pand	288(%r10),%xmm3
	por	%xmm2,%xmm0
	por	%xmm3,%xmm1
	pxor	%xmm1,%xmm0
	pshufd	$0x4e,%xmm0,%xmm1
	por	%xmm1,%xmm0
	lea	256(%rdi),%rdi
.byte	102,72,15,126,194
	lea	64+32+8(%rsp),%rbx

	mov	%rdx,%r9
	mulxq	0(%rsi),%r8,%rax
	mulxq	8(%rsi),%r11,%r12
	add	%rax,%r11
	mulxq	16(%rsi),%rax,%r13
	adc	%rax,%r12
	adc	$0,%r13
	mulxq	24(%rsi),%rax,%r14

	mov	%r8,%r15
	imul	32+8(%rsp),%r8
	xor	%rbp,%rbp
	mov	%r8,%rdx

	mov	%rdi,8+8(%rsp)

	lea	32(%rsi),%rsi
	adcxq	%rax,%r13
	adcxq	%rbp,%r14

	mulxq	0(%rcx),%rax,%r10
	adcxq	%rax,%r15
	adoxq	%r11,%r10
	mulxq	8(%rcx),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11
	mulxq	16(%rcx),%rax,%r12
	mov	24+8(%rsp),%rdi
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

	mov	8(%rsp),%rax
	adc	%rbp,%r15
	lea	(%rsi,%rax,1),%rsi
	add	%r15,%r14
	mov	8+8(%rsp),%rdi
	adc	%rbp,%rbp
	mov	%r14,-8(%rbx)
	jmp	.Lmulx4x_outer

.align	32
.Lmulx4x_outer:
	lea	16-256(%rbx),%r10
	pxor	%xmm4,%xmm4
.byte	0x67,0x67
	pxor	%xmm5,%xmm5
	movdqa	-128(%rdi),%xmm0
	movdqa	-112(%rdi),%xmm1
	movdqa	-96(%rdi),%xmm2
	pand	256(%r10),%xmm0
	movdqa	-80(%rdi),%xmm3
	pand	272(%r10),%xmm1
	por	%xmm0,%xmm4
	pand	288(%r10),%xmm2
	por	%xmm1,%xmm5
	pand	304(%r10),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	-64(%rdi),%xmm0
	movdqa	-48(%rdi),%xmm1
	movdqa	-32(%rdi),%xmm2
	pand	320(%r10),%xmm0
	movdqa	-16(%rdi),%xmm3
	pand	336(%r10),%xmm1
	por	%xmm0,%xmm4
	pand	352(%r10),%xmm2
	por	%xmm1,%xmm5
	pand	368(%r10),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	0(%rdi),%xmm0
	movdqa	16(%rdi),%xmm1
	movdqa	32(%rdi),%xmm2
	pand	384(%r10),%xmm0
	movdqa	48(%rdi),%xmm3
	pand	400(%r10),%xmm1
	por	%xmm0,%xmm4
	pand	416(%r10),%xmm2
	por	%xmm1,%xmm5
	pand	432(%r10),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	64(%rdi),%xmm0
	movdqa	80(%rdi),%xmm1
	movdqa	96(%rdi),%xmm2
	pand	448(%r10),%xmm0
	movdqa	112(%rdi),%xmm3
	pand	464(%r10),%xmm1
	por	%xmm0,%xmm4
	pand	480(%r10),%xmm2
	por	%xmm1,%xmm5
	pand	496(%r10),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	por	%xmm5,%xmm4
	pshufd	$0x4e,%xmm4,%xmm0
	por	%xmm4,%xmm0
	lea	256(%rdi),%rdi
.byte	102,72,15,126,194

	mov	%rbp,(%rbx)
	lea	32(%rbx,%rax,1),%rbx
	mulxq	0(%rsi),%r8,%r11
	xor	%rbp,%rbp
	mov	%rdx,%r9
	mulxq	8(%rsi),%r14,%r12
	adoxq	-32(%rbx),%r8
	adcxq	%r14,%r11
	mulxq	16(%rsi),%r15,%r13
	adoxq	-24(%rbx),%r11
	adcxq	%r15,%r12
	mulxq	24(%rsi),%rdx,%r14
	adoxq	-16(%rbx),%r12
	adcxq	%rdx,%r13
	lea	(%rcx,%rax,1),%rcx
	lea	32(%rsi),%rsi
	adoxq	-8(%rbx),%r13
	adcxq	%rbp,%r14
	adoxq	%rbp,%r14

	mov	%r8,%r15
	imul	32+8(%rsp),%r8

	mov	%r8,%rdx
	xor	%rbp,%rbp
	mov	%rdi,8+8(%rsp)

	mulxq	0(%rcx),%rax,%r10
	adcxq	%rax,%r15
	adoxq	%r11,%r10
	mulxq	8(%rcx),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11
	mulxq	16(%rcx),%rax,%r12
	adcxq	%rax,%r11
	adoxq	%r13,%r12
	mulxq	24(%rcx),%rax,%r15
	mov	%r9,%rdx
	mov	24+8(%rsp),%rdi
	mov	%r10,-32(%rbx)
	adcxq	%rax,%r12
	mov	%r11,-24(%rbx)
	adoxq	%rbp,%r15
	mov	%r12,-16(%rbx)
	lea	32(%rcx),%rcx
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
	mov	%r11,-32(%rbx)
	mulxq	24(%rcx),%rax,%r15
	mov	%r9,%rdx
	lea	32(%rcx),%rcx
	mov	%r12,-24(%rbx)
	adcxq	%rax,%r13
	adoxq	%rbp,%r15
	mov	%r13,-16(%rbx)

	decq	%rdi
	jnz	.Lmulx4x_inner

	mov	0+8(%rsp),%rax
	adc	%rbp,%r15
	sub	0(%rbx),%rdi
	mov	8+8(%rsp),%rdi
	mov	16+8(%rsp),%r10
	adc	%r15,%r14
	lea	(%rsi,%rax,1),%rsi
	adc	%rbp,%rbp
	mov	%r14,-8(%rbx)

	cmp	%r10,%rdi
	jb	.Lmulx4x_outer

	mov	-8(%rcx),%r10
	mov	%rbp,%r8
	mov	(%rcx,%rax,1),%r12
	lea	(%rcx,%rax,1),%rbp
	mov	%rax,%rcx
	lea	(%rbx,%rax,1),%rdi
	xor	%eax,%eax
	xor	%r15,%r15
	sub	%r14,%r10
	adc	%r15,%r15
	or	%r15,%r8
	sarq	$3+2,%rcx
	sub	%r8,%rax
	mov	56+8(%rsp),%rdx
	decq	%r12
	mov	8(%rbp),%r13
	xor	%r8,%r8
	mov	16(%rbp),%r14
	mov	24(%rbp),%r15
	jmp	.Lsqrx4x_sub_entry
.cfi_endproc	
.size	mulx4x_internal,.-mulx4x_internal
.type	bn_powerx5,@function
.align	32
bn_powerx5:
.cfi_startproc	
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
.Lpowerx5_enter:
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
.Lpowerx5_prologue:

	shll	$3,%r9d
	lea	(%r9,%r9,2),%r10
	negq	%r9
	mov	(%r8),%r8








	lea	-320(%rsp,%r9,2),%r11
	mov	%rsp,%rbp
	sub	%rdi,%r11
	and	$4095,%r11
	cmp	%r11,%r10
	jb	.Lpwrx_sp_alt
	sub	%r11,%rbp
	lea	-320(%rbp,%r9,2),%rbp
	jmp	.Lpwrx_sp_done

.align	32
.Lpwrx_sp_alt:
	lea	4096-320(,%r9,2),%r10
	lea	-320(%rbp,%r9,2),%rbp
	sub	%r10,%r11
	mov	$0,%r10
	cmovc	%r10,%r11
	sub	%r11,%rbp
.Lpwrx_sp_done:
	and	$-64,%rbp
	mov	%rsp,%r11
	sub	%rbp,%r11
	and	$-4096,%r11
	lea	(%r11,%rbp,1),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lpwrx_page_walk
	jmp	.Lpwrx_page_walk_done

.Lpwrx_page_walk:
	lea	-4096(%rsp),%rsp
	mov	(%rsp),%r10
	cmp	%rbp,%rsp
	ja	.Lpwrx_page_walk
.Lpwrx_page_walk_done:

	mov	%r9,%r10
	negq	%r9












	pxor	%xmm0,%xmm0
.byte	102,72,15,110,207
.byte	102,72,15,110,209
.byte	102,73,15,110,218
.byte	102,72,15,110,226
	mov	%r8,32(%rsp)
	mov	%rax,40(%rsp)
.cfi_escape	0x0f,0x05,0x77,0x28,0x06,0x23,0x08
.Lpowerx5_body:

	call	__bn_sqrx8x_internal
	call	__bn_postx4x_internal
	call	__bn_sqrx8x_internal
	call	__bn_postx4x_internal
	call	__bn_sqrx8x_internal
	call	__bn_postx4x_internal
	call	__bn_sqrx8x_internal
	call	__bn_postx4x_internal
	call	__bn_sqrx8x_internal
	call	__bn_postx4x_internal

	mov	%r10,%r9
	mov	%rsi,%rdi
.byte	102,72,15,126,209
.byte	102,72,15,126,226
	mov	40(%rsp),%rax

	call	mulx4x_internal

	mov	40(%rsp),%rsi
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
.Lpowerx5_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc	
.size	bn_powerx5,.-bn_powerx5

.globl	bn_sqrx8x_internal
.hidden	bn_sqrx8x_internal
.type	bn_sqrx8x_internal,@function
.align	32
bn_sqrx8x_internal:
__bn_sqrx8x_internal:
.cfi_startproc	








































	lea	48+8(%rsp),%rdi
	lea	(%rsi,%r9,1),%rbp
	mov	%r9,0+8(%rsp)
	mov	%rbp,8+8(%rsp)
	jmp	.Lsqr8x_zero_start

.align	32
.byte	0x66,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00
.Lsqrx8x_zero:
.byte	0x3e
	movdqa	%xmm0,0(%rdi)
	movdqa	%xmm0,16(%rdi)
	movdqa	%xmm0,32(%rdi)
	movdqa	%xmm0,48(%rdi)
.Lsqr8x_zero_start:
	movdqa	%xmm0,64(%rdi)
	movdqa	%xmm0,80(%rdi)
	movdqa	%xmm0,96(%rdi)
	movdqa	%xmm0,112(%rdi)
	lea	128(%rdi),%rdi
	sub	$64,%r9
	jnz	.Lsqrx8x_zero

	mov	0(%rsi),%rdx

	xor	%r10,%r10
	xor	%r11,%r11
	xor	%r12,%r12
	xor	%r13,%r13
	xor	%r14,%r14
	xor	%r15,%r15
	lea	48+8(%rsp),%rdi
	xor	%rbp,%rbp
	jmp	.Lsqrx8x_outer_loop

.align	32
.Lsqrx8x_outer_loop:
	mulxq	8(%rsi),%r8,%rax
	adcxq	%r9,%r8
	adoxq	%rax,%r10
	mulxq	16(%rsi),%r9,%rax
	adcxq	%r10,%r9
	adoxq	%rax,%r11
.byte	0xc4,0xe2,0xab,0xf6,0x86,0x18,0x00,0x00,0x00
	adcxq	%r11,%r10
	adoxq	%rax,%r12
.byte	0xc4,0xe2,0xa3,0xf6,0x86,0x20,0x00,0x00,0x00
	adcxq	%r12,%r11
	adoxq	%rax,%r13
	mulxq	40(%rsi),%r12,%rax
	adcxq	%r13,%r12
	adoxq	%rax,%r14
	mulxq	48(%rsi),%r13,%rax
	adcxq	%r14,%r13
	adoxq	%r15,%rax
	mulxq	56(%rsi),%r14,%r15
	mov	8(%rsi),%rdx
	adcxq	%rax,%r14
	adoxq	%rbp,%r15
	adc	64(%rdi),%r15
	mov	%r8,8(%rdi)
	mov	%r9,16(%rdi)
	sbb	%rcx,%rcx
	xor	%rbp,%rbp


	mulxq	16(%rsi),%r8,%rbx
	mulxq	24(%rsi),%r9,%rax
	adcxq	%r10,%r8
	adoxq	%rbx,%r9
	mulxq	32(%rsi),%r10,%rbx
	adcxq	%r11,%r9
	adoxq	%rax,%r10
.byte	0xc4,0xe2,0xa3,0xf6,0x86,0x28,0x00,0x00,0x00
	adcxq	%r12,%r10
	adoxq	%rbx,%r11
.byte	0xc4,0xe2,0x9b,0xf6,0x9e,0x30,0x00,0x00,0x00
	adcxq	%r13,%r11
	adoxq	%r14,%r12
.byte	0xc4,0x62,0x93,0xf6,0xb6,0x38,0x00,0x00,0x00
	mov	16(%rsi),%rdx
	adcxq	%rax,%r12
	adoxq	%rbx,%r13
	adcxq	%r15,%r13
	adoxq	%rbp,%r14
	adcxq	%rbp,%r14

	mov	%r8,24(%rdi)
	mov	%r9,32(%rdi)

	mulxq	24(%rsi),%r8,%rbx
	mulxq	32(%rsi),%r9,%rax
	adcxq	%r10,%r8
	adoxq	%rbx,%r9
	mulxq	40(%rsi),%r10,%rbx
	adcxq	%r11,%r9
	adoxq	%rax,%r10
.byte	0xc4,0xe2,0xa3,0xf6,0x86,0x30,0x00,0x00,0x00
	adcxq	%r12,%r10
	adoxq	%r13,%r11
.byte	0xc4,0x62,0x9b,0xf6,0xae,0x38,0x00,0x00,0x00
.byte	0x3e
	mov	24(%rsi),%rdx
	adcxq	%rbx,%r11
	adoxq	%rax,%r12
	adcxq	%r14,%r12
	mov	%r8,40(%rdi)
	mov	%r9,48(%rdi)
	mulxq	32(%rsi),%r8,%rax
	adoxq	%rbp,%r13
	adcxq	%rbp,%r13

	mulxq	40(%rsi),%r9,%rbx
	adcxq	%r10,%r8
	adoxq	%rax,%r9
	mulxq	48(%rsi),%r10,%rax
	adcxq	%r11,%r9
	adoxq	%r12,%r10
	mulxq	56(%rsi),%r11,%r12
	mov	32(%rsi),%rdx
	mov	40(%rsi),%r14
	adcxq	%rbx,%r10
	adoxq	%rax,%r11
	mov	48(%rsi),%r15
	adcxq	%r13,%r11
	adoxq	%rbp,%r12
	adcxq	%rbp,%r12

	mov	%r8,56(%rdi)
	mov	%r9,64(%rdi)

	mulxq	%r14,%r9,%rax
	mov	56(%rsi),%r8
	adcxq	%r10,%r9
	mulxq	%r15,%r10,%rbx
	adoxq	%rax,%r10
	adcxq	%r11,%r10
	mulxq	%r8,%r11,%rax
	mov	%r14,%rdx
	adoxq	%rbx,%r11
	adcxq	%r12,%r11

	adcxq	%rbp,%rax

	mulxq	%r15,%r14,%rbx
	mulxq	%r8,%r12,%r13
	mov	%r15,%rdx
	lea	64(%rsi),%rsi
	adcxq	%r14,%r11
	adoxq	%rbx,%r12
	adcxq	%rax,%r12
	adoxq	%rbp,%r13

.byte	0x67,0x67
	mulxq	%r8,%r8,%r14
	adcxq	%r8,%r13
	adcxq	%rbp,%r14

	cmp	8+8(%rsp),%rsi
	je	.Lsqrx8x_outer_break

	negq	%rcx
	mov	$-8,%rcx
	mov	%rbp,%r15
	mov	64(%rdi),%r8
	adcxq	72(%rdi),%r9
	adcxq	80(%rdi),%r10
	adcxq	88(%rdi),%r11
	adc	96(%rdi),%r12
	adc	104(%rdi),%r13
	adc	112(%rdi),%r14
	adc	120(%rdi),%r15
	lea	(%rsi),%rbp
	lea	128(%rdi),%rdi
	sbb	%rax,%rax

	mov	-64(%rsi),%rdx
	mov	%rax,16+8(%rsp)
	mov	%rdi,24+8(%rsp)


	xor	%eax,%eax
	jmp	.Lsqrx8x_loop

.align	32
.Lsqrx8x_loop:
	mov	%r8,%rbx
	mulxq	0(%rbp),%rax,%r8
	adcxq	%rax,%rbx
	adoxq	%r9,%r8

	mulxq	8(%rbp),%rax,%r9
	adcxq	%rax,%r8
	adoxq	%r10,%r9

	mulxq	16(%rbp),%rax,%r10
	adcxq	%rax,%r9
	adoxq	%r11,%r10

	mulxq	24(%rbp),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11

.byte	0xc4,0x62,0xfb,0xf6,0xa5,0x20,0x00,0x00,0x00
	adcxq	%rax,%r11
	adoxq	%r13,%r12

	mulxq	40(%rbp),%rax,%r13
	adcxq	%rax,%r12
	adoxq	%r14,%r13

	mulxq	48(%rbp),%rax,%r14
	mov	%rbx,(%rdi,%rcx,8)
	mov	$0,%ebx
	adcxq	%rax,%r13
	adoxq	%r15,%r14

.byte	0xc4,0x62,0xfb,0xf6,0xbd,0x38,0x00,0x00,0x00
	mov	8(%rsi,%rcx,8),%rdx
	adcxq	%rax,%r14
	adoxq	%rbx,%r15
	adcxq	%rbx,%r15

.byte	0x67
	incq	%rcx
	jnz	.Lsqrx8x_loop

	lea	64(%rbp),%rbp
	mov	$-8,%rcx
	cmp	8+8(%rsp),%rbp
	je	.Lsqrx8x_break

	sub	16+8(%rsp),%rbx
.byte	0x66
	mov	-64(%rsi),%rdx
	adcxq	0(%rdi),%r8
	adcxq	8(%rdi),%r9
	adc	16(%rdi),%r10
	adc	24(%rdi),%r11
	adc	32(%rdi),%r12
	adc	40(%rdi),%r13
	adc	48(%rdi),%r14
	adc	56(%rdi),%r15
	lea	64(%rdi),%rdi
.byte	0x67
	sbb	%rax,%rax
	xor	%ebx,%ebx
	mov	%rax,16+8(%rsp)
	jmp	.Lsqrx8x_loop

.align	32
.Lsqrx8x_break:
	xor	%rbp,%rbp
	sub	16+8(%rsp),%rbx
	adcxq	%rbp,%r8
	mov	24+8(%rsp),%rcx
	adcxq	%rbp,%r9
	mov	0(%rsi),%rdx
	adc	$0,%r10
	mov	%r8,0(%rdi)
	adc	$0,%r11
	adc	$0,%r12
	adc	$0,%r13
	adc	$0,%r14
	adc	$0,%r15
	cmp	%rcx,%rdi
	je	.Lsqrx8x_outer_loop

	mov	%r9,8(%rdi)
	mov	8(%rcx),%r9
	mov	%r10,16(%rdi)
	mov	16(%rcx),%r10
	mov	%r11,24(%rdi)
	mov	24(%rcx),%r11
	mov	%r12,32(%rdi)
	mov	32(%rcx),%r12
	mov	%r13,40(%rdi)
	mov	40(%rcx),%r13
	mov	%r14,48(%rdi)
	mov	48(%rcx),%r14
	mov	%r15,56(%rdi)
	mov	56(%rcx),%r15
	mov	%rcx,%rdi
	jmp	.Lsqrx8x_outer_loop

.align	32
.Lsqrx8x_outer_break:
	mov	%r9,72(%rdi)
.byte	102,72,15,126,217
	mov	%r10,80(%rdi)
	mov	%r11,88(%rdi)
	mov	%r12,96(%rdi)
	mov	%r13,104(%rdi)
	mov	%r14,112(%rdi)
	lea	48+8(%rsp),%rdi
	mov	(%rsi,%rcx,1),%rdx

	mov	8(%rdi),%r11
	xor	%r10,%r10
	mov	0+8(%rsp),%r9
	adoxq	%r11,%r11
	mov	16(%rdi),%r12
	mov	24(%rdi),%r13


.align	32
.Lsqrx4x_shift_n_add:
	mulxq	%rdx,%rax,%rbx
	adoxq	%r12,%r12
	adcxq	%r10,%rax
.byte	0x48,0x8b,0x94,0x0e,0x08,0x00,0x00,0x00
.byte	0x4c,0x8b,0x97,0x20,0x00,0x00,0x00
	adoxq	%r13,%r13
	adcxq	%r11,%rbx
	mov	40(%rdi),%r11
	mov	%rax,0(%rdi)
	mov	%rbx,8(%rdi)

	mulxq	%rdx,%rax,%rbx
	adoxq	%r10,%r10
	adcxq	%r12,%rax
	mov	16(%rsi,%rcx,1),%rdx
	mov	48(%rdi),%r12
	adoxq	%r11,%r11
	adcxq	%r13,%rbx
	mov	56(%rdi),%r13
	mov	%rax,16(%rdi)
	mov	%rbx,24(%rdi)

	mulxq	%rdx,%rax,%rbx
	adoxq	%r12,%r12
	adcxq	%r10,%rax
	mov	24(%rsi,%rcx,1),%rdx
	lea	32(%rcx),%rcx
	mov	64(%rdi),%r10
	adoxq	%r13,%r13
	adcxq	%r11,%rbx
	mov	72(%rdi),%r11
	mov	%rax,32(%rdi)
	mov	%rbx,40(%rdi)

	mulxq	%rdx,%rax,%rbx
	adoxq	%r10,%r10
	adcxq	%r12,%rax
	jrcxz	.Lsqrx4x_shift_n_add_break
.byte	0x48,0x8b,0x94,0x0e,0x00,0x00,0x00,0x00
	adoxq	%r11,%r11
	adcxq	%r13,%rbx
	mov	80(%rdi),%r12
	mov	88(%rdi),%r13
	mov	%rax,48(%rdi)
	mov	%rbx,56(%rdi)
	lea	64(%rdi),%rdi
	nop
	jmp	.Lsqrx4x_shift_n_add

.align	32
.Lsqrx4x_shift_n_add_break:
	adcxq	%r13,%rbx
	mov	%rax,48(%rdi)
	mov	%rbx,56(%rdi)
	lea	64(%rdi),%rdi
.byte	102,72,15,126,213
__bn_sqrx8x_reduction:
	xor	%eax,%eax
	mov	32+8(%rsp),%rbx
	mov	48+8(%rsp),%rdx
	lea	-64(%rbp,%r9,1),%rcx

	mov	%rcx,0+8(%rsp)
	mov	%rdi,8+8(%rsp)

	lea	48+8(%rsp),%rdi
	jmp	.Lsqrx8x_reduction_loop

.align	32
.Lsqrx8x_reduction_loop:
	mov	8(%rdi),%r9
	mov	16(%rdi),%r10
	mov	24(%rdi),%r11
	mov	32(%rdi),%r12
	mov	%rdx,%r8
	imul	%rbx,%rdx
	mov	40(%rdi),%r13
	mov	48(%rdi),%r14
	mov	56(%rdi),%r15
	mov	%rax,24+8(%rsp)

	lea	64(%rdi),%rdi
	xor	%rsi,%rsi
	mov	$-8,%rcx
	jmp	.Lsqrx8x_reduce

.align	32
.Lsqrx8x_reduce:
	mov	%r8,%rbx
	mulxq	0(%rbp),%rax,%r8
	adcxq	%rbx,%rax
	adoxq	%r9,%r8

	mulxq	8(%rbp),%rbx,%r9
	adcxq	%rbx,%r8
	adoxq	%r10,%r9

	mulxq	16(%rbp),%rbx,%r10
	adcxq	%rbx,%r9
	adoxq	%r11,%r10

	mulxq	24(%rbp),%rbx,%r11
	adcxq	%rbx,%r10
	adoxq	%r12,%r11

.byte	0xc4,0x62,0xe3,0xf6,0xa5,0x20,0x00,0x00,0x00
	mov	%rdx,%rax
	mov	%r8,%rdx
	adcxq	%rbx,%r11
	adoxq	%r13,%r12

	mulxq	32+8(%rsp),%rbx,%rdx
	mov	%rax,%rdx
	mov	%rax,64+48+8(%rsp,%rcx,8)

	mulxq	40(%rbp),%rax,%r13
	adcxq	%rax,%r12
	adoxq	%r14,%r13

	mulxq	48(%rbp),%rax,%r14
	adcxq	%rax,%r13
	adoxq	%r15,%r14

	mulxq	56(%rbp),%rax,%r15
	mov	%rbx,%rdx
	adcxq	%rax,%r14
	adoxq	%rsi,%r15
	adcxq	%rsi,%r15

.byte	0x67,0x67,0x67
	incq	%rcx
	jnz	.Lsqrx8x_reduce

	mov	%rsi,%rax
	cmp	0+8(%rsp),%rbp
	jae	.Lsqrx8x_no_tail

	mov	48+8(%rsp),%rdx
	add	0(%rdi),%r8
	lea	64(%rbp),%rbp
	mov	$-8,%rcx
	adcxq	8(%rdi),%r9
	adcxq	16(%rdi),%r10
	adc	24(%rdi),%r11
	adc	32(%rdi),%r12
	adc	40(%rdi),%r13
	adc	48(%rdi),%r14
	adc	56(%rdi),%r15
	lea	64(%rdi),%rdi
	sbb	%rax,%rax

	xor	%rsi,%rsi
	mov	%rax,16+8(%rsp)
	jmp	.Lsqrx8x_tail

.align	32
.Lsqrx8x_tail:
	mov	%r8,%rbx
	mulxq	0(%rbp),%rax,%r8
	adcxq	%rax,%rbx
	adoxq	%r9,%r8

	mulxq	8(%rbp),%rax,%r9
	adcxq	%rax,%r8
	adoxq	%r10,%r9

	mulxq	16(%rbp),%rax,%r10
	adcxq	%rax,%r9
	adoxq	%r11,%r10

	mulxq	24(%rbp),%rax,%r11
	adcxq	%rax,%r10
	adoxq	%r12,%r11

.byte	0xc4,0x62,0xfb,0xf6,0xa5,0x20,0x00,0x00,0x00
	adcxq	%rax,%r11
	adoxq	%r13,%r12

	mulxq	40(%rbp),%rax,%r13
	adcxq	%rax,%r12
	adoxq	%r14,%r13

	mulxq	48(%rbp),%rax,%r14
	adcxq	%rax,%r13
	adoxq	%r15,%r14

	mulxq	56(%rbp),%rax,%r15
	mov	72+48+8(%rsp,%rcx,8),%rdx
	adcxq	%rax,%r14
	adoxq	%rsi,%r15
	mov	%rbx,(%rdi,%rcx,8)
	mov	%r8,%rbx
	adcxq	%rsi,%r15

	incq	%rcx
	jnz	.Lsqrx8x_tail

	cmp	0+8(%rsp),%rbp
	jae	.Lsqrx8x_tail_done

	sub	16+8(%rsp),%rsi
	mov	48+8(%rsp),%rdx
	lea	64(%rbp),%rbp
	adc	0(%rdi),%r8
	adc	8(%rdi),%r9
	adc	16(%rdi),%r10
	adc	24(%rdi),%r11
	adc	32(%rdi),%r12
	adc	40(%rdi),%r13
	adc	48(%rdi),%r14
	adc	56(%rdi),%r15
	lea	64(%rdi),%rdi
	sbb	%rax,%rax
	sub	$8,%rcx

	xor	%rsi,%rsi
	mov	%rax,16+8(%rsp)
	jmp	.Lsqrx8x_tail

.align	32
.Lsqrx8x_tail_done:
	xor	%rax,%rax
	add	24+8(%rsp),%r8
	adc	$0,%r9
	adc	$0,%r10
	adc	$0,%r11
	adc	$0,%r12
	adc	$0,%r13
	adc	$0,%r14
	adc	$0,%r15
	adc	$0,%rax

	sub	16+8(%rsp),%rsi
.Lsqrx8x_no_tail:
	adc	0(%rdi),%r8
.byte	102,72,15,126,217
	adc	8(%rdi),%r9
	mov	56(%rbp),%rsi
.byte	102,72,15,126,213
	adc	16(%rdi),%r10
	adc	24(%rdi),%r11
	adc	32(%rdi),%r12
	adc	40(%rdi),%r13
	adc	48(%rdi),%r14
	adc	56(%rdi),%r15
	adc	$0,%rax

	mov	32+8(%rsp),%rbx
	mov	64(%rdi,%rcx,1),%rdx

	mov	%r8,0(%rdi)
	lea	64(%rdi),%r8
	mov	%r9,8(%rdi)
	mov	%r10,16(%rdi)
	mov	%r11,24(%rdi)
	mov	%r12,32(%rdi)
	mov	%r13,40(%rdi)
	mov	%r14,48(%rdi)
	mov	%r15,56(%rdi)

	lea	64(%rdi,%rcx,1),%rdi
	cmp	8+8(%rsp),%r8
	jb	.Lsqrx8x_reduction_loop
	.byte	0xf3,0xc3
.cfi_endproc	
.size	bn_sqrx8x_internal,.-bn_sqrx8x_internal
.align	32
__bn_postx4x_internal:
.cfi_startproc	
	mov	0(%rbp),%r12
	mov	%rcx,%r10
	mov	%rcx,%r9
	negq	%rax
	sarq	$3+2,%rcx

.byte	102,72,15,126,202
.byte	102,72,15,126,206
	decq	%r12
	mov	8(%rbp),%r13
	xor	%r8,%r8
	mov	16(%rbp),%r14
	mov	24(%rbp),%r15
	jmp	.Lsqrx4x_sub_entry

.align	16
.Lsqrx4x_sub:
	mov	0(%rbp),%r12
	mov	8(%rbp),%r13
	mov	16(%rbp),%r14
	mov	24(%rbp),%r15
.Lsqrx4x_sub_entry:
	andnq	%rax,%r12,%r12
	lea	32(%rbp),%rbp
	andnq	%rax,%r13,%r13
	andnq	%rax,%r14,%r14
	andnq	%rax,%r15,%r15

	negq	%r8
	adc	0(%rdi),%r12
	adc	8(%rdi),%r13
	adc	16(%rdi),%r14
	adc	24(%rdi),%r15
	mov	%r12,0(%rdx)
	lea	32(%rdi),%rdi
	mov	%r13,8(%rdx)
	sbb	%r8,%r8
	mov	%r14,16(%rdx)
	mov	%r15,24(%rdx)
	lea	32(%rdx),%rdx

	incq	%rcx
	jnz	.Lsqrx4x_sub

	negq	%r9

	.byte	0xf3,0xc3
.cfi_endproc	
.size	__bn_postx4x_internal,.-__bn_postx4x_internal
.globl	bn_get_bits5
.type	bn_get_bits5,@function
.align	16
bn_get_bits5:
.cfi_startproc	
	lea	0(%rdi),%r10
	lea	1(%rdi),%r11
	mov	%esi,%ecx
	shrl	$4,%esi
	and	$15,%ecx
	lea	-8(%rcx),%eax
	cmp	$11,%ecx
	cmovaq	%r11,%r10
	cmoval	%eax,%ecx
	movzwl	(%r10,%rsi,2),%eax
	shrl	%cl,%eax
	and	$31,%eax
	.byte	0xf3,0xc3
.cfi_endproc	
.size	bn_get_bits5,.-bn_get_bits5

.globl	bn_scatter5
.type	bn_scatter5,@function
.align	16
bn_scatter5:
.cfi_startproc	
	cmp	$0,%esi
	jz	.Lscatter_epilogue
	lea	(%rdx,%rcx,8),%rdx
.Lscatter:
	mov	(%rdi),%rax
	lea	8(%rdi),%rdi
	mov	%rax,(%rdx)
	lea	256(%rdx),%rdx
	sub	$1,%esi
	jnz	.Lscatter
.Lscatter_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc	
.size	bn_scatter5,.-bn_scatter5

.globl	bn_gather5
.type	bn_gather5,@function
.align	32
bn_gather5:
.LSEH_begin_bn_gather5:
.cfi_startproc	

.byte	0x4c,0x8d,0x14,0x24
.byte	0x48,0x81,0xec,0x08,0x01,0x00,0x00
	lea	.Linc(%rip),%rax
	and	$-16,%rsp

	movd	%ecx,%xmm5
	movdqa	0(%rax),%xmm0
	movdqa	16(%rax),%xmm1
	lea	128(%rdx),%r11
	lea	128(%rsp),%rax

	pshufd	$0,%xmm5,%xmm5
	movdqa	%xmm1,%xmm4
	movdqa	%xmm1,%xmm2
	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm4,%xmm3

	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,-128(%rax)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,-112(%rax)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,-96(%rax)
	movdqa	%xmm4,%xmm2
	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,-80(%rax)
	movdqa	%xmm4,%xmm3

	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,-64(%rax)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,-48(%rax)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,-32(%rax)
	movdqa	%xmm4,%xmm2
	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,-16(%rax)
	movdqa	%xmm4,%xmm3

	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,0(%rax)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,16(%rax)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,32(%rax)
	movdqa	%xmm4,%xmm2
	paddd	%xmm0,%xmm1
	pcmpeqd	%xmm5,%xmm0
	movdqa	%xmm3,48(%rax)
	movdqa	%xmm4,%xmm3

	paddd	%xmm1,%xmm2
	pcmpeqd	%xmm5,%xmm1
	movdqa	%xmm0,64(%rax)
	movdqa	%xmm4,%xmm0

	paddd	%xmm2,%xmm3
	pcmpeqd	%xmm5,%xmm2
	movdqa	%xmm1,80(%rax)
	movdqa	%xmm4,%xmm1

	paddd	%xmm3,%xmm0
	pcmpeqd	%xmm5,%xmm3
	movdqa	%xmm2,96(%rax)
	movdqa	%xmm4,%xmm2
	movdqa	%xmm3,112(%rax)
	jmp	.Lgather

.align	32
.Lgather:
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	movdqa	-128(%r11),%xmm0
	movdqa	-112(%r11),%xmm1
	movdqa	-96(%r11),%xmm2
	pand	-128(%rax),%xmm0
	movdqa	-80(%r11),%xmm3
	pand	-112(%rax),%xmm1
	por	%xmm0,%xmm4
	pand	-96(%rax),%xmm2
	por	%xmm1,%xmm5
	pand	-80(%rax),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	-64(%r11),%xmm0
	movdqa	-48(%r11),%xmm1
	movdqa	-32(%r11),%xmm2
	pand	-64(%rax),%xmm0
	movdqa	-16(%r11),%xmm3
	pand	-48(%rax),%xmm1
	por	%xmm0,%xmm4
	pand	-32(%rax),%xmm2
	por	%xmm1,%xmm5
	pand	-16(%rax),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	0(%r11),%xmm0
	movdqa	16(%r11),%xmm1
	movdqa	32(%r11),%xmm2
	pand	0(%rax),%xmm0
	movdqa	48(%r11),%xmm3
	pand	16(%rax),%xmm1
	por	%xmm0,%xmm4
	pand	32(%rax),%xmm2
	por	%xmm1,%xmm5
	pand	48(%rax),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	movdqa	64(%r11),%xmm0
	movdqa	80(%r11),%xmm1
	movdqa	96(%r11),%xmm2
	pand	64(%rax),%xmm0
	movdqa	112(%r11),%xmm3
	pand	80(%rax),%xmm1
	por	%xmm0,%xmm4
	pand	96(%rax),%xmm2
	por	%xmm1,%xmm5
	pand	112(%rax),%xmm3
	por	%xmm2,%xmm4
	por	%xmm3,%xmm5
	por	%xmm5,%xmm4
	lea	256(%r11),%r11
	pshufd	$0x4e,%xmm4,%xmm0
	por	%xmm4,%xmm0
	mov	%xmm0,(%rdi)
	lea	8(%rdi),%rdi
	sub	$1,%esi
	jnz	.Lgather

	lea	(%r10),%rsp
	.byte	0xf3,0xc3
.LSEH_end_bn_gather5:
.cfi_endproc	
.size	bn_gather5,.-bn_gather5
.section	.rodata
.align	64
.Linc:
.long	0,0, 1,1
.long	2,2, 2,2
.byte	77,111,110,116,103,111,109,101,114,121,32,77,117,108,116,105,112,108,105,99,97,116,105,111,110,32,119,105,116,104,32,115,99,97,116,116,101,114,47,103,97,116,104,101,114,32,102,111,114,32,120,56,54,95,54,52,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,104,116,116,112,115,58,47,47,103,105,116,104,117,98,46,99,111,109,47,100,111,116,45,97,115,109,62,0
.previous	
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
