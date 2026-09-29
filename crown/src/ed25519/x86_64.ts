/**
 * Curve25519 field arithmetic for x86_64.
 *
 * TypeScript port of OpenSSL crypto/ec/asm/x25519-x86_64.pl.
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Provides the radix-2^51 (fe51) helpers used by the ed25519 group
 * operations and the radix-2^64 (fe64) helpers used by the X25519 ladder
 * in OpenSSL crypto/ec/curve25519.c under X25519_ASM. All symbols are
 * self-contained; `x25519_fe64_eligible` reports ADX/BMI2 support by
 * executing CPUID directly.
 *
 * Reference configuration: default (`elf` output, no config pins; the
 * perl has no $avx probe and emits both the fe51 and fe64 sets).
 *
 * Register map (fe51_*): h=%rdi f=%rsi g=%rdx  (mul121666: f=%rsi)
 * Register map (fe64_*): h=%rdi f=%rsi g=%rdx, all limb vectors as four
 * little-endian u64 limbs.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

/**
 * Curve25519 field arithmetic for x86_64.
 *
 * TypeScript port of OpenSSL crypto/ec/asm/x25519-x86_64.pl.
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Reference configuration: default `elf` output with the perl's
 * `$ENV{CC}` assembler probe succeeding (GNU as >= 2.23), i.e. `$addx=1`
 * — the real ADX/BMI2 fe64 bodies are emitted, not ud2 stubs. The perl
 * has no $avx probe and emits both the radix-2^51 (fe51) set used by the
 * ed25519 group operations and the radix-2^64 (fe64) set used by the
 * X25519 ladder (curve25519.c under X25519_ASM).
 * Register map: h=%rdi f=%rsi g=%rdx (fe51_mul121666/fe64_mul121666:
 * f=%rsi only). fe64 values are four little-endian u64 limbs, partially
 * reduced mod 2^256-38; only fe64_tobytes fully reduces.
 */

const code = `.text

.globl	x25519_fe51_mul
.type	x25519_fe51_mul,@function
.align	32
x25519_fe51_mul:
.cfi_startproc
	pushq	%rbp
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbp,-16
	pushq	%rbx
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbx,-24
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_adjust_cfa_offset	8
.cfi_offset	%r15,-56
	lea	-40(%rsp),%rsp
.cfi_adjust_cfa_offset	40
.Lfe51_mul_body:

	mov	0(%rsi),%rax
	mov	0(%rdx),%r11
	mov	8(%rdx),%r12
	mov	16(%rdx),%r13
	mov	24(%rdx),%rbp
	mov	32(%rdx),%r14

	mov	%rdi,32(%rsp)
	mov	%rax,%rdi
	mulq	%r11
	mov	%r11,0(%rsp)
	mov	%rax,%rbx
	mov	%rdi,%rax
	mov	%rdx,%rcx
	mulq	%r12
	mov	%r12,8(%rsp)
	mov	%rax,%r8
	mov	%rdi,%rax
	lea	(%r14,%r14,8),%r15
	mov	%rdx,%r9
	mulq	%r13
	mov	%r13,16(%rsp)
	mov	%rax,%r10
	mov	%rdi,%rax
	lea	(%r14,%r15,2),%rdi
	mov	%rdx,%r11
	mulq	%rbp
	mov	%rax,%r12
	mov	0(%rsi),%rax
	mov	%rdx,%r13
	mulq	%r14
	mov	%rax,%r14
	mov	8(%rsi),%rax
	mov	%rdx,%r15

	mulq	%rdi
	add	%rax,%rbx
	mov	16(%rsi),%rax
	adc	%rdx,%rcx
	mulq	%rdi
	add	%rax,%r8
	mov	24(%rsi),%rax
	adc	%rdx,%r9
	mulq	%rdi
	add	%rax,%r10
	mov	32(%rsi),%rax
	adc	%rdx,%r11
	mulq	%rdi
	imul	$19,%rbp,%rdi
	add	%rax,%r12
	mov	8(%rsi),%rax
	adc	%rdx,%r13
	mulq	%rbp
	mov	16(%rsp),%rbp
	add	%rax,%r14
	mov	16(%rsi),%rax
	adc	%rdx,%r15

	mulq	%rdi
	add	%rax,%rbx
	mov	24(%rsi),%rax
	adc	%rdx,%rcx
	mulq	%rdi
	add	%rax,%r8
	mov	32(%rsi),%rax
	adc	%rdx,%r9
	mulq	%rdi
	imul	$19,%rbp,%rdi
	add	%rax,%r10
	mov	8(%rsi),%rax
	adc	%rdx,%r11
	mulq	%rbp
	add	%rax,%r12
	mov	16(%rsi),%rax
	adc	%rdx,%r13
	mulq	%rbp
	mov	8(%rsp),%rbp
	add	%rax,%r14
	mov	24(%rsi),%rax
	adc	%rdx,%r15

	mulq	%rdi
	add	%rax,%rbx
	mov	32(%rsi),%rax
	adc	%rdx,%rcx
	mulq	%rdi
	add	%rax,%r8
	mov	8(%rsi),%rax
	adc	%rdx,%r9
	mulq	%rbp
	imul	$19,%rbp,%rdi
	add	%rax,%r10
	mov	16(%rsi),%rax
	adc	%rdx,%r11
	mulq	%rbp
	add	%rax,%r12
	mov	24(%rsi),%rax
	adc	%rdx,%r13
	mulq	%rbp
	mov	0(%rsp),%rbp
	add	%rax,%r14
	mov	32(%rsi),%rax
	adc	%rdx,%r15

	mulq	%rdi
	add	%rax,%rbx
	mov	8(%rsi),%rax
	adc	%rdx,%rcx
	mulq	%rbp
	add	%rax,%r8
	mov	16(%rsi),%rax
	adc	%rdx,%r9
	mulq	%rbp
	add	%rax,%r10
	mov	24(%rsi),%rax
	adc	%rdx,%r11
	mulq	%rbp
	add	%rax,%r12
	mov	32(%rsi),%rax
	adc	%rdx,%r13
	mulq	%rbp
	add	%rax,%r14
	adc	%rdx,%r15

	mov	32(%rsp),%rdi
	jmp	.Lreduce51
.Lfe51_mul_epilogue:
.cfi_endproc
.size	x25519_fe51_mul,.-x25519_fe51_mul

.globl	x25519_fe51_sqr
.type	x25519_fe51_sqr,@function
.align	32
x25519_fe51_sqr:
.cfi_startproc
	pushq	%rbp
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbp,-16
	pushq	%rbx
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbx,-24
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_adjust_cfa_offset	8
.cfi_offset	%r15,-56
	lea	-40(%rsp),%rsp
.cfi_adjust_cfa_offset	40
.Lfe51_sqr_body:

	mov	0(%rsi),%rax
	mov	16(%rsi),%r15
	mov	32(%rsi),%rbp

	mov	%rdi,32(%rsp)
	lea	(%rax,%rax,1),%r14
	mulq	%rax
	mov	%rax,%rbx
	mov	8(%rsi),%rax
	mov	%rdx,%rcx
	mulq	%r14
	mov	%rax,%r8
	mov	%r15,%rax
	mov	%r15,0(%rsp)
	mov	%rdx,%r9
	mulq	%r14
	mov	%rax,%r10
	mov	24(%rsi),%rax
	mov	%rdx,%r11
	imul	$19,%rbp,%rdi
	mulq	%r14
	mov	%rax,%r12
	mov	%rbp,%rax
	mov	%rdx,%r13
	mulq	%r14
	mov	%rax,%r14
	mov	%rbp,%rax
	mov	%rdx,%r15

	mulq	%rdi
	add	%rax,%r12
	mov	8(%rsi),%rax
	adc	%rdx,%r13

	mov	24(%rsi),%rsi
	lea	(%rax,%rax,1),%rbp
	mulq	%rax
	add	%rax,%r10
	mov	0(%rsp),%rax
	adc	%rdx,%r11
	mulq	%rbp
	add	%rax,%r12
	mov	%rbp,%rax
	adc	%rdx,%r13
	mulq	%rsi
	add	%rax,%r14
	mov	%rbp,%rax
	adc	%rdx,%r15
	imul	$19,%rsi,%rbp
	mulq	%rdi
	add	%rax,%rbx
	lea	(%rsi,%rsi,1),%rax
	adc	%rdx,%rcx

	mulq	%rdi
	add	%rax,%r10
	mov	%rsi,%rax
	adc	%rdx,%r11
	mulq	%rbp
	add	%rax,%r8
	mov	0(%rsp),%rax
	adc	%rdx,%r9

	lea	(%rax,%rax,1),%rsi
	mulq	%rax
	add	%rax,%r14
	mov	%rbp,%rax
	adc	%rdx,%r15
	mulq	%rsi
	add	%rax,%rbx
	mov	%rsi,%rax
	adc	%rdx,%rcx
	mulq	%rdi
	add	%rax,%r8
	adc	%rdx,%r9

	mov	32(%rsp),%rdi
	jmp	.Lreduce51

.align	32
.Lreduce51:
	mov	$0x7ffffffffffff,%rbp

	mov	%r10,%rdx
	shrq	$51,%r10
	shlq	$13,%r11
	and	%rbp,%rdx
	or	%r10,%r11
	add	%r11,%r12
	adc	$0,%r13

	mov	%rbx,%rax
	shrq	$51,%rbx
	shlq	$13,%rcx
	and	%rbp,%rax
	or	%rbx,%rcx
	add	%rcx,%r8
	adc	$0,%r9

	mov	%r12,%rbx
	shrq	$51,%r12
	shlq	$13,%r13
	and	%rbp,%rbx
	or	%r12,%r13
	add	%r13,%r14
	adc	$0,%r15

	mov	%r8,%rcx
	shrq	$51,%r8
	shlq	$13,%r9
	and	%rbp,%rcx
	or	%r8,%r9
	add	%r9,%rdx

	mov	%r14,%r10
	shrq	$51,%r14
	shlq	$13,%r15
	and	%rbp,%r10
	or	%r14,%r15

	lea	(%r15,%r15,8),%r14
	lea	(%r15,%r14,2),%r15
	add	%r15,%rax

	mov	%rdx,%r8
	and	%rbp,%rdx
	shrq	$51,%r8
	add	%r8,%rbx

	mov	%rax,%r9
	and	%rbp,%rax
	shrq	$51,%r9
	add	%r9,%rcx

	mov	%rax,0(%rdi)
	mov	%rcx,8(%rdi)
	mov	%rdx,16(%rdi)
	mov	%rbx,24(%rdi)
	mov	%r10,32(%rdi)

	mov	40(%rsp),%r15
.cfi_restore	%r15
	mov	48(%rsp),%r14
.cfi_restore	%r14
	mov	56(%rsp),%r13
.cfi_restore	%r13
	mov	64(%rsp),%r12
.cfi_restore	%r12
	mov	72(%rsp),%rbx
.cfi_restore	%rbx
	mov	80(%rsp),%rbp
.cfi_restore	%rbp
	lea	88(%rsp),%rsp
.cfi_adjust_cfa_offset	88
.Lfe51_sqr_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	x25519_fe51_sqr,.-x25519_fe51_sqr

.globl	x25519_fe51_mul121666
.type	x25519_fe51_mul121666,@function
.align	32
x25519_fe51_mul121666:
.cfi_startproc
	pushq	%rbp
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbp,-16
	pushq	%rbx
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbx,-24
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_adjust_cfa_offset	8
.cfi_offset	%r15,-56
	lea	-40(%rsp),%rsp
.cfi_adjust_cfa_offset	40
.Lfe51_mul121666_body:
	mov	$121666,%eax

	mulq	0(%rsi)
	mov	%rax,%rbx
	mov	$121666,%eax
	mov	%rdx,%rcx
	mulq	8(%rsi)
	mov	%rax,%r8
	mov	$121666,%eax
	mov	%rdx,%r9
	mulq	16(%rsi)
	mov	%rax,%r10
	mov	$121666,%eax
	mov	%rdx,%r11
	mulq	24(%rsi)
	mov	%rax,%r12
	mov	$121666,%eax
	mov	%rdx,%r13
	mulq	32(%rsi)
	mov	%rax,%r14
	mov	%rdx,%r15

	jmp	.Lreduce51
.Lfe51_mul121666_epilogue:
.cfi_endproc
.size	x25519_fe51_mul121666,.-x25519_fe51_mul121666

.globl	x25519_fe64_eligible
.type	x25519_fe64_eligible,@function
.align	32
x25519_fe64_eligible:
.cfi_startproc
	mov	OPENSSL_ia32cap_P+8(%rip),%ecx
	xor	%eax,%eax
	and	$0x80100,%ecx
	cmp	$0x80100,%ecx
	cmovel	%ecx,%eax
	.byte	0xf3,0xc3
.cfi_endproc
.size	x25519_fe64_eligible,.-x25519_fe64_eligible

.globl	x25519_fe64_mul
.type	x25519_fe64_mul,@function
.align	32
x25519_fe64_mul:
.cfi_startproc
	pushq	%rbp
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbp,-16
	pushq	%rbx
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbx,-24
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_adjust_cfa_offset	8
.cfi_offset	%r15,-56
	pushq	%rdi
.cfi_adjust_cfa_offset	8
.cfi_offset	%rdi,-64
	lea	-16(%rsp),%rsp
.cfi_adjust_cfa_offset	16
.Lfe64_mul_body:

	mov	%rdx,%rax
	mov	0(%rdx),%rbp
	mov	0(%rsi),%rdx
	mov	8(%rax),%rcx
	mov	16(%rax),%r14
	mov	24(%rax),%r15

	mulxq	%rbp,%r8,%rax
	xor	%edi,%edi
	mulxq	%rcx,%r9,%rbx
	adcxq	%rax,%r9
	mulxq	%r14,%r10,%rax
	adcxq	%rbx,%r10
	mulxq	%r15,%r11,%r12
	mov	8(%rsi),%rdx
	adcxq	%rax,%r11
	mov	%r14,(%rsp)
	adcxq	%rdi,%r12

	mulxq	%rbp,%rax,%rbx
	adoxq	%rax,%r9
	adcxq	%rbx,%r10
	mulxq	%rcx,%rax,%rbx
	adoxq	%rax,%r10
	adcxq	%rbx,%r11
	mulxq	%r14,%rax,%rbx
	adoxq	%rax,%r11
	adcxq	%rbx,%r12
	mulxq	%r15,%rax,%r13
	mov	16(%rsi),%rdx
	adoxq	%rax,%r12
	adcxq	%rdi,%r13
	adoxq	%rdi,%r13

	mulxq	%rbp,%rax,%rbx
	adcxq	%rax,%r10
	adoxq	%rbx,%r11
	mulxq	%rcx,%rax,%rbx
	adcxq	%rax,%r11
	adoxq	%rbx,%r12
	mulxq	%r14,%rax,%rbx
	adcxq	%rax,%r12
	adoxq	%rbx,%r13
	mulxq	%r15,%rax,%r14
	mov	24(%rsi),%rdx
	adcxq	%rax,%r13
	adoxq	%rdi,%r14
	adcxq	%rdi,%r14

	mulxq	%rbp,%rax,%rbx
	adoxq	%rax,%r11
	adcxq	%rbx,%r12
	mulxq	%rcx,%rax,%rbx
	adoxq	%rax,%r12
	adcxq	%rbx,%r13
	mulxq	(%rsp),%rax,%rbx
	adoxq	%rax,%r13
	adcxq	%rbx,%r14
	mulxq	%r15,%rax,%r15
	mov	$38,%edx
	adoxq	%rax,%r14
	adcxq	%rdi,%r15
	adoxq	%rdi,%r15

	jmp	.Lreduce64
.Lfe64_mul_epilogue:
.cfi_endproc
.size	x25519_fe64_mul,.-x25519_fe64_mul

.globl	x25519_fe64_sqr
.type	x25519_fe64_sqr,@function
.align	32
x25519_fe64_sqr:
.cfi_startproc
	pushq	%rbp
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbp,-16
	pushq	%rbx
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbx,-24
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	%r12,-32
	pushq	%r13
.cfi_adjust_cfa_offset	8
.cfi_offset	%r13,-40
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	%r14,-48
	pushq	%r15
.cfi_adjust_cfa_offset	8
.cfi_offset	%r15,-56
	pushq	%rdi
.cfi_adjust_cfa_offset	8
.cfi_offset	%rdi,-64
	lea	-16(%rsp),%rsp
.cfi_adjust_cfa_offset	16
.Lfe64_sqr_body:

	mov	0(%rsi),%rdx
	mov	8(%rsi),%rcx
	mov	16(%rsi),%rbp
	mov	24(%rsi),%rsi


	mulxq	%rdx,%r8,%r15
	mulxq	%rcx,%r9,%rax
	xor	%edi,%edi
	mulxq	%rbp,%r10,%rbx
	adcxq	%rax,%r10
	mulxq	%rsi,%r11,%r12
	mov	%rcx,%rdx
	adcxq	%rbx,%r11
	adcxq	%rdi,%r12


	mulxq	%rbp,%rax,%rbx
	adoxq	%rax,%r11
	adcxq	%rbx,%r12
	mulxq	%rsi,%rax,%r13
	mov	%rbp,%rdx
	adoxq	%rax,%r12
	adcxq	%rdi,%r13


	mulxq	%rsi,%rax,%r14
	mov	%rcx,%rdx
	adoxq	%rax,%r13
	adcxq	%rdi,%r14
	adoxq	%rdi,%r14

	adcxq	%r9,%r9
	adoxq	%r15,%r9
	adcxq	%r10,%r10
	mulxq	%rdx,%rax,%rbx
	mov	%rbp,%rdx
	adcxq	%r11,%r11
	adoxq	%rax,%r10
	adcxq	%r12,%r12
	adoxq	%rbx,%r11
	mulxq	%rdx,%rax,%rbx
	mov	%rsi,%rdx
	adcxq	%r13,%r13
	adoxq	%rax,%r12
	adcxq	%r14,%r14
	adoxq	%rbx,%r13
	mulxq	%rdx,%rax,%r15
	mov	$38,%edx
	adoxq	%rax,%r14
	adcxq	%rdi,%r15
	adoxq	%rdi,%r15
	jmp	.Lreduce64

.align	32
.Lreduce64:
	mulxq	%r12,%rax,%rbx
	adcxq	%rax,%r8
	adoxq	%rbx,%r9
	mulxq	%r13,%rax,%rbx
	adcxq	%rax,%r9
	adoxq	%rbx,%r10
	mulxq	%r14,%rax,%rbx
	adcxq	%rax,%r10
	adoxq	%rbx,%r11
	mulxq	%r15,%rax,%r12
	adcxq	%rax,%r11
	adoxq	%rdi,%r12
	adcxq	%rdi,%r12

	mov	16(%rsp),%rdi
	imul	%rdx,%r12

	add	%r12,%r8
	adc	$0,%r9
	adc	$0,%r10
	adc	$0,%r11

	sbb	%rax,%rax
	and	$38,%rax

	add	%rax,%r8
	mov	%r9,8(%rdi)
	mov	%r10,16(%rdi)
	mov	%r11,24(%rdi)
	mov	%r8,0(%rdi)

	mov	24(%rsp),%r15
.cfi_restore	%r15
	mov	32(%rsp),%r14
.cfi_restore	%r14
	mov	40(%rsp),%r13
.cfi_restore	%r13
	mov	48(%rsp),%r12
.cfi_restore	%r12
	mov	56(%rsp),%rbx
.cfi_restore	%rbx
	mov	64(%rsp),%rbp
.cfi_restore	%rbp
	lea	72(%rsp),%rsp
.cfi_adjust_cfa_offset	88
.Lfe64_sqr_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	x25519_fe64_sqr,.-x25519_fe64_sqr

.globl	x25519_fe64_mul121666
.type	x25519_fe64_mul121666,@function
.align	32
x25519_fe64_mul121666:
.Lfe64_mul121666_body:
.cfi_startproc
	mov	$121666,%edx
	mulxq	0(%rsi),%r8,%rcx
	mulxq	8(%rsi),%r9,%rax
	add	%rcx,%r9
	mulxq	16(%rsi),%r10,%rcx
	adc	%rax,%r10
	mulxq	24(%rsi),%r11,%rax
	adc	%rcx,%r11
	adc	$0,%rax

	imul	$38,%rax,%rax

	add	%rax,%r8
	adc	$0,%r9
	adc	$0,%r10
	adc	$0,%r11

	sbb	%rax,%rax
	and	$38,%rax

	add	%rax,%r8
	mov	%r9,8(%rdi)
	mov	%r10,16(%rdi)
	mov	%r11,24(%rdi)
	mov	%r8,0(%rdi)

.Lfe64_mul121666_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	x25519_fe64_mul121666,.-x25519_fe64_mul121666

.globl	x25519_fe64_add
.type	x25519_fe64_add,@function
.align	32
x25519_fe64_add:
.Lfe64_add_body:
.cfi_startproc
	mov	0(%rsi),%r8
	mov	8(%rsi),%r9
	mov	16(%rsi),%r10
	mov	24(%rsi),%r11

	add	0(%rdx),%r8
	adc	8(%rdx),%r9
	adc	16(%rdx),%r10
	adc	24(%rdx),%r11

	sbb	%rax,%rax
	and	$38,%rax

	add	%rax,%r8
	adc	$0,%r9
	adc	$0,%r10
	mov	%r9,8(%rdi)
	adc	$0,%r11
	mov	%r10,16(%rdi)
	sbb	%rax,%rax
	mov	%r11,24(%rdi)
	and	$38,%rax

	add	%rax,%r8
	mov	%r8,0(%rdi)

.Lfe64_add_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	x25519_fe64_add,.-x25519_fe64_add

.globl	x25519_fe64_sub
.type	x25519_fe64_sub,@function
.align	32
x25519_fe64_sub:
.Lfe64_sub_body:
.cfi_startproc
	mov	0(%rsi),%r8
	mov	8(%rsi),%r9
	mov	16(%rsi),%r10
	mov	24(%rsi),%r11

	sub	0(%rdx),%r8
	sbb	8(%rdx),%r9
	sbb	16(%rdx),%r10
	sbb	24(%rdx),%r11

	sbb	%rax,%rax
	and	$38,%rax

	sub	%rax,%r8
	sbb	$0,%r9
	sbb	$0,%r10
	mov	%r9,8(%rdi)
	sbb	$0,%r11
	mov	%r10,16(%rdi)
	sbb	%rax,%rax
	mov	%r11,24(%rdi)
	and	$38,%rax

	sub	%rax,%r8
	mov	%r8,0(%rdi)

.Lfe64_sub_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	x25519_fe64_sub,.-x25519_fe64_sub

.globl	x25519_fe64_tobytes
.type	x25519_fe64_tobytes,@function
.align	32
x25519_fe64_tobytes:
.Lfe64_to_body:
.cfi_startproc
	mov	0(%rsi),%r8
	mov	8(%rsi),%r9
	mov	16(%rsi),%r10
	mov	24(%rsi),%r11


	lea	(%r11,%r11,1),%rax
	sarq	$63,%r11
	shrq	$1,%rax
	and	$19,%r11
	add	$19,%r11

	add	%r11,%r8
	adc	$0,%r9
	adc	$0,%r10
	adc	$0,%rax

	lea	(%rax,%rax,1),%r11
	sarq	$63,%rax
	shrq	$1,%r11
	notq	%rax
	and	$19,%rax

	sub	%rax,%r8
	sbb	$0,%r9
	sbb	$0,%r10
	sbb	$0,%r11

	mov	%r8,0(%rdi)
	mov	%r9,8(%rdi)
	mov	%r10,16(%rdi)
	mov	%r11,24(%rdi)

.Lfe64_to_epilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	x25519_fe64_tobytes,.-x25519_fe64_tobytes
.byte	88,50,53,53,49,57,32,112,114,105,109,105,116,105,118,101,115,32,102,111,114,32,120,56,54,95,54,52,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,104,116,116,112,115,58,47,47,103,105,116,104,117,98,46,99,111,109,47,100,111,116,45,97,115,109,62,0
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
