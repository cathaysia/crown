/**
 * Bit-sliced AES for x86_64.
 *
 * TypeScript port of OpenSSL crypto/aes/asm/bsaes-x86_64.pl.
 * Pinned to $win64=0 (unix SysV; Win64 SEH blocks dropped) and $ecb=0
 * (the perl default: suppresses the unreferenced ECB helpers).
 *
 * Exported symbols:
 *   ossl_bsaes_cbc_encrypt
 *   ossl_bsaes_ctr32_encrypt_blocks
 *   ossl_bsaes_xts_encrypt
 *   ossl_bsaes_xts_decrypt
 *
 * Internal (non-global) symbols:
 *   _bsaes_encrypt8, _bsaes_decrypt8, _bsaes_key_convert, _bsaes_const
 *
 * External references:
 *   asm_AES_encrypt, asm_AES_decrypt, asm_AES_cbc_encrypt
 *
 * Encoding note: translateAssembly turns .asciz into .byte via charCodeAt
 * (Latin-1). The credit string contains U+00E4 ("Kasper" with diaeresis);
 * it is written below as the two code units U+00C3 U+00A4 so the emitted
 * .byte list is the UTF-8 pair 195,164 that perl x86_64-xlate.pl produces.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text

.extern	asm_AES_encrypt
.extern	asm_AES_decrypt

.type	_bsaes_encrypt8,@abi-omnipotent
.align	64
_bsaes_encrypt8:
.cfi_startproc
	lea	.LBS0(%rip), %r11	# constants table

	movdqa	(%rax), %xmm8		# round 0 key
	lea	0x10(%rax), %rax
	movdqa	0x50(%r11), %xmm7	# .LM0SR
	pxor	%xmm8, %xmm15	# xor with round0 key
	pxor	%xmm8, %xmm0
	pxor	%xmm8, %xmm1
	pxor	%xmm8, %xmm2
	 pshufb	%xmm7, %xmm15
	 pshufb	%xmm7, %xmm0
	pxor	%xmm8, %xmm3
	pxor	%xmm8, %xmm4
	 pshufb	%xmm7, %xmm1
	 pshufb	%xmm7, %xmm2
	pxor	%xmm8, %xmm5
	pxor	%xmm8, %xmm6
	 pshufb	%xmm7, %xmm3
	 pshufb	%xmm7, %xmm4
	 pshufb	%xmm7, %xmm5
	 pshufb	%xmm7, %xmm6
_bsaes_encrypt8_bitslice:
	movdqa	0x00(%r11),%xmm7	# .LBS0
	movdqa	0x10(%r11),%xmm8	# .LBS1
	movdqa	%xmm5,%xmm9
	psrlq	$1,%xmm5
	 movdqa	%xmm3,%xmm10
	 psrlq	$1,%xmm3
	pxor  	%xmm6,%xmm5
	 pxor  	%xmm4,%xmm3
	pand	%xmm7,%xmm5
	 pand	%xmm7,%xmm3
	pxor	%xmm5,%xmm6
	psllq	$1,%xmm5
	 pxor	%xmm3,%xmm4
	 psllq	$1,%xmm3
	pxor	%xmm9,%xmm5
	 pxor	%xmm10,%xmm3
	movdqa	%xmm1,%xmm9
	psrlq	$1,%xmm1
	 movdqa	%xmm15,%xmm10
	 psrlq	$1,%xmm15
	pxor  	%xmm2,%xmm1
	 pxor  	%xmm0,%xmm15
	pand	%xmm7,%xmm1
	 pand	%xmm7,%xmm15
	pxor	%xmm1,%xmm2
	psllq	$1,%xmm1
	 pxor	%xmm15,%xmm0
	 psllq	$1,%xmm15
	pxor	%xmm9,%xmm1
	 pxor	%xmm10,%xmm15
	movdqa	0x20(%r11),%xmm7	# .LBS2
	movdqa	%xmm4,%xmm9
	psrlq	$2,%xmm4
	 movdqa	%xmm3,%xmm10
	 psrlq	$2,%xmm3
	pxor  	%xmm6,%xmm4
	 pxor  	%xmm5,%xmm3
	pand	%xmm8,%xmm4
	 pand	%xmm8,%xmm3
	pxor	%xmm4,%xmm6
	psllq	$2,%xmm4
	 pxor	%xmm3,%xmm5
	 psllq	$2,%xmm3
	pxor	%xmm9,%xmm4
	 pxor	%xmm10,%xmm3
	movdqa	%xmm0,%xmm9
	psrlq	$2,%xmm0
	 movdqa	%xmm15,%xmm10
	 psrlq	$2,%xmm15
	pxor  	%xmm2,%xmm0
	 pxor  	%xmm1,%xmm15
	pand	%xmm8,%xmm0
	 pand	%xmm8,%xmm15
	pxor	%xmm0,%xmm2
	psllq	$2,%xmm0
	 pxor	%xmm15,%xmm1
	 psllq	$2,%xmm15
	pxor	%xmm9,%xmm0
	 pxor	%xmm10,%xmm15
	movdqa	%xmm2,%xmm9
	psrlq	$4,%xmm2
	 movdqa	%xmm1,%xmm10
	 psrlq	$4,%xmm1
	pxor  	%xmm6,%xmm2
	 pxor  	%xmm5,%xmm1
	pand	%xmm7,%xmm2
	 pand	%xmm7,%xmm1
	pxor	%xmm2,%xmm6
	psllq	$4,%xmm2
	 pxor	%xmm1,%xmm5
	 psllq	$4,%xmm1
	pxor	%xmm9,%xmm2
	 pxor	%xmm10,%xmm1
	movdqa	%xmm0,%xmm9
	psrlq	$4,%xmm0
	 movdqa	%xmm15,%xmm10
	 psrlq	$4,%xmm15
	pxor  	%xmm4,%xmm0
	 pxor  	%xmm3,%xmm15
	pand	%xmm7,%xmm0
	 pand	%xmm7,%xmm15
	pxor	%xmm0,%xmm4
	psllq	$4,%xmm0
	 pxor	%xmm15,%xmm3
	 psllq	$4,%xmm15
	pxor	%xmm9,%xmm0
	 pxor	%xmm10,%xmm15
	dec	%r10d
	jmp	.Lenc_sbox
.align	16
.Lenc_loop:
	pxor	0x00(%rax),%xmm15
	pxor	0x10(%rax),%xmm0
	pxor	0x20(%rax),%xmm1
	pxor	0x30(%rax),%xmm2
	pshufb	%xmm7,%xmm15
	pshufb	%xmm7,%xmm0
	pxor	0x40(%rax),%xmm3
	pxor	0x50(%rax),%xmm4
	pshufb	%xmm7,%xmm1
	pshufb	%xmm7,%xmm2
	pxor	0x60(%rax),%xmm5
	pxor	0x70(%rax),%xmm6
	pshufb	%xmm7,%xmm3
	pshufb	%xmm7,%xmm4
	pshufb	%xmm7,%xmm5
	pshufb	%xmm7,%xmm6
	lea	0x80(%rax),%rax
.Lenc_sbox:
	pxor	%xmm5, %xmm4
	pxor	%xmm0, %xmm1
	pxor	%xmm15, %xmm2
	pxor	%xmm1, %xmm5
	pxor 	%xmm15, %xmm4

	pxor	%xmm2, %xmm5
	pxor	%xmm6, %xmm2
	pxor	%xmm4, %xmm6
	pxor	%xmm3, %xmm2
	pxor	%xmm4, %xmm3
	pxor	%xmm0, %xmm2

	pxor	%xmm6, %xmm1
	pxor	%xmm4, %xmm0
	movdqa	%xmm6, %xmm10
	movdqa	%xmm0, %xmm9
	movdqa	%xmm4, %xmm8
	movdqa	%xmm1, %xmm12
	movdqa	%xmm5, %xmm11

	pxor	%xmm3, %xmm10
	pxor	%xmm1, %xmm9
	pxor	%xmm2, %xmm8
	 movdqa	%xmm10, %xmm13
	pxor	%xmm3, %xmm12
	 movdqa	%xmm9, %xmm7
	pxor	%xmm15, %xmm11
	 movdqa	%xmm10, %xmm14

	por	%xmm8, %xmm9
	por	%xmm11, %xmm10
	pxor	%xmm7, %xmm14
	pand	%xmm11, %xmm13
	pxor	%xmm8, %xmm11
	pand	%xmm8, %xmm7
	pand	%xmm11, %xmm14
	movdqa	%xmm2, %xmm11
	pxor	%xmm15, %xmm11
	pand	%xmm11, %xmm12
	pxor	%xmm12, %xmm10
	pxor	%xmm12, %xmm9
	movdqa	%xmm6, %xmm12
	movdqa	%xmm4, %xmm11
	pxor	%xmm0, %xmm12
	pxor	%xmm5, %xmm11
	movdqa	%xmm12, %xmm8
	pand	%xmm11, %xmm12
	por	%xmm11, %xmm8
	pxor	%xmm12, %xmm7
	pxor	%xmm14, %xmm10
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm8
	movdqa	%xmm1, %xmm11
	pxor	%xmm13, %xmm7
	movdqa	%xmm3, %xmm12
	pxor	%xmm13, %xmm8
	movdqa	%xmm0, %xmm13
	pand	%xmm2, %xmm11
	movdqa	%xmm6, %xmm14
	pand	%xmm15, %xmm12
	pand	%xmm4, %xmm13
	por	%xmm5, %xmm14
	pxor	%xmm11, %xmm10
	pxor	%xmm12, %xmm9
	pxor	%xmm13, %xmm8
	pxor	%xmm14, %xmm7

	#Inv_GF16 	0, 	1, 	2, 	3, s0, s1, s2, s3

	# new smaller inversion

	movdqa	%xmm10, %xmm11
	pand	%xmm8, %xmm10
	pxor	%xmm9, %xmm11

	movdqa	%xmm7, %xmm13
	movdqa	%xmm11, %xmm14
	pxor	%xmm10, %xmm13
	pand	%xmm13, %xmm14

	movdqa	%xmm8, %xmm12
	pxor	%xmm9, %xmm14
	pxor	%xmm7, %xmm12

	pxor	%xmm9, %xmm10

	pand	%xmm10, %xmm12

	movdqa	%xmm13, %xmm9
	pxor	%xmm7, %xmm12

	pxor	%xmm12, %xmm9
	pxor	%xmm12, %xmm8

	pand	%xmm7, %xmm9

	pxor	%xmm9, %xmm13
	pxor	%xmm9, %xmm8

	pand	%xmm14, %xmm13

	pxor	%xmm11, %xmm13
	movdqa	%xmm5, %xmm11
	movdqa	%xmm4, %xmm7
	movdqa	%xmm14, %xmm9
	pxor 	%xmm13, %xmm9
	pand	%xmm5, %xmm9
	pxor	%xmm4, %xmm5
	pand	%xmm14, %xmm4
	pand	%xmm13, %xmm5
	pxor	%xmm4, %xmm5
	pxor	%xmm9, %xmm4
	pxor	%xmm15, %xmm11
	pxor	%xmm2, %xmm7
	pxor	%xmm12, %xmm14
	pxor	%xmm8, %xmm13
	movdqa	%xmm14, %xmm10
	 movdqa	%xmm12, %xmm9
	pxor	%xmm13, %xmm10
	 pxor 	%xmm8, %xmm9
	pand	%xmm11, %xmm10
	 pand	%xmm15, %xmm9
	pxor	%xmm7, %xmm11
	 pxor	%xmm2, %xmm15
	pand	%xmm14, %xmm7
	 pand	%xmm12, %xmm2
	pand	%xmm13, %xmm11
	 pand	%xmm8, %xmm15
	pxor	%xmm11, %xmm7
	 pxor	%xmm2, %xmm15
	pxor	%xmm10, %xmm11
	 pxor	%xmm9, %xmm2
	pxor	%xmm11, %xmm5
	pxor	%xmm11, %xmm15
	pxor	%xmm7, %xmm4
	pxor	%xmm7, %xmm2

	movdqa	%xmm6, %xmm11
	movdqa	%xmm0, %xmm7
	pxor	%xmm3, %xmm11
	pxor	%xmm1, %xmm7
	movdqa	%xmm14, %xmm10
	 movdqa	%xmm12, %xmm9
	pxor	%xmm13, %xmm10
	 pxor 	%xmm8, %xmm9
	pand	%xmm11, %xmm10
	 pand	%xmm3, %xmm9
	pxor	%xmm7, %xmm11
	 pxor	%xmm1, %xmm3
	pand	%xmm14, %xmm7
	 pand	%xmm12, %xmm1
	pand	%xmm13, %xmm11
	 pand	%xmm8, %xmm3
	pxor	%xmm11, %xmm7
	 pxor	%xmm1, %xmm3
	pxor	%xmm10, %xmm11
	 pxor	%xmm9, %xmm1
	pxor	%xmm12, %xmm14
	pxor	%xmm8, %xmm13
	movdqa	%xmm14, %xmm10
	pxor 	%xmm13, %xmm10
	pand	%xmm6, %xmm10
	pxor	%xmm0, %xmm6
	pand	%xmm14, %xmm0
	pand	%xmm13, %xmm6
	pxor	%xmm0, %xmm6
	pxor	%xmm10, %xmm0
	pxor	%xmm11, %xmm6
	pxor	%xmm11, %xmm3
	pxor	%xmm7, %xmm0
	pxor	%xmm7, %xmm1
	pxor	%xmm15, %xmm6
	pxor	%xmm5, %xmm0
	pxor	%xmm6, %xmm3
	pxor	%xmm15, %xmm5
	pxor	%xmm0, %xmm15

	pxor	%xmm4, %xmm0
	pxor	%xmm1, %xmm4
	pxor	%xmm2, %xmm1
	pxor	%xmm4, %xmm2
	pxor	%xmm4, %xmm3

	pxor	%xmm2, %xmm5
	dec	%r10d
	jl	.Lenc_done
	pshufd	$0x93, %xmm15, %xmm7	# x0 <<< 32
	pshufd	$0x93, %xmm0, %xmm8
	 pxor	%xmm7, %xmm15		# x0 ^ (x0 <<< 32)
	pshufd	$0x93, %xmm3, %xmm9
	 pxor	%xmm8, %xmm0
	pshufd	$0x93, %xmm5, %xmm10
	 pxor	%xmm9, %xmm3
	pshufd	$0x93, %xmm2, %xmm11
	 pxor	%xmm10, %xmm5
	pshufd	$0x93, %xmm6, %xmm12
	 pxor	%xmm11, %xmm2
	pshufd	$0x93, %xmm1, %xmm13
	 pxor	%xmm12, %xmm6
	pshufd	$0x93, %xmm4, %xmm14
	 pxor	%xmm13, %xmm1
	 pxor	%xmm14, %xmm4

	pxor	%xmm15, %xmm8
	pxor	%xmm4, %xmm7
	pxor	%xmm4, %xmm8
	 pshufd	$0x4E, %xmm15, %xmm15 	# (x0 ^ (x0 <<< 32)) <<< 64)
	pxor	%xmm0, %xmm9
	 pshufd	$0x4E, %xmm0, %xmm0
	pxor	%xmm2, %xmm12
	 pxor	%xmm7, %xmm15
	pxor	%xmm6, %xmm13
	 pxor	%xmm8, %xmm0
	pxor	%xmm5, %xmm11
	 pshufd	$0x4E, %xmm2, %xmm7
	pxor	%xmm1, %xmm14
	 pshufd	$0x4E, %xmm6, %xmm8
	pxor	%xmm3, %xmm10
	 pshufd	$0x4E, %xmm5, %xmm2
	pxor	%xmm4, %xmm10
	 pshufd	$0x4E, %xmm4, %xmm6
	pxor	%xmm4, %xmm11
	 pshufd	$0x4E, %xmm1, %xmm5
	pxor	%xmm11, %xmm7
	 pshufd	$0x4E, %xmm3, %xmm1
	pxor	%xmm12, %xmm8
	pxor	%xmm10, %xmm2
	pxor	%xmm14, %xmm6
	pxor	%xmm13, %xmm5
	 movdqa	%xmm7, %xmm3
	pxor	%xmm9, %xmm1
	 movdqa	%xmm8, %xmm4
	movdqa	0x30(%r11), %xmm7	# .LSR
	jnz	.Lenc_loop
	movdqa	0x40(%r11), %xmm7	# .LSRM0
	jmp	.Lenc_loop
.align	16
.Lenc_done:
	movdqa	0x00(%r11),%xmm7	# .LBS0
	movdqa	0x10(%r11),%xmm8	# .LBS1
	movdqa	%xmm1,%xmm9
	psrlq	$1,%xmm1
	 movdqa	%xmm2,%xmm10
	 psrlq	$1,%xmm2
	pxor  	%xmm4,%xmm1
	 pxor  	%xmm6,%xmm2
	pand	%xmm7,%xmm1
	 pand	%xmm7,%xmm2
	pxor	%xmm1,%xmm4
	psllq	$1,%xmm1
	 pxor	%xmm2,%xmm6
	 psllq	$1,%xmm2
	pxor	%xmm9,%xmm1
	 pxor	%xmm10,%xmm2
	movdqa	%xmm3,%xmm9
	psrlq	$1,%xmm3
	 movdqa	%xmm15,%xmm10
	 psrlq	$1,%xmm15
	pxor  	%xmm5,%xmm3
	 pxor  	%xmm0,%xmm15
	pand	%xmm7,%xmm3
	 pand	%xmm7,%xmm15
	pxor	%xmm3,%xmm5
	psllq	$1,%xmm3
	 pxor	%xmm15,%xmm0
	 psllq	$1,%xmm15
	pxor	%xmm9,%xmm3
	 pxor	%xmm10,%xmm15
	movdqa	0x20(%r11),%xmm7	# .LBS2
	movdqa	%xmm6,%xmm9
	psrlq	$2,%xmm6
	 movdqa	%xmm2,%xmm10
	 psrlq	$2,%xmm2
	pxor  	%xmm4,%xmm6
	 pxor  	%xmm1,%xmm2
	pand	%xmm8,%xmm6
	 pand	%xmm8,%xmm2
	pxor	%xmm6,%xmm4
	psllq	$2,%xmm6
	 pxor	%xmm2,%xmm1
	 psllq	$2,%xmm2
	pxor	%xmm9,%xmm6
	 pxor	%xmm10,%xmm2
	movdqa	%xmm0,%xmm9
	psrlq	$2,%xmm0
	 movdqa	%xmm15,%xmm10
	 psrlq	$2,%xmm15
	pxor  	%xmm5,%xmm0
	 pxor  	%xmm3,%xmm15
	pand	%xmm8,%xmm0
	 pand	%xmm8,%xmm15
	pxor	%xmm0,%xmm5
	psllq	$2,%xmm0
	 pxor	%xmm15,%xmm3
	 psllq	$2,%xmm15
	pxor	%xmm9,%xmm0
	 pxor	%xmm10,%xmm15
	movdqa	%xmm5,%xmm9
	psrlq	$4,%xmm5
	 movdqa	%xmm3,%xmm10
	 psrlq	$4,%xmm3
	pxor  	%xmm4,%xmm5
	 pxor  	%xmm1,%xmm3
	pand	%xmm7,%xmm5
	 pand	%xmm7,%xmm3
	pxor	%xmm5,%xmm4
	psllq	$4,%xmm5
	 pxor	%xmm3,%xmm1
	 psllq	$4,%xmm3
	pxor	%xmm9,%xmm5
	 pxor	%xmm10,%xmm3
	movdqa	%xmm0,%xmm9
	psrlq	$4,%xmm0
	 movdqa	%xmm15,%xmm10
	 psrlq	$4,%xmm15
	pxor  	%xmm6,%xmm0
	 pxor  	%xmm2,%xmm15
	pand	%xmm7,%xmm0
	 pand	%xmm7,%xmm15
	pxor	%xmm0,%xmm6
	psllq	$4,%xmm0
	 pxor	%xmm15,%xmm2
	 psllq	$4,%xmm15
	pxor	%xmm9,%xmm0
	 pxor	%xmm10,%xmm15
	movdqa	(%rax), %xmm7		# last round key
	pxor	%xmm7, %xmm3
	pxor	%xmm7, %xmm5
	pxor	%xmm7, %xmm2
	pxor	%xmm7, %xmm6
	pxor	%xmm7, %xmm1
	pxor	%xmm7, %xmm4
	pxor	%xmm7, %xmm15
	pxor	%xmm7, %xmm0
	ret
.cfi_endproc
.size	_bsaes_encrypt8,.-_bsaes_encrypt8

.type	_bsaes_decrypt8,@abi-omnipotent
.align	64
_bsaes_decrypt8:
.cfi_startproc
	lea	.LBS0(%rip), %r11	# constants table

	movdqa	(%rax), %xmm8		# round 0 key
	lea	0x10(%rax), %rax
	movdqa	-0x30(%r11), %xmm7	# .LM0ISR
	pxor	%xmm8, %xmm15	# xor with round0 key
	pxor	%xmm8, %xmm0
	pxor	%xmm8, %xmm1
	pxor	%xmm8, %xmm2
	 pshufb	%xmm7, %xmm15
	 pshufb	%xmm7, %xmm0
	pxor	%xmm8, %xmm3
	pxor	%xmm8, %xmm4
	 pshufb	%xmm7, %xmm1
	 pshufb	%xmm7, %xmm2
	pxor	%xmm8, %xmm5
	pxor	%xmm8, %xmm6
	 pshufb	%xmm7, %xmm3
	 pshufb	%xmm7, %xmm4
	 pshufb	%xmm7, %xmm5
	 pshufb	%xmm7, %xmm6
	movdqa	0x00(%r11),%xmm7	# .LBS0
	movdqa	0x10(%r11),%xmm8	# .LBS1
	movdqa	%xmm5,%xmm9
	psrlq	$1,%xmm5
	 movdqa	%xmm3,%xmm10
	 psrlq	$1,%xmm3
	pxor  	%xmm6,%xmm5
	 pxor  	%xmm4,%xmm3
	pand	%xmm7,%xmm5
	 pand	%xmm7,%xmm3
	pxor	%xmm5,%xmm6
	psllq	$1,%xmm5
	 pxor	%xmm3,%xmm4
	 psllq	$1,%xmm3
	pxor	%xmm9,%xmm5
	 pxor	%xmm10,%xmm3
	movdqa	%xmm1,%xmm9
	psrlq	$1,%xmm1
	 movdqa	%xmm15,%xmm10
	 psrlq	$1,%xmm15
	pxor  	%xmm2,%xmm1
	 pxor  	%xmm0,%xmm15
	pand	%xmm7,%xmm1
	 pand	%xmm7,%xmm15
	pxor	%xmm1,%xmm2
	psllq	$1,%xmm1
	 pxor	%xmm15,%xmm0
	 psllq	$1,%xmm15
	pxor	%xmm9,%xmm1
	 pxor	%xmm10,%xmm15
	movdqa	0x20(%r11),%xmm7	# .LBS2
	movdqa	%xmm4,%xmm9
	psrlq	$2,%xmm4
	 movdqa	%xmm3,%xmm10
	 psrlq	$2,%xmm3
	pxor  	%xmm6,%xmm4
	 pxor  	%xmm5,%xmm3
	pand	%xmm8,%xmm4
	 pand	%xmm8,%xmm3
	pxor	%xmm4,%xmm6
	psllq	$2,%xmm4
	 pxor	%xmm3,%xmm5
	 psllq	$2,%xmm3
	pxor	%xmm9,%xmm4
	 pxor	%xmm10,%xmm3
	movdqa	%xmm0,%xmm9
	psrlq	$2,%xmm0
	 movdqa	%xmm15,%xmm10
	 psrlq	$2,%xmm15
	pxor  	%xmm2,%xmm0
	 pxor  	%xmm1,%xmm15
	pand	%xmm8,%xmm0
	 pand	%xmm8,%xmm15
	pxor	%xmm0,%xmm2
	psllq	$2,%xmm0
	 pxor	%xmm15,%xmm1
	 psllq	$2,%xmm15
	pxor	%xmm9,%xmm0
	 pxor	%xmm10,%xmm15
	movdqa	%xmm2,%xmm9
	psrlq	$4,%xmm2
	 movdqa	%xmm1,%xmm10
	 psrlq	$4,%xmm1
	pxor  	%xmm6,%xmm2
	 pxor  	%xmm5,%xmm1
	pand	%xmm7,%xmm2
	 pand	%xmm7,%xmm1
	pxor	%xmm2,%xmm6
	psllq	$4,%xmm2
	 pxor	%xmm1,%xmm5
	 psllq	$4,%xmm1
	pxor	%xmm9,%xmm2
	 pxor	%xmm10,%xmm1
	movdqa	%xmm0,%xmm9
	psrlq	$4,%xmm0
	 movdqa	%xmm15,%xmm10
	 psrlq	$4,%xmm15
	pxor  	%xmm4,%xmm0
	 pxor  	%xmm3,%xmm15
	pand	%xmm7,%xmm0
	 pand	%xmm7,%xmm15
	pxor	%xmm0,%xmm4
	psllq	$4,%xmm0
	 pxor	%xmm15,%xmm3
	 psllq	$4,%xmm15
	pxor	%xmm9,%xmm0
	 pxor	%xmm10,%xmm15
	dec	%r10d
	jmp	.Ldec_sbox
.align	16
.Ldec_loop:
	pxor	0x00(%rax),%xmm15
	pxor	0x10(%rax),%xmm0
	pxor	0x20(%rax),%xmm1
	pxor	0x30(%rax),%xmm2
	pshufb	%xmm7,%xmm15
	pshufb	%xmm7,%xmm0
	pxor	0x40(%rax),%xmm3
	pxor	0x50(%rax),%xmm4
	pshufb	%xmm7,%xmm1
	pshufb	%xmm7,%xmm2
	pxor	0x60(%rax),%xmm5
	pxor	0x70(%rax),%xmm6
	pshufb	%xmm7,%xmm3
	pshufb	%xmm7,%xmm4
	pshufb	%xmm7,%xmm5
	pshufb	%xmm7,%xmm6
	lea	0x80(%rax),%rax
.Ldec_sbox:
	pxor	%xmm3, %xmm2

	pxor	%xmm6, %xmm3
	pxor	%xmm6, %xmm1
	pxor	%xmm3, %xmm5
	pxor	%xmm5, %xmm6
	pxor	%xmm6, %xmm0

	pxor	%xmm0, %xmm15
	pxor	%xmm4, %xmm1
	pxor	%xmm15, %xmm2
	pxor	%xmm15, %xmm4
	pxor	%xmm2, %xmm0
	movdqa	%xmm2, %xmm10
	movdqa	%xmm6, %xmm9
	movdqa	%xmm0, %xmm8
	movdqa	%xmm3, %xmm12
	movdqa	%xmm4, %xmm11

	pxor	%xmm15, %xmm10
	pxor	%xmm3, %xmm9
	pxor	%xmm5, %xmm8
	 movdqa	%xmm10, %xmm13
	pxor	%xmm15, %xmm12
	 movdqa	%xmm9, %xmm7
	pxor	%xmm1, %xmm11
	 movdqa	%xmm10, %xmm14

	por	%xmm8, %xmm9
	por	%xmm11, %xmm10
	pxor	%xmm7, %xmm14
	pand	%xmm11, %xmm13
	pxor	%xmm8, %xmm11
	pand	%xmm8, %xmm7
	pand	%xmm11, %xmm14
	movdqa	%xmm5, %xmm11
	pxor	%xmm1, %xmm11
	pand	%xmm11, %xmm12
	pxor	%xmm12, %xmm10
	pxor	%xmm12, %xmm9
	movdqa	%xmm2, %xmm12
	movdqa	%xmm0, %xmm11
	pxor	%xmm6, %xmm12
	pxor	%xmm4, %xmm11
	movdqa	%xmm12, %xmm8
	pand	%xmm11, %xmm12
	por	%xmm11, %xmm8
	pxor	%xmm12, %xmm7
	pxor	%xmm14, %xmm10
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm8
	movdqa	%xmm3, %xmm11
	pxor	%xmm13, %xmm7
	movdqa	%xmm15, %xmm12
	pxor	%xmm13, %xmm8
	movdqa	%xmm6, %xmm13
	pand	%xmm5, %xmm11
	movdqa	%xmm2, %xmm14
	pand	%xmm1, %xmm12
	pand	%xmm0, %xmm13
	por	%xmm4, %xmm14
	pxor	%xmm11, %xmm10
	pxor	%xmm12, %xmm9
	pxor	%xmm13, %xmm8
	pxor	%xmm14, %xmm7

	#Inv_GF16 	0, 	1, 	2, 	3, s0, s1, s2, s3

	# new smaller inversion

	movdqa	%xmm10, %xmm11
	pand	%xmm8, %xmm10
	pxor	%xmm9, %xmm11

	movdqa	%xmm7, %xmm13
	movdqa	%xmm11, %xmm14
	pxor	%xmm10, %xmm13
	pand	%xmm13, %xmm14

	movdqa	%xmm8, %xmm12
	pxor	%xmm9, %xmm14
	pxor	%xmm7, %xmm12

	pxor	%xmm9, %xmm10

	pand	%xmm10, %xmm12

	movdqa	%xmm13, %xmm9
	pxor	%xmm7, %xmm12

	pxor	%xmm12, %xmm9
	pxor	%xmm12, %xmm8

	pand	%xmm7, %xmm9

	pxor	%xmm9, %xmm13
	pxor	%xmm9, %xmm8

	pand	%xmm14, %xmm13

	pxor	%xmm11, %xmm13
	movdqa	%xmm4, %xmm11
	movdqa	%xmm0, %xmm7
	movdqa	%xmm14, %xmm9
	pxor 	%xmm13, %xmm9
	pand	%xmm4, %xmm9
	pxor	%xmm0, %xmm4
	pand	%xmm14, %xmm0
	pand	%xmm13, %xmm4
	pxor	%xmm0, %xmm4
	pxor	%xmm9, %xmm0
	pxor	%xmm1, %xmm11
	pxor	%xmm5, %xmm7
	pxor	%xmm12, %xmm14
	pxor	%xmm8, %xmm13
	movdqa	%xmm14, %xmm10
	 movdqa	%xmm12, %xmm9
	pxor	%xmm13, %xmm10
	 pxor 	%xmm8, %xmm9
	pand	%xmm11, %xmm10
	 pand	%xmm1, %xmm9
	pxor	%xmm7, %xmm11
	 pxor	%xmm5, %xmm1
	pand	%xmm14, %xmm7
	 pand	%xmm12, %xmm5
	pand	%xmm13, %xmm11
	 pand	%xmm8, %xmm1
	pxor	%xmm11, %xmm7
	 pxor	%xmm5, %xmm1
	pxor	%xmm10, %xmm11
	 pxor	%xmm9, %xmm5
	pxor	%xmm11, %xmm4
	pxor	%xmm11, %xmm1
	pxor	%xmm7, %xmm0
	pxor	%xmm7, %xmm5

	movdqa	%xmm2, %xmm11
	movdqa	%xmm6, %xmm7
	pxor	%xmm15, %xmm11
	pxor	%xmm3, %xmm7
	movdqa	%xmm14, %xmm10
	 movdqa	%xmm12, %xmm9
	pxor	%xmm13, %xmm10
	 pxor 	%xmm8, %xmm9
	pand	%xmm11, %xmm10
	 pand	%xmm15, %xmm9
	pxor	%xmm7, %xmm11
	 pxor	%xmm3, %xmm15
	pand	%xmm14, %xmm7
	 pand	%xmm12, %xmm3
	pand	%xmm13, %xmm11
	 pand	%xmm8, %xmm15
	pxor	%xmm11, %xmm7
	 pxor	%xmm3, %xmm15
	pxor	%xmm10, %xmm11
	 pxor	%xmm9, %xmm3
	pxor	%xmm12, %xmm14
	pxor	%xmm8, %xmm13
	movdqa	%xmm14, %xmm10
	pxor 	%xmm13, %xmm10
	pand	%xmm2, %xmm10
	pxor	%xmm6, %xmm2
	pand	%xmm14, %xmm6
	pand	%xmm13, %xmm2
	pxor	%xmm6, %xmm2
	pxor	%xmm10, %xmm6
	pxor	%xmm11, %xmm2
	pxor	%xmm11, %xmm15
	pxor	%xmm7, %xmm6
	pxor	%xmm7, %xmm3
	pxor	%xmm6, %xmm0
	pxor	%xmm4, %xmm5

	pxor	%xmm0, %xmm3
	pxor	%xmm6, %xmm1
	pxor	%xmm6, %xmm4
	pxor	%xmm1, %xmm3
	 pxor 	%xmm15, %xmm6
	pxor	%xmm4, %xmm3
	 pxor	%xmm5, %xmm2
	 pxor	%xmm0, %xmm5
	pxor	%xmm3, %xmm2

	pxor	%xmm15, %xmm3
	pxor	%xmm2, %xmm6
	dec	%r10d
	jl	.Ldec_done
	# multiplication by 0x05-0x00-0x04-0x00
	pshufd	$0x4E, %xmm15, %xmm7
	pshufd	$0x4E, %xmm2, %xmm13
	pxor	%xmm15, %xmm7
	pshufd	$0x4E, %xmm4, %xmm14
	pxor	%xmm2, %xmm13
	pshufd	$0x4E, %xmm0, %xmm8
	pxor	%xmm4, %xmm14
	pshufd	$0x4E, %xmm5, %xmm9
	pxor	%xmm0, %xmm8
	pshufd	$0x4E, %xmm3, %xmm10
	pxor	%xmm5, %xmm9
	 pxor	%xmm13, %xmm15
	 pxor	%xmm13, %xmm0
	pshufd	$0x4E, %xmm1, %xmm11
	pxor	%xmm3, %xmm10
	 pxor	%xmm7, %xmm5
	 pxor	%xmm8, %xmm3
	pshufd	$0x4E, %xmm6, %xmm12
	pxor	%xmm1, %xmm11
	 pxor	%xmm14, %xmm0
	 pxor	%xmm9, %xmm1
	pxor	%xmm6, %xmm12

	 pxor	%xmm14, %xmm5
	 pxor	%xmm13, %xmm3
	 pxor	%xmm13, %xmm1
	 pxor	%xmm10, %xmm6
	 pxor	%xmm11, %xmm2
	 pxor	%xmm14, %xmm1
	 pxor	%xmm14, %xmm6
	 pxor	%xmm12, %xmm4
	pshufd	$0x93, %xmm15, %xmm7	# x0 <<< 32
	pshufd	$0x93, %xmm0, %xmm8
	 pxor	%xmm7, %xmm15		# x0 ^ (x0 <<< 32)
	pshufd	$0x93, %xmm5, %xmm9
	 pxor	%xmm8, %xmm0
	pshufd	$0x93, %xmm3, %xmm10
	 pxor	%xmm9, %xmm5
	pshufd	$0x93, %xmm1, %xmm11
	 pxor	%xmm10, %xmm3
	pshufd	$0x93, %xmm6, %xmm12
	 pxor	%xmm11, %xmm1
	pshufd	$0x93, %xmm2, %xmm13
	 pxor	%xmm12, %xmm6
	pshufd	$0x93, %xmm4, %xmm14
	 pxor	%xmm13, %xmm2
	 pxor	%xmm14, %xmm4

	pxor	%xmm15, %xmm8
	pxor	%xmm4, %xmm7
	pxor	%xmm4, %xmm8
	 pshufd	$0x4E, %xmm15, %xmm15 	# (x0 ^ (x0 <<< 32)) <<< 64)
	pxor	%xmm0, %xmm9
	 pshufd	$0x4E, %xmm0, %xmm0
	pxor	%xmm1, %xmm12
	 pxor	%xmm7, %xmm15
	pxor	%xmm6, %xmm13
	 pxor	%xmm8, %xmm0
	pxor	%xmm3, %xmm11
	 pshufd	$0x4E, %xmm1, %xmm7
	pxor	%xmm2, %xmm14
	 pshufd	$0x4E, %xmm6, %xmm8
	pxor	%xmm5, %xmm10
	 pshufd	$0x4E, %xmm3, %xmm1
	pxor	%xmm4, %xmm10
	 pshufd	$0x4E, %xmm4, %xmm6
	pxor	%xmm4, %xmm11
	 pshufd	$0x4E, %xmm2, %xmm3
	pxor	%xmm11, %xmm7
	 pshufd	$0x4E, %xmm5, %xmm2
	pxor	%xmm12, %xmm8
	pxor	%xmm1, %xmm10
	pxor	%xmm14, %xmm6
	pxor	%xmm3, %xmm13
	 movdqa	%xmm7, %xmm3
	pxor	%xmm9, %xmm2
	 movdqa	%xmm13, %xmm5
	 movdqa	%xmm8, %xmm4
	 movdqa	%xmm2, %xmm1
	 movdqa	%xmm10, %xmm2
	movdqa	-0x10(%r11), %xmm7	# .LISR
	jnz	.Ldec_loop
	movdqa	-0x20(%r11), %xmm7	# .LISRM0
	jmp	.Ldec_loop
.align	16
.Ldec_done:
	movdqa	0x00(%r11),%xmm7	# .LBS0
	movdqa	0x10(%r11),%xmm8	# .LBS1
	movdqa	%xmm2,%xmm9
	psrlq	$1,%xmm2
	 movdqa	%xmm1,%xmm10
	 psrlq	$1,%xmm1
	pxor  	%xmm4,%xmm2
	 pxor  	%xmm6,%xmm1
	pand	%xmm7,%xmm2
	 pand	%xmm7,%xmm1
	pxor	%xmm2,%xmm4
	psllq	$1,%xmm2
	 pxor	%xmm1,%xmm6
	 psllq	$1,%xmm1
	pxor	%xmm9,%xmm2
	 pxor	%xmm10,%xmm1
	movdqa	%xmm5,%xmm9
	psrlq	$1,%xmm5
	 movdqa	%xmm15,%xmm10
	 psrlq	$1,%xmm15
	pxor  	%xmm3,%xmm5
	 pxor  	%xmm0,%xmm15
	pand	%xmm7,%xmm5
	 pand	%xmm7,%xmm15
	pxor	%xmm5,%xmm3
	psllq	$1,%xmm5
	 pxor	%xmm15,%xmm0
	 psllq	$1,%xmm15
	pxor	%xmm9,%xmm5
	 pxor	%xmm10,%xmm15
	movdqa	0x20(%r11),%xmm7	# .LBS2
	movdqa	%xmm6,%xmm9
	psrlq	$2,%xmm6
	 movdqa	%xmm1,%xmm10
	 psrlq	$2,%xmm1
	pxor  	%xmm4,%xmm6
	 pxor  	%xmm2,%xmm1
	pand	%xmm8,%xmm6
	 pand	%xmm8,%xmm1
	pxor	%xmm6,%xmm4
	psllq	$2,%xmm6
	 pxor	%xmm1,%xmm2
	 psllq	$2,%xmm1
	pxor	%xmm9,%xmm6
	 pxor	%xmm10,%xmm1
	movdqa	%xmm0,%xmm9
	psrlq	$2,%xmm0
	 movdqa	%xmm15,%xmm10
	 psrlq	$2,%xmm15
	pxor  	%xmm3,%xmm0
	 pxor  	%xmm5,%xmm15
	pand	%xmm8,%xmm0
	 pand	%xmm8,%xmm15
	pxor	%xmm0,%xmm3
	psllq	$2,%xmm0
	 pxor	%xmm15,%xmm5
	 psllq	$2,%xmm15
	pxor	%xmm9,%xmm0
	 pxor	%xmm10,%xmm15
	movdqa	%xmm3,%xmm9
	psrlq	$4,%xmm3
	 movdqa	%xmm5,%xmm10
	 psrlq	$4,%xmm5
	pxor  	%xmm4,%xmm3
	 pxor  	%xmm2,%xmm5
	pand	%xmm7,%xmm3
	 pand	%xmm7,%xmm5
	pxor	%xmm3,%xmm4
	psllq	$4,%xmm3
	 pxor	%xmm5,%xmm2
	 psllq	$4,%xmm5
	pxor	%xmm9,%xmm3
	 pxor	%xmm10,%xmm5
	movdqa	%xmm0,%xmm9
	psrlq	$4,%xmm0
	 movdqa	%xmm15,%xmm10
	 psrlq	$4,%xmm15
	pxor  	%xmm6,%xmm0
	 pxor  	%xmm1,%xmm15
	pand	%xmm7,%xmm0
	 pand	%xmm7,%xmm15
	pxor	%xmm0,%xmm6
	psllq	$4,%xmm0
	 pxor	%xmm15,%xmm1
	 psllq	$4,%xmm15
	pxor	%xmm9,%xmm0
	 pxor	%xmm10,%xmm15
	movdqa	(%rax), %xmm7		# last round key
	pxor	%xmm7, %xmm5
	pxor	%xmm7, %xmm3
	pxor	%xmm7, %xmm1
	pxor	%xmm7, %xmm6
	pxor	%xmm7, %xmm2
	pxor	%xmm7, %xmm4
	pxor	%xmm7, %xmm15
	pxor	%xmm7, %xmm0
	ret
.cfi_endproc
.size	_bsaes_decrypt8,.-_bsaes_decrypt8
.type	_bsaes_key_convert,@abi-omnipotent
.align	16
_bsaes_key_convert:
.cfi_startproc
	lea	.Lmasks(%rip), %r11
	movdqu	(%rcx), %xmm7		# load round 0 key
	lea	0x10(%rcx), %rcx
	movdqa	0x00(%r11), %xmm0	# 0x01...
	movdqa	0x10(%r11), %xmm1	# 0x02...
	movdqa	0x20(%r11), %xmm2	# 0x04...
	movdqa	0x30(%r11), %xmm3	# 0x08...
	movdqa	0x40(%r11), %xmm4	# .LM0
	pcmpeqd	%xmm5, %xmm5		# .LNOT

	movdqu	(%rcx), %xmm6		# load round 1 key
	movdqa	%xmm7, (%rax)		# save round 0 key
	lea	0x10(%rax), %rax
	dec	%r10d
	jmp	.Lkey_loop
.align	16
.Lkey_loop:
	pshufb	%xmm4, %xmm6		# .LM0

	movdqa	%xmm0,	%xmm8
	movdqa	%xmm1,	%xmm9

	pand	%xmm6,	%xmm8
	pand	%xmm6,	%xmm9
	movdqa	%xmm2,	%xmm10
	pcmpeqb	%xmm0,	%xmm8
	psllq	$4,	%xmm0		# 0x10...
	movdqa	%xmm3,	%xmm11
	pcmpeqb	%xmm1,	%xmm9
	psllq	$4,	%xmm1		# 0x20...

	pand	%xmm6,	%xmm10
	pand	%xmm6,	%xmm11
	movdqa	%xmm0,	%xmm12
	pcmpeqb	%xmm2,	%xmm10
	psllq	$4,	%xmm2		# 0x40...
	movdqa	%xmm1,	%xmm13
	pcmpeqb	%xmm3,	%xmm11
	psllq	$4,	%xmm3		# 0x80...

	movdqa	%xmm2,	%xmm14
	movdqa	%xmm3,	%xmm15
	 pxor	%xmm5,	%xmm8		# "pnot"
	 pxor	%xmm5,	%xmm9

	pand	%xmm6,	%xmm12
	pand	%xmm6,	%xmm13
	 movdqa	%xmm8, 0x00(%rax)	# write bit-sliced round key
	pcmpeqb	%xmm0,	%xmm12
	psrlq	$4,	%xmm0		# 0x01...
	 movdqa	%xmm9, 0x10(%rax)
	pcmpeqb	%xmm1,	%xmm13
	psrlq	$4,	%xmm1		# 0x02...
	 lea	0x10(%rcx), %rcx

	pand	%xmm6,	%xmm14
	pand	%xmm6,	%xmm15
	 movdqa	%xmm10, 0x20(%rax)
	pcmpeqb	%xmm2,	%xmm14
	psrlq	$4,	%xmm2		# 0x04...
	 movdqa	%xmm11, 0x30(%rax)
	pcmpeqb	%xmm3,	%xmm15
	psrlq	$4,	%xmm3		# 0x08...
	 movdqu	(%rcx), %xmm6		# load next round key

	pxor	%xmm5, %xmm13		# "pnot"
	pxor	%xmm5, %xmm14
	movdqa	%xmm12, 0x40(%rax)
	movdqa	%xmm13, 0x50(%rax)
	movdqa	%xmm14, 0x60(%rax)
	movdqa	%xmm15, 0x70(%rax)
	lea	0x80(%rax),%rax
	dec	%r10d
	jnz	.Lkey_loop

	movdqa	0x50(%r11), %xmm7	# .L63
	#movdqa	%xmm6, (%rax)		# don't save last round key
	ret
.cfi_endproc
.size	_bsaes_key_convert,.-_bsaes_key_convert
.extern	asm_AES_cbc_encrypt
.globl	ossl_bsaes_cbc_encrypt
.type	ossl_bsaes_cbc_encrypt,@abi-omnipotent
.align	16
ossl_bsaes_cbc_encrypt:
.cfi_startproc
	endbranch
	cmp	$0,%r9d
	jne	asm_AES_cbc_encrypt
	cmp	$128,%rdx
	jb	asm_AES_cbc_encrypt

	mov	%rsp, %rax
.Lcbc_dec_prologue:
	push	%rbp
.cfi_push	%rbp
	push	%rbx
.cfi_push	%rbx
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	lea	-0x48(%rsp), %rsp
.cfi_adjust_cfa_offset	0x48
	mov	%rsp, %rbp		# backup %rsp
.cfi_def_cfa_register	%rbp
	mov	240(%rcx), %eax	# rounds
	mov	%rdi, %r12		# backup arguments
	mov	%rsi, %r13
	mov	%rdx, %r14
	mov	%rcx, %r15
	mov	%r8, %rbx
	shr	$4, %r14		# bytes to blocks

	mov	%eax, %edx		# rounds
	shl	$7, %rax		# 128 bytes per inner round key
	sub	$96, %rax	# size of bit-sliced key schedule
	sub	%rax, %rsp

	mov	%rsp, %rax		# pass key schedule
	mov	%r15, %rcx		# pass key
	mov	%edx, %r10d		# pass rounds
	call	_bsaes_key_convert
	pxor	(%rsp),%xmm7		# fix up 0 round key
	movdqa	%xmm6,(%rax)		# save last round key
	movdqa	%xmm7,(%rsp)

	movdqu	(%rbx), %xmm14	# load IV
	sub	$8,%r14
.Lcbc_dec_loop:
	movdqu	0x00(%r12), %xmm15	# load input
	movdqu	0x10(%r12), %xmm0
	movdqu	0x20(%r12), %xmm1
	movdqu	0x30(%r12), %xmm2
	movdqu	0x40(%r12), %xmm3
	movdqu	0x50(%r12), %xmm4
	mov	%rsp, %rax		# pass key schedule
	movdqu	0x60(%r12), %xmm5
	mov	%edx,%r10d		# pass rounds
	movdqu	0x70(%r12), %xmm6
	movdqa	%xmm14, 0x20(%rbp)	# put aside IV

	call	_bsaes_decrypt8

	pxor	0x20(%rbp), %xmm15	# ^= IV
	movdqu	0x00(%r12), %xmm7	# re-load input
	movdqu	0x10(%r12), %xmm8
	pxor	%xmm7, %xmm0
	movdqu	0x20(%r12), %xmm9
	pxor	%xmm8, %xmm5
	movdqu	0x30(%r12), %xmm10
	pxor	%xmm9, %xmm3
	movdqu	0x40(%r12), %xmm11
	pxor	%xmm10, %xmm1
	movdqu	0x50(%r12), %xmm12
	pxor	%xmm11, %xmm6
	movdqu	0x60(%r12), %xmm13
	pxor	%xmm12, %xmm2
	movdqu	0x70(%r12), %xmm14	# IV
	pxor	%xmm13, %xmm4
	movdqu	%xmm15, 0x00(%r13)	# write output
	lea	0x80(%r12), %r12
	movdqu	%xmm0, 0x10(%r13)
	movdqu	%xmm5, 0x20(%r13)
	movdqu	%xmm3, 0x30(%r13)
	movdqu	%xmm1, 0x40(%r13)
	movdqu	%xmm6, 0x50(%r13)
	movdqu	%xmm2, 0x60(%r13)
	movdqu	%xmm4, 0x70(%r13)
	lea	0x80(%r13), %r13
	sub	$8,%r14
	jnc	.Lcbc_dec_loop

	add	$8,%r14
	jz	.Lcbc_dec_done

	movdqu	0x00(%r12), %xmm15	# load input
	mov	%rsp, %rax		# pass key schedule
	mov	%edx, %r10d		# pass rounds
	cmp	$2,%r14
	jb	.Lcbc_dec_one
	movdqu	0x10(%r12), %xmm0
	je	.Lcbc_dec_two
	movdqu	0x20(%r12), %xmm1
	cmp	$4,%r14
	jb	.Lcbc_dec_three
	movdqu	0x30(%r12), %xmm2
	je	.Lcbc_dec_four
	movdqu	0x40(%r12), %xmm3
	cmp	$6,%r14
	jb	.Lcbc_dec_five
	movdqu	0x50(%r12), %xmm4
	je	.Lcbc_dec_six
	movdqu	0x60(%r12), %xmm5
	movdqa	%xmm14, 0x20(%rbp)	# put aside IV
	call	_bsaes_decrypt8
	pxor	0x20(%rbp), %xmm15	# ^= IV
	movdqu	0x00(%r12), %xmm7	# re-load input
	movdqu	0x10(%r12), %xmm8
	pxor	%xmm7, %xmm0
	movdqu	0x20(%r12), %xmm9
	pxor	%xmm8, %xmm5
	movdqu	0x30(%r12), %xmm10
	pxor	%xmm9, %xmm3
	movdqu	0x40(%r12), %xmm11
	pxor	%xmm10, %xmm1
	movdqu	0x50(%r12), %xmm12
	pxor	%xmm11, %xmm6
	movdqu	0x60(%r12), %xmm14	# IV
	pxor	%xmm12, %xmm2
	movdqu	%xmm15, 0x00(%r13)	# write output
	movdqu	%xmm0, 0x10(%r13)
	movdqu	%xmm5, 0x20(%r13)
	movdqu	%xmm3, 0x30(%r13)
	movdqu	%xmm1, 0x40(%r13)
	movdqu	%xmm6, 0x50(%r13)
	movdqu	%xmm2, 0x60(%r13)
	jmp	.Lcbc_dec_done
.align	16
.Lcbc_dec_six:
	movdqa	%xmm14, 0x20(%rbp)	# put aside IV
	call	_bsaes_decrypt8
	pxor	0x20(%rbp), %xmm15	# ^= IV
	movdqu	0x00(%r12), %xmm7	# re-load input
	movdqu	0x10(%r12), %xmm8
	pxor	%xmm7, %xmm0
	movdqu	0x20(%r12), %xmm9
	pxor	%xmm8, %xmm5
	movdqu	0x30(%r12), %xmm10
	pxor	%xmm9, %xmm3
	movdqu	0x40(%r12), %xmm11
	pxor	%xmm10, %xmm1
	movdqu	0x50(%r12), %xmm14	# IV
	pxor	%xmm11, %xmm6
	movdqu	%xmm15, 0x00(%r13)	# write output
	movdqu	%xmm0, 0x10(%r13)
	movdqu	%xmm5, 0x20(%r13)
	movdqu	%xmm3, 0x30(%r13)
	movdqu	%xmm1, 0x40(%r13)
	movdqu	%xmm6, 0x50(%r13)
	jmp	.Lcbc_dec_done
.align	16
.Lcbc_dec_five:
	movdqa	%xmm14, 0x20(%rbp)	# put aside IV
	call	_bsaes_decrypt8
	pxor	0x20(%rbp), %xmm15	# ^= IV
	movdqu	0x00(%r12), %xmm7	# re-load input
	movdqu	0x10(%r12), %xmm8
	pxor	%xmm7, %xmm0
	movdqu	0x20(%r12), %xmm9
	pxor	%xmm8, %xmm5
	movdqu	0x30(%r12), %xmm10
	pxor	%xmm9, %xmm3
	movdqu	0x40(%r12), %xmm14	# IV
	pxor	%xmm10, %xmm1
	movdqu	%xmm15, 0x00(%r13)	# write output
	movdqu	%xmm0, 0x10(%r13)
	movdqu	%xmm5, 0x20(%r13)
	movdqu	%xmm3, 0x30(%r13)
	movdqu	%xmm1, 0x40(%r13)
	jmp	.Lcbc_dec_done
.align	16
.Lcbc_dec_four:
	movdqa	%xmm14, 0x20(%rbp)	# put aside IV
	call	_bsaes_decrypt8
	pxor	0x20(%rbp), %xmm15	# ^= IV
	movdqu	0x00(%r12), %xmm7	# re-load input
	movdqu	0x10(%r12), %xmm8
	pxor	%xmm7, %xmm0
	movdqu	0x20(%r12), %xmm9
	pxor	%xmm8, %xmm5
	movdqu	0x30(%r12), %xmm14	# IV
	pxor	%xmm9, %xmm3
	movdqu	%xmm15, 0x00(%r13)	# write output
	movdqu	%xmm0, 0x10(%r13)
	movdqu	%xmm5, 0x20(%r13)
	movdqu	%xmm3, 0x30(%r13)
	jmp	.Lcbc_dec_done
.align	16
.Lcbc_dec_three:
	movdqa	%xmm14, 0x20(%rbp)	# put aside IV
	call	_bsaes_decrypt8
	pxor	0x20(%rbp), %xmm15	# ^= IV
	movdqu	0x00(%r12), %xmm7	# re-load input
	movdqu	0x10(%r12), %xmm8
	pxor	%xmm7, %xmm0
	movdqu	0x20(%r12), %xmm14	# IV
	pxor	%xmm8, %xmm5
	movdqu	%xmm15, 0x00(%r13)	# write output
	movdqu	%xmm0, 0x10(%r13)
	movdqu	%xmm5, 0x20(%r13)
	jmp	.Lcbc_dec_done
.align	16
.Lcbc_dec_two:
	movdqa	%xmm14, 0x20(%rbp)	# put aside IV
	call	_bsaes_decrypt8
	pxor	0x20(%rbp), %xmm15	# ^= IV
	movdqu	0x00(%r12), %xmm7	# re-load input
	movdqu	0x10(%r12), %xmm14	# IV
	pxor	%xmm7, %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	movdqu	%xmm0, 0x10(%r13)
	jmp	.Lcbc_dec_done
.align	16
.Lcbc_dec_one:
	lea	(%r12), %rdi
	lea	0x20(%rbp), %rsi	# buffer output
	lea	(%r15), %rdx
	call	asm_AES_decrypt		# doesn't touch %xmm
	pxor	0x20(%rbp), %xmm14	# ^= IV
	movdqu	%xmm14, (%r13)	# write output
	movdqa	%xmm15, %xmm14	# IV

.Lcbc_dec_done:
	movdqu	%xmm14, (%rbx)	# return IV
	lea	(%rsp), %rax
	pxor	%xmm0, %xmm0
.Lcbc_dec_bzero:			# wipe key schedule [if any]
	movdqa	%xmm0, 0x00(%rax)
	movdqa	%xmm0, 0x10(%rax)
	lea	0x20(%rax), %rax
	cmp	%rax, %rbp
	ja	.Lcbc_dec_bzero

	lea	0x78(%rbp),%rax
.cfi_def_cfa	%rax,8
	mov	-48(%rax), %r15
.cfi_restore	%r15
	mov	-40(%rax), %r14
.cfi_restore	%r14
	mov	-32(%rax), %r13
.cfi_restore	%r13
	mov	-24(%rax), %r12
.cfi_restore	%r12
	mov	-16(%rax), %rbx
.cfi_restore	%rbx
	mov	-8(%rax), %rbp
.cfi_restore	%rbp
	lea	(%rax), %rsp		# restore %rsp
.cfi_def_cfa_register	%rsp
.Lcbc_dec_epilogue:
	ret
.cfi_endproc
.size	ossl_bsaes_cbc_encrypt,.-ossl_bsaes_cbc_encrypt

.globl	ossl_bsaes_ctr32_encrypt_blocks
.type	ossl_bsaes_ctr32_encrypt_blocks,@abi-omnipotent
.align	16
ossl_bsaes_ctr32_encrypt_blocks:
.cfi_startproc
	endbranch
	mov	%rsp, %rax
.Lctr_enc_prologue:
	push	%rbp
.cfi_push	%rbp
	push	%rbx
.cfi_push	%rbx
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	lea	-0x48(%rsp), %rsp
.cfi_adjust_cfa_offset	0x48
	mov	%rsp, %rbp		# backup %rsp
.cfi_def_cfa_register	%rbp
	movdqu	(%r8), %xmm0		# load counter
	mov	240(%rcx), %eax	# rounds
	mov	%rdi, %r12		# backup arguments
	mov	%rsi, %r13
	mov	%rdx, %r14
	mov	%rcx, %r15
	movdqa	%xmm0, 0x20(%rbp)	# copy counter
	cmp	$8, %rdx
	jb	.Lctr_enc_short

	mov	%eax, %ebx		# rounds
	shl	$7, %rax		# 128 bytes per inner round key
	sub	$96, %rax	# size of bit-sliced key schedule
	sub	%rax, %rsp

	mov	%rsp, %rax		# pass key schedule
	mov	%r15, %rcx		# pass key
	mov	%ebx, %r10d		# pass rounds
	call	_bsaes_key_convert
	pxor	%xmm6,%xmm7		# fix up last round key
	movdqa	%xmm7,(%rax)		# save last round key

	movdqa	(%rsp), %xmm8		# load round0 key
	lea	.LADD1(%rip), %r11
	movdqa	0x20(%rbp), %xmm15	# counter copy
	movdqa	-0x20(%r11), %xmm7	# .LSWPUP
	pshufb	%xmm7, %xmm8	# byte swap upper part
	pshufb	%xmm7, %xmm15
	movdqa	%xmm8, (%rsp)		# save adjusted round0 key
	jmp	.Lctr_enc_loop
.align	16
.Lctr_enc_loop:
	movdqa	%xmm15, 0x20(%rbp)	# save counter
	movdqa	%xmm15, %xmm0	# prepare 8 counter values
	movdqa	%xmm15, %xmm1
	paddd	0x00(%r11), %xmm0	# .LADD1
	movdqa	%xmm15, %xmm2
	paddd	0x10(%r11), %xmm1	# .LADD2
	movdqa	%xmm15, %xmm3
	paddd	0x20(%r11), %xmm2	# .LADD3
	movdqa	%xmm15, %xmm4
	paddd	0x30(%r11), %xmm3	# .LADD4
	movdqa	%xmm15, %xmm5
	paddd	0x40(%r11), %xmm4	# .LADD5
	movdqa	%xmm15, %xmm6
	paddd	0x50(%r11), %xmm5	# .LADD6
	paddd	0x60(%r11), %xmm6	# .LADD7

	# Borrow prologue from _bsaes_encrypt8 to use the opportunity
	# to flip byte order in 32-bit counter
	movdqa	(%rsp), %xmm8		# round 0 key
	lea	0x10(%rsp), %rax	# pass key schedule
	movdqa	-0x10(%r11), %xmm7	# .LSWPUPM0SR
	pxor	%xmm8, %xmm15	# xor with round0 key
	pxor	%xmm8, %xmm0
	pxor	%xmm8, %xmm1
	pxor	%xmm8, %xmm2
	 pshufb	%xmm7, %xmm15
	 pshufb	%xmm7, %xmm0
	pxor	%xmm8, %xmm3
	pxor	%xmm8, %xmm4
	 pshufb	%xmm7, %xmm1
	 pshufb	%xmm7, %xmm2
	pxor	%xmm8, %xmm5
	pxor	%xmm8, %xmm6
	 pshufb	%xmm7, %xmm3
	 pshufb	%xmm7, %xmm4
	 pshufb	%xmm7, %xmm5
	 pshufb	%xmm7, %xmm6
	lea	.LBS0(%rip), %r11	# constants table
	mov	%ebx,%r10d		# pass rounds

	call	_bsaes_encrypt8_bitslice

	sub	$8,%r14
	jc	.Lctr_enc_loop_done

	movdqu	0x00(%r12), %xmm7	# load input
	movdqu	0x10(%r12), %xmm8
	movdqu	0x20(%r12), %xmm9
	movdqu	0x30(%r12), %xmm10
	movdqu	0x40(%r12), %xmm11
	movdqu	0x50(%r12), %xmm12
	movdqu	0x60(%r12), %xmm13
	movdqu	0x70(%r12), %xmm14
	lea	0x80(%r12),%r12
	pxor	%xmm15, %xmm7
	movdqa	0x20(%rbp), %xmm15	# load counter
	pxor	%xmm8, %xmm0
	movdqu	%xmm7, 0x00(%r13)	# write output
	pxor	%xmm9, %xmm3
	movdqu	%xmm0, 0x10(%r13)
	pxor	%xmm10, %xmm5
	movdqu	%xmm3, 0x20(%r13)
	pxor	%xmm11, %xmm2
	movdqu	%xmm5, 0x30(%r13)
	pxor	%xmm12, %xmm6
	movdqu	%xmm2, 0x40(%r13)
	pxor	%xmm13, %xmm1
	movdqu	%xmm6, 0x50(%r13)
	pxor	%xmm14, %xmm4
	movdqu	%xmm1, 0x60(%r13)
	lea	.LADD1(%rip), %r11
	movdqu	%xmm4, 0x70(%r13)
	lea	0x80(%r13), %r13
	paddd	0x70(%r11), %xmm15	# .LADD8
	jnz	.Lctr_enc_loop

	jmp	.Lctr_enc_done
.align	16
.Lctr_enc_loop_done:
	add	$8, %r14
	movdqu	0x00(%r12), %xmm7	# load input
	pxor	%xmm7, %xmm15
	movdqu	%xmm15, 0x00(%r13)	# write output
	cmp	$2,%r14
	jb	.Lctr_enc_done
	movdqu	0x10(%r12), %xmm8
	pxor	%xmm8, %xmm0
	movdqu	%xmm0, 0x10(%r13)
	je	.Lctr_enc_done
	movdqu	0x20(%r12), %xmm9
	pxor	%xmm9, %xmm3
	movdqu	%xmm3, 0x20(%r13)
	cmp	$4,%r14
	jb	.Lctr_enc_done
	movdqu	0x30(%r12), %xmm10
	pxor	%xmm10, %xmm5
	movdqu	%xmm5, 0x30(%r13)
	je	.Lctr_enc_done
	movdqu	0x40(%r12), %xmm11
	pxor	%xmm11, %xmm2
	movdqu	%xmm2, 0x40(%r13)
	cmp	$6,%r14
	jb	.Lctr_enc_done
	movdqu	0x50(%r12), %xmm12
	pxor	%xmm12, %xmm6
	movdqu	%xmm6, 0x50(%r13)
	je	.Lctr_enc_done
	movdqu	0x60(%r12), %xmm13
	pxor	%xmm13, %xmm1
	movdqu	%xmm1, 0x60(%r13)
	jmp	.Lctr_enc_done

.align	16
.Lctr_enc_short:
	lea	0x20(%rbp), %rdi
	lea	0x30(%rbp), %rsi
	lea	(%r15), %rdx
	call	asm_AES_encrypt
	movdqu	(%r12), %xmm0
	lea	16(%r12), %r12
	mov	0x2c(%rbp), %eax	# load 32-bit counter
	bswap	%eax
	pxor	0x30(%rbp), %xmm0
	inc	%eax			# increment
	movdqu	%xmm0, (%r13)
	bswap	%eax
	lea	16(%r13), %r13
	mov	%eax, 0x2c(%rsp)	# save 32-bit counter
	dec	%r14
	jnz	.Lctr_enc_short

.Lctr_enc_done:
	lea	(%rsp), %rax
	pxor	%xmm0, %xmm0
.Lctr_enc_bzero:			# wipe key schedule [if any]
	movdqa	%xmm0, 0x00(%rax)
	movdqa	%xmm0, 0x10(%rax)
	lea	0x20(%rax), %rax
	cmp	%rax, %rbp
	ja	.Lctr_enc_bzero

	lea	0x78(%rbp),%rax
.cfi_def_cfa	%rax,8
	mov	-48(%rax), %r15
.cfi_restore	%r15
	mov	-40(%rax), %r14
.cfi_restore	%r14
	mov	-32(%rax), %r13
.cfi_restore	%r13
	mov	-24(%rax), %r12
.cfi_restore	%r12
	mov	-16(%rax), %rbx
.cfi_restore	%rbx
	mov	-8(%rax), %rbp
.cfi_restore	%rbp
	lea	(%rax), %rsp		# restore %rsp
.cfi_def_cfa_register	%rsp
.Lctr_enc_epilogue:
	ret
.cfi_endproc
.size	ossl_bsaes_ctr32_encrypt_blocks,.-ossl_bsaes_ctr32_encrypt_blocks
.globl	ossl_bsaes_xts_encrypt
.type	ossl_bsaes_xts_encrypt,@abi-omnipotent
.align	16
ossl_bsaes_xts_encrypt:
.cfi_startproc
	endbranch
	mov	%rsp, %rax
.Lxts_enc_prologue:
	push	%rbp
.cfi_push	%rbp
	push	%rbx
.cfi_push	%rbx
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	lea	-0x48(%rsp), %rsp
.cfi_adjust_cfa_offset	0x48
	mov	%rsp, %rbp		# backup %rsp
.cfi_def_cfa_register	%rbp
	mov	%rdi, %r12		# backup arguments
	mov	%rsi, %r13
	mov	%rdx, %r14
	mov	%rcx, %r15

	lea	(%r9), %rdi
	lea	0x20(%rbp), %rsi
	lea	(%r8), %rdx
	call	asm_AES_encrypt		# generate initial tweak

	mov	240(%r15), %eax		# rounds
	mov	%r14, %rbx		# backup %r14

	mov	%eax, %edx		# rounds
	shl	$7, %rax		# 128 bytes per inner round key
	sub	$96, %rax	# size of bit-sliced key schedule
	sub	%rax, %rsp

	mov	%rsp, %rax		# pass key schedule
	mov	%r15, %rcx		# pass key
	mov	%edx, %r10d		# pass rounds
	call	_bsaes_key_convert
	pxor	%xmm6, %xmm7		# fix up last round key
	movdqa	%xmm7, (%rax)		# save last round key

	and	$-16, %r14
	sub	$0x80, %rsp		# place for tweak[8]
	movdqa	0x20(%rbp), %xmm6	# initial tweak

	pxor	%xmm14, %xmm14
	movdqa	.Lxts_magic(%rip), %xmm12
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits

	sub	$0x80, %r14
	jc	.Lxts_enc_short
	jmp	.Lxts_enc_loop

.align	16
.Lxts_enc_loop:
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm15
	movdqa	%xmm6, 0(%rsp)# save tweak[0]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm0
	movdqa	%xmm6, 16(%rsp)# save tweak[1]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	0(%r12), %xmm7
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm1
	movdqa	%xmm6, 32(%rsp)# save tweak[2]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	16(%r12), %xmm8
	pxor	%xmm7, %xmm15# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm2
	movdqa	%xmm6, 48(%rsp)# save tweak[3]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	32(%r12), %xmm9
	pxor	%xmm8, %xmm0# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm3
	movdqa	%xmm6, 64(%rsp)# save tweak[4]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	48(%r12), %xmm10
	pxor	%xmm9, %xmm1# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm4
	movdqa	%xmm6, 80(%rsp)# save tweak[5]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	64(%r12), %xmm11
	pxor	%xmm10, %xmm2# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm5
	movdqa	%xmm6, 96(%rsp)# save tweak[6]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	80(%r12), %xmm12
	pxor	%xmm11, %xmm3# input[] ^ tweak[]
	movdqu	0x60(%r12), %xmm13
	pxor	%xmm12, %xmm4
	movdqu	0x70(%r12), %xmm14
	lea	0x80(%r12), %r12
	movdqa	%xmm6, 0x70(%rsp)
	pxor	%xmm13, %xmm5
	lea	0x80(%rsp), %rax	# pass key schedule
	pxor	%xmm14, %xmm6
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_encrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm3
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm5
	movdqu	%xmm3, 0x20(%r13)
	pxor	0x40(%rsp), %xmm2
	movdqu	%xmm5, 0x30(%r13)
	pxor	0x50(%rsp), %xmm6
	movdqu	%xmm2, 0x40(%r13)
	pxor	0x60(%rsp), %xmm1
	movdqu	%xmm6, 0x50(%r13)
	pxor	0x70(%rsp), %xmm4
	movdqu	%xmm1, 0x60(%r13)
	movdqu	%xmm4, 0x70(%r13)
	lea	0x80(%r13), %r13

	movdqa	0x70(%rsp), %xmm6	# prepare next iteration tweak
	pxor	%xmm14, %xmm14
	movdqa	.Lxts_magic(%rip), %xmm12
	pcmpgtd	%xmm6, %xmm14
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6

	sub	$0x80,%r14
	jnc	.Lxts_enc_loop

.Lxts_enc_short:
	add	$0x80, %r14
	jz	.Lxts_enc_done
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm15
	movdqa	%xmm6, 0(%rsp)# save tweak[0]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm0
	movdqa	%xmm6, 16(%rsp)# save tweak[1]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	0(%r12), %xmm7
	cmp	$16,%r14
	je	.Lxts_enc_1
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm1
	movdqa	%xmm6, 32(%rsp)# save tweak[2]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	16(%r12), %xmm8
	cmp	$32,%r14
	je	.Lxts_enc_2
	pxor	%xmm7, %xmm15# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm2
	movdqa	%xmm6, 48(%rsp)# save tweak[3]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	32(%r12), %xmm9
	cmp	$48,%r14
	je	.Lxts_enc_3
	pxor	%xmm8, %xmm0# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm3
	movdqa	%xmm6, 64(%rsp)# save tweak[4]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	48(%r12), %xmm10
	cmp	$64,%r14
	je	.Lxts_enc_4
	pxor	%xmm9, %xmm1# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm4
	movdqa	%xmm6, 80(%rsp)# save tweak[5]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	64(%r12), %xmm11
	cmp	$80,%r14
	je	.Lxts_enc_5
	pxor	%xmm10, %xmm2# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm5
	movdqa	%xmm6, 96(%rsp)# save tweak[6]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	80(%r12), %xmm12
	cmp	$96,%r14
	je	.Lxts_enc_6
	pxor	%xmm11, %xmm3# input[] ^ tweak[]
	movdqu	0x60(%r12), %xmm13
	pxor	%xmm12, %xmm4
	movdqa	%xmm6, 0x70(%rsp)
	lea	0x70(%r12), %r12
	pxor	%xmm13, %xmm5
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_encrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm3
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm5
	movdqu	%xmm3, 0x20(%r13)
	pxor	0x40(%rsp), %xmm2
	movdqu	%xmm5, 0x30(%r13)
	pxor	0x50(%rsp), %xmm6
	movdqu	%xmm2, 0x40(%r13)
	pxor	0x60(%rsp), %xmm1
	movdqu	%xmm6, 0x50(%r13)
	movdqu	%xmm1, 0x60(%r13)
	lea	0x70(%r13), %r13

	movdqa	0x70(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_enc_done
.align	16
.Lxts_enc_6:
	pxor	%xmm11, %xmm3
	lea	0x60(%r12), %r12
	pxor	%xmm12, %xmm4
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_encrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm3
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm5
	movdqu	%xmm3, 0x20(%r13)
	pxor	0x40(%rsp), %xmm2
	movdqu	%xmm5, 0x30(%r13)
	pxor	0x50(%rsp), %xmm6
	movdqu	%xmm2, 0x40(%r13)
	movdqu	%xmm6, 0x50(%r13)
	lea	0x60(%r13), %r13

	movdqa	0x60(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_enc_done
.align	16
.Lxts_enc_5:
	pxor	%xmm10, %xmm2
	lea	0x50(%r12), %r12
	pxor	%xmm11, %xmm3
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_encrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm3
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm5
	movdqu	%xmm3, 0x20(%r13)
	pxor	0x40(%rsp), %xmm2
	movdqu	%xmm5, 0x30(%r13)
	movdqu	%xmm2, 0x40(%r13)
	lea	0x50(%r13), %r13

	movdqa	0x50(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_enc_done
.align	16
.Lxts_enc_4:
	pxor	%xmm9, %xmm1
	lea	0x40(%r12), %r12
	pxor	%xmm10, %xmm2
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_encrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm3
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm5
	movdqu	%xmm3, 0x20(%r13)
	movdqu	%xmm5, 0x30(%r13)
	lea	0x40(%r13), %r13

	movdqa	0x40(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_enc_done
.align	16
.Lxts_enc_3:
	pxor	%xmm8, %xmm0
	lea	0x30(%r12), %r12
	pxor	%xmm9, %xmm1
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_encrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm3
	movdqu	%xmm0, 0x10(%r13)
	movdqu	%xmm3, 0x20(%r13)
	lea	0x30(%r13), %r13

	movdqa	0x30(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_enc_done
.align	16
.Lxts_enc_2:
	pxor	%xmm7, %xmm15
	lea	0x20(%r12), %r12
	pxor	%xmm8, %xmm0
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_encrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	movdqu	%xmm0, 0x10(%r13)
	lea	0x20(%r13), %r13

	movdqa	0x20(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_enc_done
.align	16
.Lxts_enc_1:
	pxor	%xmm15, %xmm7
	lea	0x10(%r12), %r12
	movdqa	%xmm7, 0x20(%rbp)
	lea	0x20(%rbp), %rdi
	lea	0x20(%rbp), %rsi
	lea	(%r15), %rdx
	call	asm_AES_encrypt		# doesn't touch %xmm
	pxor	0x20(%rbp), %xmm15	# ^= tweak[]
	#pxor	%xmm7, %xmm15
	#lea	0x80(%rsp), %rax	# pass key schedule
	#mov	%edx, %r10d		# pass rounds
	#call	_bsaes_encrypt8
	#pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	movdqu	%xmm15, 0x00(%r13)	# write output
	lea	0x10(%r13), %r13

	movdqa	0x10(%rsp), %xmm6	# next iteration tweak

.Lxts_enc_done:
	and	$15, %ebx
	jz	.Lxts_enc_ret
	mov	%r13, %rdx

.Lxts_enc_steal:
	movzb	(%r12), %eax
	movzb	-16(%rdx), %ecx
	lea	1(%r12), %r12
	mov	%al, -16(%rdx)
	mov	%cl, 0(%rdx)
	lea	1(%rdx), %rdx
	sub	$1,%ebx
	jnz	.Lxts_enc_steal

	movdqu	-16(%r13), %xmm15
	lea	0x20(%rbp), %rdi
	pxor	%xmm6, %xmm15
	lea	0x20(%rbp), %rsi
	movdqa	%xmm15, 0x20(%rbp)
	lea	(%r15), %rdx
	call	asm_AES_encrypt		# doesn't touch %xmm
	pxor	0x20(%rbp), %xmm6
	movdqu	%xmm6, -16(%r13)

.Lxts_enc_ret:
	lea	(%rsp), %rax
	pxor	%xmm0, %xmm0
.Lxts_enc_bzero:			# wipe key schedule [if any]
	movdqa	%xmm0, 0x00(%rax)
	movdqa	%xmm0, 0x10(%rax)
	lea	0x20(%rax), %rax
	cmp	%rax, %rbp
	ja	.Lxts_enc_bzero

	lea	0x78(%rbp),%rax
.cfi_def_cfa	%rax,8
	mov	-48(%rax), %r15
.cfi_restore	%r15
	mov	-40(%rax), %r14
.cfi_restore	%r14
	mov	-32(%rax), %r13
.cfi_restore	%r13
	mov	-24(%rax), %r12
.cfi_restore	%r12
	mov	-16(%rax), %rbx
.cfi_restore	%rbx
	mov	-8(%rax), %rbp
.cfi_restore	%rbp
	lea	(%rax), %rsp		# restore %rsp
.cfi_def_cfa_register	%rsp
.Lxts_enc_epilogue:
	ret
.cfi_endproc
.size	ossl_bsaes_xts_encrypt,.-ossl_bsaes_xts_encrypt

.globl	ossl_bsaes_xts_decrypt
.type	ossl_bsaes_xts_decrypt,@abi-omnipotent
.align	16
ossl_bsaes_xts_decrypt:
.cfi_startproc
	endbranch
	mov	%rsp, %rax
.Lxts_dec_prologue:
	push	%rbp
.cfi_push	%rbp
	push	%rbx
.cfi_push	%rbx
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	lea	-0x48(%rsp), %rsp
.cfi_adjust_cfa_offset	0x48
	mov	%rsp, %rbp		# backup %rsp
	mov	%rdi, %r12		# backup arguments
	mov	%rsi, %r13
	mov	%rdx, %r14
	mov	%rcx, %r15

	lea	(%r9), %rdi
	lea	0x20(%rbp), %rsi
	lea	(%r8), %rdx
	call	asm_AES_encrypt		# generate initial tweak

	mov	240(%r15), %eax		# rounds
	mov	%r14, %rbx		# backup %r14

	mov	%eax, %edx		# rounds
	shl	$7, %rax		# 128 bytes per inner round key
	sub	$96, %rax	# size of bit-sliced key schedule
	sub	%rax, %rsp

	mov	%rsp, %rax		# pass key schedule
	mov	%r15, %rcx		# pass key
	mov	%edx, %r10d		# pass rounds
	call	_bsaes_key_convert
	pxor	(%rsp), %xmm7		# fix up round 0 key
	movdqa	%xmm6, (%rax)		# save last round key
	movdqa	%xmm7, (%rsp)

	xor	%eax, %eax		# if (%r14%16) len-=16;
	and	$-16, %r14
	test	$15, %ebx
	setnz	%al
	shl	$4, %rax
	sub	%rax, %r14

	sub	$0x80, %rsp		# place for tweak[8]
	movdqa	0x20(%rbp), %xmm6	# initial tweak

	pxor	%xmm14, %xmm14
	movdqa	.Lxts_magic(%rip), %xmm12
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits

	sub	$0x80, %r14
	jc	.Lxts_dec_short
	jmp	.Lxts_dec_loop

.align	16
.Lxts_dec_loop:
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm15
	movdqa	%xmm6, 0(%rsp)# save tweak[0]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm0
	movdqa	%xmm6, 16(%rsp)# save tweak[1]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	0(%r12), %xmm7
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm1
	movdqa	%xmm6, 32(%rsp)# save tweak[2]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	16(%r12), %xmm8
	pxor	%xmm7, %xmm15# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm2
	movdqa	%xmm6, 48(%rsp)# save tweak[3]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	32(%r12), %xmm9
	pxor	%xmm8, %xmm0# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm3
	movdqa	%xmm6, 64(%rsp)# save tweak[4]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	48(%r12), %xmm10
	pxor	%xmm9, %xmm1# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm4
	movdqa	%xmm6, 80(%rsp)# save tweak[5]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	64(%r12), %xmm11
	pxor	%xmm10, %xmm2# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm5
	movdqa	%xmm6, 96(%rsp)# save tweak[6]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	80(%r12), %xmm12
	pxor	%xmm11, %xmm3# input[] ^ tweak[]
	movdqu	0x60(%r12), %xmm13
	pxor	%xmm12, %xmm4
	movdqu	0x70(%r12), %xmm14
	lea	0x80(%r12), %r12
	movdqa	%xmm6, 0x70(%rsp)
	pxor	%xmm13, %xmm5
	lea	0x80(%rsp), %rax	# pass key schedule
	pxor	%xmm14, %xmm6
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_decrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm5
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm3
	movdqu	%xmm5, 0x20(%r13)
	pxor	0x40(%rsp), %xmm1
	movdqu	%xmm3, 0x30(%r13)
	pxor	0x50(%rsp), %xmm6
	movdqu	%xmm1, 0x40(%r13)
	pxor	0x60(%rsp), %xmm2
	movdqu	%xmm6, 0x50(%r13)
	pxor	0x70(%rsp), %xmm4
	movdqu	%xmm2, 0x60(%r13)
	movdqu	%xmm4, 0x70(%r13)
	lea	0x80(%r13), %r13

	movdqa	0x70(%rsp), %xmm6	# prepare next iteration tweak
	pxor	%xmm14, %xmm14
	movdqa	.Lxts_magic(%rip), %xmm12
	pcmpgtd	%xmm6, %xmm14
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6

	sub	$0x80,%r14
	jnc	.Lxts_dec_loop

.Lxts_dec_short:
	add	$0x80, %r14
	jz	.Lxts_dec_done
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm15
	movdqa	%xmm6, 0(%rsp)# save tweak[0]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm0
	movdqa	%xmm6, 16(%rsp)# save tweak[1]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	0(%r12), %xmm7
	cmp	$16,%r14
	je	.Lxts_dec_1
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm1
	movdqa	%xmm6, 32(%rsp)# save tweak[2]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	16(%r12), %xmm8
	cmp	$32,%r14
	je	.Lxts_dec_2
	pxor	%xmm7, %xmm15# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm2
	movdqa	%xmm6, 48(%rsp)# save tweak[3]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	32(%r12), %xmm9
	cmp	$48,%r14
	je	.Lxts_dec_3
	pxor	%xmm8, %xmm0# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm3
	movdqa	%xmm6, 64(%rsp)# save tweak[4]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	48(%r12), %xmm10
	cmp	$64,%r14
	je	.Lxts_dec_4
	pxor	%xmm9, %xmm1# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm4
	movdqa	%xmm6, 80(%rsp)# save tweak[5]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	64(%r12), %xmm11
	cmp	$80,%r14
	je	.Lxts_dec_5
	pxor	%xmm10, %xmm2# input[] ^ tweak[]
	pshufd	$0x13, %xmm14, %xmm13
	pxor	%xmm14, %xmm14
	movdqa	%xmm6, %xmm5
	movdqa	%xmm6, 96(%rsp)# save tweak[6]
	paddq	%xmm6, %xmm6	# psllq	1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	pcmpgtd	%xmm6, %xmm14		# broadcast upper bits
	pxor	%xmm13, %xmm6
	movdqu	80(%r12), %xmm12
	cmp	$96,%r14
	je	.Lxts_dec_6
	pxor	%xmm11, %xmm3# input[] ^ tweak[]
	movdqu	0x60(%r12), %xmm13
	pxor	%xmm12, %xmm4
	movdqa	%xmm6, 0x70(%rsp)
	lea	0x70(%r12), %r12
	pxor	%xmm13, %xmm5
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_decrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm5
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm3
	movdqu	%xmm5, 0x20(%r13)
	pxor	0x40(%rsp), %xmm1
	movdqu	%xmm3, 0x30(%r13)
	pxor	0x50(%rsp), %xmm6
	movdqu	%xmm1, 0x40(%r13)
	pxor	0x60(%rsp), %xmm2
	movdqu	%xmm6, 0x50(%r13)
	movdqu	%xmm2, 0x60(%r13)
	lea	0x70(%r13), %r13

	movdqa	0x70(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_dec_done
.align	16
.Lxts_dec_6:
	pxor	%xmm11, %xmm3
	lea	0x60(%r12), %r12
	pxor	%xmm12, %xmm4
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_decrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm5
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm3
	movdqu	%xmm5, 0x20(%r13)
	pxor	0x40(%rsp), %xmm1
	movdqu	%xmm3, 0x30(%r13)
	pxor	0x50(%rsp), %xmm6
	movdqu	%xmm1, 0x40(%r13)
	movdqu	%xmm6, 0x50(%r13)
	lea	0x60(%r13), %r13

	movdqa	0x60(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_dec_done
.align	16
.Lxts_dec_5:
	pxor	%xmm10, %xmm2
	lea	0x50(%r12), %r12
	pxor	%xmm11, %xmm3
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_decrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm5
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm3
	movdqu	%xmm5, 0x20(%r13)
	pxor	0x40(%rsp), %xmm1
	movdqu	%xmm3, 0x30(%r13)
	movdqu	%xmm1, 0x40(%r13)
	lea	0x50(%r13), %r13

	movdqa	0x50(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_dec_done
.align	16
.Lxts_dec_4:
	pxor	%xmm9, %xmm1
	lea	0x40(%r12), %r12
	pxor	%xmm10, %xmm2
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_decrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm5
	movdqu	%xmm0, 0x10(%r13)
	pxor	0x30(%rsp), %xmm3
	movdqu	%xmm5, 0x20(%r13)
	movdqu	%xmm3, 0x30(%r13)
	lea	0x40(%r13), %r13

	movdqa	0x40(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_dec_done
.align	16
.Lxts_dec_3:
	pxor	%xmm8, %xmm0
	lea	0x30(%r12), %r12
	pxor	%xmm9, %xmm1
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_decrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	pxor	0x20(%rsp), %xmm5
	movdqu	%xmm0, 0x10(%r13)
	movdqu	%xmm5, 0x20(%r13)
	lea	0x30(%r13), %r13

	movdqa	0x30(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_dec_done
.align	16
.Lxts_dec_2:
	pxor	%xmm7, %xmm15
	lea	0x20(%r12), %r12
	pxor	%xmm8, %xmm0
	lea	0x80(%rsp), %rax	# pass key schedule
	mov	%edx, %r10d		# pass rounds

	call	_bsaes_decrypt8

	pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	pxor	0x10(%rsp), %xmm0
	movdqu	%xmm15, 0x00(%r13)	# write output
	movdqu	%xmm0, 0x10(%r13)
	lea	0x20(%r13), %r13

	movdqa	0x20(%rsp), %xmm6	# next iteration tweak
	jmp	.Lxts_dec_done
.align	16
.Lxts_dec_1:
	pxor	%xmm15, %xmm7
	lea	0x10(%r12), %r12
	movdqa	%xmm7, 0x20(%rbp)
	lea	0x20(%rbp), %rdi
	lea	0x20(%rbp), %rsi
	lea	(%r15), %rdx
	call	asm_AES_decrypt		# doesn't touch %xmm
	pxor	0x20(%rbp), %xmm15	# ^= tweak[]
	#pxor	%xmm7, %xmm15
	#lea	0x80(%rsp), %rax	# pass key schedule
	#mov	%edx, %r10d		# pass rounds
	#call	_bsaes_decrypt8
	#pxor	0x00(%rsp), %xmm15	# ^= tweak[]
	movdqu	%xmm15, 0x00(%r13)	# write output
	lea	0x10(%r13), %r13

	movdqa	0x10(%rsp), %xmm6	# next iteration tweak

.Lxts_dec_done:
	and	$15, %ebx
	jz	.Lxts_dec_ret

	pxor	%xmm14, %xmm14
	movdqa	.Lxts_magic(%rip), %xmm12
	pcmpgtd	%xmm6, %xmm14
	pshufd	$0x13, %xmm14, %xmm13
	movdqa	%xmm6, %xmm5
	paddq	%xmm6, %xmm6	# psllq 1,
	pand	%xmm12, %xmm13		# isolate carry and residue
	movdqu	(%r12), %xmm15
	pxor	%xmm13, %xmm6

	lea	0x20(%rbp), %rdi
	pxor	%xmm6, %xmm15
	lea	0x20(%rbp), %rsi
	movdqa	%xmm15, 0x20(%rbp)
	lea	(%r15), %rdx
	call	asm_AES_decrypt		# doesn't touch %xmm
	pxor	0x20(%rbp), %xmm6
	mov	%r13, %rdx
	movdqu	%xmm6, (%r13)

.Lxts_dec_steal:
	movzb	16(%r12), %eax
	movzb	(%rdx), %ecx
	lea	1(%r12), %r12
	mov	%al, (%rdx)
	mov	%cl, 16(%rdx)
	lea	1(%rdx), %rdx
	sub	$1,%ebx
	jnz	.Lxts_dec_steal

	movdqu	(%r13), %xmm15
	lea	0x20(%rbp), %rdi
	pxor	%xmm5, %xmm15
	lea	0x20(%rbp), %rsi
	movdqa	%xmm15, 0x20(%rbp)
	lea	(%r15), %rdx
	call	asm_AES_decrypt		# doesn't touch %xmm
	pxor	0x20(%rbp), %xmm5
	movdqu	%xmm5, (%r13)

.Lxts_dec_ret:
	lea	(%rsp), %rax
	pxor	%xmm0, %xmm0
.Lxts_dec_bzero:			# wipe key schedule [if any]
	movdqa	%xmm0, 0x00(%rax)
	movdqa	%xmm0, 0x10(%rax)
	lea	0x20(%rax), %rax
	cmp	%rax, %rbp
	ja	.Lxts_dec_bzero

	lea	0x78(%rbp),%rax
.cfi_def_cfa	%rax,8
	mov	-48(%rax), %r15
.cfi_restore	%r15
	mov	-40(%rax), %r14
.cfi_restore	%r14
	mov	-32(%rax), %r13
.cfi_restore	%r13
	mov	-24(%rax), %r12
.cfi_restore	%r12
	mov	-16(%rax), %rbx
.cfi_restore	%rbx
	mov	-8(%rax), %rbp
.cfi_restore	%rbp
	lea	(%rax), %rsp		# restore %rsp
.cfi_def_cfa_register	%rsp
.Lxts_dec_epilogue:
	ret
.cfi_endproc
.size	ossl_bsaes_xts_decrypt,.-ossl_bsaes_xts_decrypt
.type	_bsaes_const,@object
.section .rodata align=64
.align	64
_bsaes_const:
.LM0ISR:	# InvShiftRows constants
	.quad	0x0a0e0206070b0f03, 0x0004080c0d010509
.LISRM0:
	.quad	0x01040b0e0205080f, 0x0306090c00070a0d
.LISR:
	.quad	0x0504070602010003, 0x0f0e0d0c080b0a09
.LBS0:		# bit-slice constants
	.quad	0x5555555555555555, 0x5555555555555555
.LBS1:
	.quad	0x3333333333333333, 0x3333333333333333
.LBS2:
	.quad	0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
.LSR:		# shiftrows constants
	.quad	0x0504070600030201, 0x0f0e0d0c0a09080b
.LSRM0:
	.quad	0x0304090e00050a0f, 0x01060b0c0207080d
.LM0SR:
	.quad	0x0a0e02060f03070b, 0x0004080c05090d01
.LSWPUP:	# byte-swap upper dword
	.quad	0x0706050403020100, 0x0c0d0e0f0b0a0908
.LSWPUPM0SR:
	.quad	0x0a0d02060c03070b, 0x0004080f05090e01
.LADD1:		# counter increment constants
	.quad	0x0000000000000000, 0x0000000100000000
.LADD2:
	.quad	0x0000000000000000, 0x0000000200000000
.LADD3:
	.quad	0x0000000000000000, 0x0000000300000000
.LADD4:
	.quad	0x0000000000000000, 0x0000000400000000
.LADD5:
	.quad	0x0000000000000000, 0x0000000500000000
.LADD6:
	.quad	0x0000000000000000, 0x0000000600000000
.LADD7:
	.quad	0x0000000000000000, 0x0000000700000000
.LADD8:
	.quad	0x0000000000000000, 0x0000000800000000
.Lxts_magic:
	.long	0x87,0,1,0
.Lmasks:
	.quad	0x0101010101010101, 0x0101010101010101
	.quad	0x0202020202020202, 0x0202020202020202
	.quad	0x0404040404040404, 0x0404040404040404
	.quad	0x0808080808080808, 0x0808080808080808
.LM0:
	.quad	0x02060a0e03070b0f, 0x0004080c0105090d
.L63:
	.quad	0x6363636363636363, 0x6363636363636363
.align	64
.size	_bsaes_const,.-_bsaes_const
.asciz	"Bit-sliced AES for x86_64/SSSE3, Emilia KÃ¤sper, Peter Schwabe, Andy Polyakov"
`;

export default translateAssembly(code);
