/**
 * AES-NI for x86_64.
 *
 * TypeScript port of OpenSSL crypto/aes/asm/aesni-x86_64.pl.
 * Pinned to $win64=0 (unix SysV ABI; Win64 SEH blocks dropped).
 *
 * Exported symbols:
 *   aesni_encrypt
 *   aesni_decrypt
 *   aesni_ecb_encrypt
 *   aesni_ccm64_encrypt_blocks
 *   aesni_ccm64_decrypt_blocks
 *   aesni_ctr32_encrypt_blocks
 *   aesni_xts_encrypt
 *   aesni_xts_decrypt
 *   aesni_ocb_encrypt
 *   aesni_ocb_decrypt
 *   aesni_cbc_encrypt
 *   aesni_set_decrypt_key
 *   aesni_set_encrypt_key
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text
.extern	OPENSSL_ia32cap_P
.globl	aesni_encrypt
.type	aesni_encrypt,@abi-omnipotent
.align	16
aesni_encrypt:
.cfi_startproc
	endbranch
	movups	(%rdi),%xmm2		# load input
	mov	240(%rdx),%eax	# key->rounds
	movups	(%rdx),%xmm0
	movups	16(%rdx),%xmm1
	lea	32(%rdx),%rdx
	xorps	%xmm0,%xmm2
.Loop_enc1_1:
	.byte	102,15,56,220,209
	dec	%eax
	movups	(%rdx),%xmm1
	lea	16(%rdx),%rdx
	jnz	.Loop_enc1_1	# loop body is 16 bytes
	.byte	102,15,56,221,209
	 pxor	%xmm0,%xmm0	# clear register bank
	 pxor	%xmm1,%xmm1
	movups	%xmm2,(%rsi)		# output
	 pxor	%xmm2,%xmm2
	ret
.cfi_endproc
.size	aesni_encrypt,.-aesni_encrypt

.globl	aesni_decrypt
.type	aesni_decrypt,@abi-omnipotent
.align	16
aesni_decrypt:
.cfi_startproc
	endbranch
	movups	(%rdi),%xmm2		# load input
	mov	240(%rdx),%eax	# key->rounds
	movups	(%rdx),%xmm0
	movups	16(%rdx),%xmm1
	lea	32(%rdx),%rdx
	xorps	%xmm0,%xmm2
.Loop_dec1_2:
	.byte	102,15,56,222,209
	dec	%eax
	movups	(%rdx),%xmm1
	lea	16(%rdx),%rdx
	jnz	.Loop_dec1_2	# loop body is 16 bytes
	.byte	102,15,56,223,209
	 pxor	%xmm0,%xmm0	# clear register bank
	 pxor	%xmm1,%xmm1
	movups	%xmm2,(%rsi)		# output
	 pxor	%xmm2,%xmm2
	ret
.cfi_endproc
.size	aesni_decrypt, .-aesni_decrypt
.type	_aesni_encrypt2,@abi-omnipotent
.align	16
_aesni_encrypt2:
.cfi_startproc
	movups	(%rcx),%xmm0
	shl	$4,%eax
	movups	16(%rcx),%xmm1
	xorps	%xmm0,%xmm2
	xorps	%xmm0,%xmm3
	movups	32(%rcx),%xmm0
	lea	32(%rcx,%eax),%rcx
	neg	%rax				# %eax
	add	$16,%rax

.Lenc_loop2:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Lenc_loop2

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,221,208
	.byte	102,15,56,221,216
	ret
.cfi_endproc
.size	_aesni_encrypt2,.-_aesni_encrypt2
.type	_aesni_decrypt2,@abi-omnipotent
.align	16
_aesni_decrypt2:
.cfi_startproc
	movups	(%rcx),%xmm0
	shl	$4,%eax
	movups	16(%rcx),%xmm1
	xorps	%xmm0,%xmm2
	xorps	%xmm0,%xmm3
	movups	32(%rcx),%xmm0
	lea	32(%rcx,%eax),%rcx
	neg	%rax				# %eax
	add	$16,%rax

.Ldec_loop2:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Ldec_loop2

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,223,208
	.byte	102,15,56,223,216
	ret
.cfi_endproc
.size	_aesni_decrypt2,.-_aesni_decrypt2
.type	_aesni_encrypt3,@abi-omnipotent
.align	16
_aesni_encrypt3:
.cfi_startproc
	movups	(%rcx),%xmm0
	shl	$4,%eax
	movups	16(%rcx),%xmm1
	xorps	%xmm0,%xmm2
	xorps	%xmm0,%xmm3
	xorps	%xmm0,%xmm4
	movups	32(%rcx),%xmm0
	lea	32(%rcx,%eax),%rcx
	neg	%rax				# %eax
	add	$16,%rax

.Lenc_loop3:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Lenc_loop3

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,221,208
	.byte	102,15,56,221,216
	.byte	102,15,56,221,224
	ret
.cfi_endproc
.size	_aesni_encrypt3,.-_aesni_encrypt3
.type	_aesni_decrypt3,@abi-omnipotent
.align	16
_aesni_decrypt3:
.cfi_startproc
	movups	(%rcx),%xmm0
	shl	$4,%eax
	movups	16(%rcx),%xmm1
	xorps	%xmm0,%xmm2
	xorps	%xmm0,%xmm3
	xorps	%xmm0,%xmm4
	movups	32(%rcx),%xmm0
	lea	32(%rcx,%eax),%rcx
	neg	%rax				# %eax
	add	$16,%rax

.Ldec_loop3:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Ldec_loop3

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,223,208
	.byte	102,15,56,223,216
	.byte	102,15,56,223,224
	ret
.cfi_endproc
.size	_aesni_decrypt3,.-_aesni_decrypt3
.type	_aesni_encrypt4,@abi-omnipotent
.align	16
_aesni_encrypt4:
.cfi_startproc
	movups	(%rcx),%xmm0
	shl	$4,%eax
	movups	16(%rcx),%xmm1
	xorps	%xmm0,%xmm2
	xorps	%xmm0,%xmm3
	xorps	%xmm0,%xmm4
	xorps	%xmm0,%xmm5
	movups	32(%rcx),%xmm0
	lea	32(%rcx,%eax),%rcx
	neg	%rax				# %eax
	.byte	0x0f,0x1f,0x00
	add	$16,%rax

.Lenc_loop4:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Lenc_loop4

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,221,208
	.byte	102,15,56,221,216
	.byte	102,15,56,221,224
	.byte	102,15,56,221,232
	ret
.cfi_endproc
.size	_aesni_encrypt4,.-_aesni_encrypt4
.type	_aesni_decrypt4,@abi-omnipotent
.align	16
_aesni_decrypt4:
.cfi_startproc
	movups	(%rcx),%xmm0
	shl	$4,%eax
	movups	16(%rcx),%xmm1
	xorps	%xmm0,%xmm2
	xorps	%xmm0,%xmm3
	xorps	%xmm0,%xmm4
	xorps	%xmm0,%xmm5
	movups	32(%rcx),%xmm0
	lea	32(%rcx,%eax),%rcx
	neg	%rax				# %eax
	.byte	0x0f,0x1f,0x00
	add	$16,%rax

.Ldec_loop4:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Ldec_loop4

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,223,208
	.byte	102,15,56,223,216
	.byte	102,15,56,223,224
	.byte	102,15,56,223,232
	ret
.cfi_endproc
.size	_aesni_decrypt4,.-_aesni_decrypt4
.type	_aesni_encrypt6,@abi-omnipotent
.align	16
_aesni_encrypt6:
.cfi_startproc
	movups		(%rcx),%xmm0
	shl		$4,%eax
	movups		16(%rcx),%xmm1
	xorps		%xmm0,%xmm2
	pxor		%xmm0,%xmm3
	pxor		%xmm0,%xmm4
	.byte	102,15,56,220,209
	lea		32(%rcx,%eax),%rcx
	neg		%rax			# %eax
	.byte	102,15,56,220,217
	pxor		%xmm0,%xmm5
	pxor		%xmm0,%xmm6
	.byte	102,15,56,220,225
	pxor		%xmm0,%xmm7
	movups		(%rcx,%rax),%xmm0
	add		$16,%rax
	jmp		.Lenc_loop6_enter
.align	16
.Lenc_loop6:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
.Lenc_loop6_enter:
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Lenc_loop6

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,15,56,221,208
	.byte	102,15,56,221,216
	.byte	102,15,56,221,224
	.byte	102,15,56,221,232
	.byte	102,15,56,221,240
	.byte	102,15,56,221,248
	ret
.cfi_endproc
.size	_aesni_encrypt6,.-_aesni_encrypt6
.type	_aesni_decrypt6,@abi-omnipotent
.align	16
_aesni_decrypt6:
.cfi_startproc
	movups		(%rcx),%xmm0
	shl		$4,%eax
	movups		16(%rcx),%xmm1
	xorps		%xmm0,%xmm2
	pxor		%xmm0,%xmm3
	pxor		%xmm0,%xmm4
	.byte	102,15,56,222,209
	lea		32(%rcx,%eax),%rcx
	neg		%rax			# %eax
	.byte	102,15,56,222,217
	pxor		%xmm0,%xmm5
	pxor		%xmm0,%xmm6
	.byte	102,15,56,222,225
	pxor		%xmm0,%xmm7
	movups		(%rcx,%rax),%xmm0
	add		$16,%rax
	jmp		.Ldec_loop6_enter
.align	16
.Ldec_loop6:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
.Ldec_loop6_enter:
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Ldec_loop6

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,15,56,223,208
	.byte	102,15,56,223,216
	.byte	102,15,56,223,224
	.byte	102,15,56,223,232
	.byte	102,15,56,223,240
	.byte	102,15,56,223,248
	ret
.cfi_endproc
.size	_aesni_decrypt6,.-_aesni_decrypt6
.type	_aesni_encrypt8,@abi-omnipotent
.align	16
_aesni_encrypt8:
.cfi_startproc
	movups		(%rcx),%xmm0
	shl		$4,%eax
	movups		16(%rcx),%xmm1
	xorps		%xmm0,%xmm2
	xorps		%xmm0,%xmm3
	pxor		%xmm0,%xmm4
	pxor		%xmm0,%xmm5
	pxor		%xmm0,%xmm6
	lea		32(%rcx,%eax),%rcx
	neg		%rax			# %eax
	.byte	102,15,56,220,209
	pxor		%xmm0,%xmm7
	pxor		%xmm0,%xmm8
	.byte	102,15,56,220,217
	pxor		%xmm0,%xmm9
	movups		(%rcx,%rax),%xmm0
	add		$16,%rax
	jmp		.Lenc_loop8_inner
.align	16
.Lenc_loop8:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
.Lenc_loop8_inner:
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
.Lenc_loop8_enter:
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	.byte	102,68,15,56,220,192
	.byte	102,68,15,56,220,200
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Lenc_loop8

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
	.byte	102,15,56,221,208
	.byte	102,15,56,221,216
	.byte	102,15,56,221,224
	.byte	102,15,56,221,232
	.byte	102,15,56,221,240
	.byte	102,15,56,221,248
	.byte	102,68,15,56,221,192
	.byte	102,68,15,56,221,200
	ret
.cfi_endproc
.size	_aesni_encrypt8,.-_aesni_encrypt8
.type	_aesni_decrypt8,@abi-omnipotent
.align	16
_aesni_decrypt8:
.cfi_startproc
	movups		(%rcx),%xmm0
	shl		$4,%eax
	movups		16(%rcx),%xmm1
	xorps		%xmm0,%xmm2
	xorps		%xmm0,%xmm3
	pxor		%xmm0,%xmm4
	pxor		%xmm0,%xmm5
	pxor		%xmm0,%xmm6
	lea		32(%rcx,%eax),%rcx
	neg		%rax			# %eax
	.byte	102,15,56,222,209
	pxor		%xmm0,%xmm7
	pxor		%xmm0,%xmm8
	.byte	102,15,56,222,217
	pxor		%xmm0,%xmm9
	movups		(%rcx,%rax),%xmm0
	add		$16,%rax
	jmp		.Ldec_loop8_inner
.align	16
.Ldec_loop8:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
.Ldec_loop8_inner:
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,68,15,56,222,193
	.byte	102,68,15,56,222,201
.Ldec_loop8_enter:
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	.byte	102,68,15,56,222,192
	.byte	102,68,15,56,222,200
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Ldec_loop8

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,68,15,56,222,193
	.byte	102,68,15,56,222,201
	.byte	102,15,56,223,208
	.byte	102,15,56,223,216
	.byte	102,15,56,223,224
	.byte	102,15,56,223,232
	.byte	102,15,56,223,240
	.byte	102,15,56,223,248
	.byte	102,68,15,56,223,192
	.byte	102,68,15,56,223,200
	ret
.cfi_endproc
.size	_aesni_decrypt8,.-_aesni_decrypt8
.globl	aesni_ecb_encrypt
.type	aesni_ecb_encrypt,@function,5
.align	16
aesni_ecb_encrypt:
.cfi_startproc
	endbranch
	and	$-16,%rdx		# if (%rdx<16)
	jz	.Lecb_ret		# return

	mov	240(%rcx),%eax	# key->rounds
	movups	(%rcx),%xmm0
	mov	%rcx,%r11		# backup %rcx
	mov	%eax,%r10d		# backup %eax
	test	%r8d,%r8d		# 5th argument
	jz	.Lecb_decrypt
#--------------------------- ECB ENCRYPT ------------------------------#
	cmp	$0x80,%rdx		# if (%rdx<8*16)
	jb	.Lecb_enc_tail		# short input

	movdqu	(%rdi),%xmm2		# load 8 input blocks
	movdqu	0x10(%rdi),%xmm3
	movdqu	0x20(%rdi),%xmm4
	movdqu	0x30(%rdi),%xmm5
	movdqu	0x40(%rdi),%xmm6
	movdqu	0x50(%rdi),%xmm7
	movdqu	0x60(%rdi),%xmm8
	movdqu	0x70(%rdi),%xmm9
	lea	0x80(%rdi),%rdi		# %rdi+=8*16
	sub	$0x80,%rdx		# %rdx-=8*16 (can be zero)
	jmp	.Lecb_enc_loop8_enter
.align 16
.Lecb_enc_loop8:
	movups	%xmm2,(%rsi)		# store 8 output blocks
	mov	%r11,%rcx		# restore %rcx
	movdqu	(%rdi),%xmm2		# load 8 input blocks
	mov	%r10d,%eax		# restore %eax
	movups	%xmm3,0x10(%rsi)
	movdqu	0x10(%rdi),%xmm3
	movups	%xmm4,0x20(%rsi)
	movdqu	0x20(%rdi),%xmm4
	movups	%xmm5,0x30(%rsi)
	movdqu	0x30(%rdi),%xmm5
	movups	%xmm6,0x40(%rsi)
	movdqu	0x40(%rdi),%xmm6
	movups	%xmm7,0x50(%rsi)
	movdqu	0x50(%rdi),%xmm7
	movups	%xmm8,0x60(%rsi)
	movdqu	0x60(%rdi),%xmm8
	movups	%xmm9,0x70(%rsi)
	lea	0x80(%rsi),%rsi		# %rsi+=8*16
	movdqu	0x70(%rdi),%xmm9
	lea	0x80(%rdi),%rdi		# %rdi+=8*16
.Lecb_enc_loop8_enter:

	call	_aesni_encrypt8

	sub	$0x80,%rdx
	jnc	.Lecb_enc_loop8		# loop if %rdx-=8*16 didn't borrow

	movups	%xmm2,(%rsi)		# store 8 output blocks
	mov	%r11,%rcx		# restore %rcx
	movups	%xmm3,0x10(%rsi)
	mov	%r10d,%eax		# restore %eax
	movups	%xmm4,0x20(%rsi)
	movups	%xmm5,0x30(%rsi)
	movups	%xmm6,0x40(%rsi)
	movups	%xmm7,0x50(%rsi)
	movups	%xmm8,0x60(%rsi)
	movups	%xmm9,0x70(%rsi)
	lea	0x80(%rsi),%rsi		# %rsi+=8*16
	add	$0x80,%rdx		# restore real remaining %rdx
	jz	.Lecb_ret		# done if (%rdx==0)

.Lecb_enc_tail:				# %rdx is less than 8*16
	movups	(%rdi),%xmm2
	cmp	$0x20,%rdx
	jb	.Lecb_enc_one
	movups	0x10(%rdi),%xmm3
	je	.Lecb_enc_two
	movups	0x20(%rdi),%xmm4
	cmp	$0x40,%rdx
	jb	.Lecb_enc_three
	movups	0x30(%rdi),%xmm5
	je	.Lecb_enc_four
	movups	0x40(%rdi),%xmm6
	cmp	$0x60,%rdx
	jb	.Lecb_enc_five
	movups	0x50(%rdi),%xmm7
	je	.Lecb_enc_six
	movdqu	0x60(%rdi),%xmm8
	xorps	%xmm9,%xmm9
	call	_aesni_encrypt8
	movups	%xmm2,(%rsi)		# store 7 output blocks
	movups	%xmm3,0x10(%rsi)
	movups	%xmm4,0x20(%rsi)
	movups	%xmm5,0x30(%rsi)
	movups	%xmm6,0x40(%rsi)
	movups	%xmm7,0x50(%rsi)
	movups	%xmm8,0x60(%rsi)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_one:
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_enc1_3:
	.byte	102,15,56,220,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_enc1_3	# loop body is 16 bytes
	.byte	102,15,56,221,209
	movups	%xmm2,(%rsi)		# store one output block
	jmp	.Lecb_ret
.align	16
.Lecb_enc_two:
	call	_aesni_encrypt2
	movups	%xmm2,(%rsi)		# store 2 output blocks
	movups	%xmm3,0x10(%rsi)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_three:
	call	_aesni_encrypt3
	movups	%xmm2,(%rsi)		# store 3 output blocks
	movups	%xmm3,0x10(%rsi)
	movups	%xmm4,0x20(%rsi)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_four:
	call	_aesni_encrypt4
	movups	%xmm2,(%rsi)		# store 4 output blocks
	movups	%xmm3,0x10(%rsi)
	movups	%xmm4,0x20(%rsi)
	movups	%xmm5,0x30(%rsi)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_five:
	xorps	%xmm7,%xmm7
	call	_aesni_encrypt6
	movups	%xmm2,(%rsi)		# store 5 output blocks
	movups	%xmm3,0x10(%rsi)
	movups	%xmm4,0x20(%rsi)
	movups	%xmm5,0x30(%rsi)
	movups	%xmm6,0x40(%rsi)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_six:
	call	_aesni_encrypt6
	movups	%xmm2,(%rsi)		# store 6 output blocks
	movups	%xmm3,0x10(%rsi)
	movups	%xmm4,0x20(%rsi)
	movups	%xmm5,0x30(%rsi)
	movups	%xmm6,0x40(%rsi)
	movups	%xmm7,0x50(%rsi)
	jmp	.Lecb_ret
#--------------------------- ECB DECRYPT ------------------------------#
.align	16
.Lecb_decrypt:
	cmp	$0x80,%rdx		# if (%rdx<8*16)
	jb	.Lecb_dec_tail		# short input

	movdqu	(%rdi),%xmm2		# load 8 input blocks
	movdqu	0x10(%rdi),%xmm3
	movdqu	0x20(%rdi),%xmm4
	movdqu	0x30(%rdi),%xmm5
	movdqu	0x40(%rdi),%xmm6
	movdqu	0x50(%rdi),%xmm7
	movdqu	0x60(%rdi),%xmm8
	movdqu	0x70(%rdi),%xmm9
	lea	0x80(%rdi),%rdi		# %rdi+=8*16
	sub	$0x80,%rdx		# %rdx-=8*16 (can be zero)
	jmp	.Lecb_dec_loop8_enter
.align 16
.Lecb_dec_loop8:
	movups	%xmm2,(%rsi)		# store 8 output blocks
	mov	%r11,%rcx		# restore %rcx
	movdqu	(%rdi),%xmm2		# load 8 input blocks
	mov	%r10d,%eax		# restore %eax
	movups	%xmm3,0x10(%rsi)
	movdqu	0x10(%rdi),%xmm3
	movups	%xmm4,0x20(%rsi)
	movdqu	0x20(%rdi),%xmm4
	movups	%xmm5,0x30(%rsi)
	movdqu	0x30(%rdi),%xmm5
	movups	%xmm6,0x40(%rsi)
	movdqu	0x40(%rdi),%xmm6
	movups	%xmm7,0x50(%rsi)
	movdqu	0x50(%rdi),%xmm7
	movups	%xmm8,0x60(%rsi)
	movdqu	0x60(%rdi),%xmm8
	movups	%xmm9,0x70(%rsi)
	lea	0x80(%rsi),%rsi		# %rsi+=8*16
	movdqu	0x70(%rdi),%xmm9
	lea	0x80(%rdi),%rdi		# %rdi+=8*16
.Lecb_dec_loop8_enter:

	call	_aesni_decrypt8

	movups	(%r11),%xmm0
	sub	$0x80,%rdx
	jnc	.Lecb_dec_loop8		# loop if %rdx-=8*16 didn't borrow

	movups	%xmm2,(%rsi)		# store 8 output blocks
	 pxor	%xmm2,%xmm2		# clear register bank
	mov	%r11,%rcx		# restore %rcx
	movups	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3
	mov	%r10d,%eax		# restore %eax
	movups	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	movups	%xmm5,0x30(%rsi)
	 pxor	%xmm5,%xmm5
	movups	%xmm6,0x40(%rsi)
	 pxor	%xmm6,%xmm6
	movups	%xmm7,0x50(%rsi)
	 pxor	%xmm7,%xmm7
	movups	%xmm8,0x60(%rsi)
	 pxor	%xmm8,%xmm8
	movups	%xmm9,0x70(%rsi)
	 pxor	%xmm9,%xmm9
	lea	0x80(%rsi),%rsi		# %rsi+=8*16
	add	$0x80,%rdx		# restore real remaining %rdx
	jz	.Lecb_ret		# done if (%rdx==0)

.Lecb_dec_tail:
	movups	(%rdi),%xmm2
	cmp	$0x20,%rdx
	jb	.Lecb_dec_one
	movups	0x10(%rdi),%xmm3
	je	.Lecb_dec_two
	movups	0x20(%rdi),%xmm4
	cmp	$0x40,%rdx
	jb	.Lecb_dec_three
	movups	0x30(%rdi),%xmm5
	je	.Lecb_dec_four
	movups	0x40(%rdi),%xmm6
	cmp	$0x60,%rdx
	jb	.Lecb_dec_five
	movups	0x50(%rdi),%xmm7
	je	.Lecb_dec_six
	movups	0x60(%rdi),%xmm8
	movups	(%rcx),%xmm0
	xorps	%xmm9,%xmm9
	call	_aesni_decrypt8
	movups	%xmm2,(%rsi)		# store 7 output blocks
	 pxor	%xmm2,%xmm2		# clear register bank
	movups	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3
	movups	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	movups	%xmm5,0x30(%rsi)
	 pxor	%xmm5,%xmm5
	movups	%xmm6,0x40(%rsi)
	 pxor	%xmm6,%xmm6
	movups	%xmm7,0x50(%rsi)
	 pxor	%xmm7,%xmm7
	movups	%xmm8,0x60(%rsi)
	 pxor	%xmm8,%xmm8
	 pxor	%xmm9,%xmm9
	jmp	.Lecb_ret
.align	16
.Lecb_dec_one:
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_dec1_4:
	.byte	102,15,56,222,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_dec1_4	# loop body is 16 bytes
	.byte	102,15,56,223,209
	movups	%xmm2,(%rsi)		# store one output block
	 pxor	%xmm2,%xmm2		# clear register bank
	jmp	.Lecb_ret
.align	16
.Lecb_dec_two:
	call	_aesni_decrypt2
	movups	%xmm2,(%rsi)		# store 2 output blocks
	 pxor	%xmm2,%xmm2		# clear register bank
	movups	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3
	jmp	.Lecb_ret
.align	16
.Lecb_dec_three:
	call	_aesni_decrypt3
	movups	%xmm2,(%rsi)		# store 3 output blocks
	 pxor	%xmm2,%xmm2		# clear register bank
	movups	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3
	movups	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	jmp	.Lecb_ret
.align	16
.Lecb_dec_four:
	call	_aesni_decrypt4
	movups	%xmm2,(%rsi)		# store 4 output blocks
	 pxor	%xmm2,%xmm2		# clear register bank
	movups	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3
	movups	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	movups	%xmm5,0x30(%rsi)
	 pxor	%xmm5,%xmm5
	jmp	.Lecb_ret
.align	16
.Lecb_dec_five:
	xorps	%xmm7,%xmm7
	call	_aesni_decrypt6
	movups	%xmm2,(%rsi)		# store 5 output blocks
	 pxor	%xmm2,%xmm2		# clear register bank
	movups	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3
	movups	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	movups	%xmm5,0x30(%rsi)
	 pxor	%xmm5,%xmm5
	movups	%xmm6,0x40(%rsi)
	 pxor	%xmm6,%xmm6
	 pxor	%xmm7,%xmm7
	jmp	.Lecb_ret
.align	16
.Lecb_dec_six:
	call	_aesni_decrypt6
	movups	%xmm2,(%rsi)		# store 6 output blocks
	 pxor	%xmm2,%xmm2		# clear register bank
	movups	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3
	movups	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	movups	%xmm5,0x30(%rsi)
	 pxor	%xmm5,%xmm5
	movups	%xmm6,0x40(%rsi)
	 pxor	%xmm6,%xmm6
	movups	%xmm7,0x50(%rsi)
	 pxor	%xmm7,%xmm7

.Lecb_ret:
	xorps	%xmm0,%xmm0	# %xmm0
	pxor	%xmm1,%xmm1
	ret
.cfi_endproc
.size	aesni_ecb_encrypt,.-aesni_ecb_encrypt
.globl	aesni_ccm64_encrypt_blocks
.type	aesni_ccm64_encrypt_blocks,@function,6
.align	16
aesni_ccm64_encrypt_blocks:
.cfi_startproc
	endbranch
	mov	240(%rcx),%eax		# key->rounds
	movdqu	(%r8),%xmm6
	movdqa	.Lincrement64(%rip),%xmm9
	movdqa	.Lbswap_mask(%rip),%xmm7

	shl	$4,%eax
	mov	$16,%r10d
	lea	0(%rcx),%r11
	movdqu	(%r9),%xmm3
	movdqa	%xmm6,%xmm2
	lea	32(%rcx,%eax),%rcx		# end of key schedule
	pshufb	%xmm7,%xmm6
	sub	%rax,%r10			# twisted %eax
	jmp	.Lccm64_enc_outer
.align	16
.Lccm64_enc_outer:
	movups	(%r11),%xmm0
	mov	%r10,%rax
	movups	(%rdi),%xmm8			# load inp

	xorps	%xmm0,%xmm2		# counter
	movups	16(%r11),%xmm1
	xorps	%xmm8,%xmm0
	xorps	%xmm0,%xmm3		# cmac^=inp
	movups	32(%r11),%xmm0

.Lccm64_enc2_loop:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	movups	(%rcx,%rax),%xmm1
	add	$32,%rax
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	movups	-16(%rcx,%rax),%xmm0
	jnz	.Lccm64_enc2_loop
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	paddq	%xmm9,%xmm6
	dec	%rdx				# %rdx-- (%rdx is in blocks)
	.byte	102,15,56,221,208
	.byte	102,15,56,221,216

	lea	16(%rdi),%rdi
	xorps	%xmm2,%xmm8			# inp ^= E(iv)
	movdqa	%xmm6,%xmm2
	movups	%xmm8,(%rsi)			# save output
	pshufb	%xmm7,%xmm2
	lea	16(%rsi),%rsi			# %rsi+=16
	jnz	.Lccm64_enc_outer		# loop if (%rdx!=0)

	 pxor	%xmm0,%xmm0		# clear register bank
	 pxor	%xmm1,%xmm1
	 pxor	%xmm2,%xmm2
	movups	%xmm3,(%r9)			# store resulting mac
	 pxor	%xmm3,%xmm3
	 pxor	%xmm8,%xmm8
	 pxor	%xmm6,%xmm6
	ret
.cfi_endproc
.size	aesni_ccm64_encrypt_blocks,.-aesni_ccm64_encrypt_blocks
.globl	aesni_ccm64_decrypt_blocks
.type	aesni_ccm64_decrypt_blocks,@function,6
.align	16
aesni_ccm64_decrypt_blocks:
.cfi_startproc
	endbranch
	mov	240(%rcx),%eax		# key->rounds
	movups	(%r8),%xmm6
	movdqu	(%r9),%xmm3
	movdqa	.Lincrement64(%rip),%xmm9
	movdqa	.Lbswap_mask(%rip),%xmm7

	movaps	%xmm6,%xmm2
	mov	%eax,%r10d
	mov	%rcx,%r11
	pshufb	%xmm7,%xmm6
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_enc1_5:
	.byte	102,15,56,220,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_enc1_5	# loop body is 16 bytes
	.byte	102,15,56,221,209
	shl	$4,%r10d
	mov	$16,%eax
	movups	(%rdi),%xmm8			# load inp
	paddq	%xmm9,%xmm6
	lea	16(%rdi),%rdi			# %rdi+=16
	sub	%r10,%rax			# twisted %eax
	lea	32(%r11,%r10d),%rcx		# end of key schedule
	mov	%rax,%r10
	jmp	.Lccm64_dec_outer
.align	16
.Lccm64_dec_outer:
	xorps	%xmm2,%xmm8			# inp ^= E(iv)
	movdqa	%xmm6,%xmm2
	movups	%xmm8,(%rsi)			# save output
	lea	16(%rsi),%rsi			# %rsi+=16
	pshufb	%xmm7,%xmm2

	sub	$1,%rdx			# %rdx-- (%rdx is in blocks)
	jz	.Lccm64_dec_break		# if (%rdx==0) break

	movups	(%r11),%xmm0
	mov	%r10,%rax
	movups	16(%r11),%xmm1
	xorps	%xmm0,%xmm8
	xorps	%xmm0,%xmm2
	xorps	%xmm8,%xmm3			# cmac^=out
	movups	32(%r11),%xmm0
	jmp	.Lccm64_dec2_loop
.align	16
.Lccm64_dec2_loop:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	movups	(%rcx,%rax),%xmm1
	add	$32,%rax
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	movups	-16(%rcx,%rax),%xmm0
	jnz	.Lccm64_dec2_loop
	movups	(%rdi),%xmm8			# load input
	paddq	%xmm9,%xmm6
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,221,208
	.byte	102,15,56,221,216
	lea	16(%rdi),%rdi			# %rdi+=16
	jmp	.Lccm64_dec_outer

.align	16
.Lccm64_dec_break:
	#xorps	%xmm8,%xmm3			# cmac^=out
	mov	240(%r11),%eax
	movups	(%r11),%xmm0
	movups	16(%r11),%xmm1
	xorps	%xmm0,%xmm8
	lea	32(%r11),%r11
	xorps	%xmm8,%xmm3
.Loop_enc1_6:
	.byte	102,15,56,220,217
	dec	%eax
	movups	(%r11),%xmm1
	lea	16(%r11),%r11
	jnz	.Loop_enc1_6	# loop body is 16 bytes
	.byte	102,15,56,221,217
	 pxor	%xmm0,%xmm0		# clear register bank
	 pxor	%xmm1,%xmm1
	 pxor	%xmm2,%xmm2
	movups	%xmm3,(%r9)			# store resulting mac
	 pxor	%xmm3,%xmm3
	 pxor	%xmm8,%xmm8
	 pxor	%xmm6,%xmm6
	ret
.cfi_endproc
.size	aesni_ccm64_decrypt_blocks,.-aesni_ccm64_decrypt_blocks
.globl	aesni_ctr32_encrypt_blocks
.type	aesni_ctr32_encrypt_blocks,@function,5
.align	16
aesni_ctr32_encrypt_blocks:
.cfi_startproc
	endbranch
	cmp	$1,%rdx
	jne	.Lctr32_bulk

	# handle single block without allocating stack frame,
	# useful when handling edges
	movups	(%r8),%xmm2
	movups	(%rdi),%xmm3
	mov	240(%rcx),%edx			# key->rounds
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_enc1_7:
	.byte	102,15,56,220,209
	dec	%edx
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_enc1_7	# loop body is 16 bytes
	.byte	102,15,56,221,209
	 pxor	%xmm0,%xmm0		# clear register bank
	 pxor	%xmm1,%xmm1
	xorps	%xmm3,%xmm2
	 pxor	%xmm3,%xmm3
	movups	%xmm2,(%rsi)
	 xorps	%xmm2,%xmm2
	jmp	.Lctr32_epilogue

.align	16
.Lctr32_bulk:
	lea	(%rsp),%r11			# use %r11 as frame pointer
.cfi_def_cfa_register	%r11
	push	%rbp
.cfi_push	%rbp
	sub	$128,%rsp
	and	$-16,%rsp	# Linux kernel stack can be incorrectly seeded

	# 8 16-byte words on top of stack are counter values
	# xor-ed with zero-round key

	movdqu	(%r8),%xmm2
	movdqu	(%rcx),%xmm0
	mov	12(%r8),%r8d			# counter LSB
	pxor	%xmm0,%xmm2
	mov	12(%rcx),%ebp			# 0-round key LSB
	movdqa	%xmm2,0x00(%rsp)		# populate counter block
	bswap	%r8d
	movdqa	%xmm2,%xmm3
	movdqa	%xmm2,%xmm4
	movdqa	%xmm2,%xmm5
	movdqa	%xmm2,0x40(%rsp)
	movdqa	%xmm2,0x50(%rsp)
	movdqa	%xmm2,0x60(%rsp)
	mov	%rdx,%r10			# about to borrow %rdx
	movdqa	%xmm2,0x70(%rsp)

	lea	1(%r8d),%rax
	 lea	2(%r8d),%rdx
	bswap	%eax
	 bswap	%edx
	xor	%ebp,%eax
	 xor	%ebp,%edx
	pinsrd	$3,%eax,%xmm3
	lea	3(%r8d),%rax
	movdqa	%xmm3,0x10(%rsp)
	 pinsrd	$3,%edx,%xmm4
	bswap	%eax
	 mov	%r10,%rdx			# restore %rdx
	 lea	4(%r8d),%r10
	 movdqa	%xmm4,0x20(%rsp)
	xor	%ebp,%eax
	 bswap	%r10d
	pinsrd	$3,%eax,%xmm5
	 xor	%ebp,%r10d
	movdqa	%xmm5,0x30(%rsp)
	lea	5(%r8d),%r9
	 mov	%r10d,0x40+12(%rsp)
	bswap	%r9d
	 lea	6(%r8d),%r10
	mov	240(%rcx),%eax		# key->rounds
	xor	%ebp,%r9d
	 bswap	%r10d
	mov	%r9d,0x50+12(%rsp)
	 xor	%ebp,%r10d
	lea	7(%r8d),%r9
	 mov	%r10d,0x60+12(%rsp)
	bswap	%r9d
	 mov	OPENSSL_ia32cap_P+4(%rip),%r10d
	xor	%ebp,%r9d
	 and	$71303168,%r10d		# isolate XSAVE+MOVBE
	mov	%r9d,0x70+12(%rsp)

	movups	0x10(%rcx),%xmm1

	movdqa	0x40(%rsp),%xmm6
	movdqa	0x50(%rsp),%xmm7

	cmp	$8,%rdx		# %rdx is in blocks
	jb	.Lctr32_tail		# short input if (%rdx<8)

	sub	$6,%rdx		# %rdx is biased by -6
	cmp	$4194304,%r10d		# check for MOVBE without XSAVE
	je	.Lctr32_6x		# [which denotes Atom Silvermont]

	lea	0x80(%rcx),%rcx		# size optimization
	sub	$2,%rdx		# %rdx is biased by -8
	jmp	.Lctr32_loop8

.align	16
.Lctr32_6x:
	shl	$4,%eax
	mov	$48,%r10d
	bswap	%ebp
	lea	32(%rcx,%eax),%rcx	# end of key schedule
	sub	%rax,%r10		# twisted %eax
	jmp	.Lctr32_loop6

.align	16
.Lctr32_loop6:
	 add	$6,%r8d		# next counter value
	movups	-48(%rcx,%r10d),%xmm0
	.byte	102,15,56,220,209
	 mov	%r8d,%eax
	 xor	%ebp,%eax
	.byte	102,15,56,220,217
	 .byte	0x0f,0x38,0xf1,0x44,0x24,12	# store next counter value
	 lea	1(%r8d),%eax
	.byte	102,15,56,220,225
	 xor	%ebp,%eax
	 .byte	0x0f,0x38,0xf1,0x44,0x24,28
	.byte	102,15,56,220,233
	 lea	2(%r8d),%eax
	 xor	%ebp,%eax
	.byte	102,15,56,220,241
	 .byte	0x0f,0x38,0xf1,0x44,0x24,44
	 lea	3(%r8d),%eax
	.byte	102,15,56,220,249
	movups	-32(%rcx,%r10d),%xmm1
	 xor	%ebp,%eax

	.byte	102,15,56,220,208
	 .byte	0x0f,0x38,0xf1,0x44,0x24,60
	 lea	4(%r8d),%eax
	.byte	102,15,56,220,216
	 xor	%ebp,%eax
	 .byte	0x0f,0x38,0xf1,0x44,0x24,76
	.byte	102,15,56,220,224
	 lea	5(%r8d),%eax
	 xor	%ebp,%eax
	.byte	102,15,56,220,232
	 .byte	0x0f,0x38,0xf1,0x44,0x24,92
	 mov	%r10,%rax		# mov	%r10d,%eax
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	movups	-16(%rcx,%r10d),%xmm0

	call	.Lenc_loop6

	movdqu	(%rdi),%xmm8		# load 6 input blocks
	movdqu	0x10(%rdi),%xmm9
	movdqu	0x20(%rdi),%xmm10
	movdqu	0x30(%rdi),%xmm11
	movdqu	0x40(%rdi),%xmm12
	movdqu	0x50(%rdi),%xmm13
	lea	0x60(%rdi),%rdi		# %rdi+=6*16
	movups	-64(%rcx,%r10d),%xmm1
	pxor	%xmm2,%xmm8		# inp^=E(ctr)
	movaps	0x00(%rsp),%xmm2	# load next counter [xor-ed with 0 round]
	pxor	%xmm3,%xmm9
	movaps	0x10(%rsp),%xmm3
	pxor	%xmm4,%xmm10
	movaps	0x20(%rsp),%xmm4
	pxor	%xmm5,%xmm11
	movaps	0x30(%rsp),%xmm5
	pxor	%xmm6,%xmm12
	movaps	0x40(%rsp),%xmm6
	pxor	%xmm7,%xmm13
	movaps	0x50(%rsp),%xmm7
	movdqu	%xmm8,(%rsi)		# store 6 output blocks
	movdqu	%xmm9,0x10(%rsi)
	movdqu	%xmm10,0x20(%rsi)
	movdqu	%xmm11,0x30(%rsi)
	movdqu	%xmm12,0x40(%rsi)
	movdqu	%xmm13,0x50(%rsi)
	lea	0x60(%rsi),%rsi		# %rsi+=6*16

	sub	$6,%rdx
	jnc	.Lctr32_loop6		# loop if %rdx-=6 didn't borrow

	add	$6,%rdx		# restore real remaining %rdx
	jz	.Lctr32_done		# done if (%rdx==0)

	lea	-48(%r10d),%eax
	lea	-80(%rcx,%r10d),%rcx	# restore %rcx
	neg	%eax
	shr	$4,%eax		# restore %eax
	jmp	.Lctr32_tail

.align	32
.Lctr32_loop8:
	 add		$8,%r8d		# next counter value
	movdqa		0x60(%rsp),%xmm8
	.byte	102,15,56,220,209
	 mov		%r8d,%r9d
	movdqa		0x70(%rsp),%xmm9
	.byte	102,15,56,220,217
	 bswap		%r9d
	movups		0x20-0x80(%rcx),%xmm0
	.byte	102,15,56,220,225
	 xor		%ebp,%r9d
	 nop
	.byte	102,15,56,220,233
	 mov		%r9d,0x00+12(%rsp)	# store next counter value
	 lea		1(%r8d),%r9
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
	movups		0x30-0x80(%rcx),%xmm1
	 bswap		%r9d
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	 xor		%ebp,%r9d
	 .byte		0x66,0x90
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	 mov		%r9d,16+12(%rsp)
	 lea		2(%r8d),%r9
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	.byte	102,68,15,56,220,192
	.byte	102,68,15,56,220,200
	movups		64-0x80(%rcx),%xmm0
	 bswap		%r9d
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	 xor		%ebp,%r9d
	 .byte		0x66,0x90
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	 mov		%r9d,32+12(%rsp)
	 lea		3(%r8d),%r9
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
	movups		80-0x80(%rcx),%xmm1
	 bswap		%r9d
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	 xor		%ebp,%r9d
	 .byte		0x66,0x90
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	 mov		%r9d,48+12(%rsp)
	 lea		4(%r8d),%r9
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	.byte	102,68,15,56,220,192
	.byte	102,68,15,56,220,200
	movups		96-0x80(%rcx),%xmm0
	 bswap		%r9d
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	 xor		%ebp,%r9d
	 .byte		0x66,0x90
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	 mov		%r9d,64+12(%rsp)
	 lea		5(%r8d),%r9
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
	movups		112-0x80(%rcx),%xmm1
	 bswap		%r9d
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	 xor		%ebp,%r9d
	 .byte		0x66,0x90
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	 mov		%r9d,80+12(%rsp)
	 lea		6(%r8d),%r9
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	.byte	102,68,15,56,220,192
	.byte	102,68,15,56,220,200
	movups		128-0x80(%rcx),%xmm0
	 bswap		%r9d
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	 xor		%ebp,%r9d
	 .byte		0x66,0x90
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	 mov		%r9d,96+12(%rsp)
	 lea		7(%r8d),%r9
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
	movups		144-0x80(%rcx),%xmm1
	 bswap		%r9d
	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	 xor		%ebp,%r9d
	 movdqu		0x00(%rdi),%xmm10		# start loading input
	.byte	102,15,56,220,232
	 mov		%r9d,0x70+12(%rsp)
	 cmp		$11,%eax
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	.byte	102,68,15,56,220,192
	.byte	102,68,15,56,220,200
	movups		0xa0-0x80(%rcx),%xmm0

	jb		.Lctr32_enc_done

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
	movups		0xb0-0x80(%rcx),%xmm1

	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	.byte	102,68,15,56,220,192
	.byte	102,68,15,56,220,200
	movups		0xc0-0x80(%rcx),%xmm0
	je		.Lctr32_enc_done

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
	movups		0xd0-0x80(%rcx),%xmm1

	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	.byte	102,68,15,56,220,192
	.byte	102,68,15,56,220,200
	movups		0xe0-0x80(%rcx),%xmm0
	jmp		.Lctr32_enc_done

.align	16
.Lctr32_enc_done:
	movdqu		0x10(%rdi),%xmm11
	pxor		%xmm0,%xmm10		# input^=round[last]
	movdqu		0x20(%rdi),%xmm12
	pxor		%xmm0,%xmm11
	movdqu		0x30(%rdi),%xmm13
	pxor		%xmm0,%xmm12
	movdqu		0x40(%rdi),%xmm14
	pxor		%xmm0,%xmm13
	movdqu		0x50(%rdi),%xmm15
	pxor		%xmm0,%xmm14
	pxor		%xmm0,%xmm15
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193
	.byte	102,68,15,56,220,201
	movdqu		0x60(%rdi),%xmm1	# borrow %xmm1 for inp[6]
	lea		0x80(%rdi),%rdi		# %rdi+=8*16

	.byte	102,65,15,56,221,210
	pxor		%xmm0,%xmm1	# borrowed
	movdqu		0x70-0x80(%rdi),%xmm10
	.byte	102,65,15,56,221,219
	pxor		%xmm0,%xmm10
	movdqa		0x00(%rsp),%xmm11		# load next counter block
	.byte	102,65,15,56,221,228
	.byte	102,65,15,56,221,237
	movdqa		0x10(%rsp),%xmm12
	movdqa		0x20(%rsp),%xmm13
	.byte	102,65,15,56,221,246
	.byte	102,65,15,56,221,255
	movdqa		0x30(%rsp),%xmm14
	movdqa		0x40(%rsp),%xmm15
	.byte	102,68,15,56,221,193
	movdqa		0x50(%rsp),%xmm0
	movups		0x10-0x80(%rcx),%xmm1#real 1st-round key
	.byte	102,69,15,56,221,202

	movups		%xmm2,(%rsi)		# store 8 output blocks
	movdqa		%xmm11,%xmm2
	movups		%xmm3,0x10(%rsi)
	movdqa		%xmm12,%xmm3
	movups		%xmm4,0x20(%rsi)
	movdqa		%xmm13,%xmm4
	movups		%xmm5,0x30(%rsi)
	movdqa		%xmm14,%xmm5
	movups		%xmm6,0x40(%rsi)
	movdqa		%xmm15,%xmm6
	movups		%xmm7,0x50(%rsi)
	movdqa		%xmm0,%xmm7
	movups		%xmm8,0x60(%rsi)
	movups		%xmm9,0x70(%rsi)
	lea		0x80(%rsi),%rsi		# %rsi+=8*16

	sub	$8,%rdx
	jnc	.Lctr32_loop8			# loop if %rdx-=8 didn't borrow

	add	$8,%rdx			# restore real remaining %rdx
	jz	.Lctr32_done			# done if (%rdx==0)
	lea	-0x80(%rcx),%rcx

.Lctr32_tail:
	# note that at this point %xmm2..5 are populated with
	# counter values xor-ed with 0-round key
	lea	16(%rcx),%rcx
	cmp	$4,%rdx
	jb	.Lctr32_loop3
	je	.Lctr32_loop4

	# if (%rdx>4) compute 7 E(counter)
	shl		$4,%eax
	movdqa		0x60(%rsp),%xmm8
	pxor		%xmm9,%xmm9

	movups		16(%rcx),%xmm0
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	lea		32-16(%rcx,%eax),%rcx# prepare for .Lenc_loop8_enter
	neg		%rax
	.byte	102,15,56,220,225
	add		$16,%rax		# prepare for .Lenc_loop8_enter
	 movups		(%rdi),%xmm10
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	 movups		0x10(%rdi),%xmm11		# pre-load input
	 movups		0x20(%rdi),%xmm12
	.byte	102,15,56,220,249
	.byte	102,68,15,56,220,193

	call            .Lenc_loop8_enter

	movdqu	0x30(%rdi),%xmm13
	pxor	%xmm10,%xmm2
	movdqu	0x40(%rdi),%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)			# store output
	pxor	%xmm12,%xmm4
	movdqu	%xmm3,0x10(%rsi)
	pxor	%xmm13,%xmm5
	movdqu	%xmm4,0x20(%rsi)
	pxor	%xmm10,%xmm6
	movdqu	%xmm5,0x30(%rsi)
	movdqu	%xmm6,0x40(%rsi)
	cmp	$6,%rdx
	jb	.Lctr32_done			# %rdx was 5, stop store

	movups	0x50(%rdi),%xmm11
	xorps	%xmm11,%xmm7
	movups	%xmm7,0x50(%rsi)
	je	.Lctr32_done			# %rdx was 6, stop store

	movups	0x60(%rdi),%xmm12
	xorps	%xmm12,%xmm8
	movups	%xmm8,0x60(%rsi)
	jmp	.Lctr32_done			# %rdx was 7, stop store

.align	32
.Lctr32_loop4:
	.byte	102,15,56,220,209
	lea		16(%rcx),%rcx
	dec		%eax
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	movups		(%rcx),%xmm1
	jnz		.Lctr32_loop4
	.byte	102,15,56,221,209
	.byte	102,15,56,221,217
	 movups		(%rdi),%xmm10		# load input
	 movups		0x10(%rdi),%xmm11
	.byte	102,15,56,221,225
	.byte	102,15,56,221,233
	 movups		0x20(%rdi),%xmm12
	 movups		0x30(%rdi),%xmm13

	xorps	%xmm10,%xmm2
	movups	%xmm2,(%rsi)			# store output
	xorps	%xmm11,%xmm3
	movups	%xmm3,0x10(%rsi)
	pxor	%xmm12,%xmm4
	movdqu	%xmm4,0x20(%rsi)
	pxor	%xmm13,%xmm5
	movdqu	%xmm5,0x30(%rsi)
	jmp	.Lctr32_done			# %rdx was 4, stop store

.align	32
.Lctr32_loop3:
	.byte	102,15,56,220,209
	lea		16(%rcx),%rcx
	dec		%eax
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	movups		(%rcx),%xmm1
	jnz		.Lctr32_loop3
	.byte	102,15,56,221,209
	.byte	102,15,56,221,217
	.byte	102,15,56,221,225

	movups	(%rdi),%xmm10			# load input
	xorps	%xmm10,%xmm2
	movups	%xmm2,(%rsi)			# store output
	cmp	$2,%rdx
	jb	.Lctr32_done			# %rdx was 1, stop store

	movups	0x10(%rdi),%xmm11
	xorps	%xmm11,%xmm3
	movups	%xmm3,0x10(%rsi)
	je	.Lctr32_done			# %rdx was 2, stop store

	movups	0x20(%rdi),%xmm12
	xorps	%xmm12,%xmm4
	movups	%xmm4,0x20(%rsi)		# %rdx was 3, stop store

.Lctr32_done:
	xorps	%xmm0,%xmm0			# clear register bank
	xor	%ebp,%ebp
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	movaps	%xmm0,0x00(%rsp)		# clear stack
	pxor	%xmm8,%xmm8
	movaps	%xmm0,0x10(%rsp)
	pxor	%xmm9,%xmm9
	movaps	%xmm0,0x20(%rsp)
	pxor	%xmm10,%xmm10
	movaps	%xmm0,0x30(%rsp)
	pxor	%xmm11,%xmm11
	movaps	%xmm0,0x40(%rsp)
	pxor	%xmm12,%xmm12
	movaps	%xmm0,0x50(%rsp)
	pxor	%xmm13,%xmm13
	movaps	%xmm0,0x60(%rsp)
	pxor	%xmm14,%xmm14
	movaps	%xmm0,0x70(%rsp)
	pxor	%xmm15,%xmm15
	mov	-8(%r11),%rbp
.cfi_restore	%rbp
	lea	(%r11),%rsp
.cfi_def_cfa_register	%rsp
.Lctr32_epilogue:
	ret
.cfi_endproc
.size	aesni_ctr32_encrypt_blocks,.-aesni_ctr32_encrypt_blocks
.globl	aesni_xts_encrypt
.type	aesni_xts_encrypt,@function,6
.align	16
aesni_xts_encrypt:
.cfi_startproc
	endbranch
	lea	(%rsp),%r11			# frame pointer
.cfi_def_cfa_register	%r11
	push	%rbp
.cfi_push	%rbp
	sub	$112,%rsp
	and	$-16,%rsp	# Linux kernel stack can be incorrectly seeded
	movups	(%r9),%xmm2			# load clear-text tweak
	mov	240(%r8),%eax		# key2->rounds
	mov	240(%rcx),%r10d		# key1->rounds
	movups	(%r8),%xmm0
	movups	16(%r8),%xmm1
	lea	32(%r8),%r8
	xorps	%xmm0,%xmm2
.Loop_enc1_8:
	.byte	102,15,56,220,209
	dec	%eax
	movups	(%r8),%xmm1
	lea	16(%r8),%r8
	jnz	.Loop_enc1_8	# loop body is 16 bytes
	.byte	102,15,56,221,209
	movups	(%rcx),%xmm0			# zero round key
	mov	%rcx,%rbp			# backup %rcx
	mov	%r10d,%eax			# backup %eax
	shl	$4,%r10d
	mov	%rdx,%r9			# backup %rdx
	and	$-16,%rdx

	movups	16(%rcx,%r10d),%xmm1	# last round key

	movdqa	.Lxts_magic(%rip),%xmm8
	movdqa	%xmm2,%xmm15
	pshufd	$0x5f,%xmm2,%xmm9
	pxor	%xmm0,%xmm1
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	movdqa	%xmm15,%xmm10
	psrad	$31,%xmm14			# broadcast upper bits
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	pxor	%xmm0,%xmm10
	pxor	%xmm14,%xmm15
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	movdqa	%xmm15,%xmm11
	psrad	$31,%xmm14			# broadcast upper bits
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	pxor	%xmm0,%xmm11
	pxor	%xmm14,%xmm15
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	movdqa	%xmm15,%xmm12
	psrad	$31,%xmm14			# broadcast upper bits
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	pxor	%xmm0,%xmm12
	pxor	%xmm14,%xmm15
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	movdqa	%xmm15,%xmm13
	psrad	$31,%xmm14			# broadcast upper bits
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	pxor	%xmm0,%xmm13
	pxor	%xmm14,%xmm15
	movdqa	%xmm15,%xmm14
	psrad	$31,%xmm9
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm9
	pxor	%xmm0,%xmm14
	pxor	%xmm9,%xmm15
	movaps	%xmm1,0x60(%rsp)		# save round[0]^round[last]

	sub	$16*6,%rdx
	jc	.Lxts_enc_short			# if %rdx-=6*16 borrowed

	mov	$16+96,%eax
	lea	32(%rbp,%r10d),%rcx		# end of key schedule
	sub	%r10,%rax			# twisted %eax
	movups	16(%rbp),%xmm1
	mov	%rax,%r10			# backup twisted %eax
	lea	.Lxts_magic(%rip),%r8
	jmp	.Lxts_enc_grandloop

.align	32
.Lxts_enc_grandloop:
	movdqu	0(%rdi),%xmm2		# load input
	movdqa	%xmm0,%xmm8
	movdqu	16(%rdi),%xmm3
	pxor	%xmm10,%xmm2		# input^=tweak^round[0]
	movdqu	32(%rdi),%xmm4
	pxor	%xmm11,%xmm3
	 .byte	102,15,56,220,209
	movdqu	48(%rdi),%xmm5
	pxor	%xmm12,%xmm4
	 .byte	102,15,56,220,217
	movdqu	64(%rdi),%xmm6
	pxor	%xmm13,%xmm5
	 .byte	102,15,56,220,225
	movdqu	80(%rdi),%xmm7
	pxor	%xmm15,%xmm8		# round[0]^=tweak[5]
	 movdqa	0x60(%rsp),%xmm9		# load round[0]^round[last]
	pxor	%xmm14,%xmm6
	 .byte	102,15,56,220,233
	movups	32(%rbp),%xmm0
	lea	96(%rdi),%rdi
	pxor	%xmm8,%xmm7

	 pxor	%xmm9,%xmm10		# calculate tweaks^round[last]
	.byte	102,15,56,220,241
	 pxor	%xmm9,%xmm11
	 movdqa	%xmm10,0(%rsp)		# put aside tweaks^round[last]
	.byte	102,15,56,220,249
	movups		48(%rbp),%xmm1
	 pxor	%xmm9,%xmm12

	.byte	102,15,56,220,208
	 pxor	%xmm9,%xmm13
	 movdqa	%xmm11,16(%rsp)
	.byte	102,15,56,220,216
	 pxor	%xmm9,%xmm14
	 movdqa	%xmm12,32(%rsp)
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	 pxor	%xmm9,%xmm8
	 movdqa	%xmm14,64(%rsp)
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	movups		64(%rbp),%xmm0
	 movdqa	%xmm8,80(%rsp)
	pshufd	$0x5f,%xmm15,%xmm9
	jmp	.Lxts_enc_loop6
.align	32
.Lxts_enc_loop6:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	movups		-64(%rcx,%rax),%xmm1
	add		$32,%rax

	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	movups		-80(%rcx,%rax),%xmm0
	jnz		.Lxts_enc_loop6

	movdqa	(%r8),%xmm8			# start calculating next tweak
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	 .byte	102,15,56,220,209
	paddq	%xmm15,%xmm15
	psrad	$31,%xmm14
	 .byte	102,15,56,220,217
	pand	%xmm8,%xmm14
	movups	(%rbp),%xmm10		# load round[0]
	 .byte	102,15,56,220,225
	 .byte	102,15,56,220,233
	 .byte	102,15,56,220,241
	pxor	%xmm14,%xmm15
	movaps	%xmm10,%xmm11		# copy round[0]
	 .byte	102,15,56,220,249
	 movups	-64(%rcx),%xmm1

	movdqa	%xmm9,%xmm14
	 .byte	102,15,56,220,208
	paddd	%xmm9,%xmm9
	pxor	%xmm15,%xmm10
	 .byte	102,15,56,220,216
	psrad	$31,%xmm14
	paddq	%xmm15,%xmm15
	 .byte	102,15,56,220,224
	 .byte	102,15,56,220,232
	pand	%xmm8,%xmm14
	movaps	%xmm11,%xmm12
	 .byte	102,15,56,220,240
	pxor	%xmm14,%xmm15
	movdqa	%xmm9,%xmm14
	 .byte	102,15,56,220,248
	 movups	-48(%rcx),%xmm0

	paddd	%xmm9,%xmm9
	 .byte	102,15,56,220,209
	pxor	%xmm15,%xmm11
	psrad	$31,%xmm14
	 .byte	102,15,56,220,217
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	 .byte	102,15,56,220,225
	 .byte	102,15,56,220,233
	 movdqa	%xmm13,48(%rsp)
	pxor	%xmm14,%xmm15
	 .byte	102,15,56,220,241
	movaps	%xmm12,%xmm13
	movdqa	%xmm9,%xmm14
	 .byte	102,15,56,220,249
	 movups	-32(%rcx),%xmm1

	paddd	%xmm9,%xmm9
	 .byte	102,15,56,220,208
	pxor	%xmm15,%xmm12
	psrad	$31,%xmm14
	 .byte	102,15,56,220,216
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	 .byte	102,15,56,220,224
	 .byte	102,15,56,220,232
	 .byte	102,15,56,220,240
	pxor	%xmm14,%xmm15
	movaps	%xmm13,%xmm14
	 .byte	102,15,56,220,248

	movdqa	%xmm9,%xmm0
	paddd	%xmm9,%xmm9
	 .byte	102,15,56,220,209
	pxor	%xmm15,%xmm13
	psrad	$31,%xmm0
	 .byte	102,15,56,220,217
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm0
	 .byte	102,15,56,220,225
	 .byte	102,15,56,220,233
	pxor	%xmm0,%xmm15
	movups		(%rbp),%xmm0
	 .byte	102,15,56,220,241
	 .byte	102,15,56,220,249
	movups		16(%rbp),%xmm1

	pxor	%xmm15,%xmm14
	 .byte	102,15,56,221,84,36,0
	psrad	$31,%xmm9
	paddq	%xmm15,%xmm15
	 .byte	102,15,56,221,92,36,16
	 .byte	102,15,56,221,100,36,32
	pand	%xmm8,%xmm9
	mov	%r10,%rax			# restore %eax
	 .byte	102,15,56,221,108,36,48
	 .byte	102,15,56,221,116,36,64
	 .byte	102,15,56,221,124,36,80
	pxor	%xmm9,%xmm15

	lea	96(%rsi),%rsi		# %rsi+=6*16
	movups	%xmm2,-96(%rsi)		# store 6 output blocks
	movups	%xmm3,-80(%rsi)
	movups	%xmm4,-64(%rsi)
	movups	%xmm5,-48(%rsi)
	movups	%xmm6,-32(%rsi)
	movups	%xmm7,-16(%rsi)
	sub	$16*6,%rdx
	jnc	.Lxts_enc_grandloop		# loop if %rdx-=6*16 didn't borrow

	mov	$16+96,%eax
	sub	%r10d,%eax
	mov	%rbp,%rcx			# restore %rcx
	shr	$4,%eax			# restore original value

.Lxts_enc_short:
	# at the point %xmm10 %xmm11 %xmm12 %xmm13 %xmm14 %xmm15 are populated with tweak values
	mov	%eax,%r10d			# backup %eax
	pxor	%xmm0,%xmm10
	add	$16*6,%rdx			# restore real remaining %rdx
	jz	.Lxts_enc_done			# done if (%rdx==0)

	pxor	%xmm0,%xmm11
	cmp	$0x20,%rdx
	jb	.Lxts_enc_one			# %rdx is 1*16
	pxor	%xmm0,%xmm12
	je	.Lxts_enc_two			# %rdx is 2*16

	pxor	%xmm0,%xmm13
	cmp	$0x40,%rdx
	jb	.Lxts_enc_three			# %rdx is 3*16
	pxor	%xmm0,%xmm14
	je	.Lxts_enc_four			# %rdx is 4*16

	movdqu	(%rdi),%xmm2			# %rdx is 5*16
	movdqu	16*1(%rdi),%xmm3
	movdqu	16*2(%rdi),%xmm4
	pxor	%xmm10,%xmm2
	movdqu	16*3(%rdi),%xmm5
	pxor	%xmm11,%xmm3
	movdqu	16*4(%rdi),%xmm6
	lea	16*5(%rdi),%rdi			# %rdi+=5*16
	pxor	%xmm12,%xmm4
	pxor	%xmm13,%xmm5
	pxor	%xmm14,%xmm6
	pxor	%xmm7,%xmm7

	call	_aesni_encrypt6

	xorps	%xmm10,%xmm2
	movdqa	%xmm15,%xmm10
	xorps	%xmm11,%xmm3
	xorps	%xmm12,%xmm4
	movdqu	%xmm2,(%rsi)			# store 5 output blocks
	xorps	%xmm13,%xmm5
	movdqu	%xmm3,16*1(%rsi)
	xorps	%xmm14,%xmm6
	movdqu	%xmm4,16*2(%rsi)
	movdqu	%xmm5,16*3(%rsi)
	movdqu	%xmm6,16*4(%rsi)
	lea	16*5(%rsi),%rsi			# %rsi+=5*16
	jmp	.Lxts_enc_done

.align	16
.Lxts_enc_one:
	movups	(%rdi),%xmm2
	lea	16*1(%rdi),%rdi			# inp+=1*16
	xorps	%xmm10,%xmm2
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_enc1_9:
	.byte	102,15,56,220,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_enc1_9	# loop body is 16 bytes
	.byte	102,15,56,221,209
	xorps	%xmm10,%xmm2
	movdqa	%xmm11,%xmm10
	movups	%xmm2,(%rsi)			# store one output block
	lea	16*1(%rsi),%rsi			# %rsi+=1*16
	jmp	.Lxts_enc_done

.align	16
.Lxts_enc_two:
	movups	(%rdi),%xmm2
	movups	16(%rdi),%xmm3
	lea	32(%rdi),%rdi			# %rdi+=2*16
	xorps	%xmm10,%xmm2
	xorps	%xmm11,%xmm3

	call	_aesni_encrypt2

	xorps	%xmm10,%xmm2
	movdqa	%xmm12,%xmm10
	xorps	%xmm11,%xmm3
	movups	%xmm2,(%rsi)			# store 2 output blocks
	movups	%xmm3,16*1(%rsi)
	lea	16*2(%rsi),%rsi			# %rsi+=2*16
	jmp	.Lxts_enc_done

.align	16
.Lxts_enc_three:
	movups	(%rdi),%xmm2
	movups	16*1(%rdi),%xmm3
	movups	16*2(%rdi),%xmm4
	lea	16*3(%rdi),%rdi			# %rdi+=3*16
	xorps	%xmm10,%xmm2
	xorps	%xmm11,%xmm3
	xorps	%xmm12,%xmm4

	call	_aesni_encrypt3

	xorps	%xmm10,%xmm2
	movdqa	%xmm13,%xmm10
	xorps	%xmm11,%xmm3
	xorps	%xmm12,%xmm4
	movups	%xmm2,(%rsi)			# store 3 output blocks
	movups	%xmm3,16*1(%rsi)
	movups	%xmm4,16*2(%rsi)
	lea	16*3(%rsi),%rsi			# %rsi+=3*16
	jmp	.Lxts_enc_done

.align	16
.Lxts_enc_four:
	movups	(%rdi),%xmm2
	movups	16*1(%rdi),%xmm3
	movups	16*2(%rdi),%xmm4
	xorps	%xmm10,%xmm2
	movups	16*3(%rdi),%xmm5
	lea	16*4(%rdi),%rdi			# %rdi+=4*16
	xorps	%xmm11,%xmm3
	xorps	%xmm12,%xmm4
	xorps	%xmm13,%xmm5

	call	_aesni_encrypt4

	pxor	%xmm10,%xmm2
	movdqa	%xmm14,%xmm10
	pxor	%xmm11,%xmm3
	pxor	%xmm12,%xmm4
	movdqu	%xmm2,(%rsi)			# store 4 output blocks
	pxor	%xmm13,%xmm5
	movdqu	%xmm3,16*1(%rsi)
	movdqu	%xmm4,16*2(%rsi)
	movdqu	%xmm5,16*3(%rsi)
	lea	16*4(%rsi),%rsi			# %rsi+=4*16
	jmp	.Lxts_enc_done

.align	16
.Lxts_enc_done:
	and	$15,%r9			# see if %rdx%16 is 0
	jz	.Lxts_enc_ret
	mov	%r9,%rdx

.Lxts_enc_steal:
	movzb	(%rdi),%eax			# borrow %eax ...
	movzb	-16(%rsi),%ecx			# ... and %rcx
	lea	1(%rdi),%rdi
	mov	%al,-16(%rsi)
	mov	%cl,0(%rsi)
	lea	1(%rsi),%rsi
	sub	$1,%rdx
	jnz	.Lxts_enc_steal

	sub	%r9,%rsi			# rewind %rsi
	mov	%rbp,%rcx			# restore %rcx
	mov	%r10d,%eax			# restore %eax

	movups	-16(%rsi),%xmm2
	xorps	%xmm10,%xmm2
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_enc1_10:
	.byte	102,15,56,220,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_enc1_10	# loop body is 16 bytes
	.byte	102,15,56,221,209
	xorps	%xmm10,%xmm2
	movups	%xmm2,-16(%rsi)

.Lxts_enc_ret:
	xorps	%xmm0,%xmm0			# clear register bank
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	movaps	%xmm0,0x00(%rsp)		# clear stack
	pxor	%xmm8,%xmm8
	movaps	%xmm0,0x10(%rsp)
	pxor	%xmm9,%xmm9
	movaps	%xmm0,0x20(%rsp)
	pxor	%xmm10,%xmm10
	movaps	%xmm0,0x30(%rsp)
	pxor	%xmm11,%xmm11
	movaps	%xmm0,0x40(%rsp)
	pxor	%xmm12,%xmm12
	movaps	%xmm0,0x50(%rsp)
	pxor	%xmm13,%xmm13
	movaps	%xmm0,0x60(%rsp)
	pxor	%xmm14,%xmm14
	pxor	%xmm15,%xmm15
	mov	-8(%r11),%rbp
.cfi_restore	%rbp
	lea	(%r11),%rsp
.cfi_def_cfa_register	%rsp
.Lxts_enc_epilogue:
	ret
.cfi_endproc
.size	aesni_xts_encrypt,.-aesni_xts_encrypt
.globl	aesni_xts_decrypt
.type	aesni_xts_decrypt,@function,6
.align	16
aesni_xts_decrypt:
.cfi_startproc
	endbranch
	lea	(%rsp),%r11			# frame pointer
.cfi_def_cfa_register	%r11
	push	%rbp
.cfi_push	%rbp
	sub	$112,%rsp
	and	$-16,%rsp	# Linux kernel stack can be incorrectly seeded
	movups	(%r9),%xmm2			# load clear-text tweak
	mov	240(%r8),%eax		# key2->rounds
	mov	240(%rcx),%r10d		# key1->rounds
	movups	(%r8),%xmm0
	movups	16(%r8),%xmm1
	lea	32(%r8),%r8
	xorps	%xmm0,%xmm2
.Loop_enc1_11:
	.byte	102,15,56,220,209
	dec	%eax
	movups	(%r8),%xmm1
	lea	16(%r8),%r8
	jnz	.Loop_enc1_11	# loop body is 16 bytes
	.byte	102,15,56,221,209
	xor	%eax,%eax			# if (%rdx%16) len-=16;
	test	$15,%rdx
	setnz	%al
	shl	$4,%rax
	sub	%rax,%rdx

	movups	(%rcx),%xmm0			# zero round key
	mov	%rcx,%rbp			# backup %rcx
	mov	%r10d,%eax			# backup %eax
	shl	$4,%r10d
	mov	%rdx,%r9			# backup %rdx
	and	$-16,%rdx

	movups	16(%rcx,%r10d),%xmm1	# last round key

	movdqa	.Lxts_magic(%rip),%xmm8
	movdqa	%xmm2,%xmm15
	pshufd	$0x5f,%xmm2,%xmm9
	pxor	%xmm0,%xmm1
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	movdqa	%xmm15,%xmm10
	psrad	$31,%xmm14			# broadcast upper bits
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	pxor	%xmm0,%xmm10
	pxor	%xmm14,%xmm15
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	movdqa	%xmm15,%xmm11
	psrad	$31,%xmm14			# broadcast upper bits
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	pxor	%xmm0,%xmm11
	pxor	%xmm14,%xmm15
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	movdqa	%xmm15,%xmm12
	psrad	$31,%xmm14			# broadcast upper bits
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	pxor	%xmm0,%xmm12
	pxor	%xmm14,%xmm15
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	movdqa	%xmm15,%xmm13
	psrad	$31,%xmm14			# broadcast upper bits
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	pxor	%xmm0,%xmm13
	pxor	%xmm14,%xmm15
	movdqa	%xmm15,%xmm14
	psrad	$31,%xmm9
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm9
	pxor	%xmm0,%xmm14
	pxor	%xmm9,%xmm15
	movaps	%xmm1,0x60(%rsp)		# save round[0]^round[last]

	sub	$16*6,%rdx
	jc	.Lxts_dec_short			# if %rdx-=6*16 borrowed

	mov	$16+96,%eax
	lea	32(%rbp,%r10d),%rcx		# end of key schedule
	sub	%r10,%rax			# twisted %eax
	movups	16(%rbp),%xmm1
	mov	%rax,%r10			# backup twisted %eax
	lea	.Lxts_magic(%rip),%r8
	jmp	.Lxts_dec_grandloop

.align	32
.Lxts_dec_grandloop:
	movdqu	0(%rdi),%xmm2		# load input
	movdqa	%xmm0,%xmm8
	movdqu	16(%rdi),%xmm3
	pxor	%xmm10,%xmm2		# input^=tweak^round[0]
	movdqu	32(%rdi),%xmm4
	pxor	%xmm11,%xmm3
	 .byte	102,15,56,222,209
	movdqu	48(%rdi),%xmm5
	pxor	%xmm12,%xmm4
	 .byte	102,15,56,222,217
	movdqu	64(%rdi),%xmm6
	pxor	%xmm13,%xmm5
	 .byte	102,15,56,222,225
	movdqu	80(%rdi),%xmm7
	pxor	%xmm15,%xmm8		# round[0]^=tweak[5]
	 movdqa	0x60(%rsp),%xmm9		# load round[0]^round[last]
	pxor	%xmm14,%xmm6
	 .byte	102,15,56,222,233
	movups	32(%rbp),%xmm0
	lea	96(%rdi),%rdi
	pxor	%xmm8,%xmm7

	 pxor	%xmm9,%xmm10		# calculate tweaks^round[last]
	.byte	102,15,56,222,241
	 pxor	%xmm9,%xmm11
	 movdqa	%xmm10,0(%rsp)		# put aside tweaks^last round key
	.byte	102,15,56,222,249
	movups		48(%rbp),%xmm1
	 pxor	%xmm9,%xmm12

	.byte	102,15,56,222,208
	 pxor	%xmm9,%xmm13
	 movdqa	%xmm11,16(%rsp)
	.byte	102,15,56,222,216
	 pxor	%xmm9,%xmm14
	 movdqa	%xmm12,32(%rsp)
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	 pxor	%xmm9,%xmm8
	 movdqa	%xmm14,64(%rsp)
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	movups		64(%rbp),%xmm0
	 movdqa	%xmm8,80(%rsp)
	pshufd	$0x5f,%xmm15,%xmm9
	jmp	.Lxts_dec_loop6
.align	32
.Lxts_dec_loop6:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	movups		-64(%rcx,%rax),%xmm1
	add		$32,%rax

	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	movups		-80(%rcx,%rax),%xmm0
	jnz		.Lxts_dec_loop6

	movdqa	(%r8),%xmm8			# start calculating next tweak
	movdqa	%xmm9,%xmm14
	paddd	%xmm9,%xmm9
	 .byte	102,15,56,222,209
	paddq	%xmm15,%xmm15
	psrad	$31,%xmm14
	 .byte	102,15,56,222,217
	pand	%xmm8,%xmm14
	movups	(%rbp),%xmm10		# load round[0]
	 .byte	102,15,56,222,225
	 .byte	102,15,56,222,233
	 .byte	102,15,56,222,241
	pxor	%xmm14,%xmm15
	movaps	%xmm10,%xmm11		# copy round[0]
	 .byte	102,15,56,222,249
	 movups	-64(%rcx),%xmm1

	movdqa	%xmm9,%xmm14
	 .byte	102,15,56,222,208
	paddd	%xmm9,%xmm9
	pxor	%xmm15,%xmm10
	 .byte	102,15,56,222,216
	psrad	$31,%xmm14
	paddq	%xmm15,%xmm15
	 .byte	102,15,56,222,224
	 .byte	102,15,56,222,232
	pand	%xmm8,%xmm14
	movaps	%xmm11,%xmm12
	 .byte	102,15,56,222,240
	pxor	%xmm14,%xmm15
	movdqa	%xmm9,%xmm14
	 .byte	102,15,56,222,248
	 movups	-48(%rcx),%xmm0

	paddd	%xmm9,%xmm9
	 .byte	102,15,56,222,209
	pxor	%xmm15,%xmm11
	psrad	$31,%xmm14
	 .byte	102,15,56,222,217
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	 .byte	102,15,56,222,225
	 .byte	102,15,56,222,233
	 movdqa	%xmm13,48(%rsp)
	pxor	%xmm14,%xmm15
	 .byte	102,15,56,222,241
	movaps	%xmm12,%xmm13
	movdqa	%xmm9,%xmm14
	 .byte	102,15,56,222,249
	 movups	-32(%rcx),%xmm1

	paddd	%xmm9,%xmm9
	 .byte	102,15,56,222,208
	pxor	%xmm15,%xmm12
	psrad	$31,%xmm14
	 .byte	102,15,56,222,216
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm14
	 .byte	102,15,56,222,224
	 .byte	102,15,56,222,232
	 .byte	102,15,56,222,240
	pxor	%xmm14,%xmm15
	movaps	%xmm13,%xmm14
	 .byte	102,15,56,222,248

	movdqa	%xmm9,%xmm0
	paddd	%xmm9,%xmm9
	 .byte	102,15,56,222,209
	pxor	%xmm15,%xmm13
	psrad	$31,%xmm0
	 .byte	102,15,56,222,217
	paddq	%xmm15,%xmm15
	pand	%xmm8,%xmm0
	 .byte	102,15,56,222,225
	 .byte	102,15,56,222,233
	pxor	%xmm0,%xmm15
	movups		(%rbp),%xmm0
	 .byte	102,15,56,222,241
	 .byte	102,15,56,222,249
	movups		16(%rbp),%xmm1

	pxor	%xmm15,%xmm14
	 .byte	102,15,56,223,84,36,0
	psrad	$31,%xmm9
	paddq	%xmm15,%xmm15
	 .byte	102,15,56,223,92,36,16
	 .byte	102,15,56,223,100,36,32
	pand	%xmm8,%xmm9
	mov	%r10,%rax			# restore %eax
	 .byte	102,15,56,223,108,36,48
	 .byte	102,15,56,223,116,36,64
	 .byte	102,15,56,223,124,36,80
	pxor	%xmm9,%xmm15

	lea	96(%rsi),%rsi		# %rsi+=6*16
	movups	%xmm2,-96(%rsi)		# store 6 output blocks
	movups	%xmm3,-80(%rsi)
	movups	%xmm4,-64(%rsi)
	movups	%xmm5,-48(%rsi)
	movups	%xmm6,-32(%rsi)
	movups	%xmm7,-16(%rsi)
	sub	$16*6,%rdx
	jnc	.Lxts_dec_grandloop		# loop if %rdx-=6*16 didn't borrow

	mov	$16+96,%eax
	sub	%r10d,%eax
	mov	%rbp,%rcx			# restore %rcx
	shr	$4,%eax			# restore original value

.Lxts_dec_short:
	# at the point %xmm10 %xmm11 %xmm12 %xmm13 %xmm14 %xmm15 are populated with tweak values
	mov	%eax,%r10d			# backup %eax
	pxor	%xmm0,%xmm10
	pxor	%xmm0,%xmm11
	add	$16*6,%rdx			# restore real remaining %rdx
	jz	.Lxts_dec_done			# done if (%rdx==0)

	pxor	%xmm0,%xmm12
	cmp	$0x20,%rdx
	jb	.Lxts_dec_one			# %rdx is 1*16
	pxor	%xmm0,%xmm13
	je	.Lxts_dec_two			# %rdx is 2*16

	pxor	%xmm0,%xmm14
	cmp	$0x40,%rdx
	jb	.Lxts_dec_three			# %rdx is 3*16
	je	.Lxts_dec_four			# %rdx is 4*16

	movdqu	(%rdi),%xmm2			# %rdx is 5*16
	movdqu	16*1(%rdi),%xmm3
	movdqu	16*2(%rdi),%xmm4
	pxor	%xmm10,%xmm2
	movdqu	16*3(%rdi),%xmm5
	pxor	%xmm11,%xmm3
	movdqu	16*4(%rdi),%xmm6
	lea	16*5(%rdi),%rdi			# %rdi+=5*16
	pxor	%xmm12,%xmm4
	pxor	%xmm13,%xmm5
	pxor	%xmm14,%xmm6

	call	_aesni_decrypt6

	xorps	%xmm10,%xmm2
	xorps	%xmm11,%xmm3
	xorps	%xmm12,%xmm4
	movdqu	%xmm2,(%rsi)			# store 5 output blocks
	xorps	%xmm13,%xmm5
	movdqu	%xmm3,16*1(%rsi)
	xorps	%xmm14,%xmm6
	movdqu	%xmm4,16*2(%rsi)
	 pxor		%xmm14,%xmm14
	movdqu	%xmm5,16*3(%rsi)
	 pcmpgtd	%xmm15,%xmm14
	movdqu	%xmm6,16*4(%rsi)
	lea	16*5(%rsi),%rsi			# %rsi+=5*16
	 pshufd		$0x13,%xmm14,%xmm11	# %xmm9
	and	$15,%r9
	jz	.Lxts_dec_ret

	movdqa	%xmm15,%xmm10
	paddq	%xmm15,%xmm15		# psllq 1,
	pand	%xmm8,%xmm11		# isolate carry and residue
	pxor	%xmm15,%xmm11
	jmp	.Lxts_dec_done2

.align	16
.Lxts_dec_one:
	movups	(%rdi),%xmm2
	lea	16*1(%rdi),%rdi			# %rdi+=1*16
	xorps	%xmm10,%xmm2
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_dec1_12:
	.byte	102,15,56,222,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_dec1_12	# loop body is 16 bytes
	.byte	102,15,56,223,209
	xorps	%xmm10,%xmm2
	movdqa	%xmm11,%xmm10
	movups	%xmm2,(%rsi)			# store one output block
	movdqa	%xmm12,%xmm11
	lea	16*1(%rsi),%rsi			# %rsi+=1*16
	jmp	.Lxts_dec_done

.align	16
.Lxts_dec_two:
	movups	(%rdi),%xmm2
	movups	16(%rdi),%xmm3
	lea	32(%rdi),%rdi			# %rdi+=2*16
	xorps	%xmm10,%xmm2
	xorps	%xmm11,%xmm3

	call	_aesni_decrypt2

	xorps	%xmm10,%xmm2
	movdqa	%xmm12,%xmm10
	xorps	%xmm11,%xmm3
	movdqa	%xmm13,%xmm11
	movups	%xmm2,(%rsi)			# store 2 output blocks
	movups	%xmm3,16*1(%rsi)
	lea	16*2(%rsi),%rsi			# %rsi+=2*16
	jmp	.Lxts_dec_done

.align	16
.Lxts_dec_three:
	movups	(%rdi),%xmm2
	movups	16*1(%rdi),%xmm3
	movups	16*2(%rdi),%xmm4
	lea	16*3(%rdi),%rdi			# %rdi+=3*16
	xorps	%xmm10,%xmm2
	xorps	%xmm11,%xmm3
	xorps	%xmm12,%xmm4

	call	_aesni_decrypt3

	xorps	%xmm10,%xmm2
	movdqa	%xmm13,%xmm10
	xorps	%xmm11,%xmm3
	movdqa	%xmm14,%xmm11
	xorps	%xmm12,%xmm4
	movups	%xmm2,(%rsi)			# store 3 output blocks
	movups	%xmm3,16*1(%rsi)
	movups	%xmm4,16*2(%rsi)
	lea	16*3(%rsi),%rsi			# %rsi+=3*16
	jmp	.Lxts_dec_done

.align	16
.Lxts_dec_four:
	movups	(%rdi),%xmm2
	movups	16*1(%rdi),%xmm3
	movups	16*2(%rdi),%xmm4
	xorps	%xmm10,%xmm2
	movups	16*3(%rdi),%xmm5
	lea	16*4(%rdi),%rdi			# %rdi+=4*16
	xorps	%xmm11,%xmm3
	xorps	%xmm12,%xmm4
	xorps	%xmm13,%xmm5

	call	_aesni_decrypt4

	pxor	%xmm10,%xmm2
	movdqa	%xmm14,%xmm10
	pxor	%xmm11,%xmm3
	movdqa	%xmm15,%xmm11
	pxor	%xmm12,%xmm4
	movdqu	%xmm2,(%rsi)			# store 4 output blocks
	pxor	%xmm13,%xmm5
	movdqu	%xmm3,16*1(%rsi)
	movdqu	%xmm4,16*2(%rsi)
	movdqu	%xmm5,16*3(%rsi)
	lea	16*4(%rsi),%rsi			# %rsi+=4*16
	jmp	.Lxts_dec_done

.align	16
.Lxts_dec_done:
	and	$15,%r9			# see if %rdx%16 is 0
	jz	.Lxts_dec_ret
.Lxts_dec_done2:
	mov	%r9,%rdx
	mov	%rbp,%rcx			# restore %rcx
	mov	%r10d,%eax			# restore %eax

	movups	(%rdi),%xmm2
	xorps	%xmm11,%xmm2
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_dec1_13:
	.byte	102,15,56,222,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_dec1_13	# loop body is 16 bytes
	.byte	102,15,56,223,209
	xorps	%xmm11,%xmm2
	movups	%xmm2,(%rsi)

.Lxts_dec_steal:
	movzb	16(%rdi),%eax			# borrow %eax ...
	movzb	(%rsi),%ecx			# ... and %rcx
	lea	1(%rdi),%rdi
	mov	%al,(%rsi)
	mov	%cl,16(%rsi)
	lea	1(%rsi),%rsi
	sub	$1,%rdx
	jnz	.Lxts_dec_steal

	sub	%r9,%rsi			# rewind %rsi
	mov	%rbp,%rcx			# restore %rcx
	mov	%r10d,%eax			# restore %eax

	movups	(%rsi),%xmm2
	xorps	%xmm10,%xmm2
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_dec1_14:
	.byte	102,15,56,222,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_dec1_14	# loop body is 16 bytes
	.byte	102,15,56,223,209
	xorps	%xmm10,%xmm2
	movups	%xmm2,(%rsi)

.Lxts_dec_ret:
	xorps	%xmm0,%xmm0			# clear register bank
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	movaps	%xmm0,0x00(%rsp)		# clear stack
	pxor	%xmm8,%xmm8
	movaps	%xmm0,0x10(%rsp)
	pxor	%xmm9,%xmm9
	movaps	%xmm0,0x20(%rsp)
	pxor	%xmm10,%xmm10
	movaps	%xmm0,0x30(%rsp)
	pxor	%xmm11,%xmm11
	movaps	%xmm0,0x40(%rsp)
	pxor	%xmm12,%xmm12
	movaps	%xmm0,0x50(%rsp)
	pxor	%xmm13,%xmm13
	movaps	%xmm0,0x60(%rsp)
	pxor	%xmm14,%xmm14
	pxor	%xmm15,%xmm15
	mov	-8(%r11),%rbp
.cfi_restore	%rbp
	lea	(%r11),%rsp
.cfi_def_cfa_register	%rsp
.Lxts_dec_epilogue:
	ret
.cfi_endproc
.size	aesni_xts_decrypt,.-aesni_xts_decrypt
.globl	aesni_ocb_encrypt
.type	aesni_ocb_encrypt,@function,6
.align	32
aesni_ocb_encrypt:
.cfi_startproc
	endbranch
	lea	(%rsp),%rax
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
	mov	8(%rax),%rbx		# 7th argument
	mov	8+8(%rax),%rbp# 8th argument

	mov	240(%rcx),%r10d
	mov	%rcx,%r11
	shl	$4,%r10d
	movups	(%rcx),%xmm9		# round[0]
	movups	16(%rcx,%r10d),%xmm1	# round[last]

	movdqu	(%r9),%xmm15		# load last offset_i
	pxor	%xmm1,%xmm9		# round[0] ^ round[last]
	pxor	%xmm1,%xmm15		# offset_i ^ round[last]

	mov	$16+32,%eax
	lea	32(%r11,%r10d),%rcx
	movups	16(%r11),%xmm1		# round[1]
	sub	%r10,%rax			# twisted %eax
	mov	%rax,%r10			# backup twisted %eax

	movdqu	(%rbx),%xmm10		# L_0 for all odd-numbered blocks
	movdqu	(%rbp),%xmm8		# load checksum

	test	$1,%r8			# is first block number odd?
	jnz	.Locb_enc_odd

	bsf	%r8,%r12
	add	$1,%r8
	shl	$4,%r12
	movdqu	(%rbx,%r12),%xmm7		# borrow
	movdqu	(%rdi),%xmm2
	lea	16(%rdi),%rdi

	call	__ocb_encrypt1

	movdqa	%xmm7,%xmm15
	movups	%xmm2,(%rsi)
	lea	16(%rsi),%rsi
	sub	$1,%rdx
	jz	.Locb_enc_done

.Locb_enc_odd:
	lea	1(%r8),%r12		# even-numbered blocks
	lea	3(%r8),%r13
	lea	5(%r8),%r14
	lea	6(%r8),%r8
	bsf	%r12,%r12				# ntz(block)
	bsf	%r13,%r13
	bsf	%r14,%r14
	shl	$4,%r12				# ntz(block) -> table offset
	shl	$4,%r13
	shl	$4,%r14

	sub	$6,%rdx
	jc	.Locb_enc_short
	jmp	.Locb_enc_grandloop

.align	32
.Locb_enc_grandloop:
	movdqu	0(%rdi),%xmm2		# load input
	movdqu	16(%rdi),%xmm3
	movdqu	32(%rdi),%xmm4
	movdqu	48(%rdi),%xmm5
	movdqu	64(%rdi),%xmm6
	movdqu	80(%rdi),%xmm7
	lea	96(%rdi),%rdi

	call	__ocb_encrypt6

	movups	%xmm2,0(%rsi)		# store output
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)
	movups	%xmm5,48(%rsi)
	movups	%xmm6,64(%rsi)
	movups	%xmm7,80(%rsi)
	lea	96(%rsi),%rsi
	sub	$6,%rdx
	jnc	.Locb_enc_grandloop

.Locb_enc_short:
	add	$6,%rdx
	jz	.Locb_enc_done

	movdqu	0(%rdi),%xmm2
	cmp	$2,%rdx
	jb	.Locb_enc_one
	movdqu	16(%rdi),%xmm3
	je	.Locb_enc_two

	movdqu	32(%rdi),%xmm4
	cmp	$4,%rdx
	jb	.Locb_enc_three
	movdqu	48(%rdi),%xmm5
	je	.Locb_enc_four

	movdqu	64(%rdi),%xmm6
	pxor	%xmm7,%xmm7

	call	__ocb_encrypt6

	movdqa	%xmm14,%xmm15
	movups	%xmm2,0(%rsi)
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)
	movups	%xmm5,48(%rsi)
	movups	%xmm6,64(%rsi)

	jmp	.Locb_enc_done

.align	16
.Locb_enc_one:
	movdqa	%xmm10,%xmm7		# borrow

	call	__ocb_encrypt1

	movdqa	%xmm7,%xmm15
	movups	%xmm2,0(%rsi)
	jmp	.Locb_enc_done

.align	16
.Locb_enc_two:
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5

	call	__ocb_encrypt4

	movdqa	%xmm11,%xmm15
	movups	%xmm2,0(%rsi)
	movups	%xmm3,16(%rsi)

	jmp	.Locb_enc_done

.align	16
.Locb_enc_three:
	pxor	%xmm5,%xmm5

	call	__ocb_encrypt4

	movdqa	%xmm12,%xmm15
	movups	%xmm2,0(%rsi)
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)

	jmp	.Locb_enc_done

.align	16
.Locb_enc_four:
	call	__ocb_encrypt4

	movdqa	%xmm13,%xmm15
	movups	%xmm2,0(%rsi)
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)
	movups	%xmm5,48(%rsi)

.Locb_enc_done:
	pxor	%xmm0,%xmm15		# "remove" round[last]
	movdqu	%xmm8,(%rbp)		# store checksum
	movdqu	%xmm15,(%r9)		# store last offset_i

	xorps	%xmm0,%xmm0			# clear register bank
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	pxor	%xmm8,%xmm8
	pxor	%xmm9,%xmm9
	pxor	%xmm10,%xmm10
	pxor	%xmm11,%xmm11
	pxor	%xmm12,%xmm12
	pxor	%xmm13,%xmm13
	pxor	%xmm14,%xmm14
	pxor	%xmm15,%xmm15
	lea	0x28(%rsp),%rax
.cfi_def_cfa	%rax,8
	mov	-40(%rax),%r14
.cfi_restore	%r14
	mov	-32(%rax),%r13
.cfi_restore	%r13
	mov	-24(%rax),%r12
.cfi_restore	%r12
	mov	-16(%rax),%rbp
.cfi_restore	%rbp
	mov	-8(%rax),%rbx
.cfi_restore	%rbx
	lea	(%rax),%rsp
.cfi_def_cfa_register	%rsp
.Locb_enc_epilogue:
	ret
.cfi_endproc
.size	aesni_ocb_encrypt,.-aesni_ocb_encrypt

.type	__ocb_encrypt6,@abi-omnipotent
.align	32
__ocb_encrypt6:
.cfi_startproc
	 pxor		%xmm9,%xmm15	# offset_i ^ round[0]
	 movdqu		(%rbx,%r12),%xmm11
	 movdqa		%xmm10,%xmm12
	 movdqu		(%rbx,%r13),%xmm13
	 movdqa		%xmm10,%xmm14
	 pxor		%xmm15,%xmm10
	 movdqu		(%rbx,%r14),%xmm15
	 pxor		%xmm10,%xmm11
	pxor		%xmm2,%xmm8	# accumulate checksum
	pxor		%xmm10,%xmm2	# input ^ round[0] ^ offset_i
	 pxor		%xmm11,%xmm12
	pxor		%xmm3,%xmm8
	pxor		%xmm11,%xmm3
	 pxor		%xmm12,%xmm13
	pxor		%xmm4,%xmm8
	pxor		%xmm12,%xmm4
	 pxor		%xmm13,%xmm14
	pxor		%xmm5,%xmm8
	pxor		%xmm13,%xmm5
	 pxor		%xmm14,%xmm15
	pxor		%xmm6,%xmm8
	pxor		%xmm14,%xmm6
	pxor		%xmm7,%xmm8
	pxor		%xmm15,%xmm7
	movups		32(%r11),%xmm0

	lea		1(%r8),%r12	# even-numbered blocks
	lea		3(%r8),%r13
	lea		5(%r8),%r14
	add		$6,%r8
	 pxor		%xmm9,%xmm10	# offset_i ^ round[last]
	bsf		%r12,%r12			# ntz(block)
	bsf		%r13,%r13
	bsf		%r14,%r14

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	 pxor		%xmm9,%xmm11
	 pxor		%xmm9,%xmm12
	.byte	102,15,56,220,241
	 pxor		%xmm9,%xmm13
	 pxor		%xmm9,%xmm14
	.byte	102,15,56,220,249
	movups		48(%r11),%xmm1
	 pxor		%xmm9,%xmm15

	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	movups		64(%r11),%xmm0
	shl		$4,%r12			# ntz(block) -> table offset
	shl		$4,%r13
	jmp		.Locb_enc_loop6

.align	32
.Locb_enc_loop6:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax

	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	.byte	102,15,56,220,240
	.byte	102,15,56,220,248
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Locb_enc_loop6

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	.byte	102,15,56,220,241
	.byte	102,15,56,220,249
	movups		16(%r11),%xmm1
	shl		$4,%r14

	.byte	102,65,15,56,221,210
	movdqu		(%rbx),%xmm10	# L_0 for all odd-numbered blocks
	mov		%r10,%rax		# restore twisted rounds
	.byte	102,65,15,56,221,219
	.byte	102,65,15,56,221,228
	.byte	102,65,15,56,221,237
	.byte	102,65,15,56,221,246
	.byte	102,65,15,56,221,255
	ret
.cfi_endproc
.size	__ocb_encrypt6,.-__ocb_encrypt6

.type	__ocb_encrypt4,@abi-omnipotent
.align	32
__ocb_encrypt4:
.cfi_startproc
	 pxor		%xmm9,%xmm15	# offset_i ^ round[0]
	 movdqu		(%rbx,%r12),%xmm11
	 movdqa		%xmm10,%xmm12
	 movdqu		(%rbx,%r13),%xmm13
	 pxor		%xmm15,%xmm10
	 pxor		%xmm10,%xmm11
	pxor		%xmm2,%xmm8	# accumulate checksum
	pxor		%xmm10,%xmm2	# input ^ round[0] ^ offset_i
	 pxor		%xmm11,%xmm12
	pxor		%xmm3,%xmm8
	pxor		%xmm11,%xmm3
	 pxor		%xmm12,%xmm13
	pxor		%xmm4,%xmm8
	pxor		%xmm12,%xmm4
	pxor		%xmm5,%xmm8
	pxor		%xmm13,%xmm5
	movups		32(%r11),%xmm0

	 pxor		%xmm9,%xmm10	# offset_i ^ round[last]
	 pxor		%xmm9,%xmm11
	 pxor		%xmm9,%xmm12
	 pxor		%xmm9,%xmm13

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	movups		48(%r11),%xmm1

	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	movups		64(%r11),%xmm0
	jmp		.Locb_enc_loop4

.align	32
.Locb_enc_loop4:
	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax

	.byte	102,15,56,220,208
	.byte	102,15,56,220,216
	.byte	102,15,56,220,224
	.byte	102,15,56,220,232
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Locb_enc_loop4

	.byte	102,15,56,220,209
	.byte	102,15,56,220,217
	.byte	102,15,56,220,225
	.byte	102,15,56,220,233
	movups		16(%r11),%xmm1
	mov		%r10,%rax		# restore twisted rounds

	.byte	102,65,15,56,221,210
	.byte	102,65,15,56,221,219
	.byte	102,65,15,56,221,228
	.byte	102,65,15,56,221,237
	ret
.cfi_endproc
.size	__ocb_encrypt4,.-__ocb_encrypt4

.type	__ocb_encrypt1,@abi-omnipotent
.align	32
__ocb_encrypt1:
.cfi_startproc
	 pxor		%xmm15,%xmm7	# offset_i
	 pxor		%xmm9,%xmm7	# offset_i ^ round[0]
	pxor		%xmm2,%xmm8	# accumulate checksum
	pxor		%xmm7,%xmm2		# input ^ round[0] ^ offset_i
	movups		32(%r11),%xmm0

	.byte	102,15,56,220,209
	movups		48(%r11),%xmm1
	pxor		%xmm9,%xmm7	# offset_i ^ round[last]

	.byte	102,15,56,220,208
	movups		64(%r11),%xmm0
	jmp		.Locb_enc_loop1

.align	32
.Locb_enc_loop1:
	.byte	102,15,56,220,209
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax

	.byte	102,15,56,220,208
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Locb_enc_loop1

	.byte	102,15,56,220,209
	movups		16(%r11),%xmm1	# redundant in tail
	mov		%r10,%rax		# restore twisted rounds

	.byte	102,15,56,221,215
	ret
.cfi_endproc
.size	__ocb_encrypt1,.-__ocb_encrypt1

.globl	aesni_ocb_decrypt
.type	aesni_ocb_decrypt,@function,6
.align	32
aesni_ocb_decrypt:
.cfi_startproc
	endbranch
	lea	(%rsp),%rax
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
	mov	8(%rax),%rbx		# 7th argument
	mov	8+8(%rax),%rbp# 8th argument

	mov	240(%rcx),%r10d
	mov	%rcx,%r11
	shl	$4,%r10d
	movups	(%rcx),%xmm9		# round[0]
	movups	16(%rcx,%r10d),%xmm1	# round[last]

	movdqu	(%r9),%xmm15		# load last offset_i
	pxor	%xmm1,%xmm9		# round[0] ^ round[last]
	pxor	%xmm1,%xmm15		# offset_i ^ round[last]

	mov	$16+32,%eax
	lea	32(%r11,%r10d),%rcx
	movups	16(%r11),%xmm1		# round[1]
	sub	%r10,%rax			# twisted %eax
	mov	%rax,%r10			# backup twisted %eax

	movdqu	(%rbx),%xmm10		# L_0 for all odd-numbered blocks
	movdqu	(%rbp),%xmm8		# load checksum

	test	$1,%r8			# is first block number odd?
	jnz	.Locb_dec_odd

	bsf	%r8,%r12
	add	$1,%r8
	shl	$4,%r12
	movdqu	(%rbx,%r12),%xmm7		# borrow
	movdqu	(%rdi),%xmm2
	lea	16(%rdi),%rdi

	call	__ocb_decrypt1

	movdqa	%xmm7,%xmm15
	movups	%xmm2,(%rsi)
	xorps	%xmm2,%xmm8		# accumulate checksum
	lea	16(%rsi),%rsi
	sub	$1,%rdx
	jz	.Locb_dec_done

.Locb_dec_odd:
	lea	1(%r8),%r12		# even-numbered blocks
	lea	3(%r8),%r13
	lea	5(%r8),%r14
	lea	6(%r8),%r8
	bsf	%r12,%r12				# ntz(block)
	bsf	%r13,%r13
	bsf	%r14,%r14
	shl	$4,%r12				# ntz(block) -> table offset
	shl	$4,%r13
	shl	$4,%r14

	sub	$6,%rdx
	jc	.Locb_dec_short
	jmp	.Locb_dec_grandloop

.align	32
.Locb_dec_grandloop:
	movdqu	0(%rdi),%xmm2		# load input
	movdqu	16(%rdi),%xmm3
	movdqu	32(%rdi),%xmm4
	movdqu	48(%rdi),%xmm5
	movdqu	64(%rdi),%xmm6
	movdqu	80(%rdi),%xmm7
	lea	96(%rdi),%rdi

	call	__ocb_decrypt6

	movups	%xmm2,0(%rsi)		# store output
	pxor	%xmm2,%xmm8		# accumulate checksum
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm8
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm8
	movups	%xmm5,48(%rsi)
	pxor	%xmm5,%xmm8
	movups	%xmm6,64(%rsi)
	pxor	%xmm6,%xmm8
	movups	%xmm7,80(%rsi)
	pxor	%xmm7,%xmm8
	lea	96(%rsi),%rsi
	sub	$6,%rdx
	jnc	.Locb_dec_grandloop

.Locb_dec_short:
	add	$6,%rdx
	jz	.Locb_dec_done

	movdqu	0(%rdi),%xmm2
	cmp	$2,%rdx
	jb	.Locb_dec_one
	movdqu	16(%rdi),%xmm3
	je	.Locb_dec_two

	movdqu	32(%rdi),%xmm4
	cmp	$4,%rdx
	jb	.Locb_dec_three
	movdqu	48(%rdi),%xmm5
	je	.Locb_dec_four

	movdqu	64(%rdi),%xmm6
	pxor	%xmm7,%xmm7

	call	__ocb_decrypt6

	movdqa	%xmm14,%xmm15
	movups	%xmm2,0(%rsi)		# store output
	pxor	%xmm2,%xmm8		# accumulate checksum
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm8
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm8
	movups	%xmm5,48(%rsi)
	pxor	%xmm5,%xmm8
	movups	%xmm6,64(%rsi)
	pxor	%xmm6,%xmm8

	jmp	.Locb_dec_done

.align	16
.Locb_dec_one:
	movdqa	%xmm10,%xmm7		# borrow

	call	__ocb_decrypt1

	movdqa	%xmm7,%xmm15
	movups	%xmm2,0(%rsi)		# store output
	xorps	%xmm2,%xmm8		# accumulate checksum
	jmp	.Locb_dec_done

.align	16
.Locb_dec_two:
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5

	call	__ocb_decrypt4

	movdqa	%xmm11,%xmm15
	movups	%xmm2,0(%rsi)		# store output
	xorps	%xmm2,%xmm8		# accumulate checksum
	movups	%xmm3,16(%rsi)
	xorps	%xmm3,%xmm8

	jmp	.Locb_dec_done

.align	16
.Locb_dec_three:
	pxor	%xmm5,%xmm5

	call	__ocb_decrypt4

	movdqa	%xmm12,%xmm15
	movups	%xmm2,0(%rsi)		# store output
	xorps	%xmm2,%xmm8		# accumulate checksum
	movups	%xmm3,16(%rsi)
	xorps	%xmm3,%xmm8
	movups	%xmm4,32(%rsi)
	xorps	%xmm4,%xmm8

	jmp	.Locb_dec_done

.align	16
.Locb_dec_four:
	call	__ocb_decrypt4

	movdqa	%xmm13,%xmm15
	movups	%xmm2,0(%rsi)		# store output
	pxor	%xmm2,%xmm8		# accumulate checksum
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm8
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm8
	movups	%xmm5,48(%rsi)
	pxor	%xmm5,%xmm8

.Locb_dec_done:
	pxor	%xmm0,%xmm15		# "remove" round[last]
	movdqu	%xmm8,(%rbp)		# store checksum
	movdqu	%xmm15,(%r9)		# store last offset_i

	xorps	%xmm0,%xmm0			# clear register bank
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	pxor	%xmm8,%xmm8
	pxor	%xmm9,%xmm9
	pxor	%xmm10,%xmm10
	pxor	%xmm11,%xmm11
	pxor	%xmm12,%xmm12
	pxor	%xmm13,%xmm13
	pxor	%xmm14,%xmm14
	pxor	%xmm15,%xmm15
	lea	0x28(%rsp),%rax
.cfi_def_cfa	%rax,8
	mov	-40(%rax),%r14
.cfi_restore	%r14
	mov	-32(%rax),%r13
.cfi_restore	%r13
	mov	-24(%rax),%r12
.cfi_restore	%r12
	mov	-16(%rax),%rbp
.cfi_restore	%rbp
	mov	-8(%rax),%rbx
.cfi_restore	%rbx
	lea	(%rax),%rsp
.cfi_def_cfa_register	%rsp
.Locb_dec_epilogue:
	ret
.cfi_endproc
.size	aesni_ocb_decrypt,.-aesni_ocb_decrypt

.type	__ocb_decrypt6,@abi-omnipotent
.align	32
__ocb_decrypt6:
.cfi_startproc
	 pxor		%xmm9,%xmm15	# offset_i ^ round[0]
	 movdqu		(%rbx,%r12),%xmm11
	 movdqa		%xmm10,%xmm12
	 movdqu		(%rbx,%r13),%xmm13
	 movdqa		%xmm10,%xmm14
	 pxor		%xmm15,%xmm10
	 movdqu		(%rbx,%r14),%xmm15
	 pxor		%xmm10,%xmm11
	pxor		%xmm10,%xmm2	# input ^ round[0] ^ offset_i
	 pxor		%xmm11,%xmm12
	pxor		%xmm11,%xmm3
	 pxor		%xmm12,%xmm13
	pxor		%xmm12,%xmm4
	 pxor		%xmm13,%xmm14
	pxor		%xmm13,%xmm5
	 pxor		%xmm14,%xmm15
	pxor		%xmm14,%xmm6
	pxor		%xmm15,%xmm7
	movups		32(%r11),%xmm0

	lea		1(%r8),%r12	# even-numbered blocks
	lea		3(%r8),%r13
	lea		5(%r8),%r14
	add		$6,%r8
	 pxor		%xmm9,%xmm10	# offset_i ^ round[last]
	bsf		%r12,%r12			# ntz(block)
	bsf		%r13,%r13
	bsf		%r14,%r14

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	 pxor		%xmm9,%xmm11
	 pxor		%xmm9,%xmm12
	.byte	102,15,56,222,241
	 pxor		%xmm9,%xmm13
	 pxor		%xmm9,%xmm14
	.byte	102,15,56,222,249
	movups		48(%r11),%xmm1
	 pxor		%xmm9,%xmm15

	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	movups		64(%r11),%xmm0
	shl		$4,%r12			# ntz(block) -> table offset
	shl		$4,%r13
	jmp		.Locb_dec_loop6

.align	32
.Locb_dec_loop6:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax

	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Locb_dec_loop6

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	movups		16(%r11),%xmm1
	shl		$4,%r14

	.byte	102,65,15,56,223,210
	movdqu		(%rbx),%xmm10	# L_0 for all odd-numbered blocks
	mov		%r10,%rax		# restore twisted rounds
	.byte	102,65,15,56,223,219
	.byte	102,65,15,56,223,228
	.byte	102,65,15,56,223,237
	.byte	102,65,15,56,223,246
	.byte	102,65,15,56,223,255
	ret
.cfi_endproc
.size	__ocb_decrypt6,.-__ocb_decrypt6

.type	__ocb_decrypt4,@abi-omnipotent
.align	32
__ocb_decrypt4:
.cfi_startproc
	 pxor		%xmm9,%xmm15	# offset_i ^ round[0]
	 movdqu		(%rbx,%r12),%xmm11
	 movdqa		%xmm10,%xmm12
	 movdqu		(%rbx,%r13),%xmm13
	 pxor		%xmm15,%xmm10
	 pxor		%xmm10,%xmm11
	pxor		%xmm10,%xmm2	# input ^ round[0] ^ offset_i
	 pxor		%xmm11,%xmm12
	pxor		%xmm11,%xmm3
	 pxor		%xmm12,%xmm13
	pxor		%xmm12,%xmm4
	pxor		%xmm13,%xmm5
	movups		32(%r11),%xmm0

	 pxor		%xmm9,%xmm10	# offset_i ^ round[last]
	 pxor		%xmm9,%xmm11
	 pxor		%xmm9,%xmm12
	 pxor		%xmm9,%xmm13

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	movups		48(%r11),%xmm1

	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	movups		64(%r11),%xmm0
	jmp		.Locb_dec_loop4

.align	32
.Locb_dec_loop4:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax

	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Locb_dec_loop4

	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	movups		16(%r11),%xmm1
	mov		%r10,%rax		# restore twisted rounds

	.byte	102,65,15,56,223,210
	.byte	102,65,15,56,223,219
	.byte	102,65,15,56,223,228
	.byte	102,65,15,56,223,237
	ret
.cfi_endproc
.size	__ocb_decrypt4,.-__ocb_decrypt4

.type	__ocb_decrypt1,@abi-omnipotent
.align	32
__ocb_decrypt1:
.cfi_startproc
	 pxor		%xmm15,%xmm7	# offset_i
	 pxor		%xmm9,%xmm7	# offset_i ^ round[0]
	pxor		%xmm7,%xmm2		# input ^ round[0] ^ offset_i
	movups		32(%r11),%xmm0

	.byte	102,15,56,222,209
	movups		48(%r11),%xmm1
	pxor		%xmm9,%xmm7	# offset_i ^ round[last]

	.byte	102,15,56,222,208
	movups		64(%r11),%xmm0
	jmp		.Locb_dec_loop1

.align	32
.Locb_dec_loop1:
	.byte	102,15,56,222,209
	movups		(%rcx,%rax),%xmm1
	add		$32,%rax

	.byte	102,15,56,222,208
	movups		-16(%rcx,%rax),%xmm0
	jnz		.Locb_dec_loop1

	.byte	102,15,56,222,209
	movups		16(%r11),%xmm1	# redundant in tail
	mov		%r10,%rax		# restore twisted rounds

	.byte	102,15,56,223,215
	ret
.cfi_endproc
.size	__ocb_decrypt1,.-__ocb_decrypt1
.globl	aesni_cbc_encrypt
.type	aesni_cbc_encrypt,@function,6
.align	16
aesni_cbc_encrypt:
.cfi_startproc
	endbranch
	test	%rdx,%rdx		# check length
	jz	.Lcbc_ret

	mov	240(%rcx),%r10d	# key->rounds
	mov	%rcx,%r11		# backup %rcx
	test	%r9d,%r9d		# 6th argument
	jz	.Lcbc_decrypt
#--------------------------- CBC ENCRYPT ------------------------------#
	movups	(%r8),%xmm2		# load iv as initial state
	mov	%r10d,%eax
	cmp	$16,%rdx
	jb	.Lcbc_enc_tail
	sub	$16,%rdx
	jmp	.Lcbc_enc_loop
.align	16
.Lcbc_enc_loop:
	movups	(%rdi),%xmm3		# load input
	lea	16(%rdi),%rdi
	#xorps	%xmm3,%xmm2
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	xorps	%xmm0,%xmm3
	lea	32(%rcx),%rcx
	xorps	%xmm3,%xmm2
.Loop_enc1_15:
	.byte	102,15,56,220,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_enc1_15	# loop body is 16 bytes
	.byte	102,15,56,221,209
	mov	%r10d,%eax		# restore %eax
	mov	%r11,%rcx		# restore %rcx
	movups	%xmm2,0(%rsi)		# store output
	lea	16(%rsi),%rsi
	sub	$16,%rdx
	jnc	.Lcbc_enc_loop
	add	$16,%rdx
	jnz	.Lcbc_enc_tail
	 pxor	%xmm0,%xmm0	# clear register bank
	 pxor	%xmm1,%xmm1
	movups	%xmm2,(%r8)
	 pxor	%xmm2,%xmm2
	 pxor	%xmm3,%xmm3
	jmp	.Lcbc_ret

.Lcbc_enc_tail:
	mov	%rdx,%rcx	# zaps %rcx
	xchg	%rdi,%rsi	# %rdi is %rsi and %rsi is %rdi now
	.long	0x9066A4F3	# rep movsb
	mov	$16,%ecx	# zero tail
	sub	%rdx,%rcx
	xor	%eax,%eax
	.long	0x9066AAF3	# rep stosb
	lea	-16(%rdi),%rdi	# rewind %rsi by 1 block
	mov	%r10d,%eax	# restore %eax
	mov	%rdi,%rsi	# %rdi and %rsi are the same
	mov	%r11,%rcx	# restore %rcx
	xor	%rdx,%rdx	# len=16
	jmp	.Lcbc_enc_loop	# one more spin
#--------------------------- CBC DECRYPT ------------------------------#
.align	16
.Lcbc_decrypt:
	cmp	$16,%rdx
	jne	.Lcbc_decrypt_bulk

	# handle single block without allocating stack frame,
	# useful in ciphertext stealing mode
	movdqu	(%rdi),%xmm2		# load input
	movdqu	(%r8),%xmm3		# load iv
	movdqa	%xmm2,%xmm4		# future iv
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_dec1_16:
	.byte	102,15,56,222,209
	dec	%r10d
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_dec1_16	# loop body is 16 bytes
	.byte	102,15,56,223,209
	 pxor	%xmm0,%xmm0	# clear register bank
	 pxor	%xmm1,%xmm1
	movdqu	%xmm4,(%r8)		# store iv
	xorps	%xmm3,%xmm2		# ^=iv
	 pxor	%xmm3,%xmm3
	movups	%xmm2,(%rsi)		# store output
	 pxor	%xmm2,%xmm2
	jmp	.Lcbc_ret
.align	16
.Lcbc_decrypt_bulk:
	lea	(%rsp),%r11		# frame pointer
.cfi_def_cfa_register	%r11
	push	%rbp
.cfi_push	%rbp
	sub	$16,%rsp
	and	$-16,%rsp	# Linux kernel stack can be incorrectly seeded
	mov	%rcx,%rbp		# [re-]backup %rcx [after reassignment]
	movups	(%r8),%xmm10
	mov	%r10d,%eax
	cmp	$0x50,%rdx
	jbe	.Lcbc_dec_tail

	movups	(%rcx),%xmm0
	movdqu	0x00(%rdi),%xmm2	# load input
	movdqu	0x10(%rdi),%xmm3
	movdqa	%xmm2,%xmm11
	movdqu	0x20(%rdi),%xmm4
	movdqa	%xmm3,%xmm12
	movdqu	0x30(%rdi),%xmm5
	movdqa	%xmm4,%xmm13
	movdqu	0x40(%rdi),%xmm6
	movdqa	%xmm5,%xmm14
	movdqu	0x50(%rdi),%xmm7
	movdqa	%xmm6,%xmm15
	mov	OPENSSL_ia32cap_P+4(%rip),%r9d
	cmp	$0x70,%rdx
	jbe	.Lcbc_dec_six_or_seven

	and	$71303168,%r9d	# isolate XSAVE+MOVBE
	sub	$0x50,%rdx		# %rdx is biased by -5*16
	cmp	$4194304,%r9d		# check for MOVBE without XSAVE
	je	.Lcbc_dec_loop6_enter	# [which denotes Atom Silvermont]
	sub	$0x20,%rdx		# %rdx is biased by -7*16
	lea	0x70(%rcx),%rcx		# size optimization
	jmp	.Lcbc_dec_loop8_enter
.align	16
.Lcbc_dec_loop8:
	movups	%xmm9,(%rsi)
	lea	0x10(%rsi),%rsi
.Lcbc_dec_loop8_enter:
	movdqu		0x60(%rdi),%xmm8
	pxor		%xmm0,%xmm2
	movdqu		0x70(%rdi),%xmm9
	pxor		%xmm0,%xmm3
	movups		0x10-0x70(%rcx),%xmm1
	pxor		%xmm0,%xmm4
	mov		$-1,%rbp
	cmp		$0x70,%rdx	# is there at least 0x60 bytes ahead?
	pxor		%xmm0,%xmm5
	pxor		%xmm0,%xmm6
	pxor		%xmm0,%xmm7
	pxor		%xmm0,%xmm8

	.byte	102,15,56,222,209
	pxor		%xmm0,%xmm9
	movups		0x20-0x70(%rcx),%xmm0
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,68,15,56,222,193
	adc		$0,%rbp
	and		$128,%rbp
	.byte	102,68,15,56,222,201
	add		%rdi,%rbp
	movups		0x30-0x70(%rcx),%xmm1
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	.byte	102,68,15,56,222,192
	.byte	102,68,15,56,222,200
	movups		64-0x70(%rcx),%xmm0
	nop
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,68,15,56,222,193
	.byte	102,68,15,56,222,201
	movups		80-0x70(%rcx),%xmm1
	nop
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	.byte	102,68,15,56,222,192
	.byte	102,68,15,56,222,200
	movups		96-0x70(%rcx),%xmm0
	nop
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,68,15,56,222,193
	.byte	102,68,15,56,222,201
	movups		112-0x70(%rcx),%xmm1
	nop
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	.byte	102,68,15,56,222,192
	.byte	102,68,15,56,222,200
	movups		128-0x70(%rcx),%xmm0
	nop
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,68,15,56,222,193
	.byte	102,68,15,56,222,201
	movups		144-0x70(%rcx),%xmm1
	cmp		$11,%eax
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	.byte	102,68,15,56,222,192
	.byte	102,68,15,56,222,200
	movups		160-0x70(%rcx),%xmm0
	jb		.Lcbc_dec_done
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,68,15,56,222,193
	.byte	102,68,15,56,222,201
	movups		176-0x70(%rcx),%xmm1
	nop
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	.byte	102,68,15,56,222,192
	.byte	102,68,15,56,222,200
	movups		192-0x70(%rcx),%xmm0
	je		.Lcbc_dec_done
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	.byte	102,68,15,56,222,193
	.byte	102,68,15,56,222,201
	movups		208-0x70(%rcx),%xmm1
	nop
	.byte	102,15,56,222,208
	.byte	102,15,56,222,216
	.byte	102,15,56,222,224
	.byte	102,15,56,222,232
	.byte	102,15,56,222,240
	.byte	102,15,56,222,248
	.byte	102,68,15,56,222,192
	.byte	102,68,15,56,222,200
	movups		224-0x70(%rcx),%xmm0
	jmp		.Lcbc_dec_done
.align	16
.Lcbc_dec_done:
	.byte	102,15,56,222,209
	.byte	102,15,56,222,217
	pxor		%xmm0,%xmm10
	pxor		%xmm0,%xmm11
	.byte	102,15,56,222,225
	.byte	102,15,56,222,233
	pxor		%xmm0,%xmm12
	pxor		%xmm0,%xmm13
	.byte	102,15,56,222,241
	.byte	102,15,56,222,249
	pxor		%xmm0,%xmm14
	pxor		%xmm0,%xmm15
	.byte	102,68,15,56,222,193
	.byte	102,68,15,56,222,201
	movdqu		0x50(%rdi),%xmm1

	.byte	102,65,15,56,223,210
	movdqu		0x60(%rdi),%xmm10		# borrow %xmm10
	pxor		%xmm0,%xmm1
	.byte	102,65,15,56,223,219
	pxor		%xmm0,%xmm10
	movdqu		0x70(%rdi),%xmm0	# next IV
	.byte	102,65,15,56,223,228
	lea		0x80(%rdi),%rdi
	movdqu		0x00(%rbp),%xmm11
	.byte	102,65,15,56,223,237
	.byte	102,65,15,56,223,246
	movdqu		0x10(%rbp),%xmm12
	movdqu		0x20(%rbp),%xmm13
	.byte	102,65,15,56,223,255
	.byte	102,68,15,56,223,193
	movdqu		0x30(%rbp),%xmm14
	movdqu		0x40(%rbp),%xmm15
	.byte	102,69,15,56,223,202
	movdqa		%xmm0,%xmm10		# return %xmm10
	movdqu		0x50(%rbp),%xmm1
	movups		-0x70(%rcx),%xmm0

	movups		%xmm2,(%rsi)		# store output
	movdqa		%xmm11,%xmm2
	movups		%xmm3,0x10(%rsi)
	movdqa		%xmm12,%xmm3
	movups		%xmm4,0x20(%rsi)
	movdqa		%xmm13,%xmm4
	movups		%xmm5,0x30(%rsi)
	movdqa		%xmm14,%xmm5
	movups		%xmm6,0x40(%rsi)
	movdqa		%xmm15,%xmm6
	movups		%xmm7,0x50(%rsi)
	movdqa		%xmm1,%xmm7
	movups		%xmm8,0x60(%rsi)
	lea		0x70(%rsi),%rsi

	sub	$0x80,%rdx
	ja	.Lcbc_dec_loop8

	movaps	%xmm9,%xmm2
	lea	-0x70(%rcx),%rcx
	add	$0x70,%rdx
	jle	.Lcbc_dec_clear_tail_collected
	movups	%xmm9,(%rsi)
	lea	0x10(%rsi),%rsi
	cmp	$0x50,%rdx
	jbe	.Lcbc_dec_tail

	movaps	%xmm11,%xmm2
.Lcbc_dec_six_or_seven:
	cmp	$0x60,%rdx
	ja	.Lcbc_dec_seven

	movaps	%xmm7,%xmm8
	call	_aesni_decrypt6
	pxor	%xmm10,%xmm2		# ^= IV
	movaps	%xmm8,%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)
	pxor	%xmm12,%xmm4
	movdqu	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3		# clear register bank
	pxor	%xmm13,%xmm5
	movdqu	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	pxor	%xmm14,%xmm6
	movdqu	%xmm5,0x30(%rsi)
	 pxor	%xmm5,%xmm5
	pxor	%xmm15,%xmm7
	movdqu	%xmm6,0x40(%rsi)
	 pxor	%xmm6,%xmm6
	lea	0x50(%rsi),%rsi
	movdqa	%xmm7,%xmm2
	 pxor	%xmm7,%xmm7
	jmp	.Lcbc_dec_tail_collected

.align	16
.Lcbc_dec_seven:
	movups	0x60(%rdi),%xmm8
	xorps	%xmm9,%xmm9
	call	_aesni_decrypt8
	movups	0x50(%rdi),%xmm9
	pxor	%xmm10,%xmm2		# ^= IV
	movups	0x60(%rdi),%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)
	pxor	%xmm12,%xmm4
	movdqu	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3		# clear register bank
	pxor	%xmm13,%xmm5
	movdqu	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	pxor	%xmm14,%xmm6
	movdqu	%xmm5,0x30(%rsi)
	 pxor	%xmm5,%xmm5
	pxor	%xmm15,%xmm7
	movdqu	%xmm6,0x40(%rsi)
	 pxor	%xmm6,%xmm6
	pxor	%xmm9,%xmm8
	movdqu	%xmm7,0x50(%rsi)
	 pxor	%xmm7,%xmm7
	lea	0x60(%rsi),%rsi
	movdqa	%xmm8,%xmm2
	 pxor	%xmm8,%xmm8
	 pxor	%xmm9,%xmm9
	jmp	.Lcbc_dec_tail_collected

.align	16
.Lcbc_dec_loop6:
	movups	%xmm7,(%rsi)
	lea	0x10(%rsi),%rsi
	movdqu	0x00(%rdi),%xmm2	# load input
	movdqu	0x10(%rdi),%xmm3
	movdqa	%xmm2,%xmm11
	movdqu	0x20(%rdi),%xmm4
	movdqa	%xmm3,%xmm12
	movdqu	0x30(%rdi),%xmm5
	movdqa	%xmm4,%xmm13
	movdqu	0x40(%rdi),%xmm6
	movdqa	%xmm5,%xmm14
	movdqu	0x50(%rdi),%xmm7
	movdqa	%xmm6,%xmm15
.Lcbc_dec_loop6_enter:
	lea	0x60(%rdi),%rdi
	movdqa	%xmm7,%xmm8

	call	_aesni_decrypt6

	pxor	%xmm10,%xmm2		# ^= IV
	movdqa	%xmm8,%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)
	pxor	%xmm12,%xmm4
	movdqu	%xmm3,0x10(%rsi)
	pxor	%xmm13,%xmm5
	movdqu	%xmm4,0x20(%rsi)
	pxor	%xmm14,%xmm6
	mov	%rbp,%rcx
	movdqu	%xmm5,0x30(%rsi)
	pxor	%xmm15,%xmm7
	mov	%r10d,%eax
	movdqu	%xmm6,0x40(%rsi)
	lea	0x50(%rsi),%rsi
	sub	$0x60,%rdx
	ja	.Lcbc_dec_loop6

	movdqa	%xmm7,%xmm2
	add	$0x50,%rdx
	jle	.Lcbc_dec_clear_tail_collected
	movups	%xmm7,(%rsi)
	lea	0x10(%rsi),%rsi

.Lcbc_dec_tail:
	movups	(%rdi),%xmm2
	sub	$0x10,%rdx
	jbe	.Lcbc_dec_one		# %rdx is 1*16 or less

	movups	0x10(%rdi),%xmm3
	movaps	%xmm2,%xmm11
	sub	$0x10,%rdx
	jbe	.Lcbc_dec_two		# %rdx is 2*16 or less

	movups	0x20(%rdi),%xmm4
	movaps	%xmm3,%xmm12
	sub	$0x10,%rdx
	jbe	.Lcbc_dec_three		# %rdx is 3*16 or less

	movups	0x30(%rdi),%xmm5
	movaps	%xmm4,%xmm13
	sub	$0x10,%rdx
	jbe	.Lcbc_dec_four		# %rdx is 4*16 or less

	movups	0x40(%rdi),%xmm6	# %rdx is 5*16 or less
	movaps	%xmm5,%xmm14
	movaps	%xmm6,%xmm15
	xorps	%xmm7,%xmm7
	call	_aesni_decrypt6
	pxor	%xmm10,%xmm2
	movaps	%xmm15,%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)
	pxor	%xmm12,%xmm4
	movdqu	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3		# clear register bank
	pxor	%xmm13,%xmm5
	movdqu	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	pxor	%xmm14,%xmm6
	movdqu	%xmm5,0x30(%rsi)
	 pxor	%xmm5,%xmm5
	lea	0x40(%rsi),%rsi
	movdqa	%xmm6,%xmm2
	 pxor	%xmm6,%xmm6
	 pxor	%xmm7,%xmm7
	sub	$0x10,%rdx
	jmp	.Lcbc_dec_tail_collected

.align	16
.Lcbc_dec_one:
	movaps	%xmm2,%xmm11
	movups	(%rcx),%xmm0
	movups	16(%rcx),%xmm1
	lea	32(%rcx),%rcx
	xorps	%xmm0,%xmm2
.Loop_dec1_17:
	.byte	102,15,56,222,209
	dec	%eax
	movups	(%rcx),%xmm1
	lea	16(%rcx),%rcx
	jnz	.Loop_dec1_17	# loop body is 16 bytes
	.byte	102,15,56,223,209
	xorps	%xmm10,%xmm2
	movaps	%xmm11,%xmm10
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_two:
	movaps	%xmm3,%xmm12
	call	_aesni_decrypt2
	pxor	%xmm10,%xmm2
	movaps	%xmm12,%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)
	movdqa	%xmm3,%xmm2
	 pxor	%xmm3,%xmm3		# clear register bank
	lea	0x10(%rsi),%rsi
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_three:
	movaps	%xmm4,%xmm13
	call	_aesni_decrypt3
	pxor	%xmm10,%xmm2
	movaps	%xmm13,%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)
	pxor	%xmm12,%xmm4
	movdqu	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3		# clear register bank
	movdqa	%xmm4,%xmm2
	 pxor	%xmm4,%xmm4
	lea	0x20(%rsi),%rsi
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_four:
	movaps	%xmm5,%xmm14
	call	_aesni_decrypt4
	pxor	%xmm10,%xmm2
	movaps	%xmm14,%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)
	pxor	%xmm12,%xmm4
	movdqu	%xmm3,0x10(%rsi)
	 pxor	%xmm3,%xmm3		# clear register bank
	pxor	%xmm13,%xmm5
	movdqu	%xmm4,0x20(%rsi)
	 pxor	%xmm4,%xmm4
	movdqa	%xmm5,%xmm2
	 pxor	%xmm5,%xmm5
	lea	0x30(%rsi),%rsi
	jmp	.Lcbc_dec_tail_collected

.align	16
.Lcbc_dec_clear_tail_collected:
	pxor	%xmm3,%xmm3		# clear register bank
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6		# %xmm6..9
	pxor	%xmm7,%xmm7
	pxor	%xmm8,%xmm8
	pxor	%xmm9,%xmm9
.Lcbc_dec_tail_collected:
	movups	%xmm10,(%r8)
	and	$15,%rdx
	jnz	.Lcbc_dec_tail_partial
	movups	%xmm2,(%rsi)
	pxor	%xmm2,%xmm2
	jmp	.Lcbc_dec_ret
.align	16
.Lcbc_dec_tail_partial:
	movaps	%xmm2,(%rsp)
	pxor	%xmm2,%xmm2
	mov	$16,%rcx
	mov	%rsi,%rdi
	sub	%rdx,%rcx
	lea	(%rsp),%rsi
	.long	0x9066A4F3		# rep movsb
	movdqa	%xmm2,(%rsp)

.Lcbc_dec_ret:
	xorps	%xmm0,%xmm0	# %xmm0
	pxor	%xmm1,%xmm1
	mov	-8(%r11),%rbp
.cfi_restore	%rbp
	lea	(%r11),%rsp
.cfi_def_cfa_register	%rsp
.Lcbc_ret:
	ret
.cfi_endproc
.size	aesni_cbc_encrypt,.-aesni_cbc_encrypt
.globl	aesni_set_decrypt_key
.type	aesni_set_decrypt_key,@abi-omnipotent
.align	16
aesni_set_decrypt_key:
.cfi_startproc
	.byte	0x48,0x83,0xEC,0x08	# sub rsp,8
.cfi_adjust_cfa_offset	8
	call	__aesni_set_encrypt_key
	shl	$4,%esi		# rounds-1 after _aesni_set_encrypt_key
	test	%eax,%eax
	jnz	.Ldec_key_ret
	lea	16(%rdx,%esi),%rdi	# points at the end of key schedule

	movups	(%rdx),%xmm0		# just swap
	movups	(%rdi),%xmm1
	movups	%xmm0,(%rdi)
	movups	%xmm1,(%rdx)
	lea	16(%rdx),%rdx
	lea	-16(%rdi),%rdi

.Ldec_key_inverse:
	movups	(%rdx),%xmm0		# swap and inverse
	movups	(%rdi),%xmm1
	.byte	102,15,56,219,192
	.byte	102,15,56,219,201
	lea	16(%rdx),%rdx
	lea	-16(%rdi),%rdi
	movups	%xmm0,16(%rdi)
	movups	%xmm1,-16(%rdx)
	cmp	%rdx,%rdi
	ja	.Ldec_key_inverse

	movups	(%rdx),%xmm0		# inverse middle
	.byte	102,15,56,219,192
	pxor	%xmm1,%xmm1
	movups	%xmm0,(%rdi)
	pxor	%xmm0,%xmm0
.Ldec_key_ret:
	add	$8,%rsp
.cfi_adjust_cfa_offset	-8
	ret
.cfi_endproc
.LSEH_end_set_decrypt_key:
.size	aesni_set_decrypt_key,.-aesni_set_decrypt_key
.globl	aesni_set_encrypt_key
.type	aesni_set_encrypt_key,@abi-omnipotent
.align	16
aesni_set_encrypt_key:
__aesni_set_encrypt_key:
.cfi_startproc
	.byte	0x48,0x83,0xEC,0x08	# sub rsp,8
.cfi_adjust_cfa_offset	8
	mov	$-1,%rax
	test	%rdi,%rdi
	jz	.Lenc_key_ret
	test	%rdx,%rdx
	jz	.Lenc_key_ret

	mov	$268437504,%r10d	# AVX and XOP bits
	movups	(%rdi),%xmm0		# pull first 128 bits of *userKey
	xorps	%xmm4,%xmm4		# low dword of xmm4 is assumed 0
	and	OPENSSL_ia32cap_P+4(%rip),%r10d
	lea	16(%rdx),%rax		# %rax is used as modifiable copy of %rdx
	cmp	$256,%esi
	je	.L14rounds
	cmp	$192,%esi
	je	.L12rounds
	cmp	$128,%esi
	jne	.Lbad_keybits

.L10rounds:
	mov	$9,%esi			# 10 rounds for 128-bit key
	cmp	$268435456,%r10d			# AVX, bit no XOP
	je	.L10rounds_alt

	movups	%xmm0,(%rdx)			# round 0
	.byte	102,15,58,223,200,1
	call		.Lkey_expansion_128_cold
	.byte	102,15,58,223,200,2
	call		.Lkey_expansion_128
	.byte	102,15,58,223,200,4
	call		.Lkey_expansion_128
	.byte	102,15,58,223,200,8
	call		.Lkey_expansion_128
	.byte	102,15,58,223,200,16
	call		.Lkey_expansion_128
	.byte	102,15,58,223,200,32
	call		.Lkey_expansion_128
	.byte	102,15,58,223,200,64
	call		.Lkey_expansion_128
	.byte	102,15,58,223,200,128
	call		.Lkey_expansion_128
	.byte	102,15,58,223,200,27
	call		.Lkey_expansion_128
	.byte	102,15,58,223,200,54
	call		.Lkey_expansion_128
	movups	%xmm0,(%rax)
	mov	%esi,80(%rax)	# 240(%rdx)
	xor	%eax,%eax
	jmp	.Lenc_key_ret

.align	16
.L10rounds_alt:
	movdqa	.Lkey_rotate(%rip),%xmm5
	mov	$8,%r10d
	movdqa	.Lkey_rcon1(%rip),%xmm4
	movdqa	%xmm0,%xmm2
	movdqu	%xmm0,(%rdx)
	jmp	.Loop_key128

.align	16
.Loop_key128:
	pshufb		%xmm5,%xmm0
	.byte	102,15,56,221,196
	pslld		$1,%xmm4
	lea		16(%rax),%rax

	movdqa		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm3,%xmm2

	pxor		%xmm2,%xmm0
	movdqu		%xmm0,-16(%rax)
	movdqa		%xmm0,%xmm2

	dec	%r10d
	jnz	.Loop_key128

	movdqa		.Lkey_rcon1b(%rip),%xmm4

	pshufb		%xmm5,%xmm0
	.byte	102,15,56,221,196
	pslld		$1,%xmm4

	movdqa		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm3,%xmm2

	pxor		%xmm2,%xmm0
	movdqu		%xmm0,(%rax)

	movdqa		%xmm0,%xmm2
	pshufb		%xmm5,%xmm0
	.byte	102,15,56,221,196

	movdqa		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm2,%xmm3
	pslldq		$4,%xmm2
	pxor		%xmm3,%xmm2

	pxor		%xmm2,%xmm0
	movdqu		%xmm0,16(%rax)

	mov	%esi,96(%rax)	# 240(%rdx)
	xor	%eax,%eax
	jmp	.Lenc_key_ret

.align	16
.L12rounds:
	movq	16(%rdi),%xmm2			# remaining 1/3 of *userKey
	mov	$11,%esi			# 12 rounds for 192
	cmp	$268435456,%r10d			# AVX, but no XOP
	je	.L12rounds_alt

	movups	%xmm0,(%rdx)			# round 0
	.byte	102,15,58,223,202,1
	call		.Lkey_expansion_192a_cold
	.byte	102,15,58,223,202,2
	call		.Lkey_expansion_192b
	.byte	102,15,58,223,202,4
	call		.Lkey_expansion_192a
	.byte	102,15,58,223,202,8
	call		.Lkey_expansion_192b
	.byte	102,15,58,223,202,16
	call		.Lkey_expansion_192a
	.byte	102,15,58,223,202,32
	call		.Lkey_expansion_192b
	.byte	102,15,58,223,202,64
	call		.Lkey_expansion_192a
	.byte	102,15,58,223,202,128
	call		.Lkey_expansion_192b
	movups	%xmm0,(%rax)
	mov	%esi,48(%rax)	# 240(%rdx)
	xor	%rax, %rax
	jmp	.Lenc_key_ret

.align	16
.L12rounds_alt:
	movdqa	.Lkey_rotate192(%rip),%xmm5
	movdqa	.Lkey_rcon1(%rip),%xmm4
	mov	$8,%r10d
	movdqu	%xmm0,(%rdx)
	jmp	.Loop_key192

.align	16
.Loop_key192:
	movq		%xmm2,0(%rax)
	movdqa		%xmm2,%xmm1
	pshufb		%xmm5,%xmm2
	.byte	102,15,56,221,212
	pslld		$1, %xmm4
	lea		24(%rax),%rax

	movdqa		%xmm0,%xmm3
	pslldq		$4,%xmm0
	pxor		%xmm0,%xmm3
	pslldq		$4,%xmm0
	pxor		%xmm0,%xmm3
	pslldq		$4,%xmm0
	pxor		%xmm3,%xmm0

	pshufd		$0xff,%xmm0,%xmm3
	pxor		%xmm1,%xmm3
	pslldq		$4,%xmm1
	pxor		%xmm1,%xmm3

	pxor		%xmm2,%xmm0
	pxor		%xmm3,%xmm2
	movdqu		%xmm0,-16(%rax)

	dec	%r10d
	jnz	.Loop_key192

	mov	%esi,32(%rax)	# 240(%rdx)
	xor	%eax,%eax
	jmp	.Lenc_key_ret

.align	16
.L14rounds:
	movups	16(%rdi),%xmm2			# remaining half of *userKey
	mov	$13,%esi			# 14 rounds for 256
	lea	16(%rax),%rax
	cmp	$268435456,%r10d			# AVX, but no XOP
	je	.L14rounds_alt

	movups	%xmm0,(%rdx)			# round 0
	movups	%xmm2,16(%rdx)			# round 1
	.byte	102,15,58,223,202,1
	call		.Lkey_expansion_256a_cold
	.byte	102,15,58,223,200,1
	call		.Lkey_expansion_256b
	.byte	102,15,58,223,202,2
	call		.Lkey_expansion_256a
	.byte	102,15,58,223,200,2
	call		.Lkey_expansion_256b
	.byte	102,15,58,223,202,4
	call		.Lkey_expansion_256a
	.byte	102,15,58,223,200,4
	call		.Lkey_expansion_256b
	.byte	102,15,58,223,202,8
	call		.Lkey_expansion_256a
	.byte	102,15,58,223,200,8
	call		.Lkey_expansion_256b
	.byte	102,15,58,223,202,16
	call		.Lkey_expansion_256a
	.byte	102,15,58,223,200,16
	call		.Lkey_expansion_256b
	.byte	102,15,58,223,202,32
	call		.Lkey_expansion_256a
	.byte	102,15,58,223,200,32
	call		.Lkey_expansion_256b
	.byte	102,15,58,223,202,64
	call		.Lkey_expansion_256a
	movups	%xmm0,(%rax)
	mov	%esi,16(%rax)	# 240(%rdx)
	xor	%rax,%rax
	jmp	.Lenc_key_ret

.align	16
.L14rounds_alt:
	movdqa	.Lkey_rotate(%rip),%xmm5
	movdqa	.Lkey_rcon1(%rip),%xmm4
	mov	$7,%r10d
	movdqu	%xmm0,0(%rdx)
	movdqa	%xmm2,%xmm1
	movdqu	%xmm2,16(%rdx)
	jmp	.Loop_key256

.align	16
.Loop_key256:
	pshufb		%xmm5,%xmm2
	.byte	102,15,56,221,212

	movdqa		%xmm0,%xmm3
	pslldq		$4,%xmm0
	pxor		%xmm0,%xmm3
	pslldq		$4,%xmm0
	pxor		%xmm0,%xmm3
	pslldq		$4,%xmm0
	pxor		%xmm3,%xmm0
	pslld		$1,%xmm4

	pxor		%xmm2,%xmm0
	movdqu		%xmm0,(%rax)

	dec	%r10d
	jz	.Ldone_key256

	pshufd		$0xff,%xmm0,%xmm2
	pxor		%xmm3,%xmm3
	.byte	102,15,56,221,211

	movdqa		%xmm1,%xmm3
	pslldq		$4,%xmm1
	pxor		%xmm1,%xmm3
	pslldq		$4,%xmm1
	pxor		%xmm1,%xmm3
	pslldq		$4,%xmm1
	pxor		%xmm3,%xmm1

	pxor		%xmm1,%xmm2
	movdqu		%xmm2,16(%rax)
	lea		32(%rax),%rax
	movdqa		%xmm2,%xmm1

	jmp	.Loop_key256

.Ldone_key256:
	mov	%esi,16(%rax)	# 240(%rdx)
	xor	%eax,%eax
	jmp	.Lenc_key_ret

.align	16
.Lbad_keybits:
	mov	$-2,%rax
.Lenc_key_ret:
	pxor	%xmm0,%xmm0
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	add	$8,%rsp
.cfi_adjust_cfa_offset	-8
	ret
.LSEH_end_set_encrypt_key:

.align	16
.Lkey_expansion_128:
	movups	%xmm0,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_128_cold:
	shufps	$0b00010000,%xmm0,%xmm4
	xorps	%xmm4, %xmm0
	shufps	$0b10001100,%xmm0,%xmm4
	xorps	%xmm4, %xmm0
	shufps	$0b11111111,%xmm1,%xmm1	# critical path
	xorps	%xmm1,%xmm0
	ret

.align 16
.Lkey_expansion_192a:
	movups	%xmm0,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_192a_cold:
	movaps	%xmm2, %xmm5
.Lkey_expansion_192b_warm:
	shufps	$0b00010000,%xmm0,%xmm4
	movdqa	%xmm2,%xmm3
	xorps	%xmm4,%xmm0
	shufps	$0b10001100,%xmm0,%xmm4
	pslldq	$4,%xmm3
	xorps	%xmm4,%xmm0
	pshufd	$0b01010101,%xmm1,%xmm1	# critical path
	pxor	%xmm3,%xmm2
	pxor	%xmm1,%xmm0
	pshufd	$0b11111111,%xmm0,%xmm3
	pxor	%xmm3,%xmm2
	ret

.align 16
.Lkey_expansion_192b:
	movaps	%xmm0,%xmm3
	shufps	$0b01000100,%xmm0,%xmm5
	movups	%xmm5,(%rax)
	shufps	$0b01001110,%xmm2,%xmm3
	movups	%xmm3,16(%rax)
	lea	32(%rax),%rax
	jmp	.Lkey_expansion_192b_warm

.align	16
.Lkey_expansion_256a:
	movups	%xmm2,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_256a_cold:
	shufps	$0b00010000,%xmm0,%xmm4
	xorps	%xmm4,%xmm0
	shufps	$0b10001100,%xmm0,%xmm4
	xorps	%xmm4,%xmm0
	shufps	$0b11111111,%xmm1,%xmm1	# critical path
	xorps	%xmm1,%xmm0
	ret

.align 16
.Lkey_expansion_256b:
	movups	%xmm0,(%rax)
	lea	16(%rax),%rax

	shufps	$0b00010000,%xmm2,%xmm4
	xorps	%xmm4,%xmm2
	shufps	$0b10001100,%xmm2,%xmm4
	xorps	%xmm4,%xmm2
	shufps	$0b10101010,%xmm1,%xmm1	# critical path
	xorps	%xmm1,%xmm2
	ret
.cfi_endproc
.size	aesni_set_encrypt_key,.-aesni_set_encrypt_key
.size	__aesni_set_encrypt_key,.-__aesni_set_encrypt_key
.section .rodata align=64
.align	64
.Lbswap_mask:
	.byte	15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
.Lincrement32:
	.long	6,6,6,0
.Lincrement64:
	.long	1,0,0,0
.Lxts_magic:
	.long	0x87,0,1,0
.Lincrement1:
	.byte	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
.Lkey_rotate:
	.long	0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d
.Lkey_rotate192:
	.long	0x04070605,0x04070605,0x04070605,0x04070605
.Lkey_rcon1:
	.long	1,1,1,1
.Lkey_rcon1b:
	.long	0x1b,0x1b,0x1b,0x1b

.asciz  "AES for Intel AES-NI, CRYPTOGAMS by <https://github.com/dot-asm>"
.align	64
.previous
`;

export default translateAssembly(code);
