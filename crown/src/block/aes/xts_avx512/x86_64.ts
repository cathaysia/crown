/**
 * AES-XTS for x86_64 with VAES + AVX512 (aesni-xts-avx512.pl).
 *
 * TypeScript port of OpenSSL crypto/aes/asm/aesni-xts-avx512.pl.
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: GNU as >= 2.30 (the probe reads
 * `$avx512vaes`), `$win64=0`, elf output. `aesni_xts_avx512_eligible` is
 * the capability probe (AVX512F/DQ/BW/VL plus VAES, VPCLMULQDQ and VBMI2);
 * the four encrypt/decrypt entry points take `(inp, out, len, key1, key2,
 * iv)` with `len` counting data-unit bytes and the ciphertext-stealing tail
 * handled inside, exactly like `aesni_xts_encrypt`/`aesni_xts_decrypt`.
 * Body labels carry the perl's random disambiguating suffixes.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text
    .extern	OPENSSL_ia32cap_P
    .globl	aesni_xts_avx512_eligible
    .type	aesni_xts_avx512_eligible,@abi-omnipotent
    .align	32
    aesni_xts_avx512_eligible:
        mov	OPENSSL_ia32cap_P+8(%rip), %ecx
        xor	%eax,%eax
    	# 1<<31|1<<30|1<<17|1<<16 avx512vl + avx512bw + avx512dq + avx512f
        and	$0xc0030000, %ecx
        cmp	$0xc0030000, %ecx
        jne	.L_done
        mov	OPENSSL_ia32cap_P+12(%rip), %ecx
    	# 1<<10|1<<9|1<<6 vaes + vpclmulqdq + vbmi2
        and	$0x640, %ecx
        cmp	$0x640, %ecx
        cmove	%ecx,%eax
        .L_done:
        ret
    .size   aesni_xts_avx512_eligible, .-aesni_xts_avx512_eligible
      .globl	aesni_xts_128_encrypt_avx512
      .hidden	aesni_xts_128_encrypt_avx512
      .type	aesni_xts_128_encrypt_avx512,@function,6
      .align	32
      aesni_xts_128_encrypt_avx512:
      .cfi_startproc
      endbranch
push 	 %rbp
mov 	 %rsp,%rbp
sub 	 $136,%rsp
and 	 $0xffffffffffffffc0,%rsp
mov 	 %rbx,128(%rsp)
mov 	 $0x87, %r10
vmovdqu 	 (%r9),%xmm1
    vpxor	(%r8), %xmm1, %xmm1
    vaesenc	0x10(%r8), %xmm1, %xmm1
    vaesenc	0x20(%r8), %xmm1, %xmm1
    vaesenc	0x30(%r8), %xmm1, %xmm1
    vaesenc	0x40(%r8), %xmm1, %xmm1
    vaesenc	0x50(%r8), %xmm1, %xmm1
    vaesenc	0x60(%r8), %xmm1, %xmm1
    vaesenc	0x70(%r8), %xmm1, %xmm1
    vaesenc	0x80(%r8), %xmm1, %xmm1
    vaesenc	0x90(%r8), %xmm1, %xmm1
vaesenclast	0xa0(%r8), %xmm1, %xmm1
vmovdqa	%xmm1, (%rsp)

    cmp 	 $0x80,%rdx
    jl 	 .L_less_than_128_bytes_hEgxyDlCngwrfFe
    vpbroadcastq 	 %r10,%zmm25
    cmp 	 $0x100,%rdx
    jge 	 .L_start_by16_hEgxyDlCngwrfFe
    cmp 	 $0x80,%rdx
    jge 	 .L_start_by8_hEgxyDlCngwrfFe

    .L_do_n_blocks_hEgxyDlCngwrfFe:
    cmp 	 $0x0,%rdx
    je 	 .L_ret_hEgxyDlCngwrfFe
    cmp 	 $0x70,%rdx
    jge 	 .L_remaining_num_blocks_is_7_hEgxyDlCngwrfFe
    cmp 	 $0x60,%rdx
    jge 	 .L_remaining_num_blocks_is_6_hEgxyDlCngwrfFe
    cmp 	 $0x50,%rdx
    jge 	 .L_remaining_num_blocks_is_5_hEgxyDlCngwrfFe
    cmp 	 $0x40,%rdx
    jge 	 .L_remaining_num_blocks_is_4_hEgxyDlCngwrfFe
    cmp 	 $0x30,%rdx
    jge 	 .L_remaining_num_blocks_is_3_hEgxyDlCngwrfFe
    cmp 	 $0x20,%rdx
    jge 	 .L_remaining_num_blocks_is_2_hEgxyDlCngwrfFe
    cmp 	 $0x10,%rdx
    jge 	 .L_remaining_num_blocks_is_1_hEgxyDlCngwrfFe
    vmovdqa 	 %xmm0,%xmm8
    vmovdqa 	 %xmm9,%xmm0
    jmp 	 .L_steal_cipher_hEgxyDlCngwrfFe

    .L_remaining_num_blocks_is_7_hEgxyDlCngwrfFe:
    mov 	 $0x0000ffffffffffff,%r8
    kmovq 	 %r8,%k1
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2{%k1}
    add 	 $0x70,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi){%k1}
    add 	 $0x70,%rsi
    vextracti32x4 	 $0x2,%zmm2,%xmm8
    vextracti32x4 	 $0x3,%zmm10,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_hEgxyDlCngwrfFe
    jmp 	 .L_steal_cipher_hEgxyDlCngwrfFe

    .L_remaining_num_blocks_is_6_hEgxyDlCngwrfFe:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%ymm2
    add 	 $0x60,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %ymm2,0x40(%rsi)
    add 	 $0x60,%rsi
    vextracti32x4 	 $0x1,%zmm2,%xmm8
    vextracti32x4 	 $0x2,%zmm10,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_hEgxyDlCngwrfFe
    jmp 	 .L_steal_cipher_hEgxyDlCngwrfFe

    .L_remaining_num_blocks_is_5_hEgxyDlCngwrfFe:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu 	 0x40(%rdi),%xmm2
    add 	 $0x50,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu 	 %xmm2,0x40(%rsi)
    add 	 $0x50,%rsi
    vmovdqa 	 %xmm2,%xmm8
    vextracti32x4 	 $0x1,%zmm10,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_hEgxyDlCngwrfFe
    jmp 	 .L_steal_cipher_hEgxyDlCngwrfFe

    .L_remaining_num_blocks_is_4_hEgxyDlCngwrfFe:
    vmovdqu8 	 (%rdi),%zmm1
    add 	 $0x40,%rdi
vbroadcasti32x4 (%rcx), %zmm0
vpternlogq      $0x96, %zmm0, %zmm9, %zmm1
vbroadcasti32x4 16*1(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*2(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*3(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*4(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*5(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*6(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*7(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*8(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*9(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*10(%rcx), %zmm0
vaesenclast  %zmm0, %zmm1, %zmm1
vpxorq %zmm9, %zmm1, %zmm1
    vmovdqu8	%zmm1,(%rsi)
    add	$0x40,%rsi
    vextracti32x4	$0x3,%zmm1,%xmm8
    vmovdqa64	%xmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .L_remaining_num_blocks_is_3_hEgxyDlCngwrfFe:
    mov	$-1, %r8
    shr	$0x10, %r8
    kmovq	%r8, %k1
    vmovdqu8	(%rdi), %zmm1{%k1}
    add	$0x30, %rdi
vbroadcasti32x4 (%rcx), %zmm0
vpternlogq      $0x96, %zmm0, %zmm9, %zmm1
vbroadcasti32x4 16*1(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*2(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*3(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*4(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*5(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*6(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*7(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*8(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*9(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*10(%rcx), %zmm0
vaesenclast  %zmm0, %zmm1, %zmm1
vpxorq %zmm9, %zmm1, %zmm1
    vmovdqu8	%zmm1, (%rsi){%k1}
    add	$0x30, %rsi
    vextracti32x4	$0x2, %zmm1, %xmm8
    vextracti32x4	$0x3, %zmm9, %xmm0
    and	$0xf, %rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .L_remaining_num_blocks_is_2_hEgxyDlCngwrfFe:
    vmovdqu8	(%rdi), %ymm1
    add	$0x20, %rdi
vbroadcasti32x4 (%rcx), %ymm0
vpternlogq      $0x96, %ymm0, %ymm9, %ymm1
vbroadcasti32x4 16*1(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*2(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*3(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*4(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*5(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*6(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*7(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*8(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*9(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*10(%rcx), %ymm0
vaesenclast  %ymm0, %ymm1, %ymm1
vpxorq %ymm9, %ymm1, %ymm1
    vmovdqu 	 %ymm1,(%rsi)
    add 	 $0x20,%rsi
    vextracti32x4	$0x1, %zmm1, %xmm8
    vextracti32x4	$0x2,%zmm9,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_hEgxyDlCngwrfFe
    jmp 	 .L_steal_cipher_hEgxyDlCngwrfFe
    .L_remaining_num_blocks_is_1_hEgxyDlCngwrfFe:
    vmovdqu 	 (%rdi),%xmm1
    add 	 $0x10,%rdi
vpxor	%xmm9, %xmm1, %xmm1
vpxor	(%rcx), %xmm1, %xmm1
vaesenc	16*1(%rcx), %xmm1, %xmm1
vaesenc	16*2(%rcx), %xmm1, %xmm1
vaesenc	16*3(%rcx), %xmm1, %xmm1
vaesenc	16*4(%rcx), %xmm1, %xmm1
vaesenc	16*5(%rcx), %xmm1, %xmm1
vaesenc	16*6(%rcx), %xmm1, %xmm1
vaesenc	16*7(%rcx), %xmm1, %xmm1
vaesenc	16*8(%rcx), %xmm1, %xmm1
vaesenc	16*9(%rcx), %xmm1, %xmm1
    vaesenclast 16*10(%rcx), %xmm1, %xmm1
    vpxor	%xmm9, %xmm1, %xmm1
    vmovdqu 	 %xmm1,(%rsi)
    add 	 $0x10,%rsi
    vmovdqa 	 %xmm1,%xmm8
    vextracti32x4 	 $0x1,%zmm9,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_hEgxyDlCngwrfFe
    jmp 	 .L_steal_cipher_hEgxyDlCngwrfFe


    .L_start_by16_hEgxyDlCngwrfFe:
    vbroadcasti32x4 	 (%rsp),%zmm0
    vbroadcasti32x4 shufb_15_7(%rip),%zmm8
    mov 	 $0xaa,%r8
    kmovq 	 %r8,%k2
    vpshufb 	 %zmm8,%zmm0,%zmm1
    vpsllvq const_dq3210(%rip),%zmm0,%zmm4
    vpsrlvq const_dq5678(%rip),%zmm1,%zmm2
    vpclmulqdq 	 $0x0,%zmm25,%zmm2,%zmm3
    vpxorq 	 %zmm2,%zmm4,%zmm4{%k2}
    vpxord 	 %zmm4,%zmm3,%zmm9
    vpsllvq const_dq7654(%rip),%zmm0,%zmm5
    vpsrlvq const_dq1234(%rip),%zmm1,%zmm6
    vpclmulqdq 	 $0x0,%zmm25,%zmm6,%zmm7
    vpxorq 	 %zmm6,%zmm5,%zmm5{%k2}
    vpxord 	 %zmm5,%zmm7,%zmm10
    vpsrldq 	 $0xf,%zmm9,%zmm13
    vpclmulqdq 	 $0x0,%zmm25,%zmm13,%zmm14
    vpslldq 	 $0x1,%zmm9,%zmm11
    vpxord 	 %zmm14,%zmm11,%zmm11
    vpsrldq 	 $0xf,%zmm10,%zmm15
    vpclmulqdq 	 $0x0,%zmm25,%zmm15,%zmm16
    vpslldq 	 $0x1,%zmm10,%zmm12
    vpxord 	 %zmm16,%zmm12,%zmm12

    .L_main_loop_run_16_hEgxyDlCngwrfFe:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2
    vmovdqu8 	 0x80(%rdi),%zmm3
    vmovdqu8 	 0xc0(%rdi),%zmm4
    add 	 $0x100,%rdi
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
vpxorq    %zmm11, %zmm3, %zmm3
vpxorq    %zmm12, %zmm4, %zmm4
vbroadcasti32x4 (%rcx), %zmm0
vpxorq %zmm0, %zmm1, %zmm1
vpxorq %zmm0, %zmm2, %zmm2
vpxorq %zmm0, %zmm3, %zmm3
vpxorq %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm11, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm11, %zmm15
      vpxord		%zmm14, %zmm15, %zmm15
vbroadcasti32x4 0x10(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x20(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x30(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm12, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm12, %zmm16
      vpxord		%zmm14, %zmm16, %zmm16
vbroadcasti32x4 0x40(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x50(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x60(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm15, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm15, %zmm17
      vpxord		%zmm14, %zmm17, %zmm17
vbroadcasti32x4 0x70(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x80(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x90(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm16, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm16, %zmm18
      vpxord		%zmm14, %zmm18, %zmm18
vbroadcasti32x4 0xa0(%rcx), %zmm0
vaesenclast %zmm0, %zmm1, %zmm1
vaesenclast %zmm0, %zmm2, %zmm2
vaesenclast %zmm0, %zmm3, %zmm3
vaesenclast %zmm0, %zmm4, %zmm4
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
vpxorq    %zmm11, %zmm3, %zmm3
vpxorq    %zmm12, %zmm4, %zmm4
    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqa32  %zmm17, %zmm11
    vmovdqa32  %zmm18, %zmm12
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi)
    vmovdqu8 	 %zmm3,0x80(%rsi)
    vmovdqu8 	 %zmm4,0xc0(%rsi)
    add 	 $0x100,%rsi
    sub 	 $0x100,%rdx
    cmp 	 $0x100,%rdx
    jae 	 .L_main_loop_run_16_hEgxyDlCngwrfFe
    cmp 	 $0x80,%rdx
    jae 	 .L_main_loop_run_8_hEgxyDlCngwrfFe
    vextracti32x4 	 $0x3,%zmm4,%xmm0
    jmp 	 .L_do_n_blocks_hEgxyDlCngwrfFe

    .L_start_by8_hEgxyDlCngwrfFe:
    vbroadcasti32x4 	 (%rsp),%zmm0
    vbroadcasti32x4 shufb_15_7(%rip),%zmm8
    mov 	 $0xaa,%r8
    kmovq 	 %r8,%k2
    vpshufb 	 %zmm8,%zmm0,%zmm1
    vpsllvq const_dq3210(%rip),%zmm0,%zmm4
    vpsrlvq const_dq5678(%rip),%zmm1,%zmm2
    vpclmulqdq 	 $0x0,%zmm25,%zmm2,%zmm3
    vpxorq 	 %zmm2,%zmm4,%zmm4{%k2}
    vpxord 	 %zmm4,%zmm3,%zmm9
    vpsllvq const_dq7654(%rip),%zmm0,%zmm5
    vpsrlvq const_dq1234(%rip),%zmm1,%zmm6
    vpclmulqdq 	 $0x0,%zmm25,%zmm6,%zmm7
    vpxorq 	 %zmm6,%zmm5,%zmm5{%k2}
    vpxord 	 %zmm5,%zmm7,%zmm10

    .L_main_loop_run_8_hEgxyDlCngwrfFe:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2
    add 	 $0x80,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
      vpsrldq		$0xf, %zmm9, %zmm13
      vpclmulqdq	$0x0, %zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm9, %zmm15
      vpxord		%zmm14, %zmm15, %zmm15
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      vpsrldq		$0xf, %zmm10, %zmm13
      vpclmulqdq	$0x0, %zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm10, %zmm16
      vpxord		%zmm14, %zmm16, %zmm16
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
      vmovdqa32  %zmm15, %zmm9
      vmovdqa32  %zmm16, %zmm10
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi)
    add 	 $0x80,%rsi
    sub 	 $0x80,%rdx
    cmp 	 $0x80,%rdx
    jae 	 .L_main_loop_run_8_hEgxyDlCngwrfFe
    vextracti32x4 	 $0x3,%zmm2,%xmm0
    jmp 	 .L_do_n_blocks_hEgxyDlCngwrfFe

    .L_steal_cipher_hEgxyDlCngwrfFe:
    vmovdqa	%xmm8,%xmm2
    lea	vpshufb_shf_table(%rip),%rax
    vmovdqu	(%rax,%rdx,1),%xmm10
    vpshufb	%xmm10,%xmm8,%xmm8
    vmovdqu	-0x10(%rdi,%rdx,1),%xmm3
    vmovdqu	%xmm8,-0x10(%rsi,%rdx,1)
    lea	vpshufb_shf_table(%rip),%rax
    add	$16, %rax
    sub	%rdx,%rax
    vmovdqu	(%rax),%xmm10
    vpxor	mask1(%rip),%xmm10,%xmm10
    vpshufb	%xmm10,%xmm3,%xmm3
    vpblendvb	%xmm10,%xmm2,%xmm3,%xmm3
    vpxor	%xmm0,%xmm3,%xmm8
    vpxor	(%rcx),%xmm8,%xmm8
    vaesenc	0x10(%rcx),%xmm8,%xmm8
    vaesenc	0x20(%rcx),%xmm8,%xmm8
    vaesenc	0x30(%rcx),%xmm8,%xmm8
    vaesenc	0x40(%rcx),%xmm8,%xmm8
    vaesenc	0x50(%rcx),%xmm8,%xmm8
    vaesenc	0x60(%rcx),%xmm8,%xmm8
    vaesenc	0x70(%rcx),%xmm8,%xmm8
    vaesenc	0x80(%rcx),%xmm8,%xmm8
    vaesenc	0x90(%rcx),%xmm8,%xmm8
vaesenclast	0xa0(%rcx),%xmm8,%xmm8
vpxor	%xmm0,%xmm8,%xmm8
vmovdqu	%xmm8,-0x10(%rsi)
    .L_ret_hEgxyDlCngwrfFe:
    mov 	 128(%rsp),%rbx
    xor    %r8,%r8
    mov    %r8,128(%rsp)
    # Zero-out the whole of \`%zmm0\`.
    vpxorq %zmm0,%zmm0,%zmm0
    mov %rbp,%rsp
    pop %rbp
    vzeroupper
    ret

    .L_less_than_128_bytes_hEgxyDlCngwrfFe:
    vpbroadcastq	%r10, %zmm25
    cmp 	 $0x10,%rdx
    jb 	 .L_ret_hEgxyDlCngwrfFe
    vbroadcasti32x4	(%rsp), %zmm0
    vbroadcasti32x4	shufb_15_7(%rip), %zmm8
    movl    $0xaa, %r8d
    kmovq	%r8, %k2
    mov	%rdx,%r8
    and	$0x70,%r8
    cmp	$0x60,%r8
    je	.L_num_blocks_is_6_hEgxyDlCngwrfFe
    cmp	$0x50,%r8
    je	.L_num_blocks_is_5_hEgxyDlCngwrfFe
    cmp	$0x40,%r8
    je	.L_num_blocks_is_4_hEgxyDlCngwrfFe
    cmp	$0x30,%r8
    je	.L_num_blocks_is_3_hEgxyDlCngwrfFe
    cmp	$0x20,%r8
    je	.L_num_blocks_is_2_hEgxyDlCngwrfFe
    cmp	$0x10,%r8
    je	.L_num_blocks_is_1_hEgxyDlCngwrfFe

    .L_num_blocks_is_7_hEgxyDlCngwrfFe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    vpsllvq	const_dq7654(%rip), %zmm0, %zmm5
    vpsrlvq	const_dq1234(%rip), %zmm1, %zmm6
    vpclmulqdq	$0x00, %zmm25, %zmm6, %zmm7
    vpxorq	%zmm6, %zmm5, %zmm5{%k2}
    vpxord	%zmm5, %zmm7, %zmm10
    mov	$0x0000ffffffffffff, %r8
    kmovq	%r8, %k1
    vmovdqu8	16*0(%rdi), %zmm1
    vmovdqu8	16*4(%rdi), %zmm2{%k1}

    add	$0x70,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8	%zmm1, 16*0(%rsi)
    vmovdqu8	%zmm2, 16*4(%rsi){%k1}
    add	$0x70,%rsi
    vextracti32x4	$0x2, %zmm2, %xmm8
    vextracti32x4	$0x3, %zmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .L_num_blocks_is_6_hEgxyDlCngwrfFe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    vpsllvq	const_dq7654(%rip), %zmm0, %zmm5
    vpsrlvq	const_dq1234(%rip), %zmm1, %zmm6
    vpclmulqdq	$0x00, %zmm25, %zmm6, %zmm7
    vpxorq	%zmm6, %zmm5, %zmm5{%k2}
    vpxord	%zmm5, %zmm7, %zmm10
    vmovdqu8	16*0(%rdi), %zmm1
    vmovdqu8	16*4(%rdi), %ymm2
    add	$96, %rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8	%zmm1, 16*0(%rsi)
    vmovdqu8	%ymm2, 16*4(%rsi)
    add	$96, %rsi

    vextracti32x4	$0x1, %ymm2, %xmm8
    vextracti32x4	$0x2, %zmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .L_num_blocks_is_5_hEgxyDlCngwrfFe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    vpsllvq	const_dq7654(%rip), %zmm0, %zmm5
    vpsrlvq	const_dq1234(%rip), %zmm1, %zmm6
    vpclmulqdq	$0x00, %zmm25, %zmm6, %zmm7
    vpxorq	%zmm6, %zmm5, %zmm5{%k2}
    vpxord	%zmm5, %zmm7, %zmm10
    vmovdqu8	16*0(%rdi), %zmm1
    vmovdqu8	16*4(%rdi), %xmm2
    add	$80, %rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8	%zmm1, 16*0(%rsi)
    vmovdqu8	%xmm2, 16*4(%rsi)
    add	$80, %rsi

    vmovdqa	%xmm2, %xmm8
    vextracti32x4	$0x1, %zmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .L_num_blocks_is_4_hEgxyDlCngwrfFe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    vpsllvq	const_dq7654(%rip), %zmm0, %zmm5
    vpsrlvq	const_dq1234(%rip), %zmm1, %zmm6
    vpclmulqdq	$0x00, %zmm25, %zmm6, %zmm7
    vpxorq	%zmm6, %zmm5, %zmm5{%k2}
    vpxord	%zmm5, %zmm7, %zmm10
    vmovdqu8	16*0(%rdi), %zmm1
    add	$64, %rdi
vbroadcasti32x4 (%rcx), %zmm0
vpternlogq      $0x96, %zmm0, %zmm9, %zmm1
vbroadcasti32x4 16*1(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*2(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*3(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*4(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*5(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*6(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*7(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*8(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*9(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*10(%rcx), %zmm0
vaesenclast  %zmm0, %zmm1, %zmm1
vpxorq %zmm9, %zmm1, %zmm1
    vmovdqu8	%zmm1, 16*0(%rsi)
    add	$64, %rsi
    vextracti32x4	$0x3, %zmm1, %xmm8
    vmovdqa	%xmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .L_num_blocks_is_3_hEgxyDlCngwrfFe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    mov	$0x0000ffffffffffff, %r8
    kmovq	%r8, %k1
    vmovdqu8	16*0(%rdi), %zmm1{%k1}
    add	$48, %rdi
vbroadcasti32x4 (%rcx), %zmm0
vpternlogq      $0x96, %zmm0, %zmm9, %zmm1
vbroadcasti32x4 16*1(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*2(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*3(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*4(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*5(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*6(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*7(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*8(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*9(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*10(%rcx), %zmm0
vaesenclast  %zmm0, %zmm1, %zmm1
vpxorq %zmm9, %zmm1, %zmm1
    vmovdqu8	%zmm1, 16*0(%rsi){%k1}
    add	$48, %rsi
    vextracti32x4	$2, %zmm1, %xmm8
    vextracti32x4	$3, %zmm9, %xmm0
    and	$0xf,%rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .L_num_blocks_is_2_hEgxyDlCngwrfFe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9

    vmovdqu8	16*0(%rdi), %ymm1
    add	$32, %rdi
vbroadcasti32x4 (%rcx), %ymm0
vpternlogq      $0x96, %ymm0, %ymm9, %ymm1
vbroadcasti32x4 16*1(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*2(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*3(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*4(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*5(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*6(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*7(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*8(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*9(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*10(%rcx), %ymm0
vaesenclast  %ymm0, %ymm1, %ymm1
vpxorq %ymm9, %ymm1, %ymm1
    vmovdqu8	%ymm1, 16*0(%rsi)
    add	$32, %rsi

    vextracti32x4	$1, %ymm1, %xmm8
    vextracti32x4	$2, %zmm9, %xmm0
    and	$0xf,%rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .L_num_blocks_is_1_hEgxyDlCngwrfFe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9

    vmovdqu8	16*0(%rdi), %xmm1
    add	$16, %rdi
vbroadcasti32x4 (%rcx), %ymm0
vpternlogq      $0x96, %ymm0, %ymm9, %ymm1
vbroadcasti32x4 16*1(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*2(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*3(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*4(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*5(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*6(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*7(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*8(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*9(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*10(%rcx), %ymm0
vaesenclast  %ymm0, %ymm1, %ymm1
vpxorq %ymm9, %ymm1, %ymm1
    vmovdqu8	%xmm1, 16*0(%rsi)
    add	$16, %rsi

    vmovdqa	%xmm1, %xmm8
    vextracti32x4	$1, %zmm9, %xmm0
    and	$0xf,%rdx
    je	.L_ret_hEgxyDlCngwrfFe
    jmp	.L_steal_cipher_hEgxyDlCngwrfFe
    .cfi_endproc
      .globl	aesni_xts_128_decrypt_avx512
      .hidden	aesni_xts_128_decrypt_avx512
      .type	aesni_xts_128_decrypt_avx512,@function,6
      .align	32
      aesni_xts_128_decrypt_avx512:
      .cfi_startproc
      endbranch
push 	 %rbp
mov 	 %rsp,%rbp
sub 	 $136,%rsp
and 	 $0xffffffffffffffc0,%rsp
mov 	 %rbx,128(%rsp)
mov 	 $0x87, %r10
vmovdqu 	 (%r9),%xmm1
    vpxor	(%r8), %xmm1, %xmm1
    vaesenc	0x10(%r8), %xmm1, %xmm1
    vaesenc	0x20(%r8), %xmm1, %xmm1
    vaesenc	0x30(%r8), %xmm1, %xmm1
    vaesenc	0x40(%r8), %xmm1, %xmm1
    vaesenc	0x50(%r8), %xmm1, %xmm1
    vaesenc	0x60(%r8), %xmm1, %xmm1
    vaesenc	0x70(%r8), %xmm1, %xmm1
    vaesenc	0x80(%r8), %xmm1, %xmm1
    vaesenc	0x90(%r8), %xmm1, %xmm1
vaesenclast	0xa0(%r8), %xmm1, %xmm1
vmovdqa	%xmm1, (%rsp)

    cmp 	 $0x80,%rdx
    jb 	 .L_less_than_128_bytes_amivrujEyduiFoi
    vpbroadcastq 	 %r10,%zmm25
    cmp 	 $0x100,%rdx
    jge 	 .L_start_by16_amivrujEyduiFoi
    jmp 	 .L_start_by8_amivrujEyduiFoi

    .L_do_n_blocks_amivrujEyduiFoi:
    cmp 	 $0x0,%rdx
    je 	 .L_ret_amivrujEyduiFoi
    cmp 	 $0x70,%rdx
    jge 	 .L_remaining_num_blocks_is_7_amivrujEyduiFoi
    cmp 	 $0x60,%rdx
    jge 	 .L_remaining_num_blocks_is_6_amivrujEyduiFoi
    cmp 	 $0x50,%rdx
    jge 	 .L_remaining_num_blocks_is_5_amivrujEyduiFoi
    cmp 	 $0x40,%rdx
    jge 	 .L_remaining_num_blocks_is_4_amivrujEyduiFoi
    cmp 	 $0x30,%rdx
    jge 	 .L_remaining_num_blocks_is_3_amivrujEyduiFoi
    cmp 	 $0x20,%rdx
    jge 	 .L_remaining_num_blocks_is_2_amivrujEyduiFoi
    cmp 	 $0x10,%rdx
    jge 	 .L_remaining_num_blocks_is_1_amivrujEyduiFoi

    # _remaining_num_blocks_is_0:
    vmovdqu		%xmm5, %xmm1
    # xmm5 contains last full block to decrypt with next teawk
vpxor %xmm9, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm9, %xmm1, %xmm1
    vmovdqu %xmm1, -0x10(%rsi)
    vmovdqa %xmm1, %xmm8

    # Calc previous tweak
    mov		$0x1,%r8
    kmovq		%r8, %k1
    vpsllq	$0x3f,%xmm9,%xmm13
    vpsraq	$0x3f,%xmm13,%xmm14
    vpandq	%xmm25,%xmm14,%xmm5
    vpxorq        %xmm5,%xmm9,%xmm9{%k1}
    vpsrldq       $0x8,%xmm9,%xmm10
    .byte 98, 211, 181, 8, 115, 194, 1 #vpshrdq $0x1,%xmm10,%xmm9,%xmm0
    vpslldq       $0x8,%xmm13,%xmm13
    vpxorq        %xmm13,%xmm0,%xmm0
    jmp           .L_steal_cipher_amivrujEyduiFoi

    .L_remaining_num_blocks_is_7_amivrujEyduiFoi:
    mov 	 $0xffffffffffffffff,%r8
    shr 	 $0x10,%r8
    kmovq 	 %r8,%k1
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2{%k1}
    add 	         $0x70,%rdi
    and            $0xf,%rdx
    je             .L_done_7_remain_amivrujEyduiFoi
    vextracti32x4   $0x2,%zmm10,%xmm12
    vextracti32x4   $0x3,%zmm10,%xmm13
    vinserti32x4    $0x2,%xmm13,%zmm10,%zmm10
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8 	 %zmm1, (%rsi)
    vmovdqu8 	 %zmm2, 0x40(%rsi){%k1}
    add 	         $0x70, %rsi
    vextracti32x4  $0x2,%zmm2,%xmm8
    vmovdqa        %xmm12,%xmm0
    jmp            .L_steal_cipher_amivrujEyduiFoi

.L_done_7_remain_amivrujEyduiFoi:
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1, (%rsi)
    vmovdqu8        %zmm2, 0x40(%rsi){%k1}
    jmp     .L_ret_amivrujEyduiFoi

    .L_remaining_num_blocks_is_6_amivrujEyduiFoi:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%ymm2
    add 	         $0x60,%rdi
    and            $0xf, %rdx
    je             .L_done_6_remain_amivrujEyduiFoi
    vextracti32x4   $0x1,%zmm10,%xmm12
    vextracti32x4   $0x2,%zmm10,%xmm13
    vinserti32x4    $0x1,%xmm13,%zmm10,%zmm10
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8 	 %zmm1, (%rsi)
    vmovdqu8 	 %ymm2, 0x40(%rsi)
    add 	         $0x60,%rsi
    vextracti32x4  $0x1,%zmm2,%xmm8
    vmovdqa        %xmm12,%xmm0
    jmp            .L_steal_cipher_amivrujEyduiFoi

.L_done_6_remain_amivrujEyduiFoi:
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1, (%rsi)
    vmovdqu8        %ymm2,0x40(%rsi)
    jmp             .L_ret_amivrujEyduiFoi

    .L_remaining_num_blocks_is_5_amivrujEyduiFoi:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu 	 0x40(%rdi),%xmm2
    add 	         $0x50,%rdi
    and            $0xf,%rdx
    je             .L_done_5_remain_amivrujEyduiFoi
    vmovdqa        %xmm10,%xmm12
    vextracti32x4  $0x1,%zmm10,%xmm10
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8         %zmm1, (%rsi)
    vmovdqu          %xmm2, 0x40(%rsi)
    add              $0x50, %rsi
    vmovdqa          %xmm2,%xmm8
    vmovdqa          %xmm12,%xmm0
    jmp              .L_steal_cipher_amivrujEyduiFoi

.L_done_5_remain_amivrujEyduiFoi:
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1, (%rsi)
    vmovdqu8        %xmm2, 0x40(%rsi)
    jmp             .L_ret_amivrujEyduiFoi

    .L_remaining_num_blocks_is_4_amivrujEyduiFoi:
    vmovdqu8 	 (%rdi),%zmm1
    add 	         $0x40,%rdi
    and            $0xf, %rdx
    je             .L_done_4_remain_amivrujEyduiFoi
    vextracti32x4   $0x3,%zmm9,%xmm12
    vinserti32x4    $0x3,%xmm10,%zmm9,%zmm9
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1,(%rsi)
    add             $0x40,%rsi
    vextracti32x4   $0x3,%zmm1,%xmm8
    vmovdqa         %xmm12,%xmm0
    jmp             .L_steal_cipher_amivrujEyduiFoi

.L_done_4_remain_amivrujEyduiFoi:
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1, (%rsi)
    jmp             .L_ret_amivrujEyduiFoi

    .L_remaining_num_blocks_is_3_amivrujEyduiFoi:
    vmovdqu         (%rdi),%xmm1
    vmovdqu         0x10(%rdi),%xmm2
    vmovdqu         0x20(%rdi),%xmm3
    add             $0x30,%rdi
    and             $0xf,%rdx
    je              .L_done_3_remain_amivrujEyduiFoi
    vextracti32x4   $0x2,%zmm9,%xmm13
    vextracti32x4   $0x1,%zmm9,%xmm10
    vextracti32x4   $0x3,%zmm9,%xmm11
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    add 	         $0x30,%rsi
    vmovdqa 	 %xmm3,%xmm8
    vmovdqa        %xmm13,%xmm0
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_3_remain_amivrujEyduiFoi:
vextracti32x4   $0x1,%zmm9,%xmm10
vextracti32x4   $0x2,%zmm9,%xmm11
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
    vmovdqu %xmm1,(%rsi)
    vmovdqu %xmm2,0x10(%rsi)
    vmovdqu %xmm3,0x20(%rsi)
    jmp     .L_ret_amivrujEyduiFoi

    .L_remaining_num_blocks_is_2_amivrujEyduiFoi:
    vmovdqu         (%rdi),%xmm1
    vmovdqu         0x10(%rdi),%xmm2
    add             $0x20,%rdi
    and             $0xf,%rdx
    je              .L_done_2_remain_amivrujEyduiFoi
    vextracti32x4   $0x2,%zmm9,%xmm10
    vextracti32x4   $0x1,%zmm9,%xmm12
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    add 	         $0x20,%rsi
    vmovdqa 	 %xmm2,%xmm8
    vmovdqa 	 %xmm12,%xmm0
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_2_remain_amivrujEyduiFoi:
vextracti32x4   $0x1,%zmm9,%xmm10
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
    vmovdqu   %xmm1,(%rsi)
    vmovdqu   %xmm2,0x10(%rsi)
    jmp       .L_ret_amivrujEyduiFoi

    .L_remaining_num_blocks_is_1_amivrujEyduiFoi:
    vmovdqu 	 (%rdi),%xmm1
    add 	         $0x10,%rdi
    and            $0xf,%rdx
    je             .L_done_1_remain_amivrujEyduiFoi
    vextracti32x4  $0x1,%zmm9,%xmm11
vpxor %xmm11, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm11, %xmm1, %xmm1
    vmovdqu 	 %xmm1,(%rsi)
    add 	         $0x10,%rsi
    vmovdqa 	 %xmm1,%xmm8
    vmovdqa 	 %xmm9,%xmm0
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_1_remain_amivrujEyduiFoi:
vpxor %xmm9, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm9, %xmm1, %xmm1
    vmovdqu   %xmm1, (%rsi)
    jmp       .L_ret_amivrujEyduiFoi

    .L_start_by16_amivrujEyduiFoi:
    vbroadcasti32x4 	 (%rsp),%zmm0
    vbroadcasti32x4 shufb_15_7(%rip),%zmm8
    mov 	 $0xaa,%r8
    kmovq 	 %r8,%k2

    # Mult tweak by 2^{3, 2, 1, 0}
    vpshufb 	 %zmm8,%zmm0,%zmm1
    vpsllvq const_dq3210(%rip),%zmm0,%zmm4
    vpsrlvq const_dq5678(%rip),%zmm1,%zmm2
    vpclmulqdq 	 $0x0,%zmm25,%zmm2,%zmm3
    vpxorq 	 %zmm2,%zmm4,%zmm4{%k2}
    vpxord 	 %zmm4,%zmm3,%zmm9

    # Mult tweak by 2^{7, 6, 5, 4}
    vpsllvq const_dq7654(%rip),%zmm0,%zmm5
    vpsrlvq const_dq1234(%rip),%zmm1,%zmm6
    vpclmulqdq 	 $0x0,%zmm25,%zmm6,%zmm7
    vpxorq 	 %zmm6,%zmm5,%zmm5{%k2}
    vpxord 	 %zmm5,%zmm7,%zmm10

    # Make next 8 tweak values by all x 2^8
    vpsrldq 	 $0xf,%zmm9,%zmm13
    vpclmulqdq 	 $0x0,%zmm25,%zmm13,%zmm14
    vpslldq 	 $0x1,%zmm9,%zmm11
    vpxord 	 %zmm14,%zmm11,%zmm11

    vpsrldq 	 $0xf,%zmm10,%zmm15
    vpclmulqdq 	 $0x0,%zmm25,%zmm15,%zmm16
    vpslldq 	 $0x1,%zmm10,%zmm12
    vpxord 	 %zmm16,%zmm12,%zmm12

    .L_main_loop_run_16_amivrujEyduiFoi:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2
    vmovdqu8 	 0x80(%rdi),%zmm3
    vmovdqu8 	 0xc0(%rdi),%zmm4
    vmovdqu8 	 0xf0(%rdi),%xmm5
    add 	 $0x100,%rdi
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
vpxorq    %zmm11, %zmm3, %zmm3
vpxorq    %zmm12, %zmm4, %zmm4
vbroadcasti32x4 (%rcx), %zmm0
vpxorq %zmm0, %zmm1, %zmm1
vpxorq %zmm0, %zmm2, %zmm2
vpxorq %zmm0, %zmm3, %zmm3
vpxorq %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm11, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm11, %zmm15
      vpxord		%zmm14, %zmm15, %zmm15
vbroadcasti32x4 0x10(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x20(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x30(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm12, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm12, %zmm16
      vpxord		%zmm14, %zmm16, %zmm16
vbroadcasti32x4 0x40(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x50(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x60(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm15, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm15, %zmm17
      vpxord		%zmm14, %zmm17, %zmm17
vbroadcasti32x4 0x70(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x80(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x90(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm16, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm16, %zmm18
      vpxord		%zmm14, %zmm18, %zmm18
vbroadcasti32x4 0xa0(%rcx), %zmm0
vaesdeclast %zmm0, %zmm1, %zmm1
vaesdeclast %zmm0, %zmm2, %zmm2
vaesdeclast %zmm0, %zmm3, %zmm3
vaesdeclast %zmm0, %zmm4, %zmm4
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
vpxorq    %zmm11, %zmm3, %zmm3
vpxorq    %zmm12, %zmm4, %zmm4
    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqa32  %zmm17, %zmm11
    vmovdqa32  %zmm18, %zmm12
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi)
    vmovdqu8 	 %zmm3,0x80(%rsi)
    vmovdqu8 	 %zmm4,0xc0(%rsi)
    add 	 $0x100,%rsi
    sub 	 $0x100,%rdx
    cmp 	 $0x100,%rdx
    jge 	 .L_main_loop_run_16_amivrujEyduiFoi

    cmp 	 $0x80,%rdx
    jge 	 .L_main_loop_run_8_amivrujEyduiFoi
    jmp 	 .L_do_n_blocks_amivrujEyduiFoi

    .L_start_by8_amivrujEyduiFoi:
    # Make first 7 tweak values
    vbroadcasti32x4 	 (%rsp),%zmm0
    vbroadcasti32x4 shufb_15_7(%rip),%zmm8
    mov 	 $0xaa,%r8
    kmovq 	 %r8,%k2

    # Mult tweak by 2^{3, 2, 1, 0}
    vpshufb 	 %zmm8,%zmm0,%zmm1
    vpsllvq const_dq3210(%rip),%zmm0,%zmm4
    vpsrlvq const_dq5678(%rip),%zmm1,%zmm2
    vpclmulqdq 	 $0x0,%zmm25,%zmm2,%zmm3
    vpxorq 	 %zmm2,%zmm4,%zmm4{%k2}
    vpxord 	 %zmm4,%zmm3,%zmm9

    # Mult tweak by 2^{7, 6, 5, 4}
    vpsllvq const_dq7654(%rip),%zmm0,%zmm5
    vpsrlvq const_dq1234(%rip),%zmm1,%zmm6
    vpclmulqdq 	 $0x0,%zmm25,%zmm6,%zmm7
    vpxorq 	 %zmm6,%zmm5,%zmm5{%k2}
    vpxord 	 %zmm5,%zmm7,%zmm10

    .L_main_loop_run_8_amivrujEyduiFoi:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2
    vmovdqu8 	 0x70(%rdi),%xmm5
    add 	         $0x80,%rdi
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
      vpsrldq		$0xf, %zmm9, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm9, %zmm15
      vpxord		%zmm14, %zmm15, %zmm15
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
      vpsrldq		$0xf, %zmm10, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm10, %zmm16
      vpxord		%zmm14, %zmm16, %zmm16
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi)
    add 	 $0x80,%rsi
    sub 	 $0x80,%rdx
    cmp 	 $0x80,%rdx
    jge 	 .L_main_loop_run_8_amivrujEyduiFoi
    jmp 	 .L_do_n_blocks_amivrujEyduiFoi

    .L_steal_cipher_amivrujEyduiFoi:
    # start cipher stealing simplified: xmm8-last cipher block, xmm0-next tweak
    vmovdqa 	 %xmm8,%xmm2

    # shift xmm8 to the left by 16-N_val bytes
    lea vpshufb_shf_table(%rip),%rax
    vmovdqu 	 (%rax,%rdx,1),%xmm10
    vpshufb 	 %xmm10,%xmm8,%xmm8


    vmovdqu 	 -0x10(%rdi,%rdx,1),%xmm3
    vmovdqu 	 %xmm8,-0x10(%rsi,%rdx,1)

    # shift xmm3 to the right by 16-N_val bytes
    lea vpshufb_shf_table(%rip), %rax
    add $16, %rax
    sub 	 %rdx,%rax
    vmovdqu 	 (%rax),%xmm10
    vpxor mask1(%rip),%xmm10,%xmm10
    vpshufb 	 %xmm10,%xmm3,%xmm3

    vpblendvb 	 %xmm10,%xmm2,%xmm3,%xmm3

    # xor Tweak value
    vpxor 	 %xmm0,%xmm3,%xmm8

    # decrypt last block with cipher stealing
    vpxor	(%rcx),%xmm8,%xmm8
    vaesdec	0x10(%rcx),%xmm8,%xmm8
    vaesdec	0x20(%rcx),%xmm8,%xmm8
    vaesdec	0x30(%rcx),%xmm8,%xmm8
    vaesdec	0x40(%rcx),%xmm8,%xmm8
    vaesdec	0x50(%rcx),%xmm8,%xmm8
    vaesdec	0x60(%rcx),%xmm8,%xmm8
    vaesdec	0x70(%rcx),%xmm8,%xmm8
    vaesdec	0x80(%rcx),%xmm8,%xmm8
    vaesdec	0x90(%rcx),%xmm8,%xmm8
vaesdeclast	0xa0(%rcx),%xmm8,%xmm8
    # xor Tweak value
    vpxor 	 %xmm0,%xmm8,%xmm8

    .L_done_amivrujEyduiFoi:
    # store last ciphertext value
    vmovdqu 	 %xmm8,-0x10(%rsi)
    .L_ret_amivrujEyduiFoi:
    mov 	 128(%rsp),%rbx
    xor    %r8,%r8
    mov    %r8,128(%rsp)
    # Zero-out the whole of \`%zmm0\`.
    vpxorq %zmm0,%zmm0,%zmm0
    mov %rbp,%rsp
    pop %rbp
    vzeroupper
    ret

    .L_less_than_128_bytes_amivrujEyduiFoi:
    cmp 	 $0x10,%rdx
    jb 	 .L_ret_amivrujEyduiFoi

    mov 	 %rdx,%r8
    and 	 $0x70,%r8
    cmp 	 $0x60,%r8
    je 	 .L_num_blocks_is_6_amivrujEyduiFoi
    cmp 	 $0x50,%r8
    je 	 .L_num_blocks_is_5_amivrujEyduiFoi
    cmp 	 $0x40,%r8
    je 	 .L_num_blocks_is_4_amivrujEyduiFoi
    cmp 	 $0x30,%r8
    je 	 .L_num_blocks_is_3_amivrujEyduiFoi
    cmp 	 $0x20,%r8
    je 	 .L_num_blocks_is_2_amivrujEyduiFoi
    cmp 	 $0x10,%r8
    je 	 .L_num_blocks_is_1_amivrujEyduiFoi

.L_num_blocks_is_7_amivrujEyduiFoi:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 48(%rsp)
mov      %rbx, 48 + 8(%rsp)
vmovdqa  48(%rsp), %xmm12
vmovdqu  48(%rdi), %xmm4
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 64(%rsp)
mov      %rbx, 64 + 8(%rsp)
vmovdqa  64(%rsp), %xmm13
vmovdqu  64(%rdi), %xmm5
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 80(%rsp)
mov      %rbx, 80 + 8(%rsp)
vmovdqa  80(%rsp), %xmm14
vmovdqu  80(%rdi), %xmm6
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 96(%rsp)
mov      %rbx, 96 + 8(%rsp)
vmovdqa  96(%rsp), %xmm15
vmovdqu  96(%rdi), %xmm7
    add    $0x70,%rdi
    and    $0xf,%rdx
    je      .L_done_7_amivrujEyduiFoi

    .L_steal_cipher_7_amivrujEyduiFoi:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm15,%xmm16
     vmovdqa     0x10(%rsp),%xmm15
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vpxor %xmm15, %xmm7, %xmm7
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vpxor %xmm0, %xmm6, %xmm6
vpxor %xmm0, %xmm7, %xmm7
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vaesdeclast %xmm0, %xmm6, %xmm6
vaesdeclast %xmm0, %xmm7, %xmm7
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vpxor %xmm15, %xmm7, %xmm7
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    vmovdqu 	 %xmm5,0x40(%rsi)
    vmovdqu 	 %xmm6,0x50(%rsi)
    add 	         $0x70,%rsi
    vmovdqa64 	 %xmm16,%xmm0
    vmovdqa 	 %xmm7,%xmm8
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_7_amivrujEyduiFoi:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vpxor %xmm15, %xmm7, %xmm7
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vpxor %xmm0, %xmm6, %xmm6
vpxor %xmm0, %xmm7, %xmm7
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vaesdeclast %xmm0, %xmm6, %xmm6
vaesdeclast %xmm0, %xmm7, %xmm7
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vpxor %xmm15, %xmm7, %xmm7
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    vmovdqu 	 %xmm5,0x40(%rsi)
    vmovdqu 	 %xmm6,0x50(%rsi)
    add 	         $0x70,%rsi
    vmovdqa 	 %xmm7,%xmm8
    jmp 	         .L_done_amivrujEyduiFoi

.L_num_blocks_is_6_amivrujEyduiFoi:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 48(%rsp)
mov      %rbx, 48 + 8(%rsp)
vmovdqa  48(%rsp), %xmm12
vmovdqu  48(%rdi), %xmm4
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 64(%rsp)
mov      %rbx, 64 + 8(%rsp)
vmovdqa  64(%rsp), %xmm13
vmovdqu  64(%rdi), %xmm5
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 80(%rsp)
mov      %rbx, 80 + 8(%rsp)
vmovdqa  80(%rsp), %xmm14
vmovdqu  80(%rdi), %xmm6
    add    $0x60,%rdi
    and    $0xf,%rdx
    je      .L_done_6_amivrujEyduiFoi

    .L_steal_cipher_6_amivrujEyduiFoi:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm14,%xmm15
     vmovdqa     0x10(%rsp),%xmm14
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vpxor %xmm0, %xmm6, %xmm6
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vaesdeclast %xmm0, %xmm6, %xmm6
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    vmovdqu 	 %xmm5,0x40(%rsi)
    add 	         $0x60,%rsi
    vmovdqa 	 %xmm15,%xmm0
    vmovdqa 	 %xmm6,%xmm8
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_6_amivrujEyduiFoi:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vpxor %xmm0, %xmm6, %xmm6
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vaesdeclast %xmm0, %xmm6, %xmm6
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    vmovdqu 	 %xmm5,0x40(%rsi)
    add 	         $0x60,%rsi
    vmovdqa 	 %xmm6,%xmm8
    jmp 	         .L_done_amivrujEyduiFoi

.L_num_blocks_is_5_amivrujEyduiFoi:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 48(%rsp)
mov      %rbx, 48 + 8(%rsp)
vmovdqa  48(%rsp), %xmm12
vmovdqu  48(%rdi), %xmm4
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 64(%rsp)
mov      %rbx, 64 + 8(%rsp)
vmovdqa  64(%rsp), %xmm13
vmovdqu  64(%rdi), %xmm5
    add    $0x50,%rdi
    and    $0xf,%rdx
    je      .L_done_5_amivrujEyduiFoi

    .L_steal_cipher_5_amivrujEyduiFoi:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm13,%xmm14
     vmovdqa     0x10(%rsp),%xmm13
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    add 	         $0x50,%rsi
    vmovdqa 	 %xmm14,%xmm0
    vmovdqa 	 %xmm5,%xmm8
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_5_amivrujEyduiFoi:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    add 	         $0x50,%rsi
    vmovdqa 	 %xmm5,%xmm8
    jmp 	         .L_done_amivrujEyduiFoi

.L_num_blocks_is_4_amivrujEyduiFoi:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 48(%rsp)
mov      %rbx, 48 + 8(%rsp)
vmovdqa  48(%rsp), %xmm12
vmovdqu  48(%rdi), %xmm4
    add    $0x40,%rdi
    and    $0xf,%rdx
    je      .L_done_4_amivrujEyduiFoi

    .L_steal_cipher_4_amivrujEyduiFoi:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm12,%xmm13
     vmovdqa     0x10(%rsp),%xmm12
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    add 	         $0x40,%rsi
    vmovdqa 	 %xmm13,%xmm0
    vmovdqa 	 %xmm4,%xmm8
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_4_amivrujEyduiFoi:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    add 	         $0x40,%rsi
    vmovdqa 	 %xmm4,%xmm8
    jmp 	         .L_done_amivrujEyduiFoi

.L_num_blocks_is_3_amivrujEyduiFoi:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
    add    $0x30,%rdi
    and    $0xf,%rdx
    je      .L_done_3_amivrujEyduiFoi

    .L_steal_cipher_3_amivrujEyduiFoi:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm11,%xmm12
     vmovdqa     0x10(%rsp),%xmm11
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    add 	         $0x30,%rsi
    vmovdqa 	 %xmm12,%xmm0
    vmovdqa 	 %xmm3,%xmm8
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_3_amivrujEyduiFoi:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    add 	         $0x30,%rsi
    vmovdqa 	 %xmm3,%xmm8
    jmp 	         .L_done_amivrujEyduiFoi

.L_num_blocks_is_2_amivrujEyduiFoi:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
    add    $0x20,%rdi
    and    $0xf,%rdx
    je      .L_done_2_amivrujEyduiFoi

    .L_steal_cipher_2_amivrujEyduiFoi:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm10,%xmm11
     vmovdqa     0x10(%rsp),%xmm10
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
    vmovdqu 	 %xmm1,(%rsi)
    add 	         $0x20,%rsi
    vmovdqa 	 %xmm11,%xmm0
    vmovdqa 	 %xmm2,%xmm8
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_2_amivrujEyduiFoi:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
    vmovdqu 	 %xmm1,(%rsi)
    add 	         $0x20,%rsi
    vmovdqa 	 %xmm2,%xmm8
    jmp 	         .L_done_amivrujEyduiFoi

.L_num_blocks_is_1_amivrujEyduiFoi:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
    add    $0x10,%rdi
    and    $0xf,%rdx
    je      .L_done_1_amivrujEyduiFoi

    .L_steal_cipher_1_amivrujEyduiFoi:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm9,%xmm10
     vmovdqa     0x10(%rsp),%xmm9
vpxor %xmm9, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm9, %xmm1, %xmm1
    add 	         $0x10,%rsi
    vmovdqa 	 %xmm10,%xmm0
    vmovdqa 	 %xmm1,%xmm8
    jmp 	         .L_steal_cipher_amivrujEyduiFoi

.L_done_1_amivrujEyduiFoi:
vpxor %xmm9, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm9, %xmm1, %xmm1
    add 	         $0x10,%rsi
    vmovdqa 	 %xmm1,%xmm8
    jmp 	         .L_done_amivrujEyduiFoi
    .cfi_endproc
      .globl	aesni_xts_256_encrypt_avx512
      .hidden	aesni_xts_256_encrypt_avx512
      .type	aesni_xts_256_encrypt_avx512,@function,6
      .align	32
      aesni_xts_256_encrypt_avx512:
      .cfi_startproc
      endbranch
push 	 %rbp
mov 	 %rsp,%rbp
sub 	 $136,%rsp
and 	 $0xffffffffffffffc0,%rsp
mov 	 %rbx,128(%rsp)
mov 	 $0x87, %r10
vmovdqu 	 (%r9),%xmm1
    vpxor	(%r8), %xmm1, %xmm1
    vaesenc	0x10(%r8), %xmm1, %xmm1
    vaesenc	0x20(%r8), %xmm1, %xmm1
    vaesenc	0x30(%r8), %xmm1, %xmm1
    vaesenc	0x40(%r8), %xmm1, %xmm1
    vaesenc	0x50(%r8), %xmm1, %xmm1
    vaesenc	0x60(%r8), %xmm1, %xmm1
    vaesenc	0x70(%r8), %xmm1, %xmm1
    vaesenc	0x80(%r8), %xmm1, %xmm1
    vaesenc	0x90(%r8), %xmm1, %xmm1
vaesenc	0xa0(%r8), %xmm1, %xmm1
vaesenc	0xb0(%r8), %xmm1, %xmm1
vaesenc	0xc0(%r8), %xmm1, %xmm1
vaesenc	0xd0(%r8), %xmm1, %xmm1
vaesenclast	0xe0(%r8), %xmm1, %xmm1
vmovdqa	%xmm1, (%rsp)

    cmp 	 $0x80,%rdx
    jl 	 .L_less_than_128_bytes_wcpqaDvsGlbjGoe
    vpbroadcastq 	 %r10,%zmm25
    cmp 	 $0x100,%rdx
    jge 	 .L_start_by16_wcpqaDvsGlbjGoe
    cmp 	 $0x80,%rdx
    jge 	 .L_start_by8_wcpqaDvsGlbjGoe

    .L_do_n_blocks_wcpqaDvsGlbjGoe:
    cmp 	 $0x0,%rdx
    je 	 .L_ret_wcpqaDvsGlbjGoe
    cmp 	 $0x70,%rdx
    jge 	 .L_remaining_num_blocks_is_7_wcpqaDvsGlbjGoe
    cmp 	 $0x60,%rdx
    jge 	 .L_remaining_num_blocks_is_6_wcpqaDvsGlbjGoe
    cmp 	 $0x50,%rdx
    jge 	 .L_remaining_num_blocks_is_5_wcpqaDvsGlbjGoe
    cmp 	 $0x40,%rdx
    jge 	 .L_remaining_num_blocks_is_4_wcpqaDvsGlbjGoe
    cmp 	 $0x30,%rdx
    jge 	 .L_remaining_num_blocks_is_3_wcpqaDvsGlbjGoe
    cmp 	 $0x20,%rdx
    jge 	 .L_remaining_num_blocks_is_2_wcpqaDvsGlbjGoe
    cmp 	 $0x10,%rdx
    jge 	 .L_remaining_num_blocks_is_1_wcpqaDvsGlbjGoe
    vmovdqa 	 %xmm0,%xmm8
    vmovdqa 	 %xmm9,%xmm0
    jmp 	 .L_steal_cipher_wcpqaDvsGlbjGoe

    .L_remaining_num_blocks_is_7_wcpqaDvsGlbjGoe:
    mov 	 $0x0000ffffffffffff,%r8
    kmovq 	 %r8,%k1
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2{%k1}
    add 	 $0x70,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi){%k1}
    add 	 $0x70,%rsi
    vextracti32x4 	 $0x2,%zmm2,%xmm8
    vextracti32x4 	 $0x3,%zmm10,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_wcpqaDvsGlbjGoe
    jmp 	 .L_steal_cipher_wcpqaDvsGlbjGoe

    .L_remaining_num_blocks_is_6_wcpqaDvsGlbjGoe:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%ymm2
    add 	 $0x60,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %ymm2,0x40(%rsi)
    add 	 $0x60,%rsi
    vextracti32x4 	 $0x1,%zmm2,%xmm8
    vextracti32x4 	 $0x2,%zmm10,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_wcpqaDvsGlbjGoe
    jmp 	 .L_steal_cipher_wcpqaDvsGlbjGoe

    .L_remaining_num_blocks_is_5_wcpqaDvsGlbjGoe:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu 	 0x40(%rdi),%xmm2
    add 	 $0x50,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu 	 %xmm2,0x40(%rsi)
    add 	 $0x50,%rsi
    vmovdqa 	 %xmm2,%xmm8
    vextracti32x4 	 $0x1,%zmm10,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_wcpqaDvsGlbjGoe
    jmp 	 .L_steal_cipher_wcpqaDvsGlbjGoe

    .L_remaining_num_blocks_is_4_wcpqaDvsGlbjGoe:
    vmovdqu8 	 (%rdi),%zmm1
    add 	 $0x40,%rdi
vbroadcasti32x4 (%rcx), %zmm0
vpternlogq      $0x96, %zmm0, %zmm9, %zmm1
vbroadcasti32x4 16*1(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*2(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*3(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*4(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*5(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*6(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*7(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*8(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*9(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*10(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*11(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*12(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*13(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*14(%rcx), %zmm0
vaesenclast  %zmm0, %zmm1, %zmm1
vpxorq %zmm9, %zmm1, %zmm1
    vmovdqu8	%zmm1,(%rsi)
    add	$0x40,%rsi
    vextracti32x4	$0x3,%zmm1,%xmm8
    vmovdqa64	%xmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .L_remaining_num_blocks_is_3_wcpqaDvsGlbjGoe:
    mov	$-1, %r8
    shr	$0x10, %r8
    kmovq	%r8, %k1
    vmovdqu8	(%rdi), %zmm1{%k1}
    add	$0x30, %rdi
vbroadcasti32x4 (%rcx), %zmm0
vpternlogq      $0x96, %zmm0, %zmm9, %zmm1
vbroadcasti32x4 16*1(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*2(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*3(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*4(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*5(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*6(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*7(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*8(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*9(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*10(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*11(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*12(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*13(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*14(%rcx), %zmm0
vaesenclast  %zmm0, %zmm1, %zmm1
vpxorq %zmm9, %zmm1, %zmm1
    vmovdqu8	%zmm1, (%rsi){%k1}
    add	$0x30, %rsi
    vextracti32x4	$0x2, %zmm1, %xmm8
    vextracti32x4	$0x3, %zmm9, %xmm0
    and	$0xf, %rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .L_remaining_num_blocks_is_2_wcpqaDvsGlbjGoe:
    vmovdqu8	(%rdi), %ymm1
    add	$0x20, %rdi
vbroadcasti32x4 (%rcx), %ymm0
vpternlogq      $0x96, %ymm0, %ymm9, %ymm1
vbroadcasti32x4 16*1(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*2(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*3(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*4(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*5(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*6(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*7(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*8(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*9(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*10(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*11(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*12(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*13(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*14(%rcx), %ymm0
vaesenclast  %ymm0, %ymm1, %ymm1
vpxorq %ymm9, %ymm1, %ymm1
    vmovdqu 	 %ymm1,(%rsi)
    add 	 $0x20,%rsi
    vextracti32x4	$0x1, %zmm1, %xmm8
    vextracti32x4	$0x2,%zmm9,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_wcpqaDvsGlbjGoe
    jmp 	 .L_steal_cipher_wcpqaDvsGlbjGoe
    .L_remaining_num_blocks_is_1_wcpqaDvsGlbjGoe:
    vmovdqu 	 (%rdi),%xmm1
    add 	 $0x10,%rdi
vpxor	%xmm9, %xmm1, %xmm1
vpxor	(%rcx), %xmm1, %xmm1
vaesenc	16*1(%rcx), %xmm1, %xmm1
vaesenc	16*2(%rcx), %xmm1, %xmm1
vaesenc	16*3(%rcx), %xmm1, %xmm1
vaesenc	16*4(%rcx), %xmm1, %xmm1
vaesenc	16*5(%rcx), %xmm1, %xmm1
vaesenc	16*6(%rcx), %xmm1, %xmm1
vaesenc	16*7(%rcx), %xmm1, %xmm1
vaesenc	16*8(%rcx), %xmm1, %xmm1
vaesenc	16*9(%rcx), %xmm1, %xmm1
vaesenc	16*10(%rcx), %xmm1, %xmm1
vaesenc	16*11(%rcx), %xmm1, %xmm1
vaesenc	16*12(%rcx), %xmm1, %xmm1
vaesenc	16*13(%rcx), %xmm1, %xmm1
    vaesenclast 16*14(%rcx), %xmm1, %xmm1
    vpxor	%xmm9, %xmm1, %xmm1
    vmovdqu 	 %xmm1,(%rsi)
    add 	 $0x10,%rsi
    vmovdqa 	 %xmm1,%xmm8
    vextracti32x4 	 $0x1,%zmm9,%xmm0
    and 	 $0xf,%rdx
    je 	 .L_ret_wcpqaDvsGlbjGoe
    jmp 	 .L_steal_cipher_wcpqaDvsGlbjGoe


    .L_start_by16_wcpqaDvsGlbjGoe:
    vbroadcasti32x4 	 (%rsp),%zmm0
    vbroadcasti32x4 shufb_15_7(%rip),%zmm8
    mov 	 $0xaa,%r8
    kmovq 	 %r8,%k2
    vpshufb 	 %zmm8,%zmm0,%zmm1
    vpsllvq const_dq3210(%rip),%zmm0,%zmm4
    vpsrlvq const_dq5678(%rip),%zmm1,%zmm2
    vpclmulqdq 	 $0x0,%zmm25,%zmm2,%zmm3
    vpxorq 	 %zmm2,%zmm4,%zmm4{%k2}
    vpxord 	 %zmm4,%zmm3,%zmm9
    vpsllvq const_dq7654(%rip),%zmm0,%zmm5
    vpsrlvq const_dq1234(%rip),%zmm1,%zmm6
    vpclmulqdq 	 $0x0,%zmm25,%zmm6,%zmm7
    vpxorq 	 %zmm6,%zmm5,%zmm5{%k2}
    vpxord 	 %zmm5,%zmm7,%zmm10
    vpsrldq 	 $0xf,%zmm9,%zmm13
    vpclmulqdq 	 $0x0,%zmm25,%zmm13,%zmm14
    vpslldq 	 $0x1,%zmm9,%zmm11
    vpxord 	 %zmm14,%zmm11,%zmm11
    vpsrldq 	 $0xf,%zmm10,%zmm15
    vpclmulqdq 	 $0x0,%zmm25,%zmm15,%zmm16
    vpslldq 	 $0x1,%zmm10,%zmm12
    vpxord 	 %zmm16,%zmm12,%zmm12

    .L_main_loop_run_16_wcpqaDvsGlbjGoe:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2
    vmovdqu8 	 0x80(%rdi),%zmm3
    vmovdqu8 	 0xc0(%rdi),%zmm4
    add 	 $0x100,%rdi
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
vpxorq    %zmm11, %zmm3, %zmm3
vpxorq    %zmm12, %zmm4, %zmm4
vbroadcasti32x4 (%rcx), %zmm0
vpxorq %zmm0, %zmm1, %zmm1
vpxorq %zmm0, %zmm2, %zmm2
vpxorq %zmm0, %zmm3, %zmm3
vpxorq %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm11, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm11, %zmm15
      vpxord		%zmm14, %zmm15, %zmm15
vbroadcasti32x4 0x10(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x20(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x30(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm12, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm12, %zmm16
      vpxord		%zmm14, %zmm16, %zmm16
vbroadcasti32x4 0x40(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x50(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x60(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm15, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm15, %zmm17
      vpxord		%zmm14, %zmm17, %zmm17
vbroadcasti32x4 0x70(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x80(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x90(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm16, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm16, %zmm18
      vpxord		%zmm14, %zmm18, %zmm18
vbroadcasti32x4 0xa0(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0xb0(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0xc0(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0xd0(%rcx), %zmm0
vaesenc %zmm0, %zmm1, %zmm1
vaesenc %zmm0, %zmm2, %zmm2
vaesenc %zmm0, %zmm3, %zmm3
vaesenc %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0xe0(%rcx), %zmm0
vaesenclast %zmm0, %zmm1, %zmm1
vaesenclast %zmm0, %zmm2, %zmm2
vaesenclast %zmm0, %zmm3, %zmm3
vaesenclast %zmm0, %zmm4, %zmm4
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
vpxorq    %zmm11, %zmm3, %zmm3
vpxorq    %zmm12, %zmm4, %zmm4
    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqa32  %zmm17, %zmm11
    vmovdqa32  %zmm18, %zmm12
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi)
    vmovdqu8 	 %zmm3,0x80(%rsi)
    vmovdqu8 	 %zmm4,0xc0(%rsi)
    add 	 $0x100,%rsi
    sub 	 $0x100,%rdx
    cmp 	 $0x100,%rdx
    jae 	 .L_main_loop_run_16_wcpqaDvsGlbjGoe
    cmp 	 $0x80,%rdx
    jae 	 .L_main_loop_run_8_wcpqaDvsGlbjGoe
    vextracti32x4 	 $0x3,%zmm4,%xmm0
    jmp 	 .L_do_n_blocks_wcpqaDvsGlbjGoe

    .L_start_by8_wcpqaDvsGlbjGoe:
    vbroadcasti32x4 	 (%rsp),%zmm0
    vbroadcasti32x4 shufb_15_7(%rip),%zmm8
    mov 	 $0xaa,%r8
    kmovq 	 %r8,%k2
    vpshufb 	 %zmm8,%zmm0,%zmm1
    vpsllvq const_dq3210(%rip),%zmm0,%zmm4
    vpsrlvq const_dq5678(%rip),%zmm1,%zmm2
    vpclmulqdq 	 $0x0,%zmm25,%zmm2,%zmm3
    vpxorq 	 %zmm2,%zmm4,%zmm4{%k2}
    vpxord 	 %zmm4,%zmm3,%zmm9
    vpsllvq const_dq7654(%rip),%zmm0,%zmm5
    vpsrlvq const_dq1234(%rip),%zmm1,%zmm6
    vpclmulqdq 	 $0x0,%zmm25,%zmm6,%zmm7
    vpxorq 	 %zmm6,%zmm5,%zmm5{%k2}
    vpxord 	 %zmm5,%zmm7,%zmm10

    .L_main_loop_run_8_wcpqaDvsGlbjGoe:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2
    add 	 $0x80,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
      vpsrldq		$0xf, %zmm9, %zmm13
      vpclmulqdq	$0x0, %zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm9, %zmm15
      vpxord		%zmm14, %zmm15, %zmm15
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      vpsrldq		$0xf, %zmm10, %zmm13
      vpclmulqdq	$0x0, %zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm10, %zmm16
      vpxord		%zmm14, %zmm16, %zmm16
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
      vmovdqa32  %zmm15, %zmm9
      vmovdqa32  %zmm16, %zmm10
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi)
    add 	 $0x80,%rsi
    sub 	 $0x80,%rdx
    cmp 	 $0x80,%rdx
    jae 	 .L_main_loop_run_8_wcpqaDvsGlbjGoe
    vextracti32x4 	 $0x3,%zmm2,%xmm0
    jmp 	 .L_do_n_blocks_wcpqaDvsGlbjGoe

    .L_steal_cipher_wcpqaDvsGlbjGoe:
    vmovdqa	%xmm8,%xmm2
    lea	vpshufb_shf_table(%rip),%rax
    vmovdqu	(%rax,%rdx,1),%xmm10
    vpshufb	%xmm10,%xmm8,%xmm8
    vmovdqu	-0x10(%rdi,%rdx,1),%xmm3
    vmovdqu	%xmm8,-0x10(%rsi,%rdx,1)
    lea	vpshufb_shf_table(%rip),%rax
    add	$16, %rax
    sub	%rdx,%rax
    vmovdqu	(%rax),%xmm10
    vpxor	mask1(%rip),%xmm10,%xmm10
    vpshufb	%xmm10,%xmm3,%xmm3
    vpblendvb	%xmm10,%xmm2,%xmm3,%xmm3
    vpxor	%xmm0,%xmm3,%xmm8
    vpxor	(%rcx),%xmm8,%xmm8
    vaesenc	0x10(%rcx),%xmm8,%xmm8
    vaesenc	0x20(%rcx),%xmm8,%xmm8
    vaesenc	0x30(%rcx),%xmm8,%xmm8
    vaesenc	0x40(%rcx),%xmm8,%xmm8
    vaesenc	0x50(%rcx),%xmm8,%xmm8
    vaesenc	0x60(%rcx),%xmm8,%xmm8
    vaesenc	0x70(%rcx),%xmm8,%xmm8
    vaesenc	0x80(%rcx),%xmm8,%xmm8
    vaesenc	0x90(%rcx),%xmm8,%xmm8
      vaesenc	0xa0(%rcx),%xmm8,%xmm8
      vaesenc	0xb0(%rcx),%xmm8,%xmm8
      vaesenc	0xc0(%rcx),%xmm8,%xmm8
      vaesenc	0xd0(%rcx),%xmm8,%xmm8
      vaesenclast	0xe0(%rcx),%xmm8,%xmm8
vpxor	%xmm0,%xmm8,%xmm8
vmovdqu	%xmm8,-0x10(%rsi)
    .L_ret_wcpqaDvsGlbjGoe:
    mov 	 128(%rsp),%rbx
    xor    %r8,%r8
    mov    %r8,128(%rsp)
    # Zero-out the whole of \`%zmm0\`.
    vpxorq %zmm0,%zmm0,%zmm0
    mov %rbp,%rsp
    pop %rbp
    vzeroupper
    ret

    .L_less_than_128_bytes_wcpqaDvsGlbjGoe:
    vpbroadcastq	%r10, %zmm25
    cmp 	 $0x10,%rdx
    jb 	 .L_ret_wcpqaDvsGlbjGoe
    vbroadcasti32x4	(%rsp), %zmm0
    vbroadcasti32x4	shufb_15_7(%rip), %zmm8
    movl    $0xaa, %r8d
    kmovq	%r8, %k2
    mov	%rdx,%r8
    and	$0x70,%r8
    cmp	$0x60,%r8
    je	.L_num_blocks_is_6_wcpqaDvsGlbjGoe
    cmp	$0x50,%r8
    je	.L_num_blocks_is_5_wcpqaDvsGlbjGoe
    cmp	$0x40,%r8
    je	.L_num_blocks_is_4_wcpqaDvsGlbjGoe
    cmp	$0x30,%r8
    je	.L_num_blocks_is_3_wcpqaDvsGlbjGoe
    cmp	$0x20,%r8
    je	.L_num_blocks_is_2_wcpqaDvsGlbjGoe
    cmp	$0x10,%r8
    je	.L_num_blocks_is_1_wcpqaDvsGlbjGoe

    .L_num_blocks_is_7_wcpqaDvsGlbjGoe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    vpsllvq	const_dq7654(%rip), %zmm0, %zmm5
    vpsrlvq	const_dq1234(%rip), %zmm1, %zmm6
    vpclmulqdq	$0x00, %zmm25, %zmm6, %zmm7
    vpxorq	%zmm6, %zmm5, %zmm5{%k2}
    vpxord	%zmm5, %zmm7, %zmm10
    mov	$0x0000ffffffffffff, %r8
    kmovq	%r8, %k1
    vmovdqu8	16*0(%rdi), %zmm1
    vmovdqu8	16*4(%rdi), %zmm2{%k1}

    add	$0x70,%rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8	%zmm1, 16*0(%rsi)
    vmovdqu8	%zmm2, 16*4(%rsi){%k1}
    add	$0x70,%rsi
    vextracti32x4	$0x2, %zmm2, %xmm8
    vextracti32x4	$0x3, %zmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .L_num_blocks_is_6_wcpqaDvsGlbjGoe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    vpsllvq	const_dq7654(%rip), %zmm0, %zmm5
    vpsrlvq	const_dq1234(%rip), %zmm1, %zmm6
    vpclmulqdq	$0x00, %zmm25, %zmm6, %zmm7
    vpxorq	%zmm6, %zmm5, %zmm5{%k2}
    vpxord	%zmm5, %zmm7, %zmm10
    vmovdqu8	16*0(%rdi), %zmm1
    vmovdqu8	16*4(%rdi), %ymm2
    add	$96, %rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8	%zmm1, 16*0(%rsi)
    vmovdqu8	%ymm2, 16*4(%rsi)
    add	$96, %rsi

    vextracti32x4	$0x1, %ymm2, %xmm8
    vextracti32x4	$0x2, %zmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .L_num_blocks_is_5_wcpqaDvsGlbjGoe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    vpsllvq	const_dq7654(%rip), %zmm0, %zmm5
    vpsrlvq	const_dq1234(%rip), %zmm1, %zmm6
    vpclmulqdq	$0x00, %zmm25, %zmm6, %zmm7
    vpxorq	%zmm6, %zmm5, %zmm5{%k2}
    vpxord	%zmm5, %zmm7, %zmm10
    vmovdqu8	16*0(%rdi), %zmm1
    vmovdqu8	16*4(%rdi), %xmm2
    add	$80, %rdi
	vbroadcasti32x4 (%rcx), %zmm0
	vpternlogq    $0x96, %zmm0, %zmm9, %zmm1
	vpternlogq    $0x96, %zmm0, %zmm10, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesenc  %zmm0, %zmm1, %zmm1
    vaesenc  %zmm0, %zmm2, %zmm2
      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesenc  %zmm0, %zmm1, %zmm1
      vaesenc  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesenclast  %zmm0, %zmm1, %zmm1
      vaesenclast  %zmm0, %zmm2, %zmm2
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
    vmovdqu8	%zmm1, 16*0(%rsi)
    vmovdqu8	%xmm2, 16*4(%rsi)
    add	$80, %rsi

    vmovdqa	%xmm2, %xmm8
    vextracti32x4	$0x1, %zmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .L_num_blocks_is_4_wcpqaDvsGlbjGoe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    vpsllvq	const_dq7654(%rip), %zmm0, %zmm5
    vpsrlvq	const_dq1234(%rip), %zmm1, %zmm6
    vpclmulqdq	$0x00, %zmm25, %zmm6, %zmm7
    vpxorq	%zmm6, %zmm5, %zmm5{%k2}
    vpxord	%zmm5, %zmm7, %zmm10
    vmovdqu8	16*0(%rdi), %zmm1
    add	$64, %rdi
vbroadcasti32x4 (%rcx), %zmm0
vpternlogq      $0x96, %zmm0, %zmm9, %zmm1
vbroadcasti32x4 16*1(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*2(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*3(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*4(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*5(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*6(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*7(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*8(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*9(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*10(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*11(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*12(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*13(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*14(%rcx), %zmm0
vaesenclast  %zmm0, %zmm1, %zmm1
vpxorq %zmm9, %zmm1, %zmm1
    vmovdqu8	%zmm1, 16*0(%rsi)
    add	$64, %rsi
    vextracti32x4	$0x3, %zmm1, %xmm8
    vmovdqa	%xmm10, %xmm0
    and	$0xf,%rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .L_num_blocks_is_3_wcpqaDvsGlbjGoe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9
    mov	$0x0000ffffffffffff, %r8
    kmovq	%r8, %k1
    vmovdqu8	16*0(%rdi), %zmm1{%k1}
    add	$48, %rdi
vbroadcasti32x4 (%rcx), %zmm0
vpternlogq      $0x96, %zmm0, %zmm9, %zmm1
vbroadcasti32x4 16*1(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*2(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*3(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*4(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*5(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*6(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*7(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*8(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*9(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*10(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*11(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*12(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*13(%rcx), %zmm0
vaesenc  %zmm0, %zmm1, %zmm1
vbroadcasti32x4 16*14(%rcx), %zmm0
vaesenclast  %zmm0, %zmm1, %zmm1
vpxorq %zmm9, %zmm1, %zmm1
    vmovdqu8	%zmm1, 16*0(%rsi){%k1}
    add	$48, %rsi
    vextracti32x4	$2, %zmm1, %xmm8
    vextracti32x4	$3, %zmm9, %xmm0
    and	$0xf,%rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .L_num_blocks_is_2_wcpqaDvsGlbjGoe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9

    vmovdqu8	16*0(%rdi), %ymm1
    add	$32, %rdi
vbroadcasti32x4 (%rcx), %ymm0
vpternlogq      $0x96, %ymm0, %ymm9, %ymm1
vbroadcasti32x4 16*1(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*2(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*3(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*4(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*5(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*6(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*7(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*8(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*9(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*10(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*11(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*12(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*13(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*14(%rcx), %ymm0
vaesenclast  %ymm0, %ymm1, %ymm1
vpxorq %ymm9, %ymm1, %ymm1
    vmovdqu8	%ymm1, 16*0(%rsi)
    add	$32, %rsi

    vextracti32x4	$1, %ymm1, %xmm8
    vextracti32x4	$2, %zmm9, %xmm0
    and	$0xf,%rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .L_num_blocks_is_1_wcpqaDvsGlbjGoe:
    vpshufb	%zmm8, %zmm0, %zmm1
    vpsllvq	const_dq3210(%rip), %zmm0, %zmm4
    vpsrlvq	const_dq5678(%rip), %zmm1, %zmm2
    vpclmulqdq	$0x00, %zmm25, %zmm2, %zmm3
    vpxorq	%zmm2, %zmm4, %zmm4{%k2}
    vpxord	%zmm4, %zmm3, %zmm9

    vmovdqu8	16*0(%rdi), %xmm1
    add	$16, %rdi
vbroadcasti32x4 (%rcx), %ymm0
vpternlogq      $0x96, %ymm0, %ymm9, %ymm1
vbroadcasti32x4 16*1(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*2(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*3(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*4(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*5(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*6(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*7(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*8(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*9(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*10(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*11(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*12(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*13(%rcx), %ymm0
vaesenc  %ymm0, %ymm1, %ymm1
vbroadcasti32x4 16*14(%rcx), %ymm0
vaesenclast  %ymm0, %ymm1, %ymm1
vpxorq %ymm9, %ymm1, %ymm1
    vmovdqu8	%xmm1, 16*0(%rsi)
    add	$16, %rsi

    vmovdqa	%xmm1, %xmm8
    vextracti32x4	$1, %zmm9, %xmm0
    and	$0xf,%rdx
    je	.L_ret_wcpqaDvsGlbjGoe
    jmp	.L_steal_cipher_wcpqaDvsGlbjGoe
    .cfi_endproc
      .globl	aesni_xts_256_decrypt_avx512
      .hidden	aesni_xts_256_decrypt_avx512
      .type	aesni_xts_256_decrypt_avx512,@function,6
      .align	32
      aesni_xts_256_decrypt_avx512:
      .cfi_startproc
      endbranch
push 	 %rbp
mov 	 %rsp,%rbp
sub 	 $136,%rsp
and 	 $0xffffffffffffffc0,%rsp
mov 	 %rbx,128(%rsp)
mov 	 $0x87, %r10
vmovdqu 	 (%r9),%xmm1
    vpxor	(%r8), %xmm1, %xmm1
    vaesenc	0x10(%r8), %xmm1, %xmm1
    vaesenc	0x20(%r8), %xmm1, %xmm1
    vaesenc	0x30(%r8), %xmm1, %xmm1
    vaesenc	0x40(%r8), %xmm1, %xmm1
    vaesenc	0x50(%r8), %xmm1, %xmm1
    vaesenc	0x60(%r8), %xmm1, %xmm1
    vaesenc	0x70(%r8), %xmm1, %xmm1
    vaesenc	0x80(%r8), %xmm1, %xmm1
    vaesenc	0x90(%r8), %xmm1, %xmm1
vaesenc	0xa0(%r8), %xmm1, %xmm1
vaesenc	0xb0(%r8), %xmm1, %xmm1
vaesenc	0xc0(%r8), %xmm1, %xmm1
vaesenc	0xd0(%r8), %xmm1, %xmm1
vaesenclast	0xe0(%r8), %xmm1, %xmm1
vmovdqa	%xmm1, (%rsp)

    cmp 	 $0x80,%rdx
    jb 	 .L_less_than_128_bytes_EmbgEptodyewbFa
    vpbroadcastq 	 %r10,%zmm25
    cmp 	 $0x100,%rdx
    jge 	 .L_start_by16_EmbgEptodyewbFa
    jmp 	 .L_start_by8_EmbgEptodyewbFa

    .L_do_n_blocks_EmbgEptodyewbFa:
    cmp 	 $0x0,%rdx
    je 	 .L_ret_EmbgEptodyewbFa
    cmp 	 $0x70,%rdx
    jge 	 .L_remaining_num_blocks_is_7_EmbgEptodyewbFa
    cmp 	 $0x60,%rdx
    jge 	 .L_remaining_num_blocks_is_6_EmbgEptodyewbFa
    cmp 	 $0x50,%rdx
    jge 	 .L_remaining_num_blocks_is_5_EmbgEptodyewbFa
    cmp 	 $0x40,%rdx
    jge 	 .L_remaining_num_blocks_is_4_EmbgEptodyewbFa
    cmp 	 $0x30,%rdx
    jge 	 .L_remaining_num_blocks_is_3_EmbgEptodyewbFa
    cmp 	 $0x20,%rdx
    jge 	 .L_remaining_num_blocks_is_2_EmbgEptodyewbFa
    cmp 	 $0x10,%rdx
    jge 	 .L_remaining_num_blocks_is_1_EmbgEptodyewbFa

    # _remaining_num_blocks_is_0:
    vmovdqu		%xmm5, %xmm1
    # xmm5 contains last full block to decrypt with next teawk
vpxor %xmm9, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm9, %xmm1, %xmm1
    vmovdqu %xmm1, -0x10(%rsi)
    vmovdqa %xmm1, %xmm8

    # Calc previous tweak
    mov		$0x1,%r8
    kmovq		%r8, %k1
    vpsllq	$0x3f,%xmm9,%xmm13
    vpsraq	$0x3f,%xmm13,%xmm14
    vpandq	%xmm25,%xmm14,%xmm5
    vpxorq        %xmm5,%xmm9,%xmm9{%k1}
    vpsrldq       $0x8,%xmm9,%xmm10
    .byte 98, 211, 181, 8, 115, 194, 1 #vpshrdq $0x1,%xmm10,%xmm9,%xmm0
    vpslldq       $0x8,%xmm13,%xmm13
    vpxorq        %xmm13,%xmm0,%xmm0
    jmp           .L_steal_cipher_EmbgEptodyewbFa

    .L_remaining_num_blocks_is_7_EmbgEptodyewbFa:
    mov 	 $0xffffffffffffffff,%r8
    shr 	 $0x10,%r8
    kmovq 	 %r8,%k1
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2{%k1}
    add 	         $0x70,%rdi
    and            $0xf,%rdx
    je             .L_done_7_remain_EmbgEptodyewbFa
    vextracti32x4   $0x2,%zmm10,%xmm12
    vextracti32x4   $0x3,%zmm10,%xmm13
    vinserti32x4    $0x2,%xmm13,%zmm10,%zmm10
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8 	 %zmm1, (%rsi)
    vmovdqu8 	 %zmm2, 0x40(%rsi){%k1}
    add 	         $0x70, %rsi
    vextracti32x4  $0x2,%zmm2,%xmm8
    vmovdqa        %xmm12,%xmm0
    jmp            .L_steal_cipher_EmbgEptodyewbFa

.L_done_7_remain_EmbgEptodyewbFa:
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1, (%rsi)
    vmovdqu8        %zmm2, 0x40(%rsi){%k1}
    jmp     .L_ret_EmbgEptodyewbFa

    .L_remaining_num_blocks_is_6_EmbgEptodyewbFa:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%ymm2
    add 	         $0x60,%rdi
    and            $0xf, %rdx
    je             .L_done_6_remain_EmbgEptodyewbFa
    vextracti32x4   $0x1,%zmm10,%xmm12
    vextracti32x4   $0x2,%zmm10,%xmm13
    vinserti32x4    $0x1,%xmm13,%zmm10,%zmm10
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8 	 %zmm1, (%rsi)
    vmovdqu8 	 %ymm2, 0x40(%rsi)
    add 	         $0x60,%rsi
    vextracti32x4  $0x1,%zmm2,%xmm8
    vmovdqa        %xmm12,%xmm0
    jmp            .L_steal_cipher_EmbgEptodyewbFa

.L_done_6_remain_EmbgEptodyewbFa:
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1, (%rsi)
    vmovdqu8        %ymm2,0x40(%rsi)
    jmp             .L_ret_EmbgEptodyewbFa

    .L_remaining_num_blocks_is_5_EmbgEptodyewbFa:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu 	 0x40(%rdi),%xmm2
    add 	         $0x50,%rdi
    and            $0xf,%rdx
    je             .L_done_5_remain_EmbgEptodyewbFa
    vmovdqa        %xmm10,%xmm12
    vextracti32x4  $0x1,%zmm10,%xmm10
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8         %zmm1, (%rsi)
    vmovdqu          %xmm2, 0x40(%rsi)
    add              $0x50, %rsi
    vmovdqa          %xmm2,%xmm8
    vmovdqa          %xmm12,%xmm0
    jmp              .L_steal_cipher_EmbgEptodyewbFa

.L_done_5_remain_EmbgEptodyewbFa:
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1, (%rsi)
    vmovdqu8        %xmm2, 0x40(%rsi)
    jmp             .L_ret_EmbgEptodyewbFa

    .L_remaining_num_blocks_is_4_EmbgEptodyewbFa:
    vmovdqu8 	 (%rdi),%zmm1
    add 	         $0x40,%rdi
    and            $0xf, %rdx
    je             .L_done_4_remain_EmbgEptodyewbFa
    vextracti32x4   $0x3,%zmm9,%xmm12
    vinserti32x4    $0x3,%xmm10,%zmm9,%zmm9
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1,(%rsi)
    add             $0x40,%rsi
    vextracti32x4   $0x3,%zmm1,%xmm8
    vmovdqa         %xmm12,%xmm0
    jmp             .L_steal_cipher_EmbgEptodyewbFa

.L_done_4_remain_EmbgEptodyewbFa:
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8        %zmm1, (%rsi)
    jmp             .L_ret_EmbgEptodyewbFa

    .L_remaining_num_blocks_is_3_EmbgEptodyewbFa:
    vmovdqu         (%rdi),%xmm1
    vmovdqu         0x10(%rdi),%xmm2
    vmovdqu         0x20(%rdi),%xmm3
    add             $0x30,%rdi
    and             $0xf,%rdx
    je              .L_done_3_remain_EmbgEptodyewbFa
    vextracti32x4   $0x2,%zmm9,%xmm13
    vextracti32x4   $0x1,%zmm9,%xmm10
    vextracti32x4   $0x3,%zmm9,%xmm11
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    add 	         $0x30,%rsi
    vmovdqa 	 %xmm3,%xmm8
    vmovdqa        %xmm13,%xmm0
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_3_remain_EmbgEptodyewbFa:
vextracti32x4   $0x1,%zmm9,%xmm10
vextracti32x4   $0x2,%zmm9,%xmm11
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
    vmovdqu %xmm1,(%rsi)
    vmovdqu %xmm2,0x10(%rsi)
    vmovdqu %xmm3,0x20(%rsi)
    jmp     .L_ret_EmbgEptodyewbFa

    .L_remaining_num_blocks_is_2_EmbgEptodyewbFa:
    vmovdqu         (%rdi),%xmm1
    vmovdqu         0x10(%rdi),%xmm2
    add             $0x20,%rdi
    and             $0xf,%rdx
    je              .L_done_2_remain_EmbgEptodyewbFa
    vextracti32x4   $0x2,%zmm9,%xmm10
    vextracti32x4   $0x1,%zmm9,%xmm12
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    add 	         $0x20,%rsi
    vmovdqa 	 %xmm2,%xmm8
    vmovdqa 	 %xmm12,%xmm0
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_2_remain_EmbgEptodyewbFa:
vextracti32x4   $0x1,%zmm9,%xmm10
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
    vmovdqu   %xmm1,(%rsi)
    vmovdqu   %xmm2,0x10(%rsi)
    jmp       .L_ret_EmbgEptodyewbFa

    .L_remaining_num_blocks_is_1_EmbgEptodyewbFa:
    vmovdqu 	 (%rdi),%xmm1
    add 	         $0x10,%rdi
    and            $0xf,%rdx
    je             .L_done_1_remain_EmbgEptodyewbFa
    vextracti32x4  $0x1,%zmm9,%xmm11
vpxor %xmm11, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm11, %xmm1, %xmm1
    vmovdqu 	 %xmm1,(%rsi)
    add 	         $0x10,%rsi
    vmovdqa 	 %xmm1,%xmm8
    vmovdqa 	 %xmm9,%xmm0
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_1_remain_EmbgEptodyewbFa:
vpxor %xmm9, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm9, %xmm1, %xmm1
    vmovdqu   %xmm1, (%rsi)
    jmp       .L_ret_EmbgEptodyewbFa

    .L_start_by16_EmbgEptodyewbFa:
    vbroadcasti32x4 	 (%rsp),%zmm0
    vbroadcasti32x4 shufb_15_7(%rip),%zmm8
    mov 	 $0xaa,%r8
    kmovq 	 %r8,%k2

    # Mult tweak by 2^{3, 2, 1, 0}
    vpshufb 	 %zmm8,%zmm0,%zmm1
    vpsllvq const_dq3210(%rip),%zmm0,%zmm4
    vpsrlvq const_dq5678(%rip),%zmm1,%zmm2
    vpclmulqdq 	 $0x0,%zmm25,%zmm2,%zmm3
    vpxorq 	 %zmm2,%zmm4,%zmm4{%k2}
    vpxord 	 %zmm4,%zmm3,%zmm9

    # Mult tweak by 2^{7, 6, 5, 4}
    vpsllvq const_dq7654(%rip),%zmm0,%zmm5
    vpsrlvq const_dq1234(%rip),%zmm1,%zmm6
    vpclmulqdq 	 $0x0,%zmm25,%zmm6,%zmm7
    vpxorq 	 %zmm6,%zmm5,%zmm5{%k2}
    vpxord 	 %zmm5,%zmm7,%zmm10

    # Make next 8 tweak values by all x 2^8
    vpsrldq 	 $0xf,%zmm9,%zmm13
    vpclmulqdq 	 $0x0,%zmm25,%zmm13,%zmm14
    vpslldq 	 $0x1,%zmm9,%zmm11
    vpxord 	 %zmm14,%zmm11,%zmm11

    vpsrldq 	 $0xf,%zmm10,%zmm15
    vpclmulqdq 	 $0x0,%zmm25,%zmm15,%zmm16
    vpslldq 	 $0x1,%zmm10,%zmm12
    vpxord 	 %zmm16,%zmm12,%zmm12

    .L_main_loop_run_16_EmbgEptodyewbFa:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2
    vmovdqu8 	 0x80(%rdi),%zmm3
    vmovdqu8 	 0xc0(%rdi),%zmm4
    vmovdqu8 	 0xf0(%rdi),%xmm5
    add 	 $0x100,%rdi
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
vpxorq    %zmm11, %zmm3, %zmm3
vpxorq    %zmm12, %zmm4, %zmm4
vbroadcasti32x4 (%rcx), %zmm0
vpxorq %zmm0, %zmm1, %zmm1
vpxorq %zmm0, %zmm2, %zmm2
vpxorq %zmm0, %zmm3, %zmm3
vpxorq %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm11, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm11, %zmm15
      vpxord		%zmm14, %zmm15, %zmm15
vbroadcasti32x4 0x10(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x20(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x30(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm12, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm12, %zmm16
      vpxord		%zmm14, %zmm16, %zmm16
vbroadcasti32x4 0x40(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x50(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x60(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm15, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm15, %zmm17
      vpxord		%zmm14, %zmm17, %zmm17
vbroadcasti32x4 0x70(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x80(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0x90(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
      vpsrldq		$0xf, %zmm16, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm16, %zmm18
      vpxord		%zmm14, %zmm18, %zmm18
vbroadcasti32x4 0xa0(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0xb0(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0xc0(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0xd0(%rcx), %zmm0
vaesdec %zmm0, %zmm1, %zmm1
vaesdec %zmm0, %zmm2, %zmm2
vaesdec %zmm0, %zmm3, %zmm3
vaesdec %zmm0, %zmm4, %zmm4
vbroadcasti32x4 0xe0(%rcx), %zmm0
vaesdeclast %zmm0, %zmm1, %zmm1
vaesdeclast %zmm0, %zmm2, %zmm2
vaesdeclast %zmm0, %zmm3, %zmm3
vaesdeclast %zmm0, %zmm4, %zmm4
vpxorq    %zmm9, %zmm1, %zmm1
vpxorq    %zmm10, %zmm2, %zmm2
vpxorq    %zmm11, %zmm3, %zmm3
vpxorq    %zmm12, %zmm4, %zmm4
    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqa32  %zmm17, %zmm11
    vmovdqa32  %zmm18, %zmm12
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi)
    vmovdqu8 	 %zmm3,0x80(%rsi)
    vmovdqu8 	 %zmm4,0xc0(%rsi)
    add 	 $0x100,%rsi
    sub 	 $0x100,%rdx
    cmp 	 $0x100,%rdx
    jge 	 .L_main_loop_run_16_EmbgEptodyewbFa

    cmp 	 $0x80,%rdx
    jge 	 .L_main_loop_run_8_EmbgEptodyewbFa
    jmp 	 .L_do_n_blocks_EmbgEptodyewbFa

    .L_start_by8_EmbgEptodyewbFa:
    # Make first 7 tweak values
    vbroadcasti32x4 	 (%rsp),%zmm0
    vbroadcasti32x4 shufb_15_7(%rip),%zmm8
    mov 	 $0xaa,%r8
    kmovq 	 %r8,%k2

    # Mult tweak by 2^{3, 2, 1, 0}
    vpshufb 	 %zmm8,%zmm0,%zmm1
    vpsllvq const_dq3210(%rip),%zmm0,%zmm4
    vpsrlvq const_dq5678(%rip),%zmm1,%zmm2
    vpclmulqdq 	 $0x0,%zmm25,%zmm2,%zmm3
    vpxorq 	 %zmm2,%zmm4,%zmm4{%k2}
    vpxord 	 %zmm4,%zmm3,%zmm9

    # Mult tweak by 2^{7, 6, 5, 4}
    vpsllvq const_dq7654(%rip),%zmm0,%zmm5
    vpsrlvq const_dq1234(%rip),%zmm1,%zmm6
    vpclmulqdq 	 $0x0,%zmm25,%zmm6,%zmm7
    vpxorq 	 %zmm6,%zmm5,%zmm5{%k2}
    vpxord 	 %zmm5,%zmm7,%zmm10

    .L_main_loop_run_8_EmbgEptodyewbFa:
    vmovdqu8 	 (%rdi),%zmm1
    vmovdqu8 	 0x40(%rdi),%zmm2
    vmovdqu8 	 0x70(%rdi),%xmm5
    add 	         $0x80,%rdi
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # ARK
    vbroadcasti32x4 (%rcx), %zmm0
    vpxorq    %zmm0, %zmm1, %zmm1
    vpxorq    %zmm0, %zmm2, %zmm2
      vpsrldq		$0xf, %zmm9, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm9, %zmm15
      vpxord		%zmm14, %zmm15, %zmm15
    vbroadcasti32x4 0x10(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 2
    vbroadcasti32x4 0x20(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 3
    vbroadcasti32x4 0x30(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2
      vpsrldq		$0xf, %zmm10, %zmm13
      vpclmulqdq	$0x0,%zmm25, %zmm13, %zmm14
      vpslldq		$0x1, %zmm10, %zmm16
      vpxord		%zmm14, %zmm16, %zmm16
    # round 4
    vbroadcasti32x4 0x40(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 5
    vbroadcasti32x4 0x50(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 6
    vbroadcasti32x4 0x60(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 7
    vbroadcasti32x4 0x70(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 8
    vbroadcasti32x4 0x80(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

    # round 9
    vbroadcasti32x4 0x90(%rcx), %zmm0
    vaesdec  %zmm0, %zmm1, %zmm1
    vaesdec  %zmm0, %zmm2, %zmm2

      # round 10
      vbroadcasti32x4 0xa0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 11
      vbroadcasti32x4 0xb0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 12
      vbroadcasti32x4 0xc0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 13
      vbroadcasti32x4 0xd0(%rcx), %zmm0
      vaesdec  %zmm0, %zmm1, %zmm1
      vaesdec  %zmm0, %zmm2, %zmm2

      # round 14
      vbroadcasti32x4 0xe0(%rcx), %zmm0
      vaesdeclast  %zmm0, %zmm1, %zmm1
      vaesdeclast  %zmm0, %zmm2, %zmm2
    # xor Tweak values
    vpxorq    %zmm9, %zmm1, %zmm1
    vpxorq    %zmm10, %zmm2, %zmm2

    # load next Tweak values
    vmovdqa32  %zmm15, %zmm9
    vmovdqa32  %zmm16, %zmm10
    vmovdqu8 	 %zmm1,(%rsi)
    vmovdqu8 	 %zmm2,0x40(%rsi)
    add 	 $0x80,%rsi
    sub 	 $0x80,%rdx
    cmp 	 $0x80,%rdx
    jge 	 .L_main_loop_run_8_EmbgEptodyewbFa
    jmp 	 .L_do_n_blocks_EmbgEptodyewbFa

    .L_steal_cipher_EmbgEptodyewbFa:
    # start cipher stealing simplified: xmm8-last cipher block, xmm0-next tweak
    vmovdqa 	 %xmm8,%xmm2

    # shift xmm8 to the left by 16-N_val bytes
    lea vpshufb_shf_table(%rip),%rax
    vmovdqu 	 (%rax,%rdx,1),%xmm10
    vpshufb 	 %xmm10,%xmm8,%xmm8


    vmovdqu 	 -0x10(%rdi,%rdx,1),%xmm3
    vmovdqu 	 %xmm8,-0x10(%rsi,%rdx,1)

    # shift xmm3 to the right by 16-N_val bytes
    lea vpshufb_shf_table(%rip), %rax
    add $16, %rax
    sub 	 %rdx,%rax
    vmovdqu 	 (%rax),%xmm10
    vpxor mask1(%rip),%xmm10,%xmm10
    vpshufb 	 %xmm10,%xmm3,%xmm3

    vpblendvb 	 %xmm10,%xmm2,%xmm3,%xmm3

    # xor Tweak value
    vpxor 	 %xmm0,%xmm3,%xmm8

    # decrypt last block with cipher stealing
    vpxor	(%rcx),%xmm8,%xmm8
    vaesdec	0x10(%rcx),%xmm8,%xmm8
    vaesdec	0x20(%rcx),%xmm8,%xmm8
    vaesdec	0x30(%rcx),%xmm8,%xmm8
    vaesdec	0x40(%rcx),%xmm8,%xmm8
    vaesdec	0x50(%rcx),%xmm8,%xmm8
    vaesdec	0x60(%rcx),%xmm8,%xmm8
    vaesdec	0x70(%rcx),%xmm8,%xmm8
    vaesdec	0x80(%rcx),%xmm8,%xmm8
    vaesdec	0x90(%rcx),%xmm8,%xmm8
      vaesdec	0xa0(%rcx),%xmm8,%xmm8
      vaesdec	0xb0(%rcx),%xmm8,%xmm8
      vaesdec	0xc0(%rcx),%xmm8,%xmm8
      vaesdec	0xd0(%rcx),%xmm8,%xmm8
      vaesdeclast	0xe0(%rcx),%xmm8,%xmm8
    # xor Tweak value
    vpxor 	 %xmm0,%xmm8,%xmm8

    .L_done_EmbgEptodyewbFa:
    # store last ciphertext value
    vmovdqu 	 %xmm8,-0x10(%rsi)
    .L_ret_EmbgEptodyewbFa:
    mov 	 128(%rsp),%rbx
    xor    %r8,%r8
    mov    %r8,128(%rsp)
    # Zero-out the whole of \`%zmm0\`.
    vpxorq %zmm0,%zmm0,%zmm0
    mov %rbp,%rsp
    pop %rbp
    vzeroupper
    ret

    .L_less_than_128_bytes_EmbgEptodyewbFa:
    cmp 	 $0x10,%rdx
    jb 	 .L_ret_EmbgEptodyewbFa

    mov 	 %rdx,%r8
    and 	 $0x70,%r8
    cmp 	 $0x60,%r8
    je 	 .L_num_blocks_is_6_EmbgEptodyewbFa
    cmp 	 $0x50,%r8
    je 	 .L_num_blocks_is_5_EmbgEptodyewbFa
    cmp 	 $0x40,%r8
    je 	 .L_num_blocks_is_4_EmbgEptodyewbFa
    cmp 	 $0x30,%r8
    je 	 .L_num_blocks_is_3_EmbgEptodyewbFa
    cmp 	 $0x20,%r8
    je 	 .L_num_blocks_is_2_EmbgEptodyewbFa
    cmp 	 $0x10,%r8
    je 	 .L_num_blocks_is_1_EmbgEptodyewbFa

.L_num_blocks_is_7_EmbgEptodyewbFa:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 48(%rsp)
mov      %rbx, 48 + 8(%rsp)
vmovdqa  48(%rsp), %xmm12
vmovdqu  48(%rdi), %xmm4
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 64(%rsp)
mov      %rbx, 64 + 8(%rsp)
vmovdqa  64(%rsp), %xmm13
vmovdqu  64(%rdi), %xmm5
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 80(%rsp)
mov      %rbx, 80 + 8(%rsp)
vmovdqa  80(%rsp), %xmm14
vmovdqu  80(%rdi), %xmm6
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 96(%rsp)
mov      %rbx, 96 + 8(%rsp)
vmovdqa  96(%rsp), %xmm15
vmovdqu  96(%rdi), %xmm7
    add    $0x70,%rdi
    and    $0xf,%rdx
    je      .L_done_7_EmbgEptodyewbFa

    .L_steal_cipher_7_EmbgEptodyewbFa:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm15,%xmm16
     vmovdqa     0x10(%rsp),%xmm15
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vpxor %xmm15, %xmm7, %xmm7
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vpxor %xmm0, %xmm6, %xmm6
vpxor %xmm0, %xmm7, %xmm7
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vaesdeclast %xmm0, %xmm6, %xmm6
vaesdeclast %xmm0, %xmm7, %xmm7
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vpxor %xmm15, %xmm7, %xmm7
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    vmovdqu 	 %xmm5,0x40(%rsi)
    vmovdqu 	 %xmm6,0x50(%rsi)
    add 	         $0x70,%rsi
    vmovdqa64 	 %xmm16,%xmm0
    vmovdqa 	 %xmm7,%xmm8
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_7_EmbgEptodyewbFa:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vpxor %xmm15, %xmm7, %xmm7
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vpxor %xmm0, %xmm6, %xmm6
vpxor %xmm0, %xmm7, %xmm7
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vaesdec %xmm0, %xmm7, %xmm7
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vaesdeclast %xmm0, %xmm6, %xmm6
vaesdeclast %xmm0, %xmm7, %xmm7
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vpxor %xmm15, %xmm7, %xmm7
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    vmovdqu 	 %xmm5,0x40(%rsi)
    vmovdqu 	 %xmm6,0x50(%rsi)
    add 	         $0x70,%rsi
    vmovdqa 	 %xmm7,%xmm8
    jmp 	         .L_done_EmbgEptodyewbFa

.L_num_blocks_is_6_EmbgEptodyewbFa:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 48(%rsp)
mov      %rbx, 48 + 8(%rsp)
vmovdqa  48(%rsp), %xmm12
vmovdqu  48(%rdi), %xmm4
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 64(%rsp)
mov      %rbx, 64 + 8(%rsp)
vmovdqa  64(%rsp), %xmm13
vmovdqu  64(%rdi), %xmm5
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 80(%rsp)
mov      %rbx, 80 + 8(%rsp)
vmovdqa  80(%rsp), %xmm14
vmovdqu  80(%rdi), %xmm6
    add    $0x60,%rdi
    and    $0xf,%rdx
    je      .L_done_6_EmbgEptodyewbFa

    .L_steal_cipher_6_EmbgEptodyewbFa:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm14,%xmm15
     vmovdqa     0x10(%rsp),%xmm14
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vpxor %xmm0, %xmm6, %xmm6
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vaesdeclast %xmm0, %xmm6, %xmm6
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    vmovdqu 	 %xmm5,0x40(%rsi)
    add 	         $0x60,%rsi
    vmovdqa 	 %xmm15,%xmm0
    vmovdqa 	 %xmm6,%xmm8
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_6_EmbgEptodyewbFa:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vpxor %xmm0, %xmm6, %xmm6
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vaesdec %xmm0, %xmm6, %xmm6
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vaesdeclast %xmm0, %xmm6, %xmm6
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vpxor %xmm14, %xmm6, %xmm6
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    vmovdqu 	 %xmm5,0x40(%rsi)
    add 	         $0x60,%rsi
    vmovdqa 	 %xmm6,%xmm8
    jmp 	         .L_done_EmbgEptodyewbFa

.L_num_blocks_is_5_EmbgEptodyewbFa:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 48(%rsp)
mov      %rbx, 48 + 8(%rsp)
vmovdqa  48(%rsp), %xmm12
vmovdqu  48(%rdi), %xmm4
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 64(%rsp)
mov      %rbx, 64 + 8(%rsp)
vmovdqa  64(%rsp), %xmm13
vmovdqu  64(%rdi), %xmm5
    add    $0x50,%rdi
    and    $0xf,%rdx
    je      .L_done_5_EmbgEptodyewbFa

    .L_steal_cipher_5_EmbgEptodyewbFa:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm13,%xmm14
     vmovdqa     0x10(%rsp),%xmm13
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    add 	         $0x50,%rsi
    vmovdqa 	 %xmm14,%xmm0
    vmovdqa 	 %xmm5,%xmm8
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_5_EmbgEptodyewbFa:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm5
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vaesdec %xmm0, %xmm5, %xmm5
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vaesdeclast %xmm0, %xmm5, %xmm5
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vpxor %xmm13, %xmm5, %xmm5
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    vmovdqu 	 %xmm4,0x30(%rsi)
    add 	         $0x50,%rsi
    vmovdqa 	 %xmm5,%xmm8
    jmp 	         .L_done_EmbgEptodyewbFa

.L_num_blocks_is_4_EmbgEptodyewbFa:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 48(%rsp)
mov      %rbx, 48 + 8(%rsp)
vmovdqa  48(%rsp), %xmm12
vmovdqu  48(%rdi), %xmm4
    add    $0x40,%rdi
    and    $0xf,%rdx
    je      .L_done_4_EmbgEptodyewbFa

    .L_steal_cipher_4_EmbgEptodyewbFa:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm12,%xmm13
     vmovdqa     0x10(%rsp),%xmm12
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    add 	         $0x40,%rsi
    vmovdqa 	 %xmm13,%xmm0
    vmovdqa 	 %xmm4,%xmm8
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_4_EmbgEptodyewbFa:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vpxor %xmm0, %xmm4, %xmm4
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vaesdec %xmm0, %xmm4, %xmm4
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vaesdeclast %xmm0, %xmm4, %xmm4
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vpxor %xmm12, %xmm4, %xmm4
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    vmovdqu 	 %xmm3,0x20(%rsi)
    add 	         $0x40,%rsi
    vmovdqa 	 %xmm4,%xmm8
    jmp 	         .L_done_EmbgEptodyewbFa

.L_num_blocks_is_3_EmbgEptodyewbFa:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 32(%rsp)
mov      %rbx, 32 + 8(%rsp)
vmovdqa  32(%rsp), %xmm11
vmovdqu  32(%rdi), %xmm3
    add    $0x30,%rdi
    and    $0xf,%rdx
    je      .L_done_3_EmbgEptodyewbFa

    .L_steal_cipher_3_EmbgEptodyewbFa:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm11,%xmm12
     vmovdqa     0x10(%rsp),%xmm11
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    add 	         $0x30,%rsi
    vmovdqa 	 %xmm12,%xmm0
    vmovdqa 	 %xmm3,%xmm8
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_3_EmbgEptodyewbFa:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vpxor %xmm0, %xmm3, %xmm3
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vaesdec %xmm0, %xmm3, %xmm3
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vaesdeclast %xmm0, %xmm3, %xmm3
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm11, %xmm3, %xmm3
    vmovdqu 	 %xmm1,(%rsi)
    vmovdqu 	 %xmm2,0x10(%rsi)
    add 	         $0x30,%rsi
    vmovdqa 	 %xmm3,%xmm8
    jmp 	         .L_done_EmbgEptodyewbFa

.L_num_blocks_is_2_EmbgEptodyewbFa:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
xor      %r11, %r11
shl      $1, %rax
adc      %rbx, %rbx
cmovc    %r10, %r11
xor      %r11, %rax
mov      %rax, 16(%rsp)
mov      %rbx, 16 + 8(%rsp)
vmovdqa  16(%rsp), %xmm10
vmovdqu  16(%rdi), %xmm2
    add    $0x20,%rdi
    and    $0xf,%rdx
    je      .L_done_2_EmbgEptodyewbFa

    .L_steal_cipher_2_EmbgEptodyewbFa:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm10,%xmm11
     vmovdqa     0x10(%rsp),%xmm10
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
    vmovdqu 	 %xmm1,(%rsi)
    add 	         $0x20,%rsi
    vmovdqa 	 %xmm11,%xmm0
    vmovdqa 	 %xmm2,%xmm8
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_2_EmbgEptodyewbFa:
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vpxor %xmm0, %xmm2, %xmm2
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vaesdec %xmm0, %xmm2, %xmm2
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vaesdeclast %xmm0, %xmm2, %xmm2
vpxor %xmm9, %xmm1, %xmm1
vpxor %xmm10, %xmm2, %xmm2
    vmovdqu 	 %xmm1,(%rsi)
    add 	         $0x20,%rsi
    vmovdqa 	 %xmm2,%xmm8
    jmp 	         .L_done_EmbgEptodyewbFa

.L_num_blocks_is_1_EmbgEptodyewbFa:
    vmovdqa  0x0(%rsp), %xmm9
    mov      0x0(%rsp), %rax
    mov      0x08(%rsp), %rbx
    vmovdqu  0x0(%rdi), %xmm1
    add    $0x10,%rdi
    and    $0xf,%rdx
    je      .L_done_1_EmbgEptodyewbFa

    .L_steal_cipher_1_EmbgEptodyewbFa:
     xor         %r11, %r11
     shl         $1, %rax
     adc         %rbx, %rbx
     cmovc       %r10, %r11
     xor         %r11, %rax
     mov         %rax,0x10(%rsp)
     mov         %rbx,0x18(%rsp)
     vmovdqa64   %xmm9,%xmm10
     vmovdqa     0x10(%rsp),%xmm9
vpxor %xmm9, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm9, %xmm1, %xmm1
    add 	         $0x10,%rsi
    vmovdqa 	 %xmm10,%xmm0
    vmovdqa 	 %xmm1,%xmm8
    jmp 	         .L_steal_cipher_EmbgEptodyewbFa

.L_done_1_EmbgEptodyewbFa:
vpxor %xmm9, %xmm1, %xmm1
vmovdqu  (%rcx), %xmm0
vpxor %xmm0, %xmm1, %xmm1
vmovdqu 0x10(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x20(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x30(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x40(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x50(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x60(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x70(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x80(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0x90(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xa0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xb0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xc0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xd0(%rcx), %xmm0
vaesdec %xmm0, %xmm1, %xmm1
vmovdqu 0xe0(%rcx), %xmm0
vaesdeclast %xmm0, %xmm1, %xmm1
vpxor %xmm9, %xmm1, %xmm1
    add 	         $0x10,%rsi
    vmovdqa 	 %xmm1,%xmm8
    jmp 	         .L_done_EmbgEptodyewbFa
    .cfi_endproc
  .section .rodata
  .align 16

  vpshufb_shf_table:
    .quad 0x8786858483828100, 0x8f8e8d8c8b8a8988
    .quad 0x0706050403020100, 0x000e0d0c0b0a0908

  mask1:
    .quad 0x8080808080808080, 0x8080808080808080

  const_dq3210:
    .quad 0, 0, 1, 1, 2, 2, 3, 3
  const_dq5678:
    .quad 8, 8, 7, 7, 6, 6, 5, 5
  const_dq7654:
    .quad 4, 4, 5, 5, 6, 6, 7, 7
  const_dq1234:
    .quad 4, 4, 3, 3, 2, 2, 1, 1

  shufb_15_7:
    .byte  15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 7, 0xff, 0xff
    .byte  0xff, 0xff, 0xff, 0xff, 0xff

.text
`;

export default translateAssembly(code);
