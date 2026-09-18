/**
 * SM3 for x86_64 using the SM3-NI instructions (AVX2-encoded).
 *
 * TypeScript port of OpenSSL crypto/sm3/asm/sm3-x86_64.pl.
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $avx2_sm3_ni=1 and
 * $avx2_sm3_ni_native=1 (the perl probes the assembler; a clang/LLVM 17+
 * environment emits the full SM3-NI implementation with real vsm3*
 * mnemonics, which is also what rustc's LLVM consumes). Without it the
 * perl emits only a ud2 stub.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// Create 4 x 32-bit new words of message schedule W[] using SM3-NI ISA
function sm3msg(
  W03_00: string,
  W07_04: string,
  W11_08: string,
  W15_12: string,
  W19_16: string,
  T1: string,
  T2: string,
): void {
  const T3 = W19_16;
  code += `    vpalignr        $12, ${W07_04}, ${W11_08}, ${T3}
    vpsrldq         $4, ${W15_12}, ${T1}
    vsm3msg1        ${W03_00}, ${T1}, ${T3}
    vpalignr        $12, ${W03_00}, ${W07_04}, ${T1}
    vpalignr        $8, ${W11_08}, ${W15_12}, ${T2}
    vsm3msg2        ${T2}, ${T1}, ${T3}
`;
}

// Performs 4 rounds of SM3 algorithm
//   - consumes 4 words of message schedule W[]
//   - updates SM3 state registers: ABEF and CDGH
function sm3rounds4(
  ABEF: string,
  CDGH: string,
  W03_00: string,
  W07_04: string,
  T1: string,
  R: number,
): void {
  const R2 = R + 2;
  code += `    vpunpcklqdq     ${W07_04}, ${W03_00}, ${T1}
    vsm3rnds2       $${R}, ${T1}, ${ABEF}, ${CDGH}
    vpunpckhqdq     ${W07_04}, ${W03_00}, ${T1}
    vsm3rnds2       $${R2}, ${T1}, ${CDGH}, ${ABEF}
`;
}

code += '.data\n';

{
  // input arguments aliases
  const ctx = '%rdi';
  const p = '%rsi';
  const num = '%rdx';

  code += `.align 16
SHUFF_MASK:
    .byte 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

.text

# void ossl_hwsm3_block_data_order(SM3_CTX *c, const void *p, size_t num)
#
# input: ${ctx} SM3 context
#        ${p}  pointer to the data
#        ${num} number of blocks
#

.globl	ossl_hwsm3_block_data_order
.type	ossl_hwsm3_block_data_order,@function,3
.align	32
ossl_hwsm3_block_data_order:
.cfi_startproc
    endbranch
# Prolog
    push    %rbp
.cfi_push   %rbp
.cfi_def_cfa_register %rbp
.Lossl_hwsm3_block_data_order_seh_setfp:
# Prolog ends here.
.Lossl_hwsm3_block_data_order_seh_prolog_end:
    or ${num}, ${num}
    je .done_hash

    # xmm = D C B A
    # D - most significant word in an \`xmm\`
    # A - least significant word in an \`xmm\`
    vmovdqu         (${ctx}), %xmm6 # xmm6 = D C B A
    vmovdqu         16(${ctx}), %xmm7 # xmm7 = H G F E

    vpshufd         $0x1B, %xmm6, %xmm0
    vpshufd         $0x1B, %xmm7, %xmm1
    vpunpckhqdq     %xmm0, %xmm1, %xmm6
    vpunpcklqdq     %xmm0, %xmm1, %xmm7
    vpsrld          $9, %xmm7, %xmm2
    vpslld          $23, %xmm7, %xmm3
    vpxor           %xmm3, %xmm2, %xmm1
    vpsrld          $19, %xmm7, %xmm4
    vpslld          $13, %xmm7, %xmm5
    vpxor           %xmm5, %xmm4, %xmm0
    # xmm7 = ROL32(C, 23) ROL32(D, 23) ROL32(G, 13) ROL32(H, 13)
    vpblendd        $0x3, %xmm0, %xmm1, %xmm7

    vmovdqa         SHUFF_MASK(%rip), %xmm12

.align 32
.block_loop:
    vmovdqa         %xmm6, %xmm10
    vmovdqa         %xmm7, %xmm11

    # prepare W[0..15] - read and shuffle the data
    vmovdqu         (${p}), %xmm2
    vmovdqu         16(${p}), %xmm3
    vmovdqu         32(${p}), %xmm4
    vmovdqu         48(${p}), %xmm5
    vpshufb         %xmm12, %xmm2, %xmm2                            # xmm2 = W03 W02 W01 W00
    vpshufb         %xmm12, %xmm3, %xmm3                            # xmm3 = W07 W06 W05 W04
    vpshufb         %xmm12, %xmm4, %xmm4                            # xmm4 = W11 W10 W09 W08
    vpshufb         %xmm12, %xmm5, %xmm5                            # xmm5 = W15 W14 W13 W12

`;
  sm3msg('%xmm2', '%xmm3', '%xmm4', '%xmm5', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm2', '%xmm3', '%xmm1', 0);

  code += '    vmovdqa         %xmm8, %xmm2\n';
  sm3msg('%xmm3', '%xmm4', '%xmm5', '%xmm2', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm3', '%xmm4', '%xmm1', 4);

  code += '    vmovdqa         %xmm8, %xmm3\n';
  sm3msg('%xmm4', '%xmm5', '%xmm2', '%xmm3', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm4', '%xmm5', '%xmm1', 8);

  code += '    vmovdqa         %xmm8, %xmm4\n';
  sm3msg('%xmm5', '%xmm2', '%xmm3', '%xmm4', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm5', '%xmm2', '%xmm1', 12);

  code += '    vmovdqa         %xmm8, %xmm5\n';
  sm3msg('%xmm2', '%xmm3', '%xmm4', '%xmm5', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm2', '%xmm3', '%xmm1', 16);

  code += '    vmovdqa         %xmm8, %xmm2\n';
  sm3msg('%xmm3', '%xmm4', '%xmm5', '%xmm2', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm3', '%xmm4', '%xmm1', 20);

  code += '    vmovdqa         %xmm8, %xmm3\n';
  sm3msg('%xmm4', '%xmm5', '%xmm2', '%xmm3', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm4', '%xmm5', '%xmm1', 24);

  code += '    vmovdqa         %xmm8, %xmm4\n';
  sm3msg('%xmm5', '%xmm2', '%xmm3', '%xmm4', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm5', '%xmm2', '%xmm1', 28);

  code += '    vmovdqa         %xmm8, %xmm5\n';
  sm3msg('%xmm2', '%xmm3', '%xmm4', '%xmm5', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm2', '%xmm3', '%xmm1', 32);

  code += '    vmovdqa         %xmm8, %xmm2\n';
  sm3msg('%xmm3', '%xmm4', '%xmm5', '%xmm2', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm3', '%xmm4', '%xmm1', 36);

  code += '    vmovdqa         %xmm8, %xmm3\n';
  sm3msg('%xmm4', '%xmm5', '%xmm2', '%xmm3', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm4', '%xmm5', '%xmm1', 40);

  code += '    vmovdqa         %xmm8, %xmm4\n';
  sm3msg('%xmm5', '%xmm2', '%xmm3', '%xmm4', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm5', '%xmm2', '%xmm1', 44);

  code += '    vmovdqa         %xmm8, %xmm5\n';
  sm3msg('%xmm2', '%xmm3', '%xmm4', '%xmm5', '%xmm8', '%xmm9', '%xmm1');
  sm3rounds4('%xmm6', '%xmm7', '%xmm2', '%xmm3', '%xmm1', 48);

  code += '    vmovdqa         %xmm8, %xmm2\n';
  sm3rounds4('%xmm6', '%xmm7', '%xmm3', '%xmm4', '%xmm1', 52);
  sm3rounds4('%xmm6', '%xmm7', '%xmm4', '%xmm5', '%xmm1', 56);
  sm3rounds4('%xmm6', '%xmm7', '%xmm5', '%xmm2', '%xmm1', 60);

  code += `    # update hash value
    vpxor           %xmm10, %xmm6, %xmm6
    vpxor           %xmm11, %xmm7, %xmm7
    addq             $64, ${p}
    dec             ${num}
    jnz             .block_loop

    # store the hash value back in memory
    vpslld          $9, %xmm7, %xmm2
    vpsrld          $23, %xmm7, %xmm3
    vpxor           %xmm3, %xmm2, %xmm1
    vpslld          $19, %xmm7, %xmm4
    vpsrld          $13, %xmm7, %xmm5
    vpxor           %xmm5, %xmm4, %xmm0
    vpblendd        $0x3, %xmm0, %xmm1, %xmm7
    vpshufd         $0x1B, %xmm6, %xmm0
    vpshufd         $0x1B, %xmm7, %xmm1

    vpunpcklqdq     %xmm1, %xmm0, %xmm6
    vpunpckhqdq     %xmm1, %xmm0, %xmm7

    vmovdqu         %xmm6, (${ctx})
    vmovdqu         %xmm7, 16(${ctx})
.done_hash:
    # Epilog
    pop     %rbp
.cfi_pop     %rbp
    ret
.cfi_endproc
`;
}

export default translateAssembly(code);
