/**
 * SM4 for x86_64 using the SM4-NI instructions (AVX2-encoded).
 *
 * TypeScript port of OpenSSL crypto/sm4/asm/sm4-x86_64.pl.
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2025, Intel Corporation. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $avx2_sm4_ni=1 and
 * $avx2_sm4_ni_native=1 (the perl probes the assembler; a clang/LLVM 17+
 * environment emits the full SM4-NI implementation with real vsm4*
 * mnemonics, which is also what rustc's LLVM consumes). Without it the
 * perl emits only a ud2 stub.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

const prefix = 'hw_x86_64_sm4';

// input arguments aliases for set_key
const userKey = '%rdi';
const key = '%rsi';

// input arguments aliases for encrypt/decrypt
const inp = '%rdi';
const out = '%rsi';
const ks = '%rdx';

code += `.text
.section .rodata align=64
.align 16
SM4_FK:
.long 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc

.align 16
SM4_CK:
.long 0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269
.long 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9
.long 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249
.long 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9
.long 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229
.long 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299
.long 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209
.long 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279

IN_SHUFB:
.byte 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
.byte 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
.byte 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
.byte 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

OUT_SHUFB:
.byte 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
.byte 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
.byte 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
.byte 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00

.text

# int ${prefix}_set_key(const unsigned char *userKey, SM4_KEY *key)
#
# input: ${userKey} secret key
#        ${key}  round keys
#

.globl    ${prefix}_set_key
.type     ${prefix}_set_key,@function,2
.align    32
${prefix}_set_key:
.cfi_startproc
    endbranch
# Prolog
    push    %rbp
.cfi_push   %rbp
# Prolog ends here.
.Lossl_${prefix}_set_key_seh_prolog_end:

    vmovdqu         (${userKey}), %xmm0
    vpshufb         IN_SHUFB(%rip), %xmm0, %xmm0
    vpxor           SM4_FK(%rip), %xmm0, %xmm0

    vmovdqu         SM4_CK(%rip), %xmm1
    vsm4key4        %xmm1, %xmm0, %xmm0
    vmovdqu         %xmm0, (${key})
`;

// 8 key-schedule rounds: SM4_CK + {16,32,...,112}(%rip) into key+same offset
for (let i = 1; i < 8; i++) {
  const off = i * 16;
  code += `    vmovdqu         SM4_CK + ${off}(%rip), %xmm1
    vsm4key4        %xmm1, %xmm0, %xmm0
    vmovdqu         %xmm0, ${off}(${key})
`;
}

code += `
    vpxor           %xmm0, %xmm0, %xmm0 # clear register
    mov     $1, %eax
    pop     %rbp
.cfi_pop     %rbp
    ret
.cfi_endproc

# void ${prefix}_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)

.globl    ${prefix}_encrypt
.type     ${prefix}_encrypt,@function,3
.align    32
${prefix}_encrypt:
.cfi_startproc
    endbranch
# Prolog
    push    %rbp
.cfi_push   %rbp
# Prolog ends here.
.Lossl_${prefix}_encrypt_seh_prolog_end:

    vmovdqu         (${inp}), %xmm0
    vpshufb         IN_SHUFB(%rip), %xmm0, %xmm0

    # note: to simplify binary instructions translation
    mov             ${ks}, %r10

`;

for (let i = 0; i < 8; i++) {
  const off = i * 16;
  code += `    vsm4rnds4       ${off === 0 ? '' : off}(%r10), %xmm0, %xmm0\n`;
}

code += `
    vpshufb         OUT_SHUFB(%rip), %xmm0, %xmm0
    vmovdqu         %xmm0, (${out})
    vpxor           %xmm0, %xmm0, %xmm0 # clear register
    pop             %rbp
.cfi_pop            %rbp
    ret
.cfi_endproc

# void ${prefix}_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)

.globl    ${prefix}_decrypt
.type     ${prefix}_decrypt,@function,3
.align    32
${prefix}_decrypt:
.cfi_startproc
    endbranch
# Prolog
    push    %rbp
.cfi_push   %rbp
# Prolog ends here.
.Lossl_${prefix}_decrypt_seh_prolog_end:

    vmovdqu         (${inp}), %xmm0
    vpshufb         IN_SHUFB(%rip), %xmm0, %xmm0

`;

// Decrypt walks the key schedule in reverse and reverses the four dwords
// inside each xmm (vpshufd $27 == 0x1B).
for (let i = 7; i >= 0; i--) {
  const off = i * 16;
  code += `    vmovdqu         ${off === 0 ? '' : off}(${ks}), %xmm1
    vpshufd         $27, %xmm1, %xmm1
    vsm4rnds4       %xmm1, %xmm0, %xmm0
`;
}

code += `
    vpshufb         OUT_SHUFB(%rip), %xmm0, %xmm0
    vmovdqu         %xmm0, (${out})
    vpxor           %xmm0, %xmm0, %xmm0 # clear registers
    vpxor           %xmm1, %xmm1, %xmm1
    pop             %rbp
.cfi_pop            %rbp
    ret
.cfi_endproc
`;

export default translateAssembly(code);
