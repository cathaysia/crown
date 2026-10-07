/**
 * ChaCha20 stream cipher (ARMv8 SVE2) for aarch64.
 *
 * Frozen assembly output of OpenSSL crypto/chacha/asm/chacha-armv8-sve.pl (linux64 flavour),
 * preprocessed with the C preprocessor the way the OpenSSL build does
 * (arm_arch.h is included and the ARMv8 support macros are expanded),
 * then embedded verbatim. Regenerate with:
 *
 *   scripts/gen-aarch64-asm.py chacha-sve
 *
 * Copyright 2022-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0 (https://www.openssl.org/source/license.html).
 */

// Exported entry points: ChaCha20_ctr32_sve

const asm = `.arch armv8-a
.hidden OPENSSL_armcap_P
.text
.section .rodata
.align 5
.type _chacha_sve_consts,%object
_chacha_sve_consts:
.Lchacha20_consts:
.quad 0x3320646e61707865,0x6b20657479622d32
.Lrot8:
.word 0x02010003,0x04040404,0x02010003,0x04040404
.size _chacha_sve_consts,.-_chacha_sve_consts
.previous
.globl ChaCha20_ctr32_sve
.type ChaCha20_ctr32_sve,%function
.align 5
ChaCha20_ctr32_sve:

.inst 0x04a0e3e5
 cmp x2,x5,lsl #6
 b.lt .Lreturn
 mov x7,0
 adrp x6,OPENSSL_armcap_P
 ldr w6,[x6,#:lo12:OPENSSL_armcap_P]
 tst w6,#(1 << 14)
 b.eq 1f
 mov x7,1
 b 2f
1:
 cmp x5,4
 b.le .Lreturn
 adrp x6,.Lrot8
 add x6,x6,#:lo12:.Lrot8
 ldp w9,w10,[x6]
.inst 0x04aa4d3f
2:

 stp d8,d9,[sp,-192]!
 stp d10,d11,[sp,16]
 stp d12,d13,[sp,32]
 stp d14,d15,[sp,48]
 stp x16,x17,[sp,64]
 stp x18,x19,[sp,80]
 stp x20,x21,[sp,96]
 stp x22,x23,[sp,112]
 stp x24,x25,[sp,128]
 stp x26,x27,[sp,144]
 stp x28,x29,[sp,160]
 str x30,[sp,176]
 adrp x6,.Lchacha20_consts
 add x6,x6,#:lo12:.Lchacha20_consts
 ldp x23,x24,[x6]
 ldp x25,x26,[x3]
 ldp x27,x28,[x3, 16]
 ldp x29,x30,[x4]
.inst 0x2599e3e0
 cbz x7, 1f
.align 5
100:
 subs x7,x2,x5,lsl #6
 b.lt 110f
 mov x2,x7
 b.eq 101f
 cmp x2,64
 b.lt 101f
 mixin=1
 lsr x8,x23,#32
.inst 0x05a03ae0
.inst 0x05a03af9
.if mixin == 1
 mov w7,w23
.endif
.inst 0x05a03904
.inst 0x05a0391a
 lsr x10,x24,#32
.inst 0x05a03b08
.inst 0x05a03b1b
.if mixin == 1
 mov w9,w24
.endif
.inst 0x05a0394c
.inst 0x05a0395c
 lsr x12,x25,#32
.inst 0x05a03b21
.inst 0x05a03b3d
.if mixin == 1
 mov w11,w25
.endif
.inst 0x05a03985
.inst 0x05a0399e
 lsr x14,x26,#32
.inst 0x05a03b49
.inst 0x05a03b55
.if mixin == 1
 mov w13,w26
.endif
.inst 0x05a039cd
.inst 0x05a039d6
 lsr x16,x27,#32
.inst 0x05a03b62
.inst 0x05a03b77
.if mixin == 1
 mov w15,w27
.endif
.inst 0x05a03a06
.inst 0x05a03a18
 lsr x18,x28,#32
.inst 0x05a03b8a
.inst 0x05a03b91
.if mixin == 1
 mov w17,w28
.endif
.inst 0x05a03a4e
.inst 0x05a03a52
 lsr x22,x30,#32
.inst 0x05a03bcb
.inst 0x05a03bd4
.if mixin == 1
 mov w21,w30
.endif
.inst 0x05a03acf
.inst 0x05a03adf
.if mixin == 1
 add w20,w29,#1
 mov w19,w29
.inst 0x04a14690
.inst 0x04a14683
.else
.inst 0x04a147b0
.inst 0x04a147a3
.endif
 lsr x20,x29,#32
.inst 0x05a03a87
.inst 0x05a03a93
 mov x6,#10
10:
.align 5
.inst 0x04a10000
.if mixin == 1
 add w7,w7,w11
.endif
.inst 0x04a50084
.if mixin == 1
 add w8,w8,w12
.endif
.inst 0x04a90108
.if mixin == 1
 add w9,w9,w13
.endif
.inst 0x04ad018c
.if mixin == 1
 add w10,w10,w14
.endif
.if mixin == 1
 eor w19,w19,w7
.endif
.inst 0x04703403
.if mixin == 1
 ror w19,w19,16
.endif
.if mixin == 1
 eor w20,w20,w8
.endif
.inst 0x04703487
.if mixin == 1
 ror w20,w20,16
.endif
.if mixin == 1
 eor w21,w21,w9
.endif
.inst 0x0470350b
.if mixin == 1
 ror w21,w21,16
.endif
.if mixin == 1
 eor w22,w22,w10
.endif
.inst 0x0470358f
.if mixin == 1
 ror w22,w22,16
.endif
.inst 0x04a30042
.if mixin == 1
 add w15,w15,w19
.endif
.inst 0x04a700c6
.if mixin == 1
 add w16,w16,w20
.endif
.inst 0x04ab014a
.if mixin == 1
 add w17,w17,w21
.endif
.inst 0x04af01ce
.if mixin == 1
 add w18,w18,w22
.endif
.if mixin == 1
 eor w11,w11,w15
.endif
.inst 0x046c3441
.if mixin == 1
 ror w11,w11,20
.endif
.if mixin == 1
 eor w12,w12,w16
.endif
.inst 0x046c34c5
.if mixin == 1
 ror w12,w12,20
.endif
.if mixin == 1
 eor w13,w13,w17
.endif
.inst 0x046c3549
.if mixin == 1
 ror w13,w13,20
.endif
.if mixin == 1
 eor w14,w14,w18
.endif
.inst 0x046c35cd
.if mixin == 1
 ror w14,w14,20
.endif
.inst 0x04a10000
.if mixin == 1
 add w7,w7,w11
.endif
.inst 0x04a50084
.if mixin == 1
 add w8,w8,w12
.endif
.inst 0x04a90108
.if mixin == 1
 add w9,w9,w13
.endif
.inst 0x04ad018c
.if mixin == 1
 add w10,w10,w14
.endif
.if mixin == 1
 eor w19,w19,w7
.endif
.inst 0x04683403
.if mixin == 1
 ror w19,w19,24
.endif
.if mixin == 1
 eor w20,w20,w8
.endif
.inst 0x04683487
.if mixin == 1
 ror w20,w20,24
.endif
.if mixin == 1
 eor w21,w21,w9
.endif
.inst 0x0468350b
.if mixin == 1
 ror w21,w21,24
.endif
.if mixin == 1
 eor w22,w22,w10
.endif
.inst 0x0468358f
.if mixin == 1
 ror w22,w22,24
.endif
.inst 0x04a30042
.if mixin == 1
 add w15,w15,w19
.endif
.inst 0x04a700c6
.if mixin == 1
 add w16,w16,w20
.endif
.inst 0x04ab014a
.if mixin == 1
 add w17,w17,w21
.endif
.inst 0x04af01ce
.if mixin == 1
 add w18,w18,w22
.endif
.if mixin == 1
 eor w11,w11,w15
.endif
.inst 0x04673441
.if mixin == 1
 ror w11,w11,25
.endif
.if mixin == 1
 eor w12,w12,w16
.endif
.inst 0x046734c5
.if mixin == 1
 ror w12,w12,25
.endif
.if mixin == 1
 eor w13,w13,w17
.endif
.inst 0x04673549
.if mixin == 1
 ror w13,w13,25
.endif
.if mixin == 1
 eor w14,w14,w18
.endif
.inst 0x046735cd
.if mixin == 1
 ror w14,w14,25
.endif
.inst 0x04a50000
.if mixin == 1
 add w7,w7,w12
.endif
.inst 0x04a90084
.if mixin == 1
 add w8,w8,w13
.endif
.inst 0x04ad0108
.if mixin == 1
 add w9,w9,w14
.endif
.inst 0x04a1018c
.if mixin == 1
 add w10,w10,w11
.endif
.if mixin == 1
 eor w22,w22,w7
.endif
.inst 0x0470340f
.if mixin == 1
 ror w22,w22,16
.endif
.if mixin == 1
 eor w19,w19,w8
.endif
.inst 0x04703483
.if mixin == 1
 ror w19,w19,16
.endif
.if mixin == 1
 eor w20,w20,w9
.endif
.inst 0x04703507
.if mixin == 1
 ror w20,w20,16
.endif
.if mixin == 1
 eor w21,w21,w10
.endif
.inst 0x0470358b
.if mixin == 1
 ror w21,w21,16
.endif
.inst 0x04af014a
.if mixin == 1
 add w17,w17,w22
.endif
.inst 0x04a301ce
.if mixin == 1
 add w18,w18,w19
.endif
.inst 0x04a70042
.if mixin == 1
 add w15,w15,w20
.endif
.inst 0x04ab00c6
.if mixin == 1
 add w16,w16,w21
.endif
.if mixin == 1
 eor w12,w12,w17
.endif
.inst 0x046c3545
.if mixin == 1
 ror w12,w12,20
.endif
.if mixin == 1
 eor w13,w13,w18
.endif
.inst 0x046c35c9
.if mixin == 1
 ror w13,w13,20
.endif
.if mixin == 1
 eor w14,w14,w15
.endif
.inst 0x046c344d
.if mixin == 1
 ror w14,w14,20
.endif
.if mixin == 1
 eor w11,w11,w16
.endif
.inst 0x046c34c1
.if mixin == 1
 ror w11,w11,20
.endif
.inst 0x04a50000
.if mixin == 1
 add w7,w7,w12
.endif
.inst 0x04a90084
.if mixin == 1
 add w8,w8,w13
.endif
.inst 0x04ad0108
.if mixin == 1
 add w9,w9,w14
.endif
.inst 0x04a1018c
.if mixin == 1
 add w10,w10,w11
.endif
.if mixin == 1
 eor w22,w22,w7
.endif
.inst 0x0468340f
.if mixin == 1
 ror w22,w22,24
.endif
.if mixin == 1
 eor w19,w19,w8
.endif
.inst 0x04683483
.if mixin == 1
 ror w19,w19,24
.endif
.if mixin == 1
 eor w20,w20,w9
.endif
.inst 0x04683507
.if mixin == 1
 ror w20,w20,24
.endif
.if mixin == 1
 eor w21,w21,w10
.endif
.inst 0x0468358b
.if mixin == 1
 ror w21,w21,24
.endif
.inst 0x04af014a
.if mixin == 1
 add w17,w17,w22
.endif
.inst 0x04a301ce
.if mixin == 1
 add w18,w18,w19
.endif
.inst 0x04a70042
.if mixin == 1
 add w15,w15,w20
.endif
.inst 0x04ab00c6
.if mixin == 1
 add w16,w16,w21
.endif
.if mixin == 1
 eor w12,w12,w17
.endif
.inst 0x04673545
.if mixin == 1
 ror w12,w12,25
.endif
.if mixin == 1
 eor w13,w13,w18
.endif
.inst 0x046735c9
.if mixin == 1
 ror w13,w13,25
.endif
.if mixin == 1
 eor w14,w14,w15
.endif
.inst 0x0467344d
.if mixin == 1
 ror w14,w14,25
.endif
.if mixin == 1
 eor w11,w11,w16
.endif
.inst 0x046734c1
.if mixin == 1
 ror w11,w11,25
.endif
 sub x6,x6,1
 cbnz x6,10b
.if mixin == 1
 add w7,w7,w23
.endif
.inst 0x04b90000
.if mixin == 1
 add x8,x8,x23,lsr #32
.endif
.inst 0x04ba0084
.if mixin == 1
 add x7,x7,x8,lsl #32
.endif
.if mixin == 1
 add w9,w9,w24
.endif
.inst 0x04bb0108
.if mixin == 1
 add x10,x10,x24,lsr #32
.endif
.inst 0x04bc018c
.if mixin == 1
 add x9,x9,x10,lsl #32
.endif
.if mixin == 1
 ldp x8,x10,[x1],#16
.endif
.if mixin == 1
 add w11,w11,w25
.endif
.inst 0x04bd0021
.if mixin == 1
 add x12,x12,x25,lsr #32
.endif
.inst 0x04be00a5
.if mixin == 1
 add x11,x11,x12,lsl #32
.endif
.if mixin == 1
 add w13,w13,w26
.endif
.inst 0x04b50129
.if mixin == 1
 add x14,x14,x26,lsr #32
.endif
.inst 0x04b601ad
.if mixin == 1
 add x13,x13,x14,lsl #32
.endif
.if mixin == 1
 ldp x12,x14,[x1],#16
.endif
.if mixin == 1
 add w15,w15,w27
.endif
.inst 0x04b70042
.if mixin == 1
 add x16,x16,x27,lsr #32
.endif
.inst 0x04b800c6
.if mixin == 1
 add x15,x15,x16,lsl #32
.endif
.if mixin == 1
 add w17,w17,w28
.endif
.inst 0x04b1014a
.if mixin == 1
 add x18,x18,x28,lsr #32
.endif
.inst 0x04b201ce
.if mixin == 1
 add x17,x17,x18,lsl #32
.endif
.if mixin == 1
 ldp x16,x18,[x1],#16
.endif
.if mixin == 1
 add w19,w19,w29
.endif
.inst 0x04b00063
.if mixin == 1
 add x20,x20,x29,lsr #32
.endif
.inst 0x04b300e7
.if mixin == 1
 add x19,x19,x20,lsl #32
.endif
.if mixin == 1
 add w21,w21,w30
.endif
.inst 0x04b4016b
.if mixin == 1
 add x22,x22,x30,lsr #32
.endif
.inst 0x04bf01ef
.if mixin == 1
 add x21,x21,x22,lsl #32
.endif
.if mixin == 1
 ldp x20,x22,[x1],#16
.endif
.if mixin == 1
 add x29,x29,#1
.endif
 cmp x5,4
 b.ne 200f
.if mixin == 1
 eor x7,x7,x8
.endif
.if mixin == 1
 eor x9,x9,x10
.endif
.if mixin == 1
 eor x11,x11,x12
.endif
.inst 0x05a46011
.inst 0x05a46412
.inst 0x05ac6113
.inst 0x05ac6514
.inst 0x05a56035
.inst 0x05a56436
.inst 0x05ad6137
.inst 0x05ad6538
.inst 0x05f36220
.inst 0x05f36624
.inst 0x05f46248
.inst 0x05f4664c
.inst 0x05f762a1
.inst 0x05f766a5
.inst 0x05f862c9
.inst 0x05f866cd
.if mixin == 1
 eor x13,x13,x14
.endif
.if mixin == 1
 eor x15,x15,x16
.endif
.if mixin == 1
 eor x17,x17,x18
.endif
.inst 0x05a66051
.inst 0x05a66452
.inst 0x05ae6153
.inst 0x05ae6554
.inst 0x05a76075
.inst 0x05a76476
.inst 0x05af6177
.inst 0x05af6578
.inst 0x05f36222
.inst 0x05f36626
.inst 0x05f4624a
.inst 0x05f4664e
.inst 0x05f762a3
.inst 0x05f766a7
.inst 0x05f862cb
.inst 0x05f866cf
.if mixin == 1
 eor x19,x19,x20
.endif
.if mixin == 1
 eor x21,x21,x22
.endif
 ld1 {v17.4s,v18.4s,v19.4s,v20.4s},[x1],#64
 ld1 {v21.4s,v22.4s,v23.4s,v24.4s},[x1],#64
.inst 0x04b13000
.inst 0x04b23021
.inst 0x04b33042
.inst 0x04b43063
.inst 0x04b53084
.inst 0x04b630a5
.inst 0x04b730c6
.inst 0x04b830e7
 ld1 {v17.4s,v18.4s,v19.4s,v20.4s},[x1],#64
 ld1 {v21.4s,v22.4s,v23.4s,v24.4s},[x1],#64
.if mixin == 1
 stp x7,x9,[x0],#16
.endif
.inst 0x04b13108
.inst 0x04b23129
.if mixin == 1
 stp x11,x13,[x0],#16
.endif
.inst 0x04b3314a
.inst 0x04b4316b
.if mixin == 1
 stp x15,x17,[x0],#16
.endif
.inst 0x04b5318c
.inst 0x04b631ad
.if mixin == 1
 stp x19,x21,[x0],#16
.endif
.inst 0x04b731ce
.inst 0x04b831ef
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x0],#64
 st1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 st1 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
 st1 {v12.4s,v13.4s,v14.4s,v15.4s},[x0],#64
 b 210f
200:
.inst 0x05a16011
.inst 0x05a16412
.inst 0x05a36053
.inst 0x05a36454
.inst 0x05a56095
.inst 0x05a56496
.inst 0x05a760d7
.inst 0x05a764d8
.inst 0x05f36220
.inst 0x05f36621
.inst 0x05f46242
.inst 0x05f46643
.inst 0x05f762a4
.inst 0x05f766a5
.inst 0x05f862c6
.inst 0x05f866c7
.if mixin == 1
 eor x7,x7,x8
.endif
.if mixin == 1
 eor x9,x9,x10
.endif
.inst 0x05a96111
.inst 0x05a96512
.inst 0x05ab6153
.inst 0x05ab6554
.inst 0x05ad6195
.inst 0x05ad6596
.inst 0x05af61d7
.inst 0x05af65d8
.inst 0x05f36228
.inst 0x05f36629
.inst 0x05f4624a
.inst 0x05f4664b
.inst 0x05f762ac
.inst 0x05f766ad
.inst 0x05f862ce
.inst 0x05f866cf
.if mixin == 1
 eor x11,x11,x12
.endif
.if mixin == 1
 eor x13,x13,x14
.endif
.inst 0x05a46011
.inst 0x05a46412
.inst 0x05ac6113
.inst 0x05ac6514
.inst 0x05a56035
.inst 0x05a56436
.inst 0x05ad6137
.inst 0x05ad6538
.inst 0x05f36220
.inst 0x05f36624
.inst 0x05f46248
.inst 0x05f4664c
.inst 0x05f762a1
.inst 0x05f766a5
.inst 0x05f862c9
.inst 0x05f866cd
.if mixin == 1
 eor x15,x15,x16
.endif
.if mixin == 1
 eor x17,x17,x18
.endif
.inst 0x05a66051
.inst 0x05a66452
.inst 0x05ae6153
.inst 0x05ae6554
.inst 0x05a76075
.inst 0x05a76476
.inst 0x05af6177
.inst 0x05af6578
.inst 0x05f36222
.inst 0x05f36626
.inst 0x05f4624a
.inst 0x05f4664e
.inst 0x05f762a3
.inst 0x05f766a7
.inst 0x05f862cb
.inst 0x05f866cf
.if mixin == 1
 eor x19,x19,x20
.endif
.if mixin == 1
 eor x21,x21,x22
.endif
.inst 0xa540a031
.inst 0xa541a032
.inst 0xa542a033
.inst 0xa543a034
.inst 0xa544a035
.inst 0xa545a036
.inst 0xa546a037
.inst 0xa547a038
.inst 0x04215101
.inst 0x04b13000
.inst 0x04b23084
.inst 0x04b33108
.inst 0x04b4318c
.inst 0x04b53021
.inst 0x04b630a5
.inst 0x04b73129
.inst 0x04b831ad
.inst 0xa540a031
.inst 0xa541a032
.inst 0xa542a033
.inst 0xa543a034
.inst 0xa544a035
.inst 0xa545a036
.inst 0xa546a037
.inst 0xa547a038
.inst 0x04215101
.if mixin == 1
 stp x7,x9,[x0],#16
.endif
.inst 0x04b13042
.inst 0x04b230c6
.if mixin == 1
 stp x11,x13,[x0],#16
.endif
.inst 0x04b3314a
.inst 0x04b431ce
.if mixin == 1
 stp x15,x17,[x0],#16
.endif
.inst 0x04b53063
.inst 0x04b630e7
.if mixin == 1
 stp x19,x21,[x0],#16
.endif
.inst 0x04b7316b
.inst 0x04b831ef
.inst 0xe540e000
.inst 0xe541e004
.inst 0xe542e008
.inst 0xe543e00c
.inst 0xe544e001
.inst 0xe545e005
.inst 0xe546e009
.inst 0xe547e00d
.inst 0x04205100
.inst 0xe540e002
.inst 0xe541e006
.inst 0xe542e00a
.inst 0xe543e00e
.inst 0xe544e003
.inst 0xe545e007
.inst 0xe546e00b
.inst 0xe547e00f
.inst 0x04205100
210:
.inst 0x04b0e3fd
 subs x2,x2,64
 b.gt 100b
 b 110f
101:
 mixin=0
 lsr x8,x23,#32
.inst 0x05a03ae0
.inst 0x05a03af9
.if mixin == 1
 mov w7,w23
.endif
.inst 0x05a03904
.inst 0x05a0391a
 lsr x10,x24,#32
.inst 0x05a03b08
.inst 0x05a03b1b
.if mixin == 1
 mov w9,w24
.endif
.inst 0x05a0394c
.inst 0x05a0395c
 lsr x12,x25,#32
.inst 0x05a03b21
.inst 0x05a03b3d
.if mixin == 1
 mov w11,w25
.endif
.inst 0x05a03985
.inst 0x05a0399e
 lsr x14,x26,#32
.inst 0x05a03b49
.inst 0x05a03b55
.if mixin == 1
 mov w13,w26
.endif
.inst 0x05a039cd
.inst 0x05a039d6
 lsr x16,x27,#32
.inst 0x05a03b62
.inst 0x05a03b77
.if mixin == 1
 mov w15,w27
.endif
.inst 0x05a03a06
.inst 0x05a03a18
 lsr x18,x28,#32
.inst 0x05a03b8a
.inst 0x05a03b91
.if mixin == 1
 mov w17,w28
.endif
.inst 0x05a03a4e
.inst 0x05a03a52
 lsr x22,x30,#32
.inst 0x05a03bcb
.inst 0x05a03bd4
.if mixin == 1
 mov w21,w30
.endif
.inst 0x05a03acf
.inst 0x05a03adf
.if mixin == 1
 add w20,w29,#1
 mov w19,w29
.inst 0x04a14690
.inst 0x04a14683
.else
.inst 0x04a147b0
.inst 0x04a147a3
.endif
 lsr x20,x29,#32
.inst 0x05a03a87
.inst 0x05a03a93
 mov x6,#10
10:
.align 5
.inst 0x04a10000
.if mixin == 1
 add w7,w7,w11
.endif
.inst 0x04a50084
.if mixin == 1
 add w8,w8,w12
.endif
.inst 0x04a90108
.if mixin == 1
 add w9,w9,w13
.endif
.inst 0x04ad018c
.if mixin == 1
 add w10,w10,w14
.endif
.if mixin == 1
 eor w19,w19,w7
.endif
.inst 0x04703403
.if mixin == 1
 ror w19,w19,16
.endif
.if mixin == 1
 eor w20,w20,w8
.endif
.inst 0x04703487
.if mixin == 1
 ror w20,w20,16
.endif
.if mixin == 1
 eor w21,w21,w9
.endif
.inst 0x0470350b
.if mixin == 1
 ror w21,w21,16
.endif
.if mixin == 1
 eor w22,w22,w10
.endif
.inst 0x0470358f
.if mixin == 1
 ror w22,w22,16
.endif
.inst 0x04a30042
.if mixin == 1
 add w15,w15,w19
.endif
.inst 0x04a700c6
.if mixin == 1
 add w16,w16,w20
.endif
.inst 0x04ab014a
.if mixin == 1
 add w17,w17,w21
.endif
.inst 0x04af01ce
.if mixin == 1
 add w18,w18,w22
.endif
.if mixin == 1
 eor w11,w11,w15
.endif
.inst 0x046c3441
.if mixin == 1
 ror w11,w11,20
.endif
.if mixin == 1
 eor w12,w12,w16
.endif
.inst 0x046c34c5
.if mixin == 1
 ror w12,w12,20
.endif
.if mixin == 1
 eor w13,w13,w17
.endif
.inst 0x046c3549
.if mixin == 1
 ror w13,w13,20
.endif
.if mixin == 1
 eor w14,w14,w18
.endif
.inst 0x046c35cd
.if mixin == 1
 ror w14,w14,20
.endif
.inst 0x04a10000
.if mixin == 1
 add w7,w7,w11
.endif
.inst 0x04a50084
.if mixin == 1
 add w8,w8,w12
.endif
.inst 0x04a90108
.if mixin == 1
 add w9,w9,w13
.endif
.inst 0x04ad018c
.if mixin == 1
 add w10,w10,w14
.endif
.if mixin == 1
 eor w19,w19,w7
.endif
.inst 0x04683403
.if mixin == 1
 ror w19,w19,24
.endif
.if mixin == 1
 eor w20,w20,w8
.endif
.inst 0x04683487
.if mixin == 1
 ror w20,w20,24
.endif
.if mixin == 1
 eor w21,w21,w9
.endif
.inst 0x0468350b
.if mixin == 1
 ror w21,w21,24
.endif
.if mixin == 1
 eor w22,w22,w10
.endif
.inst 0x0468358f
.if mixin == 1
 ror w22,w22,24
.endif
.inst 0x04a30042
.if mixin == 1
 add w15,w15,w19
.endif
.inst 0x04a700c6
.if mixin == 1
 add w16,w16,w20
.endif
.inst 0x04ab014a
.if mixin == 1
 add w17,w17,w21
.endif
.inst 0x04af01ce
.if mixin == 1
 add w18,w18,w22
.endif
.if mixin == 1
 eor w11,w11,w15
.endif
.inst 0x04673441
.if mixin == 1
 ror w11,w11,25
.endif
.if mixin == 1
 eor w12,w12,w16
.endif
.inst 0x046734c5
.if mixin == 1
 ror w12,w12,25
.endif
.if mixin == 1
 eor w13,w13,w17
.endif
.inst 0x04673549
.if mixin == 1
 ror w13,w13,25
.endif
.if mixin == 1
 eor w14,w14,w18
.endif
.inst 0x046735cd
.if mixin == 1
 ror w14,w14,25
.endif
.inst 0x04a50000
.if mixin == 1
 add w7,w7,w12
.endif
.inst 0x04a90084
.if mixin == 1
 add w8,w8,w13
.endif
.inst 0x04ad0108
.if mixin == 1
 add w9,w9,w14
.endif
.inst 0x04a1018c
.if mixin == 1
 add w10,w10,w11
.endif
.if mixin == 1
 eor w22,w22,w7
.endif
.inst 0x0470340f
.if mixin == 1
 ror w22,w22,16
.endif
.if mixin == 1
 eor w19,w19,w8
.endif
.inst 0x04703483
.if mixin == 1
 ror w19,w19,16
.endif
.if mixin == 1
 eor w20,w20,w9
.endif
.inst 0x04703507
.if mixin == 1
 ror w20,w20,16
.endif
.if mixin == 1
 eor w21,w21,w10
.endif
.inst 0x0470358b
.if mixin == 1
 ror w21,w21,16
.endif
.inst 0x04af014a
.if mixin == 1
 add w17,w17,w22
.endif
.inst 0x04a301ce
.if mixin == 1
 add w18,w18,w19
.endif
.inst 0x04a70042
.if mixin == 1
 add w15,w15,w20
.endif
.inst 0x04ab00c6
.if mixin == 1
 add w16,w16,w21
.endif
.if mixin == 1
 eor w12,w12,w17
.endif
.inst 0x046c3545
.if mixin == 1
 ror w12,w12,20
.endif
.if mixin == 1
 eor w13,w13,w18
.endif
.inst 0x046c35c9
.if mixin == 1
 ror w13,w13,20
.endif
.if mixin == 1
 eor w14,w14,w15
.endif
.inst 0x046c344d
.if mixin == 1
 ror w14,w14,20
.endif
.if mixin == 1
 eor w11,w11,w16
.endif
.inst 0x046c34c1
.if mixin == 1
 ror w11,w11,20
.endif
.inst 0x04a50000
.if mixin == 1
 add w7,w7,w12
.endif
.inst 0x04a90084
.if mixin == 1
 add w8,w8,w13
.endif
.inst 0x04ad0108
.if mixin == 1
 add w9,w9,w14
.endif
.inst 0x04a1018c
.if mixin == 1
 add w10,w10,w11
.endif
.if mixin == 1
 eor w22,w22,w7
.endif
.inst 0x0468340f
.if mixin == 1
 ror w22,w22,24
.endif
.if mixin == 1
 eor w19,w19,w8
.endif
.inst 0x04683483
.if mixin == 1
 ror w19,w19,24
.endif
.if mixin == 1
 eor w20,w20,w9
.endif
.inst 0x04683507
.if mixin == 1
 ror w20,w20,24
.endif
.if mixin == 1
 eor w21,w21,w10
.endif
.inst 0x0468358b
.if mixin == 1
 ror w21,w21,24
.endif
.inst 0x04af014a
.if mixin == 1
 add w17,w17,w22
.endif
.inst 0x04a301ce
.if mixin == 1
 add w18,w18,w19
.endif
.inst 0x04a70042
.if mixin == 1
 add w15,w15,w20
.endif
.inst 0x04ab00c6
.if mixin == 1
 add w16,w16,w21
.endif
.if mixin == 1
 eor w12,w12,w17
.endif
.inst 0x04673545
.if mixin == 1
 ror w12,w12,25
.endif
.if mixin == 1
 eor w13,w13,w18
.endif
.inst 0x046735c9
.if mixin == 1
 ror w13,w13,25
.endif
.if mixin == 1
 eor w14,w14,w15
.endif
.inst 0x0467344d
.if mixin == 1
 ror w14,w14,25
.endif
.if mixin == 1
 eor w11,w11,w16
.endif
.inst 0x046734c1
.if mixin == 1
 ror w11,w11,25
.endif
 sub x6,x6,1
 cbnz x6,10b
.if mixin == 1
 add w7,w7,w23
.endif
.inst 0x04b90000
.if mixin == 1
 add x8,x8,x23,lsr #32
.endif
.inst 0x04ba0084
.if mixin == 1
 add x7,x7,x8,lsl #32
.endif
.if mixin == 1
 add w9,w9,w24
.endif
.inst 0x04bb0108
.if mixin == 1
 add x10,x10,x24,lsr #32
.endif
.inst 0x04bc018c
.if mixin == 1
 add x9,x9,x10,lsl #32
.endif
.if mixin == 1
 ldp x8,x10,[x1],#16
.endif
.if mixin == 1
 add w11,w11,w25
.endif
.inst 0x04bd0021
.if mixin == 1
 add x12,x12,x25,lsr #32
.endif
.inst 0x04be00a5
.if mixin == 1
 add x11,x11,x12,lsl #32
.endif
.if mixin == 1
 add w13,w13,w26
.endif
.inst 0x04b50129
.if mixin == 1
 add x14,x14,x26,lsr #32
.endif
.inst 0x04b601ad
.if mixin == 1
 add x13,x13,x14,lsl #32
.endif
.if mixin == 1
 ldp x12,x14,[x1],#16
.endif
.if mixin == 1
 add w15,w15,w27
.endif
.inst 0x04b70042
.if mixin == 1
 add x16,x16,x27,lsr #32
.endif
.inst 0x04b800c6
.if mixin == 1
 add x15,x15,x16,lsl #32
.endif
.if mixin == 1
 add w17,w17,w28
.endif
.inst 0x04b1014a
.if mixin == 1
 add x18,x18,x28,lsr #32
.endif
.inst 0x04b201ce
.if mixin == 1
 add x17,x17,x18,lsl #32
.endif
.if mixin == 1
 ldp x16,x18,[x1],#16
.endif
.if mixin == 1
 add w19,w19,w29
.endif
.inst 0x04b00063
.if mixin == 1
 add x20,x20,x29,lsr #32
.endif
.inst 0x04b300e7
.if mixin == 1
 add x19,x19,x20,lsl #32
.endif
.if mixin == 1
 add w21,w21,w30
.endif
.inst 0x04b4016b
.if mixin == 1
 add x22,x22,x30,lsr #32
.endif
.inst 0x04bf01ef
.if mixin == 1
 add x21,x21,x22,lsl #32
.endif
.if mixin == 1
 ldp x20,x22,[x1],#16
.endif
.if mixin == 1
 add x29,x29,#1
.endif
 cmp x5,4
 b.ne 200f
.if mixin == 1
 eor x7,x7,x8
.endif
.if mixin == 1
 eor x9,x9,x10
.endif
.if mixin == 1
 eor x11,x11,x12
.endif
.inst 0x05a46011
.inst 0x05a46412
.inst 0x05ac6113
.inst 0x05ac6514
.inst 0x05a56035
.inst 0x05a56436
.inst 0x05ad6137
.inst 0x05ad6538
.inst 0x05f36220
.inst 0x05f36624
.inst 0x05f46248
.inst 0x05f4664c
.inst 0x05f762a1
.inst 0x05f766a5
.inst 0x05f862c9
.inst 0x05f866cd
.if mixin == 1
 eor x13,x13,x14
.endif
.if mixin == 1
 eor x15,x15,x16
.endif
.if mixin == 1
 eor x17,x17,x18
.endif
.inst 0x05a66051
.inst 0x05a66452
.inst 0x05ae6153
.inst 0x05ae6554
.inst 0x05a76075
.inst 0x05a76476
.inst 0x05af6177
.inst 0x05af6578
.inst 0x05f36222
.inst 0x05f36626
.inst 0x05f4624a
.inst 0x05f4664e
.inst 0x05f762a3
.inst 0x05f766a7
.inst 0x05f862cb
.inst 0x05f866cf
.if mixin == 1
 eor x19,x19,x20
.endif
.if mixin == 1
 eor x21,x21,x22
.endif
 ld1 {v17.4s,v18.4s,v19.4s,v20.4s},[x1],#64
 ld1 {v21.4s,v22.4s,v23.4s,v24.4s},[x1],#64
.inst 0x04b13000
.inst 0x04b23021
.inst 0x04b33042
.inst 0x04b43063
.inst 0x04b53084
.inst 0x04b630a5
.inst 0x04b730c6
.inst 0x04b830e7
 ld1 {v17.4s,v18.4s,v19.4s,v20.4s},[x1],#64
 ld1 {v21.4s,v22.4s,v23.4s,v24.4s},[x1],#64
.if mixin == 1
 stp x7,x9,[x0],#16
.endif
.inst 0x04b13108
.inst 0x04b23129
.if mixin == 1
 stp x11,x13,[x0],#16
.endif
.inst 0x04b3314a
.inst 0x04b4316b
.if mixin == 1
 stp x15,x17,[x0],#16
.endif
.inst 0x04b5318c
.inst 0x04b631ad
.if mixin == 1
 stp x19,x21,[x0],#16
.endif
.inst 0x04b731ce
.inst 0x04b831ef
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x0],#64
 st1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 st1 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
 st1 {v12.4s,v13.4s,v14.4s,v15.4s},[x0],#64
 b 210f
200:
.inst 0x05a16011
.inst 0x05a16412
.inst 0x05a36053
.inst 0x05a36454
.inst 0x05a56095
.inst 0x05a56496
.inst 0x05a760d7
.inst 0x05a764d8
.inst 0x05f36220
.inst 0x05f36621
.inst 0x05f46242
.inst 0x05f46643
.inst 0x05f762a4
.inst 0x05f766a5
.inst 0x05f862c6
.inst 0x05f866c7
.if mixin == 1
 eor x7,x7,x8
.endif
.if mixin == 1
 eor x9,x9,x10
.endif
.inst 0x05a96111
.inst 0x05a96512
.inst 0x05ab6153
.inst 0x05ab6554
.inst 0x05ad6195
.inst 0x05ad6596
.inst 0x05af61d7
.inst 0x05af65d8
.inst 0x05f36228
.inst 0x05f36629
.inst 0x05f4624a
.inst 0x05f4664b
.inst 0x05f762ac
.inst 0x05f766ad
.inst 0x05f862ce
.inst 0x05f866cf
.if mixin == 1
 eor x11,x11,x12
.endif
.if mixin == 1
 eor x13,x13,x14
.endif
.inst 0x05a46011
.inst 0x05a46412
.inst 0x05ac6113
.inst 0x05ac6514
.inst 0x05a56035
.inst 0x05a56436
.inst 0x05ad6137
.inst 0x05ad6538
.inst 0x05f36220
.inst 0x05f36624
.inst 0x05f46248
.inst 0x05f4664c
.inst 0x05f762a1
.inst 0x05f766a5
.inst 0x05f862c9
.inst 0x05f866cd
.if mixin == 1
 eor x15,x15,x16
.endif
.if mixin == 1
 eor x17,x17,x18
.endif
.inst 0x05a66051
.inst 0x05a66452
.inst 0x05ae6153
.inst 0x05ae6554
.inst 0x05a76075
.inst 0x05a76476
.inst 0x05af6177
.inst 0x05af6578
.inst 0x05f36222
.inst 0x05f36626
.inst 0x05f4624a
.inst 0x05f4664e
.inst 0x05f762a3
.inst 0x05f766a7
.inst 0x05f862cb
.inst 0x05f866cf
.if mixin == 1
 eor x19,x19,x20
.endif
.if mixin == 1
 eor x21,x21,x22
.endif
.inst 0xa540a031
.inst 0xa541a032
.inst 0xa542a033
.inst 0xa543a034
.inst 0xa544a035
.inst 0xa545a036
.inst 0xa546a037
.inst 0xa547a038
.inst 0x04215101
.inst 0x04b13000
.inst 0x04b23084
.inst 0x04b33108
.inst 0x04b4318c
.inst 0x04b53021
.inst 0x04b630a5
.inst 0x04b73129
.inst 0x04b831ad
.inst 0xa540a031
.inst 0xa541a032
.inst 0xa542a033
.inst 0xa543a034
.inst 0xa544a035
.inst 0xa545a036
.inst 0xa546a037
.inst 0xa547a038
.inst 0x04215101
.if mixin == 1
 stp x7,x9,[x0],#16
.endif
.inst 0x04b13042
.inst 0x04b230c6
.if mixin == 1
 stp x11,x13,[x0],#16
.endif
.inst 0x04b3314a
.inst 0x04b431ce
.if mixin == 1
 stp x15,x17,[x0],#16
.endif
.inst 0x04b53063
.inst 0x04b630e7
.if mixin == 1
 stp x19,x21,[x0],#16
.endif
.inst 0x04b7316b
.inst 0x04b831ef
.inst 0xe540e000
.inst 0xe541e004
.inst 0xe542e008
.inst 0xe543e00c
.inst 0xe544e001
.inst 0xe545e005
.inst 0xe546e009
.inst 0xe547e00d
.inst 0x04205100
.inst 0xe540e002
.inst 0xe541e006
.inst 0xe542e00a
.inst 0xe543e00e
.inst 0xe544e003
.inst 0xe545e007
.inst 0xe546e00b
.inst 0xe547e00f
.inst 0x04205100
210:
.inst 0x04b0e3fd
110:
 b 2f
1:
.align 5
100:
 subs x7,x2,x5,lsl #6
 b.lt 110f
 mov x2,x7
 b.eq 101f
 cmp x2,64
 b.lt 101f
 mixin=1
 lsr x8,x23,#32
.inst 0x05a03ae0
.inst 0x05a03af9
.if mixin == 1
 mov w7,w23
.endif
.inst 0x05a03904
.inst 0x05a0391a
 lsr x10,x24,#32
.inst 0x05a03b08
.inst 0x05a03b1b
.if mixin == 1
 mov w9,w24
.endif
.inst 0x05a0394c
.inst 0x05a0395c
 lsr x12,x25,#32
.inst 0x05a03b21
.inst 0x05a03b3d
.if mixin == 1
 mov w11,w25
.endif
.inst 0x05a03985
.inst 0x05a0399e
 lsr x14,x26,#32
.inst 0x05a03b49
.inst 0x05a03b55
.if mixin == 1
 mov w13,w26
.endif
.inst 0x05a039cd
.inst 0x05a039d6
 lsr x16,x27,#32
.inst 0x05a03b62
.inst 0x05a03b77
.if mixin == 1
 mov w15,w27
.endif
.inst 0x05a03a06
.inst 0x05a03a18
 lsr x18,x28,#32
.inst 0x05a03b8a
.if mixin == 1
 mov w17,w28
.endif
.inst 0x05a03a4e
 lsr x22,x30,#32
.inst 0x05a03bcb
.if mixin == 1
 mov w21,w30
.endif
.inst 0x05a03acf
.if mixin == 1
 add w20,w29,#1
 mov w19,w29
.inst 0x04a14690
.inst 0x04a14683
.else
.inst 0x04a147b0
.inst 0x04a147a3
.endif
 lsr x20,x29,#32
.inst 0x05a03a87
 mov x6,#10
10:
.align 5
.inst 0x04a10000
.if mixin == 1
 add w7,w7,w11
.endif
.inst 0x04a50084
.if mixin == 1
 add w8,w8,w12
.endif
.inst 0x04a90108
.if mixin == 1
 add w9,w9,w13
.endif
.inst 0x04ad018c
.if mixin == 1
 add w10,w10,w14
.endif
.inst 0x04a03063
.if mixin == 1
 eor w19,w19,w7
.endif
.inst 0x04a430e7
.if mixin == 1
 eor w20,w20,w8
.endif
.inst 0x04a8316b
.if mixin == 1
 eor w21,w21,w9
.endif
.inst 0x04ac31ef
.if mixin == 1
 eor w22,w22,w10
.endif
.inst 0x05a58063
.if mixin == 1
 ror w19,w19,#16
.endif
.inst 0x05a580e7
.if mixin == 1
 ror w20,w20,#16
.endif
.inst 0x05a5816b
.if mixin == 1
 ror w21,w21,#16
.endif
.inst 0x05a581ef
.if mixin == 1
 ror w22,w22,#16
.endif
.inst 0x04a30042
.if mixin == 1
 add w15,w15,w19
.endif
.inst 0x04a700c6
.if mixin == 1
 add w16,w16,w20
.endif
.inst 0x04ab014a
.if mixin == 1
 add w17,w17,w21
.endif
.inst 0x04af01ce
.if mixin == 1
 add w18,w18,w22
.endif
.inst 0x04a23021
.if mixin == 1
 eor w11,w11,w15
.endif
.inst 0x04a630a5
.if mixin == 1
 eor w12,w12,w16
.endif
.inst 0x04aa3129
.if mixin == 1
 eor w13,w13,w17
.endif
.inst 0x04ae31ad
.if mixin == 1
 eor w14,w14,w18
.endif
.inst 0x046c9c31
.inst 0x046c9cb2
.inst 0x046c9d33
.inst 0x046c9db4
.inst 0x046c9421
.if mixin == 1
 ror w11,w11,20
.endif
.inst 0x046c94a5
.if mixin == 1
 ror w12,w12,20
.endif
.inst 0x046c9529
.if mixin == 1
 ror w13,w13,20
.endif
.inst 0x046c95ad
.if mixin == 1
 ror w14,w14,20
.endif
.inst 0x04713021
.inst 0x047230a5
.inst 0x04733129
.inst 0x047431ad
.inst 0x04a10000
.if mixin == 1
 add w7,w7,w11
.endif
.inst 0x04a50084
.if mixin == 1
 add w8,w8,w12
.endif
.inst 0x04a90108
.if mixin == 1
 add w9,w9,w13
.endif
.inst 0x04ad018c
.if mixin == 1
 add w10,w10,w14
.endif
.inst 0x04a03063
.if mixin == 1
 eor w19,w19,w7
.endif
.inst 0x04a430e7
.if mixin == 1
 eor w20,w20,w8
.endif
.inst 0x04a8316b
.if mixin == 1
 eor w21,w21,w9
.endif
.inst 0x04ac31ef
.if mixin == 1
 eor w22,w22,w10
.endif
.inst 0x053f3063
.if mixin == 1
 ror w19,w19,#24
.endif
.inst 0x053f30e7
.if mixin == 1
 ror w20,w20,#24
.endif
.inst 0x053f316b
.if mixin == 1
 ror w21,w21,#24
.endif
.inst 0x053f31ef
.if mixin == 1
 ror w22,w22,#24
.endif
.inst 0x04a30042
.if mixin == 1
 add w15,w15,w19
.endif
.inst 0x04a700c6
.if mixin == 1
 add w16,w16,w20
.endif
.inst 0x04ab014a
.if mixin == 1
 add w17,w17,w21
.endif
.inst 0x04af01ce
.if mixin == 1
 add w18,w18,w22
.endif
.inst 0x04a23021
.if mixin == 1
 eor w11,w11,w15
.endif
.inst 0x04a630a5
.if mixin == 1
 eor w12,w12,w16
.endif
.inst 0x04aa3129
.if mixin == 1
 eor w13,w13,w17
.endif
.inst 0x04ae31ad
.if mixin == 1
 eor w14,w14,w18
.endif
.inst 0x04679c31
.inst 0x04679cb2
.inst 0x04679d33
.inst 0x04679db4
.inst 0x04679421
.if mixin == 1
 ror w11,w11,25
.endif
.inst 0x046794a5
.if mixin == 1
 ror w12,w12,25
.endif
.inst 0x04679529
.if mixin == 1
 ror w13,w13,25
.endif
.inst 0x046795ad
.if mixin == 1
 ror w14,w14,25
.endif
.inst 0x04713021
.inst 0x047230a5
.inst 0x04733129
.inst 0x047431ad
.inst 0x04a50000
.if mixin == 1
 add w7,w7,w12
.endif
.inst 0x04a90084
.if mixin == 1
 add w8,w8,w13
.endif
.inst 0x04ad0108
.if mixin == 1
 add w9,w9,w14
.endif
.inst 0x04a1018c
.if mixin == 1
 add w10,w10,w11
.endif
.inst 0x04a031ef
.if mixin == 1
 eor w22,w22,w7
.endif
.inst 0x04a43063
.if mixin == 1
 eor w19,w19,w8
.endif
.inst 0x04a830e7
.if mixin == 1
 eor w20,w20,w9
.endif
.inst 0x04ac316b
.if mixin == 1
 eor w21,w21,w10
.endif
.inst 0x05a581ef
.if mixin == 1
 ror w22,w22,#16
.endif
.inst 0x05a58063
.if mixin == 1
 ror w19,w19,#16
.endif
.inst 0x05a580e7
.if mixin == 1
 ror w20,w20,#16
.endif
.inst 0x05a5816b
.if mixin == 1
 ror w21,w21,#16
.endif
.inst 0x04af014a
.if mixin == 1
 add w17,w17,w22
.endif
.inst 0x04a301ce
.if mixin == 1
 add w18,w18,w19
.endif
.inst 0x04a70042
.if mixin == 1
 add w15,w15,w20
.endif
.inst 0x04ab00c6
.if mixin == 1
 add w16,w16,w21
.endif
.inst 0x04aa30a5
.if mixin == 1
 eor w12,w12,w17
.endif
.inst 0x04ae3129
.if mixin == 1
 eor w13,w13,w18
.endif
.inst 0x04a231ad
.if mixin == 1
 eor w14,w14,w15
.endif
.inst 0x04a63021
.if mixin == 1
 eor w11,w11,w16
.endif
.inst 0x046c9cb1
.inst 0x046c9d32
.inst 0x046c9db3
.inst 0x046c9c34
.inst 0x046c94a5
.if mixin == 1
 ror w12,w12,20
.endif
.inst 0x046c9529
.if mixin == 1
 ror w13,w13,20
.endif
.inst 0x046c95ad
.if mixin == 1
 ror w14,w14,20
.endif
.inst 0x046c9421
.if mixin == 1
 ror w11,w11,20
.endif
.inst 0x047130a5
.inst 0x04723129
.inst 0x047331ad
.inst 0x04743021
.inst 0x04a50000
.if mixin == 1
 add w7,w7,w12
.endif
.inst 0x04a90084
.if mixin == 1
 add w8,w8,w13
.endif
.inst 0x04ad0108
.if mixin == 1
 add w9,w9,w14
.endif
.inst 0x04a1018c
.if mixin == 1
 add w10,w10,w11
.endif
.inst 0x04a031ef
.if mixin == 1
 eor w22,w22,w7
.endif
.inst 0x04a43063
.if mixin == 1
 eor w19,w19,w8
.endif
.inst 0x04a830e7
.if mixin == 1
 eor w20,w20,w9
.endif
.inst 0x04ac316b
.if mixin == 1
 eor w21,w21,w10
.endif
.inst 0x053f31ef
.if mixin == 1
 ror w22,w22,#24
.endif
.inst 0x053f3063
.if mixin == 1
 ror w19,w19,#24
.endif
.inst 0x053f30e7
.if mixin == 1
 ror w20,w20,#24
.endif
.inst 0x053f316b
.if mixin == 1
 ror w21,w21,#24
.endif
.inst 0x04af014a
.if mixin == 1
 add w17,w17,w22
.endif
.inst 0x04a301ce
.if mixin == 1
 add w18,w18,w19
.endif
.inst 0x04a70042
.if mixin == 1
 add w15,w15,w20
.endif
.inst 0x04ab00c6
.if mixin == 1
 add w16,w16,w21
.endif
.inst 0x04aa30a5
.if mixin == 1
 eor w12,w12,w17
.endif
.inst 0x04ae3129
.if mixin == 1
 eor w13,w13,w18
.endif
.inst 0x04a231ad
.if mixin == 1
 eor w14,w14,w15
.endif
.inst 0x04a63021
.if mixin == 1
 eor w11,w11,w16
.endif
.inst 0x04679cb1
.inst 0x04679d32
.inst 0x04679db3
.inst 0x04679c34
.inst 0x046794a5
.if mixin == 1
 ror w12,w12,25
.endif
.inst 0x04679529
.if mixin == 1
 ror w13,w13,25
.endif
.inst 0x046795ad
.if mixin == 1
 ror w14,w14,25
.endif
.inst 0x04679421
.if mixin == 1
 ror w11,w11,25
.endif
.inst 0x047130a5
.inst 0x04723129
.inst 0x047331ad
.inst 0x04743021
 sub x6,x6,1
 cbnz x6,10b
 lsr x6,x28,#32
.inst 0x05a03b91
.inst 0x05a038d2
 lsr x6,x29,#32
.inst 0x05a038d3
 lsr x6,x30,#32
.if mixin == 1
 add w7,w7,w23
.endif
.inst 0x04b90000
.if mixin == 1
 add x8,x8,x23,lsr #32
.endif
.inst 0x04ba0084
.if mixin == 1
 add x7,x7,x8,lsl #32
.endif
.if mixin == 1
 add w9,w9,w24
.endif
.inst 0x04bb0108
.if mixin == 1
 add x10,x10,x24,lsr #32
.endif
.inst 0x04bc018c
.if mixin == 1
 add x9,x9,x10,lsl #32
.endif
.if mixin == 1
 ldp x8,x10,[x1],#16
.endif
.if mixin == 1
 add w11,w11,w25
.endif
.inst 0x04bd0021
.if mixin == 1
 add x12,x12,x25,lsr #32
.endif
.inst 0x04be00a5
.if mixin == 1
 add x11,x11,x12,lsl #32
.endif
.if mixin == 1
 add w13,w13,w26
.endif
.inst 0x04b50129
.if mixin == 1
 add x14,x14,x26,lsr #32
.endif
.inst 0x04b601ad
.if mixin == 1
 add x13,x13,x14,lsl #32
.endif
.if mixin == 1
 ldp x12,x14,[x1],#16
.endif
.if mixin == 1
 add w15,w15,w27
.endif
.inst 0x04b70042
.if mixin == 1
 add x16,x16,x27,lsr #32
.endif
.inst 0x04b800c6
.if mixin == 1
 add x15,x15,x16,lsl #32
.endif
.if mixin == 1
 add w17,w17,w28
.endif
.inst 0x04b1014a
.if mixin == 1
 add x18,x18,x28,lsr #32
.endif
.inst 0x04b201ce
.if mixin == 1
 add x17,x17,x18,lsl #32
.endif
.if mixin == 1
 ldp x16,x18,[x1],#16
.endif
.inst 0x05a03bd4
.inst 0x05a038d9
.if mixin == 1
 add w19,w19,w29
.endif
.inst 0x04b00063
.if mixin == 1
 add x20,x20,x29,lsr #32
.endif
.inst 0x04b300e7
.if mixin == 1
 add x19,x19,x20,lsl #32
.endif
.if mixin == 1
 add w21,w21,w30
.endif
.inst 0x04b4016b
.if mixin == 1
 add x22,x22,x30,lsr #32
.endif
.inst 0x04b901ef
.if mixin == 1
 add x21,x21,x22,lsl #32
.endif
.if mixin == 1
 ldp x20,x22,[x1],#16
.endif
.if mixin == 1
 add x29,x29,#1
.endif
 cmp x5,4
 b.ne 200f
.if mixin == 1
 eor x7,x7,x8
.endif
.if mixin == 1
 eor x9,x9,x10
.endif
.if mixin == 1
 eor x11,x11,x12
.endif
.inst 0x05a46011
.inst 0x05a46412
.inst 0x05ac6113
.inst 0x05ac6514
.inst 0x05a56035
.inst 0x05a56436
.inst 0x05ad6137
.inst 0x05ad6538
.inst 0x05f36220
.inst 0x05f36624
.inst 0x05f46248
.inst 0x05f4664c
.inst 0x05f762a1
.inst 0x05f766a5
.inst 0x05f862c9
.inst 0x05f866cd
.if mixin == 1
 eor x13,x13,x14
.endif
.if mixin == 1
 eor x15,x15,x16
.endif
.if mixin == 1
 eor x17,x17,x18
.endif
.inst 0x05a66051
.inst 0x05a66452
.inst 0x05ae6153
.inst 0x05ae6554
.inst 0x05a76075
.inst 0x05a76476
.inst 0x05af6177
.inst 0x05af6578
.inst 0x05f36222
.inst 0x05f36626
.inst 0x05f4624a
.inst 0x05f4664e
.inst 0x05f762a3
.inst 0x05f766a7
.inst 0x05f862cb
.inst 0x05f866cf
.if mixin == 1
 eor x19,x19,x20
.endif
.if mixin == 1
 eor x21,x21,x22
.endif
 ld1 {v17.4s,v18.4s,v19.4s,v20.4s},[x1],#64
 ld1 {v21.4s,v22.4s,v23.4s,v24.4s},[x1],#64
.inst 0x04b13000
.inst 0x04b23021
.inst 0x04b33042
.inst 0x04b43063
.inst 0x04b53084
.inst 0x04b630a5
.inst 0x04b730c6
.inst 0x04b830e7
 ld1 {v17.4s,v18.4s,v19.4s,v20.4s},[x1],#64
 ld1 {v21.4s,v22.4s,v23.4s,v24.4s},[x1],#64
.if mixin == 1
 stp x7,x9,[x0],#16
.endif
.inst 0x04b13108
.inst 0x04b23129
.if mixin == 1
 stp x11,x13,[x0],#16
.endif
.inst 0x04b3314a
.inst 0x04b4316b
.if mixin == 1
 stp x15,x17,[x0],#16
.endif
.inst 0x04b5318c
.inst 0x04b631ad
.if mixin == 1
 stp x19,x21,[x0],#16
.endif
.inst 0x04b731ce
.inst 0x04b831ef
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x0],#64
 st1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 st1 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
 st1 {v12.4s,v13.4s,v14.4s,v15.4s},[x0],#64
 b 210f
200:
.inst 0x05a16011
.inst 0x05a16412
.inst 0x05a36053
.inst 0x05a36454
.inst 0x05a56095
.inst 0x05a56496
.inst 0x05a760d7
.inst 0x05a764d8
.inst 0x05f36220
.inst 0x05f36621
.inst 0x05f46242
.inst 0x05f46643
.inst 0x05f762a4
.inst 0x05f766a5
.inst 0x05f862c6
.inst 0x05f866c7
.if mixin == 1
 eor x7,x7,x8
.endif
.if mixin == 1
 eor x9,x9,x10
.endif
.inst 0x05a96111
.inst 0x05a96512
.inst 0x05ab6153
.inst 0x05ab6554
.inst 0x05ad6195
.inst 0x05ad6596
.inst 0x05af61d7
.inst 0x05af65d8
.inst 0x05f36228
.inst 0x05f36629
.inst 0x05f4624a
.inst 0x05f4664b
.inst 0x05f762ac
.inst 0x05f766ad
.inst 0x05f862ce
.inst 0x05f866cf
.if mixin == 1
 eor x11,x11,x12
.endif
.if mixin == 1
 eor x13,x13,x14
.endif
.inst 0x05a46011
.inst 0x05a46412
.inst 0x05ac6113
.inst 0x05ac6514
.inst 0x05a56035
.inst 0x05a56436
.inst 0x05ad6137
.inst 0x05ad6538
.inst 0x05f36220
.inst 0x05f36624
.inst 0x05f46248
.inst 0x05f4664c
.inst 0x05f762a1
.inst 0x05f766a5
.inst 0x05f862c9
.inst 0x05f866cd
.if mixin == 1
 eor x15,x15,x16
.endif
.if mixin == 1
 eor x17,x17,x18
.endif
.inst 0x05a66051
.inst 0x05a66452
.inst 0x05ae6153
.inst 0x05ae6554
.inst 0x05a76075
.inst 0x05a76476
.inst 0x05af6177
.inst 0x05af6578
.inst 0x05f36222
.inst 0x05f36626
.inst 0x05f4624a
.inst 0x05f4664e
.inst 0x05f762a3
.inst 0x05f766a7
.inst 0x05f862cb
.inst 0x05f866cf
.if mixin == 1
 eor x19,x19,x20
.endif
.if mixin == 1
 eor x21,x21,x22
.endif
.inst 0xa540a031
.inst 0xa541a032
.inst 0xa542a033
.inst 0xa543a034
.inst 0xa544a035
.inst 0xa545a036
.inst 0xa546a037
.inst 0xa547a038
.inst 0x04215101
.inst 0x04b13000
.inst 0x04b23084
.inst 0x04b33108
.inst 0x04b4318c
.inst 0x04b53021
.inst 0x04b630a5
.inst 0x04b73129
.inst 0x04b831ad
.inst 0xa540a031
.inst 0xa541a032
.inst 0xa542a033
.inst 0xa543a034
.inst 0xa544a035
.inst 0xa545a036
.inst 0xa546a037
.inst 0xa547a038
.inst 0x04215101
.if mixin == 1
 stp x7,x9,[x0],#16
.endif
.inst 0x04b13042
.inst 0x04b230c6
.if mixin == 1
 stp x11,x13,[x0],#16
.endif
.inst 0x04b3314a
.inst 0x04b431ce
.if mixin == 1
 stp x15,x17,[x0],#16
.endif
.inst 0x04b53063
.inst 0x04b630e7
.if mixin == 1
 stp x19,x21,[x0],#16
.endif
.inst 0x04b7316b
.inst 0x04b831ef
.inst 0xe540e000
.inst 0xe541e004
.inst 0xe542e008
.inst 0xe543e00c
.inst 0xe544e001
.inst 0xe545e005
.inst 0xe546e009
.inst 0xe547e00d
.inst 0x04205100
.inst 0xe540e002
.inst 0xe541e006
.inst 0xe542e00a
.inst 0xe543e00e
.inst 0xe544e003
.inst 0xe545e007
.inst 0xe546e00b
.inst 0xe547e00f
.inst 0x04205100
210:
.inst 0x04b0e3fd
 subs x2,x2,64
 b.gt 100b
 b 110f
101:
 mixin=0
 lsr x8,x23,#32
.inst 0x05a03ae0
.inst 0x05a03af9
.if mixin == 1
 mov w7,w23
.endif
.inst 0x05a03904
.inst 0x05a0391a
 lsr x10,x24,#32
.inst 0x05a03b08
.inst 0x05a03b1b
.if mixin == 1
 mov w9,w24
.endif
.inst 0x05a0394c
.inst 0x05a0395c
 lsr x12,x25,#32
.inst 0x05a03b21
.inst 0x05a03b3d
.if mixin == 1
 mov w11,w25
.endif
.inst 0x05a03985
.inst 0x05a0399e
 lsr x14,x26,#32
.inst 0x05a03b49
.inst 0x05a03b55
.if mixin == 1
 mov w13,w26
.endif
.inst 0x05a039cd
.inst 0x05a039d6
 lsr x16,x27,#32
.inst 0x05a03b62
.inst 0x05a03b77
.if mixin == 1
 mov w15,w27
.endif
.inst 0x05a03a06
.inst 0x05a03a18
 lsr x18,x28,#32
.inst 0x05a03b8a
.if mixin == 1
 mov w17,w28
.endif
.inst 0x05a03a4e
 lsr x22,x30,#32
.inst 0x05a03bcb
.if mixin == 1
 mov w21,w30
.endif
.inst 0x05a03acf
.if mixin == 1
 add w20,w29,#1
 mov w19,w29
.inst 0x04a14690
.inst 0x04a14683
.else
.inst 0x04a147b0
.inst 0x04a147a3
.endif
 lsr x20,x29,#32
.inst 0x05a03a87
 mov x6,#10
10:
.align 5
.inst 0x04a10000
.if mixin == 1
 add w7,w7,w11
.endif
.inst 0x04a50084
.if mixin == 1
 add w8,w8,w12
.endif
.inst 0x04a90108
.if mixin == 1
 add w9,w9,w13
.endif
.inst 0x04ad018c
.if mixin == 1
 add w10,w10,w14
.endif
.inst 0x04a03063
.if mixin == 1
 eor w19,w19,w7
.endif
.inst 0x04a430e7
.if mixin == 1
 eor w20,w20,w8
.endif
.inst 0x04a8316b
.if mixin == 1
 eor w21,w21,w9
.endif
.inst 0x04ac31ef
.if mixin == 1
 eor w22,w22,w10
.endif
.inst 0x05a58063
.if mixin == 1
 ror w19,w19,#16
.endif
.inst 0x05a580e7
.if mixin == 1
 ror w20,w20,#16
.endif
.inst 0x05a5816b
.if mixin == 1
 ror w21,w21,#16
.endif
.inst 0x05a581ef
.if mixin == 1
 ror w22,w22,#16
.endif
.inst 0x04a30042
.if mixin == 1
 add w15,w15,w19
.endif
.inst 0x04a700c6
.if mixin == 1
 add w16,w16,w20
.endif
.inst 0x04ab014a
.if mixin == 1
 add w17,w17,w21
.endif
.inst 0x04af01ce
.if mixin == 1
 add w18,w18,w22
.endif
.inst 0x04a23021
.if mixin == 1
 eor w11,w11,w15
.endif
.inst 0x04a630a5
.if mixin == 1
 eor w12,w12,w16
.endif
.inst 0x04aa3129
.if mixin == 1
 eor w13,w13,w17
.endif
.inst 0x04ae31ad
.if mixin == 1
 eor w14,w14,w18
.endif
.inst 0x046c9c31
.inst 0x046c9cb2
.inst 0x046c9d33
.inst 0x046c9db4
.inst 0x046c9421
.if mixin == 1
 ror w11,w11,20
.endif
.inst 0x046c94a5
.if mixin == 1
 ror w12,w12,20
.endif
.inst 0x046c9529
.if mixin == 1
 ror w13,w13,20
.endif
.inst 0x046c95ad
.if mixin == 1
 ror w14,w14,20
.endif
.inst 0x04713021
.inst 0x047230a5
.inst 0x04733129
.inst 0x047431ad
.inst 0x04a10000
.if mixin == 1
 add w7,w7,w11
.endif
.inst 0x04a50084
.if mixin == 1
 add w8,w8,w12
.endif
.inst 0x04a90108
.if mixin == 1
 add w9,w9,w13
.endif
.inst 0x04ad018c
.if mixin == 1
 add w10,w10,w14
.endif
.inst 0x04a03063
.if mixin == 1
 eor w19,w19,w7
.endif
.inst 0x04a430e7
.if mixin == 1
 eor w20,w20,w8
.endif
.inst 0x04a8316b
.if mixin == 1
 eor w21,w21,w9
.endif
.inst 0x04ac31ef
.if mixin == 1
 eor w22,w22,w10
.endif
.inst 0x053f3063
.if mixin == 1
 ror w19,w19,#24
.endif
.inst 0x053f30e7
.if mixin == 1
 ror w20,w20,#24
.endif
.inst 0x053f316b
.if mixin == 1
 ror w21,w21,#24
.endif
.inst 0x053f31ef
.if mixin == 1
 ror w22,w22,#24
.endif
.inst 0x04a30042
.if mixin == 1
 add w15,w15,w19
.endif
.inst 0x04a700c6
.if mixin == 1
 add w16,w16,w20
.endif
.inst 0x04ab014a
.if mixin == 1
 add w17,w17,w21
.endif
.inst 0x04af01ce
.if mixin == 1
 add w18,w18,w22
.endif
.inst 0x04a23021
.if mixin == 1
 eor w11,w11,w15
.endif
.inst 0x04a630a5
.if mixin == 1
 eor w12,w12,w16
.endif
.inst 0x04aa3129
.if mixin == 1
 eor w13,w13,w17
.endif
.inst 0x04ae31ad
.if mixin == 1
 eor w14,w14,w18
.endif
.inst 0x04679c31
.inst 0x04679cb2
.inst 0x04679d33
.inst 0x04679db4
.inst 0x04679421
.if mixin == 1
 ror w11,w11,25
.endif
.inst 0x046794a5
.if mixin == 1
 ror w12,w12,25
.endif
.inst 0x04679529
.if mixin == 1
 ror w13,w13,25
.endif
.inst 0x046795ad
.if mixin == 1
 ror w14,w14,25
.endif
.inst 0x04713021
.inst 0x047230a5
.inst 0x04733129
.inst 0x047431ad
.inst 0x04a50000
.if mixin == 1
 add w7,w7,w12
.endif
.inst 0x04a90084
.if mixin == 1
 add w8,w8,w13
.endif
.inst 0x04ad0108
.if mixin == 1
 add w9,w9,w14
.endif
.inst 0x04a1018c
.if mixin == 1
 add w10,w10,w11
.endif
.inst 0x04a031ef
.if mixin == 1
 eor w22,w22,w7
.endif
.inst 0x04a43063
.if mixin == 1
 eor w19,w19,w8
.endif
.inst 0x04a830e7
.if mixin == 1
 eor w20,w20,w9
.endif
.inst 0x04ac316b
.if mixin == 1
 eor w21,w21,w10
.endif
.inst 0x05a581ef
.if mixin == 1
 ror w22,w22,#16
.endif
.inst 0x05a58063
.if mixin == 1
 ror w19,w19,#16
.endif
.inst 0x05a580e7
.if mixin == 1
 ror w20,w20,#16
.endif
.inst 0x05a5816b
.if mixin == 1
 ror w21,w21,#16
.endif
.inst 0x04af014a
.if mixin == 1
 add w17,w17,w22
.endif
.inst 0x04a301ce
.if mixin == 1
 add w18,w18,w19
.endif
.inst 0x04a70042
.if mixin == 1
 add w15,w15,w20
.endif
.inst 0x04ab00c6
.if mixin == 1
 add w16,w16,w21
.endif
.inst 0x04aa30a5
.if mixin == 1
 eor w12,w12,w17
.endif
.inst 0x04ae3129
.if mixin == 1
 eor w13,w13,w18
.endif
.inst 0x04a231ad
.if mixin == 1
 eor w14,w14,w15
.endif
.inst 0x04a63021
.if mixin == 1
 eor w11,w11,w16
.endif
.inst 0x046c9cb1
.inst 0x046c9d32
.inst 0x046c9db3
.inst 0x046c9c34
.inst 0x046c94a5
.if mixin == 1
 ror w12,w12,20
.endif
.inst 0x046c9529
.if mixin == 1
 ror w13,w13,20
.endif
.inst 0x046c95ad
.if mixin == 1
 ror w14,w14,20
.endif
.inst 0x046c9421
.if mixin == 1
 ror w11,w11,20
.endif
.inst 0x047130a5
.inst 0x04723129
.inst 0x047331ad
.inst 0x04743021
.inst 0x04a50000
.if mixin == 1
 add w7,w7,w12
.endif
.inst 0x04a90084
.if mixin == 1
 add w8,w8,w13
.endif
.inst 0x04ad0108
.if mixin == 1
 add w9,w9,w14
.endif
.inst 0x04a1018c
.if mixin == 1
 add w10,w10,w11
.endif
.inst 0x04a031ef
.if mixin == 1
 eor w22,w22,w7
.endif
.inst 0x04a43063
.if mixin == 1
 eor w19,w19,w8
.endif
.inst 0x04a830e7
.if mixin == 1
 eor w20,w20,w9
.endif
.inst 0x04ac316b
.if mixin == 1
 eor w21,w21,w10
.endif
.inst 0x053f31ef
.if mixin == 1
 ror w22,w22,#24
.endif
.inst 0x053f3063
.if mixin == 1
 ror w19,w19,#24
.endif
.inst 0x053f30e7
.if mixin == 1
 ror w20,w20,#24
.endif
.inst 0x053f316b
.if mixin == 1
 ror w21,w21,#24
.endif
.inst 0x04af014a
.if mixin == 1
 add w17,w17,w22
.endif
.inst 0x04a301ce
.if mixin == 1
 add w18,w18,w19
.endif
.inst 0x04a70042
.if mixin == 1
 add w15,w15,w20
.endif
.inst 0x04ab00c6
.if mixin == 1
 add w16,w16,w21
.endif
.inst 0x04aa30a5
.if mixin == 1
 eor w12,w12,w17
.endif
.inst 0x04ae3129
.if mixin == 1
 eor w13,w13,w18
.endif
.inst 0x04a231ad
.if mixin == 1
 eor w14,w14,w15
.endif
.inst 0x04a63021
.if mixin == 1
 eor w11,w11,w16
.endif
.inst 0x04679cb1
.inst 0x04679d32
.inst 0x04679db3
.inst 0x04679c34
.inst 0x046794a5
.if mixin == 1
 ror w12,w12,25
.endif
.inst 0x04679529
.if mixin == 1
 ror w13,w13,25
.endif
.inst 0x046795ad
.if mixin == 1
 ror w14,w14,25
.endif
.inst 0x04679421
.if mixin == 1
 ror w11,w11,25
.endif
.inst 0x047130a5
.inst 0x04723129
.inst 0x047331ad
.inst 0x04743021
 sub x6,x6,1
 cbnz x6,10b
 lsr x6,x28,#32
.inst 0x05a03b91
.inst 0x05a038d2
 lsr x6,x29,#32
.inst 0x05a038d3
 lsr x6,x30,#32
.if mixin == 1
 add w7,w7,w23
.endif
.inst 0x04b90000
.if mixin == 1
 add x8,x8,x23,lsr #32
.endif
.inst 0x04ba0084
.if mixin == 1
 add x7,x7,x8,lsl #32
.endif
.if mixin == 1
 add w9,w9,w24
.endif
.inst 0x04bb0108
.if mixin == 1
 add x10,x10,x24,lsr #32
.endif
.inst 0x04bc018c
.if mixin == 1
 add x9,x9,x10,lsl #32
.endif
.if mixin == 1
 ldp x8,x10,[x1],#16
.endif
.if mixin == 1
 add w11,w11,w25
.endif
.inst 0x04bd0021
.if mixin == 1
 add x12,x12,x25,lsr #32
.endif
.inst 0x04be00a5
.if mixin == 1
 add x11,x11,x12,lsl #32
.endif
.if mixin == 1
 add w13,w13,w26
.endif
.inst 0x04b50129
.if mixin == 1
 add x14,x14,x26,lsr #32
.endif
.inst 0x04b601ad
.if mixin == 1
 add x13,x13,x14,lsl #32
.endif
.if mixin == 1
 ldp x12,x14,[x1],#16
.endif
.if mixin == 1
 add w15,w15,w27
.endif
.inst 0x04b70042
.if mixin == 1
 add x16,x16,x27,lsr #32
.endif
.inst 0x04b800c6
.if mixin == 1
 add x15,x15,x16,lsl #32
.endif
.if mixin == 1
 add w17,w17,w28
.endif
.inst 0x04b1014a
.if mixin == 1
 add x18,x18,x28,lsr #32
.endif
.inst 0x04b201ce
.if mixin == 1
 add x17,x17,x18,lsl #32
.endif
.if mixin == 1
 ldp x16,x18,[x1],#16
.endif
.inst 0x05a03bd4
.inst 0x05a038d9
.if mixin == 1
 add w19,w19,w29
.endif
.inst 0x04b00063
.if mixin == 1
 add x20,x20,x29,lsr #32
.endif
.inst 0x04b300e7
.if mixin == 1
 add x19,x19,x20,lsl #32
.endif
.if mixin == 1
 add w21,w21,w30
.endif
.inst 0x04b4016b
.if mixin == 1
 add x22,x22,x30,lsr #32
.endif
.inst 0x04b901ef
.if mixin == 1
 add x21,x21,x22,lsl #32
.endif
.if mixin == 1
 ldp x20,x22,[x1],#16
.endif
.if mixin == 1
 add x29,x29,#1
.endif
 cmp x5,4
 b.ne 200f
.if mixin == 1
 eor x7,x7,x8
.endif
.if mixin == 1
 eor x9,x9,x10
.endif
.if mixin == 1
 eor x11,x11,x12
.endif
.inst 0x05a46011
.inst 0x05a46412
.inst 0x05ac6113
.inst 0x05ac6514
.inst 0x05a56035
.inst 0x05a56436
.inst 0x05ad6137
.inst 0x05ad6538
.inst 0x05f36220
.inst 0x05f36624
.inst 0x05f46248
.inst 0x05f4664c
.inst 0x05f762a1
.inst 0x05f766a5
.inst 0x05f862c9
.inst 0x05f866cd
.if mixin == 1
 eor x13,x13,x14
.endif
.if mixin == 1
 eor x15,x15,x16
.endif
.if mixin == 1
 eor x17,x17,x18
.endif
.inst 0x05a66051
.inst 0x05a66452
.inst 0x05ae6153
.inst 0x05ae6554
.inst 0x05a76075
.inst 0x05a76476
.inst 0x05af6177
.inst 0x05af6578
.inst 0x05f36222
.inst 0x05f36626
.inst 0x05f4624a
.inst 0x05f4664e
.inst 0x05f762a3
.inst 0x05f766a7
.inst 0x05f862cb
.inst 0x05f866cf
.if mixin == 1
 eor x19,x19,x20
.endif
.if mixin == 1
 eor x21,x21,x22
.endif
 ld1 {v17.4s,v18.4s,v19.4s,v20.4s},[x1],#64
 ld1 {v21.4s,v22.4s,v23.4s,v24.4s},[x1],#64
.inst 0x04b13000
.inst 0x04b23021
.inst 0x04b33042
.inst 0x04b43063
.inst 0x04b53084
.inst 0x04b630a5
.inst 0x04b730c6
.inst 0x04b830e7
 ld1 {v17.4s,v18.4s,v19.4s,v20.4s},[x1],#64
 ld1 {v21.4s,v22.4s,v23.4s,v24.4s},[x1],#64
.if mixin == 1
 stp x7,x9,[x0],#16
.endif
.inst 0x04b13108
.inst 0x04b23129
.if mixin == 1
 stp x11,x13,[x0],#16
.endif
.inst 0x04b3314a
.inst 0x04b4316b
.if mixin == 1
 stp x15,x17,[x0],#16
.endif
.inst 0x04b5318c
.inst 0x04b631ad
.if mixin == 1
 stp x19,x21,[x0],#16
.endif
.inst 0x04b731ce
.inst 0x04b831ef
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x0],#64
 st1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 st1 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
 st1 {v12.4s,v13.4s,v14.4s,v15.4s},[x0],#64
 b 210f
200:
.inst 0x05a16011
.inst 0x05a16412
.inst 0x05a36053
.inst 0x05a36454
.inst 0x05a56095
.inst 0x05a56496
.inst 0x05a760d7
.inst 0x05a764d8
.inst 0x05f36220
.inst 0x05f36621
.inst 0x05f46242
.inst 0x05f46643
.inst 0x05f762a4
.inst 0x05f766a5
.inst 0x05f862c6
.inst 0x05f866c7
.if mixin == 1
 eor x7,x7,x8
.endif
.if mixin == 1
 eor x9,x9,x10
.endif
.inst 0x05a96111
.inst 0x05a96512
.inst 0x05ab6153
.inst 0x05ab6554
.inst 0x05ad6195
.inst 0x05ad6596
.inst 0x05af61d7
.inst 0x05af65d8
.inst 0x05f36228
.inst 0x05f36629
.inst 0x05f4624a
.inst 0x05f4664b
.inst 0x05f762ac
.inst 0x05f766ad
.inst 0x05f862ce
.inst 0x05f866cf
.if mixin == 1
 eor x11,x11,x12
.endif
.if mixin == 1
 eor x13,x13,x14
.endif
.inst 0x05a46011
.inst 0x05a46412
.inst 0x05ac6113
.inst 0x05ac6514
.inst 0x05a56035
.inst 0x05a56436
.inst 0x05ad6137
.inst 0x05ad6538
.inst 0x05f36220
.inst 0x05f36624
.inst 0x05f46248
.inst 0x05f4664c
.inst 0x05f762a1
.inst 0x05f766a5
.inst 0x05f862c9
.inst 0x05f866cd
.if mixin == 1
 eor x15,x15,x16
.endif
.if mixin == 1
 eor x17,x17,x18
.endif
.inst 0x05a66051
.inst 0x05a66452
.inst 0x05ae6153
.inst 0x05ae6554
.inst 0x05a76075
.inst 0x05a76476
.inst 0x05af6177
.inst 0x05af6578
.inst 0x05f36222
.inst 0x05f36626
.inst 0x05f4624a
.inst 0x05f4664e
.inst 0x05f762a3
.inst 0x05f766a7
.inst 0x05f862cb
.inst 0x05f866cf
.if mixin == 1
 eor x19,x19,x20
.endif
.if mixin == 1
 eor x21,x21,x22
.endif
.inst 0xa540a031
.inst 0xa541a032
.inst 0xa542a033
.inst 0xa543a034
.inst 0xa544a035
.inst 0xa545a036
.inst 0xa546a037
.inst 0xa547a038
.inst 0x04215101
.inst 0x04b13000
.inst 0x04b23084
.inst 0x04b33108
.inst 0x04b4318c
.inst 0x04b53021
.inst 0x04b630a5
.inst 0x04b73129
.inst 0x04b831ad
.inst 0xa540a031
.inst 0xa541a032
.inst 0xa542a033
.inst 0xa543a034
.inst 0xa544a035
.inst 0xa545a036
.inst 0xa546a037
.inst 0xa547a038
.inst 0x04215101
.if mixin == 1
 stp x7,x9,[x0],#16
.endif
.inst 0x04b13042
.inst 0x04b230c6
.if mixin == 1
 stp x11,x13,[x0],#16
.endif
.inst 0x04b3314a
.inst 0x04b431ce
.if mixin == 1
 stp x15,x17,[x0],#16
.endif
.inst 0x04b53063
.inst 0x04b630e7
.if mixin == 1
 stp x19,x21,[x0],#16
.endif
.inst 0x04b7316b
.inst 0x04b831ef
.inst 0xe540e000
.inst 0xe541e004
.inst 0xe542e008
.inst 0xe543e00c
.inst 0xe544e001
.inst 0xe545e005
.inst 0xe546e009
.inst 0xe547e00d
.inst 0x04205100
.inst 0xe540e002
.inst 0xe541e006
.inst 0xe542e00a
.inst 0xe543e00e
.inst 0xe544e003
.inst 0xe545e007
.inst 0xe546e00b
.inst 0xe547e00f
.inst 0x04205100
210:
.inst 0x04b0e3fd
110:
2:
 str w29,[x4]
 ldp d10,d11,[sp,16]
 ldp d12,d13,[sp,32]
 ldp d14,d15,[sp,48]
 ldp x16,x17,[sp,64]
 ldp x18,x19,[sp,80]
 ldp x20,x21,[sp,96]
 ldp x22,x23,[sp,112]
 ldp x24,x25,[sp,128]
 ldp x26,x27,[sp,144]
 ldp x28,x29,[sp,160]
 ldr x30,[sp,176]
 ldp d8,d9,[sp],192

.Lreturn:
 ret
.size ChaCha20_ctr32_sve,.-ChaCha20_ctr32_sve
`;

export default asm;
