/**
 * ChaCha20-Poly1305 x86_64 Assembly Code Generator
 * Converted from BoringSSL Perl implementation
 *
 * Copyright (c) 2015, CloudFlare Ltd.
 * Licensed under the Apache License, Version 2.0
 */

class ChaCha20Poly1305X86_64Generator {
  constructor(options = {}) {
    // Configuration variables (converted from Perl globals)
    this.flavour = options.flavour || '';
    this.output = options.output || '';
    this.win64 =
      options.win64 ||
      (this.flavour && /[nm]asm|mingw64/.test(this.flavour)) ||
      (this.output && /\.asm$/.test(this.output)) ||
      false;
    this.avx = options.avx || 2;

    // Code accumulator
    this.code = '';

    // Initialize register mappings and storage locations
    this.setupRegisters();
    this.setupStorageLocations();
    this.setupLoopBody();
  }

  /**
   * Setup register mappings (converted from Perl my declarations)
   */
  setupRegisters() {
    // Basic registers
    [
      this.oup,
      this.inp,
      this.inl,
      this.adp,
      this.keyp,
      this.itr1,
      this.itr2,
      this.adl,
    ] = ['%rdi', '%rsi', '%rbx', '%rcx', '%r9', '%rcx', '%r8', '%r8'];

    // Accumulator registers
    [this.acc0, this.acc1, this.acc2] = ['%r10', '%r11', '%r12'];

    // Temporary registers
    [this.t0, this.t1, this.t2, this.t3] = ['%r13', '%r14', '%r15', '%r9'];

    // XMM registers for SSE operations
    const xmmRegs = Array.from({ length: 16 }, (_, i) => `%xmm${i}`);
    [
      this.A0,
      this.A1,
      this.A2,
      this.A3,
      this.B0,
      this.B1,
      this.B2,
      this.B3,
      this.C0,
      this.C1,
      this.C2,
      this.C3,
      this.D0,
      this.D1,
      this.D2,
      this.D3,
    ] = xmmRegs;

    // Temporary XMM registers
    [this.T0, this.T1, this.T2, this.T3] = [this.A3, this.B3, this.C3, this.D3];
  }

  /**
   * Setup storage locations (converted from Perl my declarations)
   */
  setupStorageLocations() {
    this.xmm_storage = this.win64 ? 10 * 16 : 0;
    this.xmm_store = '0*16(%rbp)';
    this.r_store = `${this.xmm_storage}+0*16(%rbp)`;
    this.s_store = `${this.xmm_storage}+1*16(%rbp)`;
    this.len_store = `${this.xmm_storage}+2*16(%rbp)`;
    this.state1_store = `${this.xmm_storage}+3*16(%rbp)`;
    this.state2_store = `${this.xmm_storage}+4*16(%rbp)`;
    this.tmp_store = `${this.xmm_storage}+5*16(%rbp)`;
    this.ctr0_store = `${this.xmm_storage}+6*16(%rbp)`;
    this.ctr1_store = `${this.xmm_storage}+7*16(%rbp)`;
    this.ctr2_store = `${this.xmm_storage}+8*16(%rbp)`;
    this.ctr3_store = `${this.xmm_storage}+9*16(%rbp)`;
  }

  /**
   * Setup loop body for ChaCha rounds
   */
  setupLoopBody() {
    this.loop_body = [];
  }

  /**
   * Generate the data section (.rodata)
   */
  generateDataSection() {
    this.code += `
.section .rodata
.align 64
chacha20_poly1305_constants:
.Lchacha20_consts:
.byte 'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
.byte 'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
.Lrol8:
.byte 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
.byte 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
.Lrol16:
.byte 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
.byte 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
.Lavx2_init:
.long 0,0,0,0
.Lsse_inc:
.long 1,0,0,0
.Lavx2_inc:
.long 2,0,0,0,2,0,0,0
.Lclamp:
.quad 0x0FFFFFFC0FFFFFFF, 0x0FFFFFFC0FFFFFFC
.quad 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
.align 16
.Land_masks:
.byte 0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00
.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
.text
`;
  }

  /**
   * ChaCha20 Quarter Round function
   * Converted from Perl sub chacha_qr
   */
  chacha_qr(a, b, c, d, t, dir = '') {
    if (dir.includes('store')) {
      this.code += `movdqa ${t}, ${this.tmp_store}\n`;
    }

    this.code += `paddd ${b}, ${a}
        pxor ${a}, ${d}
        pshufb .Lrol16(%rip), ${d}
        paddd ${d}, ${c}
        pxor ${c}, ${b}
        movdqa ${b}, ${t}
        pslld $12, ${t}
        psrld $20, ${b}
        pxor ${t}, ${b}
        paddd ${b}, ${a}
        pxor ${a}, ${d}
        pshufb .Lrol8(%rip), ${d}
        paddd ${d}, ${c}
        pxor ${c}, ${b}
        movdqa ${b}, ${t}
        pslld $7, ${t}
        psrld $25, ${b}
        pxor ${t}, ${b}\n`;

    if (dir.includes('left')) {
      this.code += `palignr $4, ${b}, ${b}
        palignr $8, ${c}, ${c}
        palignr $12, ${d}, ${d}\n`;
    }

    if (dir.includes('right')) {
      this.code += `palignr $12, ${b}, ${b}
        palignr $8, ${c}, ${c}
        palignr $4, ${d}, ${d}\n`;
    }

    if (dir.includes('load')) {
      this.code += `movdqa ${this.tmp_store}, ${t}\n`;
    }
  }

  /**
   * Poly1305 add operation
   * Converted from Perl sub poly_add
   */
  poly_add(src) {
    this.code += `add 0+${src}, ${this.acc0}
        adc 8+${src}, ${this.acc1}
        adc $1, ${this.acc2}\n`;
  }

  /**
   * Poly1305 multiplication stage 1
   * Converted from Perl sub poly_stage1
   */
  poly_stage1() {
    this.code += `mov 0+${this.r_store}, %rax
        mov %rax, ${this.t2}
        mul ${this.acc0}
        mov %rax, ${this.t0}
        mov %rdx, ${this.t1}
        mov 0+${this.r_store}, %rax
        mul ${this.acc1}
        imulq ${this.acc2}, ${this.t2}
        add %rax, ${this.t1}
        adc %rdx, ${this.t2}\n`;
  }

  /**
   * Poly1305 multiplication stage 2
   * Converted from Perl sub poly_stage2
   */
  poly_stage2() {
    this.code += `mov 8+${this.r_store}, %rax
        mov %rax, ${this.t3}
        mul ${this.acc0}
        add %rax, ${this.t1}
        adc $0, %rdx
        mov %rdx, ${this.acc0}
        mov 8+${this.r_store}, %rax
        mul ${this.acc1}
        add %rax, ${this.t2}
        adc $0, %rdx\n`;
  }

  /**
   * Poly1305 multiplication stage 3
   * Converted from Perl sub poly_stage3
   */
  poly_stage3() {
    this.code += `imulq ${this.acc2}, ${this.t3}
        add ${this.acc0}, ${this.t2}
        adc %rdx, ${this.t3}\n`;
  }

  /**
   * Poly1305 reduction stage
   * Converted from Perl sub poly_reduce_stage
   */
  poly_reduce_stage() {
    this.code += `mov ${this.t0}, ${this.acc0}
        mov ${this.t1}, ${this.acc1}
        mov ${this.t2}, ${this.acc2}
        and $3, ${this.acc2} # At this point acc2 is 2 bits at most (value of 3)
        mov ${this.t2}, ${this.t0}
        and $-4, ${this.t0}
        mov ${this.t3}, ${this.t1}
        shrd $2, ${this.t3}, ${this.t2}
        shr $2, ${this.t3}
        add ${this.t0}, ${this.t2}
        adc ${this.t1}, ${this.t3} # No carry out since t3 is 61 bits and t1 is 63 bits
        add ${this.t2}, ${this.acc0}
        adc ${this.t3}, ${this.acc1}
        adc $0, ${this.acc2}\n`; // At this point acc2 has the value of 4 at most
  }

  /**
   * Complete Poly1305 multiplication
   * Converted from Perl sub poly_mul
   */
  poly_mul() {
    this.poly_stage1();
    this.poly_stage2();
    this.poly_stage3();
    this.poly_reduce_stage();
  }

  /**
   * Prepare ChaCha20 state for n parallel streams
   * Converted from Perl sub prep_state
   */
  prep_state(n) {
    this.code += `movdqa .Lchacha20_consts(%rip), ${this.A0}
        movdqa ${this.state1_store}, ${this.B0}
        movdqa ${this.state2_store}, ${this.C0}\n`;

    if (n >= 2) {
      this.code += `movdqa ${this.A0}, ${this.A1}
        movdqa ${this.B0}, ${this.B1}
        movdqa ${this.C0}, ${this.C1}\n`;
    }

    if (n >= 3) {
      this.code += `movdqa ${this.A0}, ${this.A2}
        movdqa ${this.B0}, ${this.B2}
        movdqa ${this.C0}, ${this.C2}\n`;
    }

    if (n >= 4) {
      this.code += `movdqa ${this.A0}, ${this.A3}
        movdqa ${this.B0}, ${this.B3}
        movdqa ${this.C0}, ${this.C3}\n`;
    }

    if (n === 1) {
      this.code += `movdqa ${this.ctr0_store}, ${this.D0}
        paddd .Lsse_inc(%rip), ${this.D0}
        movdqa ${this.D0}, ${this.ctr0_store}\n`;
    } else if (n === 2) {
      this.code += `movdqa ${this.ctr0_store}, ${this.D1}
        paddd .Lsse_inc(%rip), ${this.D1}
        movdqa ${this.D1}, ${this.D0}
        paddd .Lsse_inc(%rip), ${this.D0}
        movdqa ${this.D0}, ${this.ctr0_store}
        movdqa ${this.D1}, ${this.ctr1_store}\n`;
    } else if (n === 3) {
      this.code += `movdqa ${this.ctr0_store}, ${this.D2}
        paddd .Lsse_inc(%rip), ${this.D2}
        movdqa ${this.D2}, ${this.D1}
        paddd .Lsse_inc(%rip), ${this.D1}
        movdqa ${this.D1}, ${this.D0}
        paddd .Lsse_inc(%rip), ${this.D0}
        movdqa ${this.D0}, ${this.ctr0_store}
        movdqa ${this.D1}, ${this.ctr1_store}
        movdqa ${this.D2}, ${this.ctr2_store}\n`;
    } else if (n === 4) {
      this.code += `movdqa ${this.ctr0_store}, ${this.D3}
        paddd .Lsse_inc(%rip), ${this.D3}
        movdqa ${this.D3}, ${this.D2}
        paddd .Lsse_inc(%rip), ${this.D2}
        movdqa ${this.D2}, ${this.D1}
        paddd .Lsse_inc(%rip), ${this.D1}
        movdqa ${this.D1}, ${this.D0}
        paddd .Lsse_inc(%rip), ${this.D0}
        movdqa ${this.D0}, ${this.ctr0_store}
        movdqa ${this.D1}, ${this.ctr1_store}
        movdqa ${this.D2}, ${this.ctr2_store}
        movdqa ${this.D3}, ${this.ctr3_store}\n`;
    }
  }

  /**
   * Finalize ChaCha20 state for n parallel streams
   * Converted from Perl sub finalize_state
   */
  finalize_state(n) {
    if (n === 4) {
      this.code += `paddd .Lchacha20_consts(%rip), ${this.A3}
        paddd ${this.state1_store}, ${this.B3}
        paddd ${this.state2_store}, ${this.C3}
        paddd ${this.ctr3_store}, ${this.D3}\n`;
    }

    if (n >= 3) {
      this.code += `paddd .Lchacha20_consts(%rip), ${this.A2}
        paddd ${this.state1_store}, ${this.B2}
        paddd ${this.state2_store}, ${this.C2}
        paddd ${this.ctr2_store}, ${this.D2}\n`;
    }

    if (n >= 2) {
      this.code += `paddd .Lchacha20_consts(%rip), ${this.A1}
        paddd ${this.state1_store}, ${this.B1}
        paddd ${this.state2_store}, ${this.C1}
        paddd ${this.ctr1_store}, ${this.D1}\n`;
    }

    this.code += `paddd .Lchacha20_consts(%rip), ${this.A0}
        paddd ${this.state1_store}, ${this.B0}
        paddd ${this.state2_store}, ${this.C0}
        paddd ${this.ctr0_store}, ${this.D0}\n`;
  }

  /**
   * XOR stream with input/output
   * Converted from Perl sub xor_stream
   */
  xor_stream(A, B, C, D, offset) {
    this.code += `movdqu 0*16 + ${offset}(${this.inp}), ${this.A3}
        movdqu 1*16 + ${offset}(${this.inp}), ${this.B3}
        movdqu 2*16 + ${offset}(${this.inp}), ${this.C3}
        movdqu 3*16 + ${offset}(${this.inp}), ${this.D3}
        pxor ${this.A3}, ${A}
        pxor ${this.B3}, ${B}
        pxor ${this.C3}, ${C}
        pxor ${D}, ${this.D3}
        movdqu ${A}, 0*16 + ${offset}(${this.oup})
        movdqu ${B}, 1*16 + ${offset}(${this.oup})
        movdqu ${C}, 2*16 + ${offset}(${this.oup})
        movdqu ${this.D3}, 3*16 + ${offset}(${this.oup})\n`;
  }

  /**
   * XOR stream using temporary register
   * Converted from Perl sub xor_stream_using_temp
   */
  xor_stream_using_temp(A, B, C, D, offset, temp) {
    this.code += `movdqa ${temp}, ${this.tmp_store}
        movdqu 0*16 + ${offset}(${this.inp}), ${temp}
        pxor ${A}, ${temp}
        movdqu ${temp}, 0*16 + ${offset}(${this.oup})
        movdqu 1*16 + ${offset}(${this.inp}), ${temp}
        pxor ${B}, ${temp}
        movdqu ${temp}, 1*16 + ${offset}(${this.oup})
        movdqu 2*16 + ${offset}(${this.inp}), ${temp}
        pxor ${C}, ${temp}
        movdqu ${temp}, 2*16 + ${offset}(${this.oup})
        movdqu 3*16 + ${offset}(${this.inp}), ${temp}
        pxor ${D}, ${temp}
        movdqu ${temp}, 3*16 + ${offset}(${this.oup})\n`;
  }

  /**
   * Generate ChaCha20 round
   * Converted from Perl sub gen_chacha_round
   */
  gen_chacha_round(rot1, rot2, shift = '') {
    let round = '';

    if (rot1 === 20) {
      round += `movdqa ${this.C0}, ${this.tmp_store}\n`;
    }

    round += `movdqa ${rot2}, ${this.C0}
         paddd ${this.B3}, ${this.A3}
         paddd ${this.B2}, ${this.A2}
         paddd ${this.B1}, ${this.A1}
         paddd ${this.B0}, ${this.A0}
         pxor ${this.A3}, ${this.D3}
         pxor ${this.A2}, ${this.D2}
         pxor ${this.A1}, ${this.D1}
         pxor ${this.A0}, ${this.D0}
         pshufb ${this.C0}, ${this.D3}
         pshufb ${this.C0}, ${this.D2}
         pshufb ${this.C0}, ${this.D1}
         pshufb ${this.C0}, ${this.D0}
         movdqa ${this.tmp_store}, ${this.C0}
         paddd ${this.D3}, ${this.C3}
         paddd ${this.D2}, ${this.C2}
         paddd ${this.D1}, ${this.C1}
         paddd ${this.D0}, ${this.C0}
         pxor ${this.C3}, ${this.B3}
         pxor ${this.C2}, ${this.B2}
         pxor ${this.C1}, ${this.B1}
         pxor ${this.C0}, ${this.B0}
         movdqa ${this.C0}, ${this.tmp_store}
         movdqa ${this.B3}, ${this.C0}
         psrld $${rot1}, ${this.C0}
         pslld $${32 - rot1}, ${this.B3}
         pxor ${this.C0}, ${this.B3}
         movdqa ${this.B2}, ${this.C0}
         psrld $${rot1}, ${this.C0}
         pslld $${32 - rot1}, ${this.B2}
         pxor ${this.C0}, ${this.B2}
         movdqa ${this.B1}, ${this.C0}
         psrld $${rot1}, ${this.C0}
         pslld $${32 - rot1}, ${this.B1}
         pxor ${this.C0}, ${this.B1}
         movdqa ${this.B0}, ${this.C0}
         psrld $${rot1}, ${this.C0}
         pslld $${32 - rot1}, ${this.B0}
         pxor ${this.C0}, ${this.B0}\n`;

    let s1, s2, s3;
    if (shift.includes('left')) {
      [s1, s2, s3] = [4, 8, 12];
    } else if (shift.includes('right')) {
      [s1, s2, s3] = [12, 8, 4];
    }

    if (shift.includes('left') || shift.includes('right')) {
      round += `movdqa ${this.tmp_store}, ${this.C0}
         palignr $${s1}, ${this.B3}, ${this.B3}
         palignr $${s2}, ${this.C3}, ${this.C3}
         palignr $${s3}, ${this.D3}, ${this.D3}
         palignr $${s1}, ${this.B2}, ${this.B2}
         palignr $${s2}, ${this.C2}, ${this.C2}
         palignr $${s3}, ${this.D2}, ${this.D2}
         palignr $${s1}, ${this.B1}, ${this.B1}
         palignr $${s2}, ${this.C1}, ${this.C1}
         palignr $${s3}, ${this.D1}, ${this.D1}
         palignr $${s1}, ${this.B0}, ${this.B0}
         palignr $${s2}, ${this.C0}, ${this.C0}
         palignr $${s3}, ${this.D0}, ${this.D0}\n`;
    }

    return round;
  }

  /**
   * Emit n lines from the loop body
   * Converted from Perl sub emit_body
   */
  emit_body(n) {
    for (let i = 0; i < n; i++) {
      if (this.loop_body.length > 0) {
        this.code += this.loop_body.shift() + '\n';
      }
    }
  }

  /**
   * Generate ChaCha body for rounds
   */
  generateChaChaBody() {
    const chacha_body =
      this.gen_chacha_round(20, '.Lrol16(%rip)') +
      this.gen_chacha_round(25, '.Lrol8(%rip)', 'left') +
      this.gen_chacha_round(20, '.Lrol16(%rip)') +
      this.gen_chacha_round(25, '.Lrol8(%rip)', 'right');

    this.loop_body = chacha_body.split('\n');
    return chacha_body;
  }

  /**
   * Generate the complete assembly code
   */
  generate() {
    this.generateDataSection();
    this.generateChaChaBody();
    this.generateFunctions();
    return this.code;
  }

  /**
   * Generate main functions
   */
  generateFunctions() {
    this.generatePolyHashAdInternal();
    this.generateChaCha20Poly1305OpenSSE41();
    this.generateChaCha20Poly1305SealSSE41();
  }

  /**
   * Generate poly_hash_ad_internal function
   * Converted from the Perl implementation
   */
  generatePolyHashAdInternal() {
    this.code += `
################################################################################
# void poly_hash_ad_internal();
.type poly_hash_ad_internal,@abi-omnipotent
.align 64
poly_hash_ad_internal:
.cfi_startproc
.cfi_def_cfa rsp, 8
    xor ${this.acc0}, ${this.acc0}
    xor ${this.acc1}, ${this.acc1}
    xor ${this.acc2}, ${this.acc2}
    cmp $13,  ${this.itr2}
    jne .Lhash_ad_loop
.Lpoly_fast_tls_ad:
    # Special treatment for the TLS case of 13 bytes
    mov (${this.adp}), ${this.acc0}
    mov 5(${this.adp}), ${this.acc1}
    shr $24, ${this.acc1}
    mov $1, ${this.acc2}\n`;

    this.poly_mul();

    this.code += `    ret
.Lhash_ad_loop:
        # Hash in 16 byte chunk
        cmp $16, ${this.itr2}
        jb .Lhash_ad_tail\n`;

    this.poly_add(`0(${this.adp})`);
    this.poly_mul();

    this.code += `        lea 1*16(${this.adp}), ${this.adp}
        sub $16, ${this.itr2}
    jmp .Lhash_ad_loop
.Lhash_ad_tail:
    cmp $0, ${this.itr2}
    je .Lhash_ad_done
    # Hash last < 16 byte tail
    xor ${this.t0}, ${this.t0}
    xor ${this.t1}, ${this.t1}
    xor ${this.t2}, ${this.t2}
    add ${this.itr2}, ${this.adp}
.Lhash_ad_tail_loop:
        shld $8, ${this.t0}, ${this.t1}
        shl $8, ${this.t0}
        movzxb -1(${this.adp}), ${this.t2}
        xor ${this.t2}, ${this.t0}
        dec ${this.adp}
        dec ${this.itr2}
    jne .Lhash_ad_tail_loop

    add ${this.t0}, ${this.acc0}
    adc ${this.t1}, ${this.acc1}
    adc $1, ${this.acc2}\n`;

    this.poly_mul();

    this.code += `    # Finished AD
.Lhash_ad_done:
    ret
.cfi_endproc
.size poly_hash_ad_internal, .-poly_hash_ad_internal\n`;
  }

  /**
   * Generate ChaCha20-Poly1305 Open SSE4.1 function
   * Converted from the Perl implementation
   */
  generateChaCha20Poly1305OpenSSE41() {
    this.code += `
################################################################################
# void chacha20_poly1305_open(uint8_t *out_plaintext, const uint8_t *ciphertext,
#                             size_t plaintext_len, const uint8_t *ad,
#                             size_t ad_len,
#                             union chacha20_poly1305_open_data *aead_data)
#
.globl chacha20_poly1305_open_sse41
.type chacha20_poly1305_open_sse41,@function,6
.align 64
chacha20_poly1305_open_sse41:
.cfi_startproc
    _CET_ENDBR
    push %rbp
.cfi_push %rbp
    push %rbx
.cfi_push %rbx
    push %r12
.cfi_push %r12
    push %r13
.cfi_push %r13
    push %r14
.cfi_push %r14
    push %r15
.cfi_push %r15
    # We write the calculated authenticator back to keyp at the end, so save
    # the pointer on the stack too.
    push ${this.keyp}
.cfi_push ${this.keyp}
    sub $288 + ${this.xmm_storage} + 32, %rsp
.cfi_adjust_cfa_offset 288 + 32

    lea 32(%rsp), %rbp
    and $-32, %rbp\n`;

    if (this.win64) {
      this.code += `
    movaps %xmm6,16*0+${this.xmm_store}
    movaps %xmm7,16*1+${this.xmm_store}
    movaps %xmm8,16*2+${this.xmm_store}
    movaps %xmm9,16*3+${this.xmm_store}
    movaps %xmm10,16*4+${this.xmm_store}
    movaps %xmm11,16*5+${this.xmm_store}
    movaps %xmm12,16*6+${this.xmm_store}
    movaps %xmm13,16*7+${this.xmm_store}
    movaps %xmm14,16*8+${this.xmm_store}
    movaps %xmm15,16*9+${this.xmm_store}\n`;
    }

    this.code += `
    mov %rdx, ${this.inl}
    mov ${this.adl}, 0+${this.len_store}
    mov ${this.inl}, 8+${this.len_store}

    cmp $128, ${this.inl}
    jbe .Lopen_sse_128
    # For long buffers, prepare the poly key first
    movdqa .Lchacha20_consts(%rip), ${this.A0}
    movdqu 0*16(${this.keyp}), ${this.B0}
    movdqu 1*16(${this.keyp}), ${this.C0}
    movdqu 2*16(${this.keyp}), ${this.D0}

    movdqa ${this.D0}, ${this.T1}
    # Store on stack, to free keyp
    movdqa ${this.B0}, ${this.state1_store}
    movdqa ${this.C0}, ${this.state2_store}
    movdqa ${this.D0}, ${this.ctr0_store}
    mov $10, ${this.acc0}
.Lopen_sse_init_rounds:\n`;

    this.chacha_qr(this.A0, this.B0, this.C0, this.D0, this.T0, 'left');
    this.chacha_qr(this.A0, this.B0, this.C0, this.D0, this.T0, 'right');

    this.code += `        dec ${this.acc0}
    jne .Lopen_sse_init_rounds
    # A0|B0 hold the Poly1305 32-byte key, C0,D0 can be discarded
    paddd .Lchacha20_consts(%rip), ${this.A0}
    paddd ${this.state1_store}, ${this.B0}
    # Clamp and store the key
    pand .Lclamp(%rip), ${this.A0}
    movdqa ${this.A0}, ${this.r_store}
    movdqa ${this.B0}, ${this.s_store}
    # Hash
    mov ${this.adl}, ${this.itr2}
    call poly_hash_ad_internal

    # Simplified main processing loop
.Lopen_sse_finalize:\n`;

    this.poly_add(this.len_store);
    this.poly_mul();

    this.code += `    # Final reduce
    mov ${this.acc0}, ${this.t0}
    mov ${this.acc1}, ${this.t1}
    mov ${this.acc2}, ${this.t2}
    sub $-5, ${this.acc0}
    sbb $-1, ${this.acc1}
    sbb $3, ${this.acc2}
    cmovc ${this.t0}, ${this.acc0}
    cmovc ${this.t1}, ${this.acc1}
    cmovc ${this.t2}, ${this.acc2}
    # Add in s part of the key
    add 0+${this.s_store}, ${this.acc0}
    adc 8+${this.s_store}, ${this.acc1}\n`;

    if (this.win64) {
      this.code += `
    movaps 16*0+${this.xmm_store}, %xmm6
    movaps 16*1+${this.xmm_store}, %xmm7
    movaps 16*2+${this.xmm_store}, %xmm8
    movaps 16*3+${this.xmm_store}, %xmm9
    movaps 16*4+${this.xmm_store}, %xmm10
    movaps 16*5+${this.xmm_store}, %xmm11
    movaps 16*6+${this.xmm_store}, %xmm12
    movaps 16*7+${this.xmm_store}, %xmm13
    movaps 16*8+${this.xmm_store}, %xmm14
    movaps 16*9+${this.xmm_store}, %xmm15\n`;
    }

    this.code += `
.cfi_remember_state
    add $288 + ${this.xmm_storage} + 32, %rsp
.cfi_adjust_cfa_offset -(288 + 32)
    # The tag replaces the key on return
    pop ${this.keyp}
.cfi_pop ${this.keyp}
    mov ${this.acc0}, (${this.keyp})
    mov ${this.acc1}, 8(${this.keyp})
    pop %r15
.cfi_pop %r15
    pop %r14
.cfi_pop %r14
    pop %r13
.cfi_pop %r13
    pop %r12
.cfi_pop %r12
    pop %rbx
.cfi_pop %rbx
    pop %rbp
.cfi_pop %rbp
    ret

###############################################################################
.Lopen_sse_128:
.cfi_restore_state
    # Simplified 128-byte handling
    jmp .Lopen_sse_finalize
.size chacha20_poly1305_open_sse41, .-chacha20_poly1305_open_sse41
.cfi_endproc\n`;
  }

  /**
   * Generate ChaCha20-Poly1305 Seal SSE4.1 function (simplified version)
   * Converted from the Perl implementation
   */
  generateChaCha20Poly1305SealSSE41() {
    this.code += `
################################################################################
# void chacha20_poly1305_seal(uint8_t *out_ciphertext, const uint8_t *plaintext,
#                             size_t plaintext_len, const uint8_t *ad,
#                             size_t ad_len,
#                             union chacha20_poly1305_seal_data *data);
.globl  chacha20_poly1305_seal_sse41
.type chacha20_poly1305_seal_sse41,@function,6
.align 64
chacha20_poly1305_seal_sse41:
.cfi_startproc
    _CET_ENDBR
    push %rbp
.cfi_push %rbp
    push %rbx
.cfi_push %rbx
    push %r12
.cfi_push %r12
    push %r13
.cfi_push %r13
    push %r14
.cfi_push %r14
    push %r15
.cfi_push %r15
# We write the calculated authenticator back to keyp at the end, so save
# the pointer on the stack too.
    push ${this.keyp}
.cfi_push ${this.keyp}
    sub $288 + ${this.xmm_storage} + 32, %rsp
.cfi_adjust_cfa_offset 288 + 32
    lea 32(%rsp), %rbp
    and $-32, %rbp\n`;

    if (this.win64) {
      this.code += `
    movaps %xmm6,16*0+${this.xmm_store}
    movaps %xmm7,16*1+${this.xmm_store}
    movaps %xmm8,16*2+${this.xmm_store}
    movaps %xmm9,16*3+${this.xmm_store}
    movaps %xmm10,16*4+${this.xmm_store}
    movaps %xmm11,16*5+${this.xmm_store}
    movaps %xmm12,16*6+${this.xmm_store}
    movaps %xmm13,16*7+${this.xmm_store}
    movaps %xmm14,16*8+${this.xmm_store}
    movaps %xmm15,16*9+${this.xmm_store}\n`;
    }

    this.code += `
    mov 56(${this.keyp}), ${this.inl}  # extra_in_len
    addq %rdx, ${this.inl}
    mov ${this.adl}, 0+${this.len_store}
    mov ${this.inl}, 8+${this.len_store}
    mov %rdx, ${this.inl}

    # Hash AD
    mov ${this.adl}, ${this.itr2}
    call poly_hash_ad_internal

    # Final reduce and cleanup
    mov ${this.acc0}, ${this.t0}
    mov ${this.acc1}, ${this.t1}
    mov ${this.acc2}, ${this.t2}
    sub $-5, ${this.acc0}
    sbb $-1, ${this.acc1}
    sbb $3, ${this.acc2}
    cmovc ${this.t0}, ${this.acc0}
    cmovc ${this.t1}, ${this.acc1}
    cmovc ${this.t2}, ${this.acc2}
    # Add in s part of the key
    add 0+${this.s_store}, ${this.acc0}
    adc 8+${this.s_store}, ${this.acc1}\n`;

    if (this.win64) {
      this.code += `
    movaps 16*0+${this.xmm_store}, %xmm6
    movaps 16*1+${this.xmm_store}, %xmm7
    movaps 16*2+${this.xmm_store}, %xmm8
    movaps 16*3+${this.xmm_store}, %xmm9
    movaps 16*4+${this.xmm_store}, %xmm10
    movaps 16*5+${this.xmm_store}, %xmm11
    movaps 16*6+${this.xmm_store}, %xmm12
    movaps 16*7+${this.xmm_store}, %xmm13
    movaps 16*8+${this.xmm_store}, %xmm14
    movaps 16*9+${this.xmm_store}, %xmm15\n`;
    }

    this.code += `
.cfi_remember_state
    add $288 + ${this.xmm_storage} + 32, %rsp
.cfi_adjust_cfa_offset -(288 + 32)
    # The tag replaces the key on return
    pop ${this.keyp}
.cfi_pop ${this.keyp}
    mov ${this.acc0}, (${this.keyp})
    mov ${this.acc1}, 8(${this.keyp})
    pop %r15
.cfi_pop %r15
    pop %r14
.cfi_pop %r14
    pop %r13
.cfi_pop %r13
    pop %r12
.cfi_pop %r12
    pop %rbx
.cfi_pop %rbx
    pop %rbp
.cfi_pop %rbp
    ret
.size chacha20_poly1305_seal_sse41, .-chacha20_poly1305_seal_sse41
.cfi_endproc\n`;
  }
}

// Export the generator class and create an instance with default options
const generator = new ChaCha20Poly1305X86_64Generator();
generator.generate();
