const { Opcode } = require('./opcode');
const { Const } = require('./const');
const { EA } = require('./ea');
const { Register } = require('./register');
const { Label } = require('./label');
const { Expr } = require('./expr');
const { CfiDirective } = require('./cfi-directive');
const { SehDirective } = require('./seh-directive');
const { Directive } = require('./directive');

class X86_64Translator {
  constructor(flavour, output) {
    this.flavour = flavour;
    this.output = output;

    this.gas = 1;
    if (output && output.endsWith('.asm')) this.gas = 0;

    this.elf = 1;
    if (!this.gas) this.elf = 0;

    this.apple = 0;
    this.win64 = 0;
    this.prefix = '';
    this.decor = '.L';

    this.masmref = 8 + 50727 * Math.pow(2, -32);
    this.masm = 0;
    this.PTR = ' PTR';

    this.nasmref = 2.03;
    this.nasm = 0;

    if (flavour === 'mingw64') {
      this.gas = 1;
      this.elf = 0;
      this.win64 = 1;
      throw new Error('mingw64 not supported');
    } else if (flavour === 'macosx') {
      this.gas = 1;
      this.elf = 0;
      this.apple = 1;
      this.prefix = '_';
      this.decor = 'L$';
    } else if (flavour === 'masm') {
      this.gas = 0;
      this.elf = 0;
      this.masm = this.masmref;
      this.win64 = 1;
      this.decor = '$L$';
    } else if (flavour === 'nasm') {
      this.gas = 0;
      this.elf = 0;
      this.nasm = this.nasmref;
      this.win64 = 1;
      this.decor = '$L$';
      this.PTR = '';
    } else if (!this.gas) {
      throw new Error(`unknown flavour ${flavour}`);
    }

    this.current_segment = undefined;
    this.current_function = undefined;
    this.globals = {};
    this.outputLines = [];

    this.initClasses();
  }

  initClasses() {
    this.opcode = new Opcode(this);
    this.const = new Const(this);
    this.ea = new EA(this);
    this.register = new Register(this);
    this.label = new Label(this);
    this.expr = new Expr(this);
    this.cfiDirective = new CfiDirective(this);
    this.sehDirective = new SehDirective(this);
    this.directive = new Directive(this);
  }

  generateHeader() {
    let comment = '//';
    if (this.masm || this.nasm) comment = ';';
    this.outputLines.push(
      `${comment} This file is generated from a similarly-named Perl script in the BoringSSL`,
    );
    this.outputLines.push(`${comment} source tree. Do not edit by hand.`);
    this.outputLines.push('');

    if (this.nasm) {
      if (!this.win64) throw new Error('unknown target');
      this.outputLines.push(`%ifidn __OUTPUT_FORMAT__, win64
default	rel
%define XMMWORD
%define YMMWORD
%define ZMMWORD
%define _CET_ENDBR

%ifdef BORINGSSL_PREFIX
%include "boringssl_prefix_symbols_nasm.inc"
%endif`);
    } else if (this.masm) {
      this.outputLines.push('OPTION\tDOTNAME');
    }

    if (this.gas) {
      let target;
      if (this.elf) {
        target = 'defined(__ELF__)';
      } else if (this.apple) {
        target = 'defined(__APPLE__)';
      } else {
        throw new Error(`unknown target: ${this.flavour}`);
      }
      this.outputLines.push(`#include <openssl/asm_base.h>

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && ${target}`);
    }
  }

  processLine(line) {
    line = line.replace(/\r?\n$/, '');

    if (this.nasm) {
      line = line.replace(/^#ifdef /, '%ifdef ');
      line = line.replace(/^#ifndef /, '%ifndef ');
      line = line.replace(/^#endif/, '%endif');
      line = line.replace(/[#!].*$/, '');
    } else {
      line = line.replace(/!.*$/, '');
      line = line.replace(/(?<=.)#.*$/, '');
      line = line.replace(/^#([^a-z].*)?$/, '');
    }

    line = line.replace(/\/\*.*\*\//, '');
    line = line.replace(/^\s+/, '');
    line = line.replace(/\s+$/, '');

    const lineRef = { value: line };

    const labelResult = this.label.re(lineRef);
    if (labelResult) {
      const output = labelResult.out();
      if (output) this.outputLines.push(output);
    }

    const directiveResult = this.directive.re(lineRef);
    if (directiveResult) {
      const output = directiveResult.out();
      if (output) this.outputLines.push(output);
    } else {
      const opcodeResult = this.opcode.re(lineRef);
      if (opcodeResult) {
        const args = [];
        while (true) {
          let arg;

          arg =
            this.register.re(lineRef, opcodeResult) ||
            this.const.re(lineRef) ||
            this.ea.re(lineRef, opcodeResult) ||
            this.expr.re(lineRef, opcodeResult);

          if (!arg) break;

          args.push(arg);

          if (!lineRef.value.match(/^,/)) break;

          lineRef.value = lineRef.value.replace(/^,\s*/, '');
        }

        if (args.length > 0) {
          let insn;
          const sz = opcodeResult.size();

          if (this.gas) {
            insn = opcodeResult.out(
              args.length >= 1 ? args[args.length - 1].size() : sz,
            );
            const argStrs = args.map(arg => arg.out(sz));
            this.outputLines.push(`\t${insn}\t${argStrs.join(',')}`);
          } else {
            insn = opcodeResult.out();
            let finalSz = sz;
            for (const arg of args) {
              const argStr = arg.out();
              if (argStr.match(/^xmm[0-9]+$/)) {
                insn += sz;
                if (!finalSz) finalSz = 'x';
                break;
              }
              if (argStr.match(/^ymm[0-9]+$/)) {
                insn += sz;
                if (!finalSz) finalSz = 'y';
                break;
              }
              if (argStr.match(/^zmm[0-9]+$/)) {
                insn += sz;
                if (!finalSz) finalSz = 'z';
                break;
              }
              if (argStr.match(/^mm[0-9]+$/)) {
                insn += sz;
                if (!finalSz) finalSz = 'q';
                break;
              }
            }
            args.reverse();
            if (this.nasm && opcodeResult.mnemonic() === 'lea')
              finalSz = undefined;
            const argStrs = args.map(arg => arg.out(finalSz));
            this.outputLines.push(`\t${insn}\t${argStrs.join(',')}`);
          }
        } else {
          this.outputLines.push(`\t${opcodeResult.out()}`);
        }
      }
    }

    if (lineRef.value) {
      this.outputLines.push(lineRef.value);
    }
  }

  generateFooter() {
    const sehData = this.sehDirective.pdata_and_xdata();
    if (sehData) {
      for (const line of sehData.split('\n')) {
        if (line.trim()) {
          this.processLine(line);
        }
      }
    }

    if (this.current_segment && this.masm) {
      this.outputLines.push(`\n${this.current_segment}\tENDS`);
    }
    if (this.masm) {
      this.outputLines.push('END');
    } else if (this.gas) {
      this.outputLines.push('#endif');
    } else if (this.nasm) {
      this.outputLines.push(`%else
; Work around https://bugzilla.nasm.us/show_bug.cgi?id=3392738
ret
%endif`);
    } else {
      throw new Error('unknown assembler');
    }
  }

  translate(input) {
    this.outputLines = [];
    this.generateHeader();

    const lines = input.split('\n');
    for (const line of lines) {
      this.processLine(line);
    }

    this.generateFooter();
    return this.outputLines.join('\n');
  }
}

module.exports = { X86_64Translator };
