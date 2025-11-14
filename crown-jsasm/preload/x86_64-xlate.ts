/**
 * x86_64 AT&T to MASM/NASM Assembler Translator
 *
 * Ascetic x86_64 AT&T to MASM/NASM assembler translator
 * Converted from Perl to TypeScript
 *
 * Original work by <@dot-asm>
 * Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0
 *
 * This translator converts AT&T format x86_64 assembly to MASM/NASM format.
 * It's designed specifically for dual-ABI OpenSSL modules development.
 */

// Configuration
interface Config {
  flavour: Flavour;
  output: string;
  gas: boolean;
  elf: boolean;
  win64: boolean;
  prefix: string;
  decor: string;
  masm: number;
  nasm: number;
  PTR: string;
  gnuas: boolean;
}

export enum Flavour {
  Mingw64,
  Macosx,
  Masm,
  Nasm,
  Elf,
}

// Initialize configuration with defaults
export function initConfig(flavour?: Flavour): Config {
  const masmref = 8 + 50727 * Math.pow(2, -32);
  const nasmref = 2.03;

  let gas = true;
  let elf = true;
  let win64 = false;
  let prefix = '';
  let decor = '.L';
  let masm = 0;
  let nasm = 0;
  let PTR = ' PTR';
  let gnuas = false;

  if (flavour === Flavour.Mingw64) {
    gas = true;
    elf = false;
    win64 = true;
    prefix = ''; // Would need to get from compiler
  } else if (flavour === Flavour.Macosx) {
    gas = true;
    elf = false;
    prefix = '_';
    decor = 'L$';
  } else if (flavour === Flavour.Masm) {
    gas = false;
    elf = false;
    masm = masmref;
    win64 = true;
    decor = '$L$';
  } else if (flavour === Flavour.Nasm) {
    gas = false;
    elf = false;
    nasm = nasmref;
    win64 = true;
    decor = '$L$';
    PTR = '';
  }

  return {
    flavour: flavour || Flavour.Elf,
    output: '',
    gas,
    elf,
    win64,
    prefix,
    decor,
    masm,
    nasm,
    PTR,
    gnuas,
  };
}
// Generate CET property for ELF outputs
function generateCetProperty(flavour: Flavour, gnuas: boolean): string {
  if (!flavour.toString().includes('elf')) {
    return '';
  }

  // Always generate .note.gnu.property section for ELF outputs to
  // mark Intel CET support since all input files must be marked
  // with Intel CET support in order for linker to mark output with
  // Intel CET support.
  const p2align = flavour === Flavour.Elf ? 3 : 2; // elf32 uses 2
  const section = gnuas
    ? '".note.gnu.property", "a"'
    : '.note.gnu.property, #alloc';

  return `
\t.section ${section}
\t.p2align ${p2align}
\t.long 1f - 0f
\t.long 4f - 1f
\t.long 5
0:
\t# "GNU" encoded with .byte, since .asciz isn't supported
\t# on Solaris.
\t.byte 0x47
\t.byte 0x4e
\t.byte 0x55
\t.byte 0
1:
\t.p2align ${p2align}
\t.long 0xc0000002
\t.long 3f - 2f
2:
\t.long 3
3:
\t.p2align ${p2align}
4:
`;
}


// Global state
let config: Config = initConfig();
let currentSegment: string = '';
let segmentStack: string[] = [];
let currentFunction: {
  name?: string;
  abi?: string;
  narg?: number;
  scope?: string;
} = {};
let globals: Record<string, string> = {};

// DWARF constants
const DW_OP_simple: Record<string, number> = {
  deref: 0x06,
  dup: 0x12,
  drop: 0x13,
  over: 0x14,
  pick: 0x15,
  swap: 0x16,
  rot: 0x17,
  xderef: 0x18,
  abs: 0x19,
  and: 0x1a,
  div: 0x1b,
  minus: 0x1c,
  mod: 0x1d,
  mul: 0x1e,
  neg: 0x1f,
  not: 0x20,
  or: 0x21,
  plus: 0x22,
  shl: 0x24,
  shr: 0x25,
  shra: 0x26,
  xor: 0x27,
};

const DW_OP_complex: Record<string, number> = {
  constu: 0x10,
  consts: 0x11,
  plus_uconst: 0x23,
  lit0: 0x30,
  reg0: 0x50,
  breg0: 0x70,
  regx: 0x90,
  fbreg: 0x91,
  bregx: 0x92,
  piece: 0x93,
};

const DW_reg_idx: Record<string, number> = {
  '%rax': 0,
  '%rdx': 1,
  '%rcx': 2,
  '%rbx': 3,
  '%rsi': 4,
  '%rdi': 5,
  '%rbp': 6,
  '%rsp': 7,
  '%r8': 8,
  '%r9': 9,
  '%r10': 10,
  '%r11': 11,
  '%r12': 12,
  '%r13': 13,
  '%r14': 14,
  '%r15': 15,
};

// CFI state
let cfaReg = '%rsp';
let cfaRsp = -8;
let cfaStack: [string, number][] = [];

// Helper functions
function sleb128(val: number): number[] {
  const ret: number[] = [];
  const sign = val < 0 ? -1 : 0;

  while (true) {
    ret.push(val & 0x7f);
    if (val >> 6 === sign) break;
    ret[ret.length - 1] |= 0x80;
    val >>= 7;
  }

  return ret;
}

function uleb128(val: number): number[] {
  const ret: number[] = [];

  while (true) {
    ret.push(val & 0x7f);
    val >>>= 7;
    if (val === 0) break;
    ret[ret.length - 1] |= 0x80;
  }

  return ret;
}

function constOp(val: number): number[] {
  if (val >= 0 && val < 32) {
    return [DW_OP_complex.lit0 + val];
  }
  return [DW_OP_complex.consts, ...sleb128(val)];
}

function regOp(val: string): number[] {
  const match = val.match(/^(%r\w+)(?:([\+\-])((?:0x)?[0-9a-f]+))?/);
  if (!match) return [];

  const reg = DW_reg_idx[match[1]];
  const off = eval(`0 ${match[2] || '+'} ${match[3] || '0'}`);

  return [DW_OP_complex.breg0 + reg, ...sleb128(off)];
}

function cfaExpression(line: string): number[] {
  const ret: number[] = [];

  for (const token of line.split(/,\s*/)) {
    if (token.startsWith('%r')) {
      ret.push(...regOp(token));
    } else if (token.match(/(\d+)\((%r\w+)\)/)) {
      const m = token.match(/(\d+)\((%r\w+)\)/);
      ret.push(...regOp(`${m![2]}+${m![1]}`));
    } else if (token.match(/(\w+):(\-?\d+)(U?)/i)) {
      const m = token.match(/(\w+):(\-?\d+)(U?)/i)!;
      const i = parseInt(m[2]);
      ret.push(DW_OP_complex[m[1]], ...(m[3] ? uleb128(i) : sleb128(i)));
    } else if (token === '0' || parseInt(token)) {
      const i = parseInt(token);
      if (token.startsWith('+')) {
        ret.push(DW_OP_complex.plus_uconst, ...uleb128(i));
      } else {
        ret.push(...constOp(i));
      }
    } else {
      ret.push(DW_OP_simple[token]);
    }
  }

  return [15, ret.length, ...ret];
}

// VEX prefix class
class VexPrefix {
  value: string = '';

  static re(line: { value: string }): VexPrefix | null {
    const match = line.value.match(/^(\{vex\})/);
    if (!match) return null;

    const self = new VexPrefix();
    self.value = match[1];
    line.value = line.value.substring(match[0].length).trimStart();
    return self;
  }

  out(): string {
    return this.value;
  }
}

// Opcode class
class Opcode {
  op: string = '';
  sz?: string;

  static re(line: { value: string }): Opcode | null {
    const match = line.value.match(/^([a-z][a-z0-9]*)/i);
    if (!match) return null;

    const self = new Opcode();
    self.op = match[1];
    line.value = line.value.substring(match[0].length).trimStart();

    // Handle size suffixes
    if (self.op.match(/^(movz)x?([bw])/)) {
      const m = self.op.match(/^(movz)x?([bw])/)!;
      self.op = m[1];
      self.sz = m[2];
    } else if (self.op.match(/call|jmp/)) {
      self.sz = '';
    } else if (self.op.match(/^p/) && !self.op.match(/^p(ush|op|insrw)/)) {
      self.sz = '';
    } else if (self.op.match(/^[vk]/)) {
      self.sz = '';
    } else if (self.op.match(/mov[dq]/) && line.value.includes('%xmm')) {
      self.sz = '';
    } else if (self.op.match(/([a-z]{3,})([qlwb])$/)) {
      const m = self.op.match(/([a-z]{3,})([qlwb])$/)!;
      self.op = m[1];
      self.sz = m[2];
    }

    return self;
  }

  size(sz?: string): string | undefined {
    if (sz && !this.sz) this.sz = sz;
    return this.sz;
  }

  mnemonic(op?: string): string {
    if (op) this.op = op;
    return this.op;
  }

  out(arg?: string): string {
    if (config.gas) {
      if (this.op === 'movz') {
        return `${this.op}${this.sz}${arg || ''}`;
      } else if (this.op.match(/^set/)) {
        return this.op;
      } else if (this.op === 'ret') {
        let epilogue = '';
        if (config.win64 && currentFunction.abi === 'svr4') {
          epilogue = 'movq\t8(%rsp),%rdi\n\t' + 'movq\t16(%rsp),%rsi\n\t';
        }
        return epilogue + '.byte\t0xf3,0xc3';
      } else if (
        this.op === 'call' &&
        !config.elf &&
        currentSegment === '.init'
      ) {
        return '.p2align\t3\n\t.quad';
      } else {
        return `${this.op}${this.sz || ''}`;
      }
    } else {
      let op = this.op.replace(/^movz/, 'movzx');
      if (op === 'ret') {
        let ret = '';
        if (config.win64 && currentFunction.abi === 'svr4') {
          ret =
            `mov\trdi,QWORD${config.PTR}[8+rsp]\t;WIN64 epilogue\n\t` +
            `mov\trsi,QWORD${config.PTR}[16+rsp]\n\t`;
        }
        return ret + 'DB\t0F3h,0C3h\t\t;repret';
      } else if (op.match(/^(pop|push)f/)) {
        return op + (this.sz || '');
      } else if (op === 'call' && currentSegment === '.CRT$XCU') {
        return '\tDQ';
      }
      return op;
    }
  }
}

// Const class
class Const {
  value: string = '';

  static re(line: { value: string }): Const | null {
    const match = line.value.match(/^\$([^,]+)/);
    if (!match) return null;

    const self = new Const();
    self.value = match[1];
    line.value = line.value.substring(match[0].length).trimStart();
    return self;
  }

  size(): undefined {
    return undefined;
  }

  out(): string {
    let value = this.value.replace(/\b(0b[0-1]+)/g, m =>
      String(parseInt(m.substring(2), 2)),
    );

    if (config.gas) {
      value = value.replace(/(?<![\w\$\.])(0x?[0-9a-f]+)/gi, m => {
        try {
          return String(parseInt(m));
        } catch {
          return m;
        }
      });

      value = value.replace(/([0-9]+\s*[\*\/\%]\s*[0-9]+)/g, m => {
        try {
          return String(eval(m));
        } catch {
          return m;
        }
      });

      return `$${value}`;
    } else {
      if (config.masm) {
        value = value.replace(/0x([0-9a-f]+)/gi, '0$1h');
      }
      return value;
    }
  }
}

// Effective Address class
class EA {
  asterisk: string = '';
  label: string = '';
  base: string = '';
  index: string = '';
  scale: number = 1;
  opmask: string = '';
  opcode?: Opcode;

  static getSzmap(): Record<string, string> {
    if (config.gas) return {};
    return {
      b: `BYTE${config.PTR}`,
      w: `WORD${config.PTR}`,
      l: `DWORD${config.PTR}`,
      d: `DWORD${config.PTR}`,
      q: `QWORD${config.PTR}`,
      o: `OWORD${config.PTR}`,
      x: `XMMWORD${config.PTR}`,
      y: `YMMWORD${config.PTR}`,
      z: `ZMMWORD${config.PTR}`,
    };
  }

  static re(line: { value: string }, opcode: Opcode): EA | null {
    const match = line.value.match(
      /^(\*?)([^\(,]*)\(([%\w,]+)\)((?:\{[^}]+\})*)/,
    );
    if (!match) return null;

    const self = new EA();
    self.asterisk = match[1];
    self.label = match[2];
    const parts = match[3].split(',');
    self.base = parts[0] || '';
    self.index = parts[1] || '';
    self.scale = parseInt(parts[2] || '1');
    self.opmask = match[4];
    self.opcode = opcode;

    line.value = line.value.substring(match[0].length).trimStart();

    if (config.win64 && self.label.includes('@GOTPCREL')) {
      if (opcode.mnemonic() !== 'mov')
        throw new Error('GOTPCREL only with mov');
      opcode.mnemonic('lea');
      self.label = self.label.replace('@GOTPCREL', '');
    }

    self.base = self.base.replace(/^%/, '');
    self.index = self.index.replace(/^%/, '');

    return self;
  }

  size(): void {}

  out(sz?: string): string {
    let label = this.label.replace(
      /([_a-z][_a-z0-9]*)/gi,
      m => globals[m] || m,
    );
    label = label.replace(/\.L/g, config.decor);

    // Convert to 64-bit
    let index = this.index.replace(/^[er](.?[0-9xpi])[d]?$/, 'r$1');
    let base = this.base.replace(/^[er](.?[0-9xpi])[d]?$/, 'r$1');

    // Handle arithmetic in label
    label = label.replace(/(?<![\w\$\.])(0x?[0-9a-f]+)/gi, m =>
      String(parseInt(m)),
    );
    label = label.replace(/\b([0-9]+\s*[\*\/\%]\s*[0-9]+)\b/g, m =>
      String(eval(m)),
    );

    // Sign extension for 32-bit offsets
    label = label.replace(/\b([0-9]+)\b/g, m => String(parseInt(m) >>> 0));

    // Optimize base/index for rbp/r13
    if (!label && index && this.scale === 1 && base.match(/(rbp|r13)/)) {
      [base, index] = [index, base];
    }

    if (config.gas) {
      label = label.replace(/^___imp_/, '__imp__');

      if (index) {
        return (
          `${this.asterisk}${label}(${base ? '%' + base : ''},` +
          `%${index},${this.scale})${this.opmask}`
        );
      } else {
        return `${this.asterisk}${label}(%${base})${this.opmask}`;
      }
    } else {
      label = label.replace(/\./g, '$');
      label = label.replace(/(?<![\w\$\.])0x([0-9a-f]+)/gi, '0$1h');
      if (label.match(/[\*\+\-\/]/)) {
        label = `(${label})`;
      }

      const mnemonic = this.opcode?.mnemonic() || '';
      if (this.asterisk) sz = 'q';
      else if (mnemonic.match(/^v?mov([qd])$/))
        sz = mnemonic.match(/^v?mov([qd])$/)![1];
      else if (mnemonic.match(/^v?pinsr([qdwb])$/))
        sz = mnemonic.match(/^v?pinsr([qdwb])$/)![1];
      else if (mnemonic.match(/^vbroadcasti32x4$/)) sz = 'x';
      else if (mnemonic.match(/^vpbroadcast([qdwb])$/))
        sz = mnemonic.match(/^vpbroadcast([qdwb])$/)![1];
      else if (mnemonic.match(/^v(?!perm)[a-z]+[fi]128$/)) sz = 'x';

      this.opmask = this.opmask.replace(/%(k[0-7])/, '$1');

      const szmap = EA.getSzmap();
      const szStr = sz ? szmap[sz] : '';

      if (index) {
        return (
          `${szStr}[${label ? label + '+' : ''}${index}*${this.scale}` +
          `${base ? '+' + base : ''}]${this.opmask}`
        );
      } else if (base === 'rip') {
        return `${szStr}[${label}]`;
      } else {
        return `${szStr}[${label ? label + '+' : ''}${base}]${this.opmask}`;
      }
    }
  }
}

// Register class
class Register {
  asterisk: string = '';
  value: string = '';
  opmask: string = '';

  static re(line: { value: string }, opcode: Opcode): Register | null {
    const match = line.value.match(/^(\*?)%(\w+)((?:\{[^}]+\})*)/);
    if (!match) return null;

    const self = new Register();
    self.asterisk = match[1];
    self.value = match[2];
    self.opmask = match[3];

    opcode.size(self.size());
    line.value = line.value.substring(match[0].length).trimStart();
    return self;
  }

  size(): string | undefined {
    if (this.value.match(/^r[\d]+b$/i)) return 'b';
    if (this.value.match(/^r[\d]+w$/i)) return 'w';
    if (this.value.match(/^r[\d]+d$/i)) return 'l';
    if (this.value.match(/^r[\w]+$/i)) return 'q';
    if (this.value.match(/^[a-d][hl]$/i)) return 'b';
    if (this.value.match(/^[\w]{2}l$/i)) return 'b';
    if (this.value.match(/^[\w]{2}$/i)) return 'w';
    if (this.value.match(/^e[a-z]{2}$/i)) return 'l';
    return undefined;
  }

  out(): string {
    if (config.gas) {
      return `${this.asterisk}%${this.value}${this.opmask}`;
    } else {
      const opmask = this.opmask.replace(/%(k[0-7])/, '$1');
      return this.value + opmask;
    }
  }
}

// Label class
class Label {
  value: string = '';

  static re(line: { value: string }): Label | null {
    const match = line.value.match(/(^[\.\w]+):/);
    if (!match) return null;

    const self = new Label();
    self.value = match[1];
    line.value = line.value.substring(match[0].length).trimStart();

    self.value = self.value.replace(/^\.L/, config.decor);
    return self;
  }

  out(): string {
    if (config.gas) {
      let func = (globals[this.value] || this.value) + ':';
      if (
        config.win64 &&
        currentFunction.name === this.value &&
        currentFunction.abi === 'svr4'
      ) {
        func += '\n';
        func += '\tmovq\t%rdi,8(%rsp)\n';
        func += '\tmovq\t%rsi,16(%rsp)\n';
        func += '\tmovq\t%rsp,%rax\n';
        func += `${config.decor}SEH_begin_${currentFunction.name}:\n`;
        const narg = currentFunction.narg || 6;
        if (narg > 0) func += '\tmovq\t%rcx,%rdi\n';
        if (narg > 1) func += '\tmovq\t%rdx,%rsi\n';
        if (narg > 2) func += '\tmovq\t%r8,%rdx\n';
        if (narg > 3) func += '\tmovq\t%r9,%rcx\n';
        if (narg > 4) func += '\tmovq\t40(%rsp),%r8\n';
        if (narg > 5) func += '\tmovq\t48(%rsp),%r9\n';
      }
      return func;
    } else if (this.value !== currentFunction.name) {
      return this.value + (config.masm ? ':' : '') + ':';
    } else if (config.win64 && currentFunction.abi === 'svr4') {
      let func =
        `${currentFunction.name}` +
        (config.nasm ? ':' : `\tPROC ${currentFunction.scope}`) +
        '\n';
      func += `\tmov\tQWORD${config.PTR}[8+rsp],rdi\t;WIN64 prologue\n`;
      func += `\tmov\tQWORD${config.PTR}[16+rsp],rsi\n`;
      func += '\tmov\trax,rsp\n';
      func += `${config.decor}SEH_begin_${currentFunction.name}:`;
      if (config.masm) func += ':';
      func += '\n';
      const narg = currentFunction.narg || 6;
      if (narg > 0) func += '\tmov\trdi,rcx\n';
      if (narg > 1) func += '\tmov\trsi,rdx\n';
      if (narg > 2) func += '\tmov\trdx,r8\n';
      if (narg > 3) func += '\tmov\trcx,r9\n';
      if (narg > 4) func += `\tmov\tr8,QWORD${config.PTR}[40+rsp]\n`;
      if (narg > 5) func += `\tmov\tr9,QWORD${config.PTR}[48+rsp]\n`;
      func += '\n';
      return func;
    } else {
      return (
        `${currentFunction.name}` +
        (config.nasm ? ':' : `\tPROC ${currentFunction.scope}`)
      );
    }
  }
}

// Expression class
class Expr {
  value: string = '';
  opcode?: Opcode;

  static re(line: { value: string }, opcode: Opcode): Expr | null {
    const match = line.value.match(/(^[^,]+)/);
    if (!match) return null;

    const self = new Expr();
    self.value = match[1];
    self.opcode = opcode;
    line.value = line.value.substring(match[0].length).trimStart();

    self.value = self.value.replace(/@PLT/, config.elf ? '@PLT' : '');
    self.value = self.value.replace(
      /([_a-z][_a-z0-9]*)/gi,
      m => globals[m] || m,
    );
    self.value = self.value.replace(/\.L/g, config.decor);

    return self;
  }

  size(): undefined {
    return undefined;
  }

  out(): string {
    if (config.nasm && this.opcode?.mnemonic().match(/^j(?![re]cxz)/)) {
      return 'NEAR ' + this.value;
    }
    return this.value;
  }
}

// CFI Directive class
class CfiDirective {
  value?: string;

  static re(line: { value: string }): CfiDirective | null {
    const match = line.value.match(/^\s*\.cfi_(\w+)\s*/);
    if (!match) return null;

    const self = new CfiDirective();
    const dir = match[1];
    line.value = line.value.substring(match[0].length);

    switch (dir) {
      case 'startproc':
        cfaReg = '%rsp';
        cfaRsp = -8;
        break;
      case 'endproc':
        cfaReg = '%rsp';
        cfaRsp = 0;
        if (cfaStack.length > 0) {
          throw new Error('unpaired .cfi_remember_state');
        }
        break;
      case 'def_cfa_register':
        cfaReg = line.value;
        break;
      case 'def_cfa_offset':
        if (cfaReg === '%rsp') {
          cfaRsp = -1 * eval(line.value);
        }
        break;
      case 'adjust_cfa_offset':
        if (cfaReg === '%rsp') {
          cfaRsp -= eval(line.value);
        }
        break;
      case 'def_cfa':
        const parts = line.value.match(/(%r\w+)\s*,\s*(.+)/);
        if (parts) {
          cfaReg = parts[1];
          if (cfaReg === '%rsp') {
            cfaRsp = -1 * eval(parts[2]);
          }
        }
        break;
      case 'push':
        cfaRsp -= 8;
        if (cfaReg === '%rsp') {
          self.value = '.cfi_adjust_cfa_offset\t8\n';
        }
        self.value =
          (self.value || '') + `.cfi_offset\t${line.value},${cfaRsp}`;
        line.value = '';
        return self;
      case 'pop':
        cfaRsp += 8;
        if (cfaReg === '%rsp') {
          self.value = '.cfi_adjust_cfa_offset\t-8\n';
        }
        self.value = (self.value || '') + `.cfi_restore\t${line.value}`;
        line.value = '';
        return self;
      case 'cfa_expression':
        self.value =
          '.cfi_escape\t' +
          cfaExpression(line.value)
            .map(b => `0x${b.toString(16).padStart(2, '0')}`)
            .join(',');
        line.value = '';
        return self;
      case 'remember_state':
        cfaStack.push([cfaReg, cfaRsp]);
        break;
      case 'restore_state':
        [cfaReg, cfaRsp] = cfaStack.pop()!;
        break;
    }

    if (dir) {
      self.value = `.cfi_${dir}\t${line.value}`;
    }
    line.value = '';
    return self;
  }

  out(): string | undefined {
    return config.elf ? this.value : undefined;
  }
}

// Directive class - complete implementation
class Directive {
  value?: string;

  static re(line: { value: string }): Directive | CfiDirective | null {
    // Try CFI directive first
    const cfi = CfiDirective.re(line);
    if (cfi) return cfi;

    const match = line.value.match(/^\s*(\.\w+)/);
    if (!match) return null;

    const self = new Directive();
    let dir = match[1];
    line.value = line.value.substring(match[0].length).trimStart();

    // Handle directives based on gas/masm/nasm
    if (config.gas) {
      self.value = dir + '\t' + line.value;

      // .global/.globl/.extern directive
      if (dir.match(/\.global|\.globl|\.extern/)) {
        globals[line.value] = config.prefix + line.value;
        if (config.prefix) {
          line.value = globals[line.value];
        }
        if (dir.match(/\.extern/)) {
          self.value = ''; // swallow extern
        } else {
          self.value = dir + '\t' + line.value;
        }
      }
      // .type directive
      else if (dir.match(/\.type/)) {
        const parts = line.value.split(',');
        const sym = parts[0];
        const type = parts[1];
        const narg = parts[2] ? parseInt(parts[2]) : undefined;
        
        if (type === '@function') {
          currentFunction = {
            name: sym,
            abi: 'svr4',
            narg: narg,
            scope: globals[sym] !== undefined ? 'PUBLIC' : 'PRIVATE'
          };
        } else if (type === '@abi-omnipotent') {
          currentFunction = {
            name: sym,
            scope: globals[sym] !== undefined ? 'PUBLIC' : 'PRIVATE'
          };
        }
        
        line.value = line.value.replace(/@abi-omnipotent/, '@function');
        line.value = line.value.replace(/@function.*/, '@function');
        self.value = dir + '\t' + line.value;
        
        if (!config.elf) {
          self.value = '';
          const match = line.value.match(/([^,]+),@function/);
          if (config.win64 && match) {
            const symbol = match[1];
            const isDefined = globals[symbol] !== undefined;
            self.value = `.def\t${globals[symbol] || symbol};\t`;
            self.value += isDefined ? '.scl 2;' : '.scl 3;';
            self.value += '\t.type 32;\t.endef';
          }
        }
      }
      // .asciz directive
      else if (dir.match(/\.asciz/)) {
        const match = line.value.match(/^"(.*)"$/);
        if (match) {
          dir = '.byte';
          const bytes = Array.from(match[1]).map(c => c.charCodeAt(0));
          bytes.push(0);
          line.value = bytes.join(',');
          self.value = dir + '\t' + line.value;
        }
      }
      // .rva/.long/.quad/.byte directive
      else if (dir.match(/\.rva|\.long|\.quad|\.byte/)) {
        line.value = line.value.replace(
          /([_a-z][_a-z0-9]*)/gi,
          m => globals[m] || m
        );
        line.value = line.value.replace(/\.L/g, config.decor);
        self.value = dir + '\t' + line.value;
      }
      // .type directive
      else if (!config.elf && dir.match(/\.type/)) {
        self.value = '';
        const parts = line.value.match(/([^,]+),\@function/);
        if (config.win64 && parts) {
          const sym = parts[1];
          const isDefined = globals[sym] !== undefined;
          self.value = `.def\t${globals[sym] || sym};\t`;
          self.value += isDefined ? '.scl 2;' : '.scl 3;';
          self.value += '\t.type 32;\t.endef';
        }
      }
      // .size directive
      else if (!config.elf && dir.match(/\.size/)) {
        self.value = '';
        if (currentFunction.name) {
          if (config.win64 && currentFunction.abi === 'svr4') {
            self.value += `${config.decor}SEH_end_${currentFunction.name}:`;
          }
          currentFunction = {};
        }
      }
      // .align directive
      else if (!config.elf && dir.match(/\.align/)) {
        const align = parseInt(line.value);
        self.value = `.p2align\t${Math.log2(align)}`;
      }
      // .section directive
      else if (dir === '.section') {
        // Remove align option (not supported by gcc)
        self.value = self.value.replace(/(.+)\s+align\s*=.*$/, '$1');
        
        const prevSegment = segmentStack.pop();
        if (!prevSegment) {
          // If no previous section, assume .text
          segmentStack.push('.text');
        }
        
        currentSegment = line.value.replace(/([^\s]+).*$/, '$1');
        segmentStack.push(currentSegment);
        
        if (!config.elf && currentSegment === '.rodata') {
          if (config.flavour === Flavour.Macosx) {
            self.value = '.section\t__DATA,__const';
          } else if (config.flavour === Flavour.Mingw64) {
            self.value = '.section\t.rodata';
          }
        }
        if (!config.elf && currentSegment === '.init') {
          if (config.flavour === Flavour.Macosx) {
            self.value = '.mod_init_func';
          } else if (config.flavour === Flavour.Mingw64) {
            self.value = '.section\t.ctors';
          }
        }
      }
      // .text or .data directive
      else if (dir.match(/\.(text|data)/)) {
        const prevSegment = segmentStack.pop();
        if (!prevSegment) {
          segmentStack.push('.text');
        }
        currentSegment = '.' + dir.match(/\.(text|data)/)![1];
        segmentStack.push(currentSegment);
      }
      // .hidden directive
      else if (dir.match(/\.hidden/)) {
        if (config.flavour === Flavour.Macosx) {
          self.value = `.private_extern\t${config.prefix}${line.value}`;
        } else if (config.flavour === Flavour.Mingw64) {
          self.value = '';
        }
      }
      // .comm directive
      else if (dir.match(/\.comm/)) {
        self.value = `${dir}\t${config.prefix}${line.value}`;
        if (config.flavour === Flavour.Macosx) {
          self.value = self.value.replace(
            /,([0-9]+),([0-9]+)$/,
            (_, size, align) => `,${size},${Math.log2(parseInt(align))}`
          );
        }
      }
      // .previous directive
      else if (dir.match(/\.previous/)) {
        segmentStack.pop(); // pop ourselves
        currentSegment = segmentStack[0] || '';
        if (!currentSegment) {
          currentSegment = '.text';
          segmentStack.push(currentSegment);
        }
        if (config.flavour === Flavour.Mingw64 || config.flavour === Flavour.Macosx) {
          self.value = currentSegment;
        }
      }

      line.value = '';
      return self;
    }

    // Non-gas case (MASM/NASM)
    switch (dir) {
      case '.text': {
        let v = '';
        if (config.nasm) {
          const prevSegment = segmentStack.pop();
          if (!prevSegment) {
            segmentStack.push('.text');
          }
          v = 'section\t.text code align=64\n';
          currentSegment = '.text';
          segmentStack.push(currentSegment);
        } else {
          const prevSegment = segmentStack.pop();
          if (!prevSegment) {
            segmentStack.push('.text$');
          }
          if (prevSegment) {
            v = `${prevSegment}\tENDS\n`;
          }
          currentSegment = '.text$';
          segmentStack.push(currentSegment);
          v += `${currentSegment}\tSEGMENT `;
          v += config.masm >= 8 + 50727 * Math.pow(2, -32) ? 'ALIGN(256)' : 'PAGE';
          v += " 'CODE'";
        }
        self.value = v;
        break;
      }

      case '.data': {
        let v = '';
        if (config.nasm) {
          v = 'section\t.data data align=8\n';
        } else {
          const prevSegment = segmentStack.pop();
          if (prevSegment) {
            v = `${prevSegment}\tENDS\n`;
          }
          currentSegment = '_DATA';
          segmentStack.push(currentSegment);
          v += `${currentSegment}\tSEGMENT`;
        }
        self.value = v;
        break;
      }

      case '.section': {
        let v = '';
        let align = line.value.match(/(align\s*=\s*\d+$)/)?.[0] || '';
        line.value = line.value.replace(/(\s+align\s*=\s*\d+$)/, '');
        line.value = line.value.replace(/,.*/, '');
        line.value = line.value === '.init' ? '.CRT$XCU' : line.value;
        line.value = line.value === '.rodata' ? '.rdata' : line.value;

        if (config.nasm) {
          const prevSegment = segmentStack.pop();
          if (!prevSegment) {
            // Hack for ecp_nistz256-x86_64.pl
            segmentStack.push('.text');
          }
          v = `section\t${line.value}`;
          if (line.value.match(/\.([prx])data/)) {
            const alignMatch = align.match(/align\s*=\s*(\d+)/);
            if (alignMatch) {
              v += ` rdata align=${alignMatch[1]}`;
            } else {
              const type = line.value.match(/\.([prx])data/)![1];
              v += ` rdata align=${type === 'p' ? 4 : 8}`;
            }
          } else if (line.value.match(/\.CRT\$/i)) {
            v += ' rdata align=8';
          }
        } else {
          const prevSegment = segmentStack.pop();
          if (!prevSegment) {
            // Hack for ecp_nistz256-x86_64.pl (masm)
            segmentStack.push('.text$');
          }
          if (prevSegment) {
            v = `${prevSegment}\tENDS\n`;
          }
          v += `${line.value}\tSEGMENT`;
          if (line.value.match(/\.([prx])data/)) {
            v += ' READONLY';
            const alignMatch = align.match(/align\s*=\s*(\d+)$/);
            if (alignMatch) {
              if (config.masm >= 8 + 50727 * Math.pow(2, -32)) {
                v += ` ALIGN(${alignMatch[1]})`;
              }
            } else {
              const type = line.value.match(/\.([prx])data/)![1];
              if (config.masm >= 8 + 50727 * Math.pow(2, -32)) {
                v += ` ALIGN(${type === 'p' ? 4 : 8})`;
              }
            }
          } else if (line.value.match(/\.CRT\$/i)) {
            v += ' READONLY ';
            v += config.masm >= 8 + 50727 * Math.pow(2, -32) ? 'ALIGN(8)' : 'DWORD';
          }
        }
        currentSegment = line.value;
        segmentStack.push(line.value);
        self.value = v;
        break;
      }

      case '.extern': {
        self.value = `EXTERN\t${line.value}`;
        if (config.masm) {
          self.value += ':NEAR';
        }
        break;
      }

      case '.globl':
      case '.global': {
        self.value = config.masm ? 'PUBLIC' : 'global';
        self.value += `\t${line.value}`;
        break;
      }

      case '.size': {
        if (currentFunction.name) {
          self.value = '';
          if (currentFunction.abi === 'svr4') {
            self.value = `${config.decor}SEH_end_${currentFunction.name}:`;
            if (config.masm) {
              self.value += ':';
            }
            self.value += '\n';
          }
          if (config.masm && currentFunction.name) {
            self.value += `${currentFunction.name}\tENDP`;
          }
          currentFunction = {};
        }
        break;
      }

      case '.align': {
        const max = config.masm && config.masm >= 8 + 50727 * Math.pow(2, -32) ? 256 : 4096;
        const align = parseInt(line.value);
        self.value = `ALIGN\t${align > max ? max : align}`;
        break;
      }

      case '.value':
      case '.long':
      case '.rva':
      case '.quad': {
        const sz = dir.charAt(1).toUpperCase();
        const arr = line.value.split(/,\s*/);
        const last = arr.pop()!;
        
        const conv = (v: string): string => {
          v = v.replace(/^(0b[0-1]+)/g, m => String(parseInt(m.substring(2), 2)));
          if (config.masm) {
            v = v.replace(/^0x([0-9a-f]+)/gi, '0$1h');
          }
          if (sz === 'D' && (currentSegment.match(/\.[px]data/) || dir === '.rva')) {
            v = v.replace(
              /^([_a-z\$\@][_a-z0-9\$\@]*)/gi,
              m => config.nasm ? `${m} wrt ..imagebase` : `imagerel ${m}`
            );
          }
          return v;
        };

        const szMap: Record<string, string> = {
          v: 'W', l: 'D', r: 'D', q: 'Q'
        };
        const szCode = szMap[sz.toLowerCase()] || sz;
        self.value = `\tD${szCode}\t`;
        for (const item of arr) {
          self.value += conv(item) + ',';
        }
        self.value += conv(last);
        break;
      }

      case '.byte': {
        const strs = line.value.split(/,\s*/);
        strs.forEach((s, i) => {
          strs[i] = s.replace(/(0b[0-1]+)/g, m =>
            String(parseInt(m.substring(2), 2))
          );
        });
        if (config.masm) {
          strs.forEach((s, i) => {
            strs[i] = s.replace(/0x([0-9a-f]+)/gi, '0$1h');
          });
        }
        let result = '';
        while (strs.length > 16) {
          result += 'DB\t' + strs.splice(0, 16).join(',') + '\n';
        }
        if (strs.length > 0) {
          result += 'DB\t' + strs.join(',');
        }
        self.value = result;
        break;
      }

      case '.comm': {
        const parts = line.value.split(/,\s*/);
        let v = '';
        if (config.nasm) {
          v = `common\t${config.prefix}${parts[0]} ${parts[1]}`;
        } else {
          const prevSegment = segmentStack.pop();
          if (prevSegment) {
            v = `${prevSegment}\tENDS\n`;
          }
          currentSegment = '_DATA';
          segmentStack.push(currentSegment);
          v += `${currentSegment}\tSEGMENT\n`;
          v += `COMM\t${parts[0]}:DWORD:${parseInt(parts[1]) / 4}`;
        }
        self.value = v;
        break;
      }

      case '.previous': {
        let v = '';
        if (config.nasm) {
          segmentStack.pop(); // pop ourselves
          currentSegment = segmentStack.pop() || '';
          v = `section ${currentSegment}`;
          segmentStack.push(currentSegment);
        } else {
          let segment = segmentStack.pop();
          if (segment) {
            v = `${segment}\tENDS\n`;
          }
          currentSegment = segmentStack.pop() || '';
          if (currentSegment.match(/\.text\$/)) {
            v += `${currentSegment}\tSEGMENT `;
            v += config.masm >= 8 + 50727 * Math.pow(2, -32) ? 'ALIGN(256)' : 'PAGE';
            v += " 'CODE'";
            segmentStack.push(currentSegment);
          }
        }
        self.value = v;
        break;
      }
    }

    line.value = '';
    return self;
  }

  out(): string | undefined {
    return this.value;
  }
}

// Hard-coded instructions support
// Upon initial x86_64 introduction SSE>2 extensions were not introduced
// yet. In order not to be bothered by tracing exact assembler versions,
// but at the same time to provide a bare security minimum of AES-NI, we
// hard-code some instructions. Extensions past AES-NI on the other hand
// are traced by examining assembler version in individual perlasm
// modules...

const regrm: Record<string, number> = {
  '%eax': 0,
  '%ecx': 1,
  '%edx': 2,
  '%ebx': 3,
  '%esp': 4,
  '%ebp': 5,
  '%esi': 6,
  '%edi': 7,
};

function rex(
  opcode: number[],
  dst: number,
  src: number,
  rexBase: number = 0,
): void {
  let rexVal = rexBase;
  if (dst >= 8) rexVal |= 0x04;
  if (src >= 8) rexVal |= 0x01;
  if (rexVal) opcode.push(rexVal | 0x40);
}

// Elderly gas can't handle inter-register movq
function movq(arg: string): number[] {
  const match1 = arg.match(/%xmm([0-9]+),\s*%r(\w+)/);
  if (match1) {
    const src = parseInt(match1[1]);
    let dst: number;
    if (match1[2].match(/[0-9]+/)) {
      dst = parseInt(match1[2]);
    } else {
      dst = regrm[`%e${match1[2]}`];
    }
    const opcode: number[] = [0x66];
    rex(opcode, src, dst, 0x8);
    opcode.push(0x0f, 0x7e);
    opcode.push(0xc0 | ((src & 7) << 3) | (dst & 7)); // ModR/M
    return opcode;
  }

  const match2 = arg.match(/%r(\w+),\s*%xmm([0-9]+)/);
  if (match2) {
    const src = parseInt(match2[2]);
    let dst: number;
    if (match2[1].match(/[0-9]+/)) {
      dst = parseInt(match2[1]);
    } else {
      dst = regrm[`%e${match2[1]}`];
    }
    const opcode: number[] = [0x66];
    rex(opcode, src, dst, 0x8);
    opcode.push(0x0f, 0x6e);
    opcode.push(0xc0 | ((src & 7) << 3) | (dst & 7)); // ModR/M
    return opcode;
  }

  return [];
}

function pextrd(arg: string): number[] {
  const match = arg.match(/\$([0-9]+),\s*%xmm([0-9]+),\s*(%\w+)/);
  if (!match) return [];

  const imm = parseInt(match[1]);
  const src = parseInt(match[2]);
  let dst: number;

  if (match[3].match(/%r([0-9]+)d/)) {
    dst = parseInt(match[3].match(/%r([0-9]+)d/)![1]);
  } else if (match[3].match(/%e/)) {
    dst = regrm[match[3]];
  } else {
    return [];
  }

  const opcode: number[] = [0x66];
  rex(opcode, src, dst);
  opcode.push(0x0f, 0x3a, 0x16);
  opcode.push(0xc0 | ((src & 7) << 3) | (dst & 7)); // ModR/M
  opcode.push(imm);
  return opcode;
}

function pinsrd(arg: string): number[] {
  const match = arg.match(/\$([0-9]+),\s*(%\w+),\s*%xmm([0-9]+)/);
  if (!match) return [];

  const imm = parseInt(match[1]);
  const dst = parseInt(match[3]);
  let src: number;

  if (match[2].match(/%r([0-9]+)/)) {
    src = parseInt(match[2].match(/%r([0-9]+)/)![1]);
  } else if (match[2].match(/%e/)) {
    src = regrm[match[2]];
  } else {
    return [];
  }

  const opcode: number[] = [0x66];
  rex(opcode, dst, src);
  opcode.push(0x0f, 0x3a, 0x22);
  opcode.push(0xc0 | ((dst & 7) << 3) | (src & 7)); // ModR/M
  opcode.push(imm);
  return opcode;
}

function pshufb(arg: string): number[] {
  const match = arg.match(/%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!match) return [];

  const src = parseInt(match[1]);
  const dst = parseInt(match[2]);
  const opcode: number[] = [0x66];
  rex(opcode, dst, src);
  opcode.push(0x0f, 0x38, 0x00);
  opcode.push(0xc0 | (src & 7) | ((dst & 7) << 3)); // ModR/M
  return opcode;
}

function palignr(arg: string): number[] {
  const match = arg.match(/\$([0-9]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!match) return [];

  const imm = parseInt(match[1]);
  const src = parseInt(match[2]);
  const dst = parseInt(match[3]);
  const opcode: number[] = [0x66];
  rex(opcode, dst, src);
  opcode.push(0x0f, 0x3a, 0x0f);
  opcode.push(0xc0 | (src & 7) | ((dst & 7) << 3)); // ModR/M
  opcode.push(imm);
  return opcode;
}

function pclmulqdq(arg: string): number[] {
  const match = arg.match(/\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!match) return [];

  const src = parseInt(match[2]);
  const dst = parseInt(match[3]);
  const opcode: number[] = [0x66];
  rex(opcode, dst, src);
  opcode.push(0x0f, 0x3a, 0x44);
  opcode.push(0xc0 | (src & 7) | ((dst & 7) << 3)); // ModR/M

  const c = match[1];
  const imm = c.startsWith('0') ? parseInt(c, 8) : parseInt(c);
  opcode.push(imm);
  return opcode;
}

function rdrand(arg: string): number[] {
  const match = arg.match(/%[er](\w+)/);
  if (!match) return [];

  let dst: number;
  if (match[1].match(/[0-9]+/)) {
    dst = parseInt(match[1]);
  } else {
    dst = regrm[`%e${match[1]}`];
  }

  const opcode: number[] = [];
  rex(opcode, 0, dst, 8);
  opcode.push(0x0f, 0xc7, 0xf0 | (dst & 7));
  return opcode;
}

function rdseed(arg: string): number[] {
  const match = arg.match(/%[er](\w+)/);
  if (!match) return [];

  let dst: number;
  if (match[1].match(/[0-9]+/)) {
    dst = parseInt(match[1]);
  } else {
    dst = regrm[`%e${match[1]}`];
  }

  const opcode: number[] = [];
  rex(opcode, 0, dst, 8);
  opcode.push(0x0f, 0xc7, 0xf8 | (dst & 7));
  return opcode;
}

// Not all AVX-capable assemblers recognize AMD XOP extension. Since we
// are using only two instructions hand-code them in order to be excused
// from chasing assembler versions...

function rxb(
  opcode: number[],
  dst: number,
  src1: number,
  src2: number,
  rxbBase: number = 0,
): void {
  let rxbVal = rxbBase | (0x7 << 5);
  if (dst >= 8) rxbVal &= ~(0x04 << 5);
  if (src1 >= 8) rxbVal &= ~(0x01 << 5);
  if (src2 >= 8) rxbVal &= ~(0x02 << 5);
  opcode.push(rxbVal);
}

function vprotd(arg: string): number[] {
  const match = arg.match(/\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!match) return [];

  const src = parseInt(match[2]);
  const dst = parseInt(match[3]);
  const opcode: number[] = [0x8f];
  rxb(opcode, dst, src, -1, 0x08);
  opcode.push(0x78, 0xc2);
  opcode.push(0xc0 | (src & 7) | ((dst & 7) << 3)); // ModR/M

  const c = match[1];
  const imm = c.startsWith('0') ? parseInt(c, 8) : parseInt(c);
  opcode.push(imm);
  return opcode;
}

function vprotq(arg: string): number[] {
  const match = arg.match(/\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!match) return [];

  const src = parseInt(match[2]);
  const dst = parseInt(match[3]);
  const opcode: number[] = [0x8f];
  rxb(opcode, dst, src, -1, 0x08);
  opcode.push(0x78, 0xc3);
  opcode.push(0xc0 | (src & 7) | ((dst & 7) << 3)); // ModR/M

  const c = match[1];
  const imm = c.startsWith('0') ? parseInt(c, 8) : parseInt(c);
  opcode.push(imm);
  return opcode;
}

// Intel Control-flow Enforcement Technology extension. All functions and
// indirect branch targets will have to start with this instruction...
function endbranch(): number[] {
  return [0xf3, 0x0f, 0x1e, 0xfa];
}

// Instruction handler map
const hardcodedInstructions: Record<string, (arg: string) => number[]> = {
  movq,
  pextrd,
  pinsrd,
  pshufb,
  palignr,
  pclmulqdq,
  rdrand,
  rdseed,
  vprotd,
  vprotq,
  endbranch: () => endbranch(),
};

/**
 * Main translation function
 * Processes assembly input line by line and outputs translated assembly
 */
export function translateAssembly(input: string, flavour?: Flavour): string {
  // Initialize configuration
  config = initConfig(flavour);

  // Reset global state
  currentSegment = '';
  segmentStack = [];
  currentFunction = {};
  globals = {};
  cfaReg = '%rsp';
  cfaRsp = -8;
  cfaStack = [];

  // Intel Control-flow Enforcement Technology extension. All functions and
  // indirect branch targets will have to start with this instruction...
  input = input.replaceAll('endbranch', '.byte   243,15,30,250');

  const lines = input.split('\n');
  const output: string[] = [];

  // Add header for NASM/MASM
  if (config.nasm) {
    output.push('default\trel');
    output.push('%define XMMWORD');
    output.push('%define YMMWORD');
    output.push('%define ZMMWORD');
  } else if (config.masm) {
    output.push('OPTION\tDOTNAME');
  }

  // Process each line
  for (let inputLine of lines) {
    // Remove line endings and comments
    inputLine = inputLine.replace(/\r?\n$/, '');
    inputLine = inputLine.replace(/[#!].*$/, '');
    inputLine = inputLine.replace(/\/\*.*\*\//, '');
    inputLine = inputLine.trimStart().trimEnd();

    if (!inputLine) {
      output.push('');
      continue;
    }

    const line = { value: inputLine };
    let result = '';

    // Try to parse label
    const label = Label.re(line);
    if (label) {
      result += label.out();
    }

    // Try to parse directive
    const directive = Directive.re(line);
    if (directive) {
      const out = directive.out();
      if (out) result += out;
    } else {
      // Try to parse VEX prefix
      const vexPrefix = VexPrefix.re(line);
      if (vexPrefix) {
        result += vexPrefix.out();
      }

      // Try to parse opcode
      const opcode = Opcode.re(line);
      if (opcode) {
        // Check for hard-coded instructions
        const mnemonic = opcode.mnemonic();
        const hardcodedHandler = hardcodedInstructions[mnemonic];
        
        if (hardcodedHandler) {
          const bytes = hardcodedHandler(line.value);
          if (bytes.length > 0) {
            const byteStr = bytes.join(',');
            result += config.gas ? `.byte\t${byteStr}` : `DB\t${byteStr}`;
            output.push(result);
            continue;
          }
        }

        const args: (Register | Const | EA | Expr)[] = [];

        // Parse arguments
        while (line.value) {
          let arg: Register | Const | EA | Expr | null = null;

          arg = Register.re(line, opcode);
          if (!arg) arg = Const.re(line);
          if (!arg) arg = EA.re(line, opcode);
          if (!arg) arg = Expr.re(line, opcode);

          if (!arg) break;

          args.push(arg);

          if (!line.value.startsWith(',')) break;
          line.value = line.value.substring(1).trimStart();
        }

        // Generate output
        if (args.length > 0) {
          let sz = opcode.size();

          if (config.gas) {
            const lastArg = args[args.length - 1];
            const lastSize =
              'size' in lastArg && typeof lastArg.size === 'function'
                ? lastArg.size()
                : undefined;
            const insn = opcode.out(lastSize || sz);
            const argStrs = args.map(a => a.out(sz));
            result += `\t${insn}\t${argStrs.join(',')}`;
          } else {
            let insn = opcode.out();
            const reversedArgs = [...args].reverse();
            
            // Handle MASM/NASM register size suffix inference
            for (const arg of reversedArgs) {
              const argOut = arg.out();
              if (argOut.match(/^xmm[0-9]+$/)) {
                insn += sz || '';
                sz = sz || 'x';
                break;
              }
              if (argOut.match(/^ymm[0-9]+$/)) {
                insn += sz || '';
                sz = sz || 'y';
                break;
              }
              if (argOut.match(/^zmm[0-9]+$/)) {
                insn += sz || '';
                sz = sz || 'z';
                break;
              }
              if (argOut.match(/^mm[0-9]+$/)) {
                insn += sz || '';
                sz = sz || 'q';
                break;
              }
            }
            
            // Don't add size for lea in NASM
            if (config.nasm && opcode.mnemonic() === 'lea') {
              sz = undefined;
            }
            
            const argStrs = reversedArgs.map(a => a.out(sz));
            result += `\t${insn}\t${argStrs.join(',')}`;
          }
        } else {
          result += `\t${opcode.out()}`;
        }
      }
    }

    output.push(result + line.value);
  }

  // Add footer
  const cetProperty = generateCetProperty(config.flavour, config.gnuas);
  if (cetProperty) {
    output.push(cetProperty);
  }
  
  if (config.masm && currentSegment) {
    output.push(`\n${currentSegment}\tENDS`);
  }
  if (config.masm) {
    output.push('END');
  }

  return output.join('\n');
}

/*
#################################################
# Cross-reference x86_64 ABI "card"
#
# 		Unix		Win64
# %rax		*		*
# %rbx		-		-
# %rcx		#4		#1
# %rdx		#3		#2
# %rsi		#2		-
# %rdi		#1		-
# %rbp		-		-
# %rsp		-		-
# %r8		#5		#3
# %r9		#6		#4
# %r10		*		*
# %r11		*		*
# %r12		-		-
# %r13		-		-
# %r14		-		-
# %r15		-		-
#
# (*)	volatile register
# (-)	preserved by callee
# (#)	Nth argument, volatile
#
# In Unix terms top of stack is argument transfer area for arguments
# which could not be accommodated in registers. Or in other words 7th
# [integer] argument resides at 8(%rsp) upon function entry point.
# 128 bytes above %rsp constitute a "red zone" which is not touched
# by signal handlers and can be used as temporal storage without
# allocating a frame.
#
# In Win64 terms N*8 bytes on top of stack is argument transfer area,
# which belongs to/can be overwritten by callee. N is the number of
# arguments passed to callee, *but* not less than 4! This means that
# upon function entry point 5th argument resides at 40(%rsp), as well
# as that 32 bytes from 8(%rsp) can always be used as temporal
# storage [without allocating a frame]. One can actually argue that
# one can assume a "red zone" above stack pointer under Win64 as well.
# Point is that at apparently no occasion Windows kernel would alter
# the area above user stack pointer in true asynchronous manner...
#
# All the above means that if assembler programmer adheres to Unix
# register and stack layout, but disregards the "red zone" existence,
# it's possible to use following prologue and epilogue to "gear" from
# Unix to Win64 ABI in leaf functions with not more than 6 arguments.
#
# omnipotent_function:
# ifdef WIN64
#	movq	%rdi,8(%rsp)
#	movq	%rsi,16(%rsp)
#	movq	%rcx,%rdi	; if 1st argument is actually present
#	movq	%rdx,%rsi	; if 2nd argument is actually ...
#	movq	%r8,%rdx	; if 3rd argument is ...
#	movq	%r9,%rcx	; if 4th argument ...
#	movq	40(%rsp),%r8	; if 5th ...
#	movq	48(%rsp),%r9	; if 6th ...
# endif
#	...
# ifdef WIN64
#	movq	8(%rsp),%rdi
#	movq	16(%rsp),%rsi
# endif
#	ret
#
#################################################
# Win64 SEH, Structured Exception Handling.
#
# Unlike on Unix systems(*) lack of Win64 stack unwinding information
# has undesired side-effect at run-time: if an exception is raised in
# assembler subroutine such as those in question (basically we're
# referring to segmentation violations caused by malformed input
# parameters), the application is briskly terminated without invoking
# any exception handlers, most notably without generating memory dump
# or any user notification whatsoever. This poses a problem. It's
# possible to address it by registering custom language-specific
# handler that would restore processor context to the state at
# subroutine entry point and return "exception is not handled, keep
# unwinding" code. Writing such handler can be a challenge... But it's
# doable, though requires certain coding convention. Consider following
# snippet:
#
# .type	function,@function
# function:
#	movq	%rsp,%rax	# copy rsp to volatile register
#	pushq	%r15		# save non-volatile registers
#	pushq	%rbx
#	pushq	%rbp
#	movq	%rsp,%r11
#	subq	%rdi,%r11	# prepare [variable] stack frame
#	andq	$-64,%r11
#	movq	%rax,0(%r11)	# check for exceptions
#	movq	%r11,%rsp	# allocate [variable] stack frame
#	movq	%rax,0(%rsp)	# save original rsp value
# magic_point:
#	...
#	movq	0(%rsp),%rcx	# pull original rsp value
#	movq	-24(%rcx),%rbp	# restore non-volatile registers
#	movq	-16(%rcx),%rbx
#	movq	-8(%rcx),%r15
#	movq	%rcx,%rsp	# restore original rsp
# magic_epilogue:
#	ret
# .size function,.-function
#
# The key is that up to magic_point copy of original rsp value remains
# in chosen volatile register and no non-volatile register, except for
# rsp, is modified. While past magic_point rsp remains constant till
# the very end of the function. In this case custom language-specific
# exception handler would look like this:
#
# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
# {	ULONG64 *rsp = (ULONG64 *)context->Rax;
#	ULONG64  rip = context->Rip;
#
#	if (rip >= magic_point)
#	{   rsp = (ULONG64 *)context->Rsp;
#	    if (rip < magic_epilogue)
#	    {	rsp = (ULONG64 *)rsp[0];
#		context->Rbp = rsp[-3];
#		context->Rbx = rsp[-2];
#		context->R15 = rsp[-1];
#	    }
#	}
#	context->Rsp = (ULONG64)rsp;
#	context->Rdi = rsp[1];
#	context->Rsi = rsp[2];
#
#	memcpy (disp->ContextRecord,context,sizeof(CONTEXT));
#	RtlVirtualUnwind(UNW_FLAG_NHANDLER,disp->ImageBase,
#		dips->ControlPc,disp->FunctionEntry,disp->ContextRecord,
#		&disp->HandlerData,&disp->EstablisherFrame,NULL);
#	return ExceptionContinueSearch;
# }
#
# It's appropriate to implement this handler in assembler, directly in
# function's module. In order to do that one has to know members'
# offsets in CONTEXT and DISPATCHER_CONTEXT structures and some constant
# values. Here they are:
#
#	CONTEXT.Rax				120
#	CONTEXT.Rcx				128
#	CONTEXT.Rdx				136
#	CONTEXT.Rbx				144
#	CONTEXT.Rsp				152
#	CONTEXT.Rbp				160
#	CONTEXT.Rsi				168
#	CONTEXT.Rdi				176
#	CONTEXT.R8				184
#	CONTEXT.R9				192
#	CONTEXT.R10				200
#	CONTEXT.R11				208
#	CONTEXT.R12				216
#	CONTEXT.R13				224
#	CONTEXT.R14				232
#	CONTEXT.R15				240
#	CONTEXT.Rip				248
#	CONTEXT.Xmm6				512
#	sizeof(CONTEXT)				1232
#	DISPATCHER_CONTEXT.ControlPc		0
#	DISPATCHER_CONTEXT.ImageBase		8
#	DISPATCHER_CONTEXT.FunctionEntry	16
#	DISPATCHER_CONTEXT.EstablisherFrame	24
#	DISPATCHER_CONTEXT.TargetIp		32
#	DISPATCHER_CONTEXT.ContextRecord	40
#	DISPATCHER_CONTEXT.LanguageHandler	48
#	DISPATCHER_CONTEXT.HandlerData		56
#	UNW_FLAG_NHANDLER			0
#	ExceptionContinueSearch			1
#
# In order to tie the handler to the function one has to compose
# couple of structures: one for .xdata segment and one for .pdata.
#
# UNWIND_INFO structure for .xdata segment would be
#
# function_unwind_info:
#	.byte	9,0,0,0
#	.rva	handler
#
# This structure designates exception handler for a function with
# zero-length prologue, no stack frame or frame register.
#
# To facilitate composing of .pdata structures, auto-generated "gear"
# prologue copies rsp value to rax and denotes next instruction with
# .LSEH_begin_{function_name} label. This essentially defines the SEH
# styling rule mentioned in the beginning. Position of this label is
# chosen in such manner that possible exceptions raised in the "gear"
# prologue would be accounted to caller and unwound from latter's frame.
# End of function is marked with respective .LSEH_end_{function_name}
# label. To summarize, .pdata segment would contain
#
#	.rva	.LSEH_begin_function
#	.rva	.LSEH_end_function
#	.rva	function_unwind_info
#
# Reference to function_unwind_info from .xdata segment is the anchor.
# In case you wonder why references are 32-bit .rvas and not 64-bit
# .quads. References put into these two segments are required to be
# *relative* to the base address of the current binary module, a.k.a.
# image base. No Win64 module, be it .exe or .dll, can be larger than
# 2GB and thus such relative references can be and are accommodated in
# 32 bits.
#
# Having reviewed the example function code, one can argue that "movq
# %rsp,%rax" above is redundant. It is not! Keep in mind that on Unix
# rax would contain an undefined value. If this "offends" you, use
# another register and refrain from modifying rax till magic_point is
# reached, i.e. as if it was a non-volatile register. If more registers
# are required prior [variable] frame setup is completed, note that
# nobody says that you can have only one "magic point." You can
# "liberate" non-volatile registers by denoting last stack off-load
# instruction and reflecting it in finer grade unwind logic in handler.
# After all, isn't it why it's called *language-specific* handler...
#
# SE handlers are also involved in unwinding stack when executable is
# profiled or debugged. Profiling implies additional limitations that
# are too subtle to discuss here. For now it's sufficient to say that
# in order to simplify handlers one should either a) offload original
# %rsp to stack (like discussed above); or b) if you have a register to
# spare for frame pointer, choose volatile one.
#
# (*)	Note that we're talking about run-time, not debug-time. Lack of
#	unwind information makes debugging hard on both Windows and
#	Unix. "Unlike" refers to the fact that on Unix signal handler
#	will always be invoked, core dumped and appropriate exit code
#	returned to parent (for user notification).
*/
