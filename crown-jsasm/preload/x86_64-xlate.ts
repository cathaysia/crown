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

// Directive class - simplified version
class Directive {
  value?: string;

  static re(line: { value: string }): Directive | CfiDirective | null {
    // Try CFI directive first
    const cfi = CfiDirective.re(line);
    if (cfi) return cfi;

    const match = line.value.match(/^\s*(\.\w+)/);
    if (!match) return null;

    const self = new Directive();
    const dir = match[1];
    line.value = line.value.substring(match[0].length).trimStart();

    // Handle different directives based on gas/masm/nasm
    if (config.gas) {
      self.value = dir + '\t' + line.value;
      line.value = '';
    } else {
      // MASM/NASM handling would go here
      self.value = dir + '\t' + line.value;
      line.value = '';
    }

    return self;
  }

  out(): string | undefined {
    return this.value;
  }
}

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
          const sz = opcode.size();

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
            const insn = opcode.out();
            const reversedArgs = [...args].reverse();
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
  if (config.masm && currentSegment) {
    output.push(`\n${currentSegment}\tENDS`);
  }
  if (config.masm) {
    output.push('END');
  }

  return output.join('\n');
}
