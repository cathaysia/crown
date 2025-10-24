class Opcode {
  constructor(translator) {
    this.translator = translator;
  }

  re(line) {
    const obj = {};
    let ret;

    const match = line.value.match(/^([a-z][a-z0-9]*)/i);
    if (match) {
      Object.setPrototypeOf(obj, Opcode.prototype);
      obj.translator = this.translator;
      obj.op = match[1];
      ret = obj;
      line.value = line.value.substring(match[0].length);
      line.value = line.value.replace(/^\s+/, '');

      obj.sz = undefined;

      const movzMatch = obj.op.match(/^(movz)x?([bw]).*/);
      if (movzMatch) {
        obj.op = movzMatch[1];
        obj.sz = movzMatch[2];
      } else if (obj.op.match(/call|jmp|^rdrand$/)) {
        obj.sz = '';
      } else if (
        obj.op.match(/^p/) &&
        !obj.op.substring(1).match(/^(ush|op|insrw)/)
      ) {
        obj.sz = '';
      } else if (obj.op.match(/^[vk]/)) {
        obj.sz = '';
      } else if (obj.op.match(/mov[dq]/) && line.value.match(/%xmm/)) {
        obj.sz = '';
      } else {
        const orMatch = obj.op.match(/^or([qlwb])$/);
        if (orMatch) {
          obj.op = 'or';
          obj.sz = orMatch[1];
        } else {
          const sizeMatch = obj.op.match(/([a-z]{3,})([qlwb])$/);
          if (sizeMatch) {
            obj.op = sizeMatch[1];
            obj.sz = sizeMatch[2];
          }
        }
      }
    }
    return ret;
  }

  size(sz) {
    if (sz !== undefined && this.sz === undefined) {
      this.sz = sz;
    }
    return this.sz;
  }

  out() {
    const translator = this.translator;
    if (translator.gas) {
      if (this.op === 'movz') {
        return `${this.op}${this.sz}${arguments[0] || ''}`;
      } else if (this.op.match(/^set/)) {
        return this.op;
      } else if (this.op === 'ret') {
        let epilogue = '';
        if (translator.win64 && translator.current_function.abi === 'svr4') {
          epilogue = 'movq\t8(%rsp),%rdi\n\t' + 'movq\t16(%rsp),%rsi\n\t';
        }
        return epilogue + 'ret';
      } else if (
        this.op === 'call' &&
        !translator.elf &&
        translator.current_segment === '.init'
      ) {
        return '.p2align\t3\n\t.quad';
      } else {
        return this.op + this.sz;
      }
    } else {
      let op = this.op.replace(/^movz/, 'movzx');
      if (op === 'ret') {
        op = '';
        if (translator.win64 && translator.current_function.abi === 'svr4') {
          op =
            `mov\trdi,QWORD${translator.PTR}[8+rsp]\t;WIN64 epilogue\n\t` +
            `mov\trsi,QWORD${translator.PTR}[16+rsp]\n\t`;
        }
        op += 'ret';
      } else if (op.match(/^(pop|push)f/)) {
        op += this.sz;
      } else if (op === 'call' && translator.current_segment === '.CRT$XCU') {
        op = '\tDQ';
      }
      return op;
    }
  }

  mnemonic(op) {
    if (op !== undefined) {
      this.op = op;
    }
    return this.op;
  }
}

module.exports = { Opcode };
