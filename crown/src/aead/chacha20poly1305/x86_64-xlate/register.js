class Register {
  constructor(translator) {
    this.translator = translator;
  }

  re(line, opcode) {
    const obj = {};
    let ret;

    const match = line.value.match(/^(\*?)%(\w+)((?:{[^}]+})*)/);
    if (match) {
      Object.setPrototypeOf(obj, Register.prototype);
      obj.translator = this.translator;
      obj.asterisk = match[1];
      obj.value = match[2];
      obj.opmask = match[3];
      opcode.size(obj.size());
      ret = obj;
      line.value = line.value.substring(match[0].length);
      line.value = line.value.replace(/^\s+/, '');
    }
    return ret;
  }

  size() {
    if (this.value.match(/^r[\d]+b$/i)) return 'b';
    else if (this.value.match(/^r[\d]+w$/i)) return 'w';
    else if (this.value.match(/^r[\d]+d$/i)) return 'l';
    else if (this.value.match(/^r[\w]+$/i)) return 'q';
    else if (this.value.match(/^[a-d][hl]$/i)) return 'b';
    else if (this.value.match(/^[\w]{2}l$/i)) return 'b';
    else if (this.value.match(/^[\w]{2}$/i)) return 'w';
    else if (this.value.match(/^e[a-z]{2}$/i)) return 'l';
  }

  out() {
    const translator = this.translator;
    if (translator.gas) {
      return `${this.asterisk}%${this.value}${this.opmask}`;
    } else {
      this.opmask = this.opmask.replace(/%(k[0-7])/, '$1');
      return this.value + this.opmask;
    }
  }
}

module.exports = { Register };
