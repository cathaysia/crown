class Expr {
  constructor(translator) {
    this.translator = translator;
  }

  re(line, opcode) {
    const obj = {};
    let ret;

    const match = line.value.match(/(^[^,]+)/);
    if (match) {
      Object.setPrototypeOf(obj, Expr.prototype);
      obj.translator = this.translator;
      obj.value = match[1];
      ret = obj;
      line.value = line.value.substring(match[0].length);
      line.value = line.value.replace(/^\s+/, '');

      if (!this.translator.elf) obj.value = obj.value.replace(/@PLT/, '');
      obj.value = obj.value.replace(
        /([_a-z][_a-z0-9]*)/gi,
        match => this.translator.globals[match] || match,
      );
      obj.value = obj.value.replace(/\.L/g, this.translator.decor);
      obj.opcode = opcode;
    }
    return ret;
  }

  out() {
    const translator = this.translator;
    if (translator.nasm && this.opcode.mnemonic().match(/^j(?![re]cxz)/)) {
      return 'NEAR ' + this.value;
    } else {
      return this.value;
    }
  }
}

module.exports = { Expr };
