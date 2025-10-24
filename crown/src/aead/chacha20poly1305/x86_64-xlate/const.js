class Const {
  constructor(translator) {
    this.translator = translator;
  }

  re(line) {
    const obj = {};
    let ret;

    const match = line.value.match(/^\$([^,]+)/);
    if (match) {
      Object.setPrototypeOf(obj, Const.prototype);
      obj.translator = this.translator;
      obj.value = match[1];
      ret = obj;
      line.value = line.value.substring(match[0].length);
      line.value = line.value.replace(/^\s+/, '');
    }
    return ret;
  }

  out() {
    const translator = this.translator;
    this.value = this.value.replace(/\b(0b[0-1]+)/g, match =>
      parseInt(match, 2).toString(),
    );

    if (translator.gas) {
      let value = this.value;
      value = value.replace(/(?<![\w\$\.])(0x?[0-9a-f]+)/gi, match =>
        parseInt(match, 16).toString(),
      );
      if (value.match(/[0-9]+\s*[\*\/\%]\s*[0-9]+/)) {
        value = value.replace(/([0-9]+\s*[\*\/\%]\s*[0-9]+)/g, match =>
          eval(match),
        );
        this.value = value;
      }
      return `$${this.value}`;
    } else {
      let value = this.value;
      if (translator.masm) {
        value = value.replace(/0x([0-9a-f]+)/gi, '0$1h');
      }
      return value;
    }
  }
}

module.exports = { Const };
