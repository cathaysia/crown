class EA {
  constructor(translator) {
    this.translator = translator;
    this.szmap = translator.gas
      ? {}
      : {
          b: 'BYTE' + translator.PTR,
          w: 'WORD' + translator.PTR,
          l: 'DWORD' + translator.PTR,
          d: 'DWORD' + translator.PTR,
          q: 'QWORD' + translator.PTR,
          o: 'OWORD' + translator.PTR,
          x: 'XMMWORD' + translator.PTR,
          y: 'YMMWORD' + translator.PTR,
          z: 'ZMMWORD' + translator.PTR,
        };
  }

  re(line, opcode) {
    const obj = {};
    let ret;

    const match = line.value.match(
      /^(\*?)([^\(,]*)\(([%\w,]+)\)((?:{[^}]+})*)/,
    );
    if (match) {
      Object.setPrototypeOf(obj, EA.prototype);
      obj.translator = this.translator;
      obj.asterisk = match[1];
      obj.label = match[2];
      const parts = match[3].split(',');
      obj.base = parts[0];
      obj.index = parts[1];
      obj.scale = parts[2] || '1';
      obj.scale = parseInt(obj.scale);
      obj.opmask = match[4];
      ret = obj;
      line.value = line.value.substring(match[0].length);
      line.value = line.value.replace(/^\s+/, '');

      if (this.translator.win64 && obj.label.includes('@GOTPCREL')) {
        obj.label = obj.label.replace('@GOTPCREL', '');
        if (opcode.mnemonic() !== 'mov') {
          throw new Error('Expected mov instruction');
        }
        opcode.mnemonic('lea');
      }
      obj.base = obj.base.replace(/^%/, '');
      if (obj.index) {
        obj.index = obj.index.replace(/^%/, '');
      }
      obj.opcode = opcode;
    }
    return ret;
  }

  size() {}

  out(sz) {
    const translator = this.translator;
    this.label = this.label.replace(
      /([_a-z][_a-z0-9]*)/gi,
      match => translator.globals[match] || match,
    );
    this.label = this.label.replace(/\.L/g, translator.decor);

    this.index = this.index
      ? this.index.replace(/^[er](.?[0-9xpi])[d]?$/, 'r$1')
      : this.index;
    this.base = this.base.replace(/^[er](.?[0-9xpi])[d]?$/, 'r$1');

    this.label = this.label.replace(/(?<![\w\$\.])(0x?[0-9a-f]+)/gi, match =>
      parseInt(match, 16).toString(),
    );
    this.label = this.label.replace(
      /\b([0-9]+\s*[\*\/\%]\s*[0-9]+)\b/g,
      match => eval(match),
    );

    this.label = this.label.replace(/\b([0-9]+)\b/g, match => {
      const num = parseInt(match);
      return ((num << 32) >> 32).toString();
    });

    if (
      !this.label &&
      this.index &&
      this.scale === 1 &&
      this.base.match(/(rbp|r13)/)
    ) {
      const temp = this.base;
      this.base = this.index;
      this.index = temp;
    }

    if (translator.gas) {
      if (translator.flavour === 'mingw64') {
        this.label = this.label.replace(/^___imp_/, '__imp__');
      }

      if (this.index) {
        return `${this.asterisk}${this.label}(${this.base ? '%' + this.base : ''},%%${this.index},${this.scale})${this.opmask}`;
      } else {
        return `${this.asterisk}${this.label}(%${this.base})${this.opmask}`;
      }
    } else {
      this.label = this.label.replace(/\./g, '$');
      this.label = this.label.replace(/(?<![\w\$\.])0x([0-9a-f]+)/gi, '0$1h');
      if (this.label.match(/[\*\+\-\/]/)) {
        this.label = `(${this.label})`;
      }

      const mnemonic = this.opcode.mnemonic();
      if (this.asterisk) sz = 'q';
      else if (mnemonic.match(/^v?mov([qd])$/)) sz = RegExp.$1;
      else if (mnemonic.match(/^v?pinsr([qdwb])$/)) sz = RegExp.$1;
      else if (mnemonic.match(/^vpbroadcast([qdwb])$/)) sz = RegExp.$1;
      else if (mnemonic.match(/^v(?!perm)[a-z]+[fi]128$/)) sz = 'x';

      this.opmask = this.opmask.replace(/%(k[0-7])/, '$1');

      if (this.index) {
        return `${this.szmap[sz]}[${this.label ? this.label + '+' : ''}${this.index}*${this.scale}${this.base ? '+' + this.base : ''}]${this.opmask}`;
      } else if (this.base === 'rip') {
        return `${this.szmap[sz]}[${this.label}]`;
      } else {
        return `${this.szmap[sz]}[${this.label ? this.label + '+' : ''}${this.base}]${this.opmask}`;
      }
    }
  }
}

module.exports = { EA };
