class SehDirective {
  constructor(translator) {
    this.translator = translator;
    this.xdata = '';
    this.pdata = '';
    this.info = {};
    this.next_label = 0;
    this.current_label_func = '';
  }

  re(line) {
    const match = line.value.match(/^\s*\.seh_(\w+)\s*/);
    if (match) {
      const dir = match[1];
      line.value = line.value.replace(match[0], '');

      if (!this.translator.win64) {
        line.value = '';
        return;
      }

      switch (dir) {
        case 'startproc':
        case 'pushreg':
        case 'stackalloc':
        case 'setframe':
        case 'savereg':
        case 'savexmm':
        case 'endprologue':
        case 'endproc':
          break;
        default:
          throw new Error(`unknown SEH directive .seh_${dir}`);
      }

      line.value = '';
      const labelLine = { value: `${dir}:` };
      return this.translator.label.re(labelLine);
    }
  }

  pdata_and_xdata() {
    if (!this.translator.win64) return '';

    let ret = '';
    if (this.pdata !== '') {
      ret += `.section\t.pdata\n.align\t4\n${this.pdata}`;
    }
    if (this.xdata !== '') {
      ret += `.section\t.xdata\n.align\t4\n${this.xdata}`;
    }
    return ret;
  }
}

module.exports = { SehDirective };
