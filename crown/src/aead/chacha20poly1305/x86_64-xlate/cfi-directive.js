class CfiDirective {
  constructor(translator) {
    this.translator = translator;
    this.cfa_reg = '%rsp';
    this.cfa_rsp = 0;
    this.cfa_stack = [];
  }

  re(line) {
    const obj = {};
    let ret;

    const match = line.value.match(/^\s*\.cfi_(\w+)\s*/);
    if (match) {
      Object.setPrototypeOf(obj, CfiDirective.prototype);
      obj.translator = this.translator;
      ret = obj;
      obj.value = undefined;
      const dir = match[1];
      line.value = line.value.replace(match[0], '');

      switch (dir) {
        case 'startproc':
          this.cfa_reg = '%rsp';
          this.cfa_rsp = -8;
          break;
        case 'endproc':
          this.cfa_reg = '%rsp';
          this.cfa_rsp = 0;
          break;
        case 'def_cfa_register':
          this.cfa_reg = line.value;
          break;
        case 'def_cfa_offset':
          if (this.cfa_reg === '%rsp') {
            this.cfa_rsp = -1 * eval(line.value);
          }
          break;
        case 'adjust_cfa_offset':
          if (this.cfa_reg === '%rsp') {
            this.cfa_rsp -= eval(line.value);
          }
          break;
        case 'def_cfa':
          const defCfaMatch = line.value.match(/(%r\w+)\s*,\s*(.+)/);
          if (defCfaMatch) {
            this.cfa_reg = defCfaMatch[1];
            if (this.cfa_reg === '%rsp') {
              this.cfa_rsp = -1 * eval(defCfaMatch[2]);
            }
          }
          break;
        case 'push':
          this.cfa_rsp -= 8;
          if (this.cfa_reg === '%rsp') {
            obj.value = '.cfi_adjust_cfa_offset\t8\n';
          }
          obj.value =
            (obj.value || '') + `.cfi_offset\t${line.value},${this.cfa_rsp}`;
          line.value = '';
          return ret;
        case 'pop':
          this.cfa_rsp += 8;
          if (this.cfa_reg === '%rsp') {
            obj.value = '.cfi_adjust_cfa_offset\t-8\n';
          }
          obj.value = (obj.value || '') + `.cfi_restore\t${line.value}`;
          line.value = '';
          return ret;
        case 'remember_state':
          this.cfa_stack.push([this.cfa_reg, this.cfa_rsp]);
          break;
        case 'restore_state':
          [this.cfa_reg, this.cfa_rsp] = this.cfa_stack.pop();
          break;
      }

      obj.value = `.cfi_${dir}\t${line.value}`;
      line.value = '';
    }

    return ret;
  }

  out() {
    return this.translator.elf ? this.value : undefined;
  }
}

module.exports = { CfiDirective };
