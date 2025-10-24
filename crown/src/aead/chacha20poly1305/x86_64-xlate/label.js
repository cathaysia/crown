class Label {
  constructor(translator) {
    this.translator = translator;
  }

  re(line) {
    const obj = {};
    let ret;

    const match = line.value.match(/(^[\.\w]+):/);
    if (match) {
      Object.setPrototypeOf(obj, Label.prototype);
      obj.translator = this.translator;
      obj.value = match[1];
      ret = obj;
      line.value = line.value.substring(match[0].length);
      line.value = line.value.replace(/^\s+/, '');

      obj.value = obj.value.replace(/^\.L/, this.translator.decor);
    }
    return ret;
  }

  out() {
    const translator = this.translator;
    if (translator.gas) {
      let func = (translator.globals[this.value] || this.value) + ':';
      if (
        translator.win64 &&
        translator.current_function.name === this.value &&
        translator.current_function.abi === 'svr4'
      ) {
        func += '\n';
        func += '\tmovq\t%rdi,8(%rsp)\n';
        func += '\tmovq\t%rsi,16(%rsp)\n';
        func += '\tmovq\t%rsp,%rax\n';
        func += `${translator.decor}SEH_begin_${translator.current_function.name}:\n`;
        const narg = translator.current_function.narg || 6;
        if (narg > 0) func += '\tmovq\t%rcx,%rdi\n';
        if (narg > 1) func += '\tmovq\t%rdx,%rsi\n';
        if (narg > 2) func += '\tmovq\t%r8,%rdx\n';
        if (narg > 3) func += '\tmovq\t%r9,%rcx\n';
        if (narg > 4) func += '\tmovq\t40(%rsp),%r8\n';
        if (narg > 5) func += '\tmovq\t48(%rsp),%r9\n';
      }
      return func;
    } else if (this.value !== translator.current_function.name) {
      if (translator.masm) this.value += ':';
      return this.value + ':';
    } else if (translator.win64 && translator.current_function.abi === 'svr4') {
      let func =
        translator.current_function.name +
        (translator.nasm
          ? ':'
          : `\tPROC ${translator.current_function.scope}`) +
        '\n';
      func += `\tmov\tQWORD${translator.PTR}[8+rsp],rdi\t;WIN64 prologue\n`;
      func += `\tmov\tQWORD${translator.PTR}[16+rsp],rsi\n`;
      func += '\tmov\trax,rsp\n';
      func += `${translator.decor}SEH_begin_${translator.current_function.name}:`;
      if (translator.masm) func += ':';
      func += '\n';
      const narg = translator.current_function.narg || 6;
      if (narg > 0) func += '\tmov\trdi,rcx\n';
      if (narg > 1) func += '\tmov\trsi,rdx\n';
      if (narg > 2) func += '\tmov\trdx,r8\n';
      if (narg > 3) func += '\tmov\trcx,r9\n';
      if (narg > 4) func += `\tmov\tr8,QWORD${translator.PTR}[40+rsp]\n`;
      if (narg > 5) func += `\tmov\tr9,QWORD${translator.PTR}[48+rsp]\n`;
      func += '\n';
      return func;
    } else {
      return (
        translator.current_function.name +
        (translator.nasm ? ':' : `\tPROC ${translator.current_function.scope}`)
      );
    }
  }
}

module.exports = { Label };
