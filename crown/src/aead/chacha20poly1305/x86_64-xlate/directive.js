class Directive {
  constructor(translator) {
    this.translator = translator;
    this.sections = {};
  }

  re(line) {
    const obj = {};
    let ret;

    ret = this.translator.cfiDirective.re(line);
    if (ret) return ret;
    ret = this.translator.sehDirective.re(line);
    if (ret) return ret;

    const match = line.value.match(/^\s*(\.\w+)/);
    if (match) {
      Object.setPrototypeOf(obj, Directive.prototype);
      obj.translator = this.translator;
      const dir = match[1];
      ret = obj;
      obj.value = undefined;
      line.value = line.value.substring(match[0].length);
      line.value = line.value.replace(/^\s+/, '');

      const translator = this.translator;

      switch (dir) {
        case '.global':
        case '.globl':
        case '.extern':
          translator.globals[line.value] = translator.prefix + line.value;
          if (translator.prefix) line.value = translator.globals[line.value];
          break;
        case '.type':
          const typeParts = line.value.split(/\s*,\s*/);
          const [sym, type, narg] = typeParts;
          if (type === '@function') {
            translator.current_function = {
              name: sym,
              abi: 'svr4',
              narg: narg,
              scope: translator.globals[sym] ? 'PUBLIC' : 'PRIVATE',
            };
          } else if (type === '@abi-omnipotent') {
            translator.current_function = {
              name: sym,
              scope: translator.globals[sym] ? 'PUBLIC' : 'PRIVATE',
            };
          }
          line.value = line.value.replace(/@abi\-omnipotent/, '@function');
          line.value = line.value.replace(/@function.*/, '@function');
          break;
        case '.asciz':
          const ascizMatch = line.value.match(/^"(.*)"$/);
          if (ascizMatch) {
            obj.dir = '.byte';
            line.value = [...ascizMatch[1]]
              .map(c => c.charCodeAt(0))
              .concat([0])
              .join(',');
          }
          break;
        case '.rva':
        case '.long':
        case '.quad':
        case '.byte':
          line.value = line.value.replace(
            /([_a-z][_a-z0-9]*)/gi,
            match => translator.globals[match] || match,
          );
          line.value = line.value.replace(/\.L/g, translator.decor);
          break;
      }

      if (translator.gas) {
        obj.value = dir + '\t' + line.value;

        if (dir.match(/\.extern/)) {
          if (translator.flavour === 'elf') {
            obj.value += `\n.hidden ${line.value}`;
          } else {
            obj.value = '';
          }
        } else if (!translator.elf && dir.match(/\.type/)) {
          obj.value = '';
          const typeMatch = line.value.match(/([^,]+),@function/);
          if (translator.win64 && typeMatch) {
            const sym = typeMatch[1];
            obj.value = `.def\t${translator.globals[sym] || sym};\t${translator.globals[sym] ? '.scl 2;' : '.scl 3;'}\t.type 32;\t.endef`;
          }
        } else if (!translator.elf && dir.match(/\.size/)) {
          obj.value = '';
          if (translator.current_function) {
            if (
              translator.win64 &&
              translator.current_function.abi === 'svr4'
            ) {
              obj.value += `${translator.decor}SEH_end_${translator.current_function.name}:`;
            }
            translator.current_function = undefined;
          }
        } else if (!translator.elf && dir.match(/\.align/)) {
          obj.value = `.p2align\t${Math.log2(parseInt(line.value))}`;
        } else if (dir === '.section') {
          translator.current_segment = line.value;
          if (!translator.elf && translator.current_segment === '.rodata') {
            if (translator.flavour === 'macosx') {
              obj.value = '.section\t__DATA,__const';
            }
          }
          if (!translator.elf && translator.current_segment === '.init') {
            if (translator.flavour === 'macosx') {
              obj.value = '.mod_init_func';
            } else if (translator.flavour === 'mingw64') {
              obj.value = '.section\t.ctors';
            }
          }
        } else if (dir.match(/\.(text|data)/)) {
          translator.current_segment = `.${RegExp.$1}`;
        }
        line.value = '';
        return obj;
      }

      switch (dir) {
        case '.text':
          if (translator.nasm) {
            obj.value = 'section\t.text code align=64\n';
          } else {
            let v = translator.current_segment
              ? `${translator.current_segment}\tENDS\n`
              : '';
            translator.current_segment = '.text$';
            v += `${translator.current_segment}\tSEGMENT `;
            v += translator.masm >= translator.masmref ? 'ALIGN(256)' : 'PAGE';
            v += " 'CODE'";
            obj.value = v;
          }
          break;
        case '.data':
          if (translator.nasm) {
            obj.value = 'section\t.data data align=8\n';
          } else {
            let v = translator.current_segment
              ? `${translator.current_segment}\tENDS\n`
              : '';
            translator.current_segment = '_DATA';
            v += `${translator.current_segment}\tSEGMENT`;
            obj.value = v;
          }
          break;
        case '.extern':
          obj.value = `EXTERN\t${line.value}`;
          if (translator.masm) obj.value += ':NEAR';
          break;
        case '.globl':
        case '.global':
          obj.value =
            (translator.masm ? 'PUBLIC' : 'global') + `\t${line.value}`;
          break;
        case '.size':
          if (translator.current_function) {
            obj.value = undefined;
            if (translator.current_function.abi === 'svr4') {
              obj.value = `${translator.decor}SEH_end_${translator.current_function.name}:`;
              if (translator.masm) obj.value += ':';
            }
            if (translator.masm && translator.current_function.name) {
              obj.value =
                (obj.value || '') + `${translator.current_function.name}\tENDP`;
            }
            translator.current_function = undefined;
          }
          break;
        case '.align':
          const max =
            translator.masm && translator.masm >= translator.masmref
              ? 256
              : 4096;
          const alignVal = parseInt(line.value);
          obj.value = `ALIGN\t${alignVal > max ? max : alignVal}`;
          break;
        case '.byte':
          const str = line.value.split(/,\s*/);
          str.forEach((s, i) => {
            str[i] = s.replace(/(0b[0-1]+)/g, match =>
              parseInt(match, 2).toString(),
            );
          });
          if (translator.masm) {
            str.forEach((s, i) => {
              str[i] = s.replace(/0x([0-9a-f]+)/gi, '0$1h');
            });
          }
          obj.value = '';
          while (str.length > 16) {
            obj.value += '\tDB\t' + str.splice(0, 16).join(',') + '\n';
          }
          if (str.length > 0) {
            obj.value += '\tDB\t' + str.join(',');
          }
          break;
      }
      line.value = '';
    }

    return ret;
  }

  out() {
    return this.value;
  }
}

module.exports = { Directive };
