const { X86_64Translator } = require('./translator');

function translateX86_64(input, options = {}) {
  const { flavour, output } = options;
  const translator = new X86_64Translator(flavour, output);
  return translator.translate(input);
}

module.exports = {
  translateX86_64,
  X86_64Translator,
};
