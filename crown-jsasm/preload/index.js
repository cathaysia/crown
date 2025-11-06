/**
 * @typedef {Object} Context
 * @property {string} feature
 * @property {boolean} unix
 * @property {boolean} windows
 * @property {string} target_family
 * @property {string} target_os
 * @property {string} target_arch
 * @property {string} target_vendor
 * @property {string} target_env
 * @property {string} target_abi
 * @property {number} target_pointer_width
 * @property {string} target_endian
 * @property {string} target_feature
 */

/**
 * @type {Context}
 */
const CONTEXT = JSON.parse(__CONTEXT);

globalThis.windows = 'windows';
globalThis.unix = 'unix';
globalThis.feature = 'feature';
globalThis.target_family = 'target_family';
globalThis.target_os = 'target_os';
globalThis.target_arch = 'target_arch';
globalThis.target_vendor = 'target_vendor';
globalThis.target_env = 'target_env';
globalThis.target_abi = 'target_abi';
globalThis.target_pointer_width = 'target_pointer_width';
globalThis.target_endian = 'target_endian';
globalThis.target_feature = 'target_feature';

/**
 * @template {string} K
 * @param {K} key
 * @param {string | number | boolean} [value]
 * @returns {K extends "target_pointer_width" ? (value extends undefined ? number : boolean) : boolean}
 */
function cfg(key, value) {
  if (value === undefined) {
    return CONTEXT[key];
  }

  if (key !== 'target_feature' || key !== 'target_family') {
    return CONTEXT[key] === value;
  }

  const items = CONTEXT[key];
  if (typeof items !== 'string') {
    return false;
  }
  return items
    .split(',')
    .map(item => item.trim())
    .includes(value);
}

globalThis.cfg = cfg;
