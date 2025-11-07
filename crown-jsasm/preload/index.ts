interface Context {
  feature: string;
  unix: boolean;
  windows: boolean;
  target_family: string;
  target_os: string;
  target_arch: string;
  target_vendor: string;
  target_env: string;
  target_abi: string;
  target_pointer_width: number;
  target_endian: string;
  target_feature: string;
}

declare const __CONTEXT: string;

const CONTEXT: Context = JSON.parse(__CONTEXT);

(globalThis as any).windows = 'windows';
(globalThis as any).unix = 'unix';
(globalThis as any).feature = 'feature';
(globalThis as any).target_family = 'target_family';
(globalThis as any).target_os = 'target_os';
(globalThis as any).target_arch = 'target_arch';
(globalThis as any).target_vendor = 'target_vendor';
(globalThis as any).target_env = 'target_env';
(globalThis as any).target_abi = 'target_abi';
(globalThis as any).target_pointer_width = 'target_pointer_width';
(globalThis as any).target_endian = 'target_endian';
(globalThis as any).target_feature = 'target_feature';

function cfg<K extends keyof Context>(key: K): Context[K];
function cfg<K extends keyof Context>(
  key: K,
  value: string | number | boolean,
): boolean;
function cfg<K extends keyof Context>(
  key: K,
  value?: string | number | boolean,
): Context[K] | boolean {
  if (value === undefined) {
    return CONTEXT[key];
  }

  if (key !== 'target_feature' && key !== 'target_family') {
    return CONTEXT[key] === value;
  }

  const items = CONTEXT[key];
  if (typeof items !== 'string') {
    return false;
  }
  return items
    .split(',')
    .map(item => item.trim())
    .includes(value as string);
}

(globalThis as any).cfg = cfg;
