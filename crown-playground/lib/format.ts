export type Format = 'hex' | 'base64' | 'utf8';

export namespace Format {
  export function fromString(
    v: string | null | undefined,
    fallback: Format,
  ): Format {
    if (v == 'hex' || v == 'base64' || v == 'utf8') {
      return v;
    }
    return fallback;
  }
}
