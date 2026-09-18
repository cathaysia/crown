use proc_macro::{Span, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Error, LitStr};

use crown_jsasm::execute_js_with_json_context;

pub fn jsasm_file(input: TokenStream) -> TokenStream {
    let path = parse_macro_input!(input as LitStr).value();

    match execute_js_with_json_context(path.clone()) {
        Ok(result) => {
            // rustc may merge several global_asm! blobs of this crate into a
            // single assembly unit, where local .L labels would collide. Make
            // them unique per generator (the perl keeps them file-local
            // because every module is assembled from its own .s file).
            let result = tag_local_labels(&path, &result);
            let expr = LitStr::new(&result, Span::call_site().into());
            quote! { #expr }.into()
        }
        Err(error_msg) => Error::new(Span::call_site().into(), error_msg)
            .to_compile_error()
            .into(),
    }
}

// Prefixes every local label (.Lfoo) with a tag derived from the generator
// path. Directives starting with .L, like .long, are left untouched.
fn tag_local_labels(path: &str, asm: &str) -> String {
    if !asm.is_ascii() {
        return asm.to_string();
    }

    let mut tag: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    tag.truncate(tag.trim_end_matches('_').len());

    let bytes = asm.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = String::with_capacity(asm.len() + 2 * tag.len() + 16);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'.' && i + 1 < bytes.len() && bytes[i + 1] == b'L' {
            let prev_ok =
                i == 0 || !is_ident(bytes[i - 1]) && bytes[i - 1] != b'$' && bytes[i - 1] != b'.';
            let mut j = i + 2;
            while j < bytes.len() && is_ident(bytes[j]) {
                j += 1;
            }
            let ident = &asm[i + 2..j];
            if prev_ok && !ident.is_empty() && ident != "ong" {
                out.push_str(".L");
                out.push_str(&tag);
                out.push('_');
                out.push_str(ident);
                i = j;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
