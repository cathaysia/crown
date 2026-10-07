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
//
// The perl also emits file-local jump targets that are not `.L` labels: the
// `_*_shortcut` idiom of the SHA-1/SHA-256 modules (`_shaext_shortcut`,
// `_avx2_shortcut`, ...) and the bare `L...` labels the riscv.pm modules use
// (`Lstep`, `Lpolymod`, `L_round_loop`, ...). They are referenced only from
// within the same generator, so they get the same treatment; without it two
// modules defining the same name collide as soon as rustc places their blobs
// in one assembly unit. A bare `L...` name is treated as a label only when
// the generator defines it at the start of a line, so prose like "License"
// in a comment is never touched.
fn tag_local_labels(path: &str, asm: &str) -> String {
    let mut tag: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    tag.truncate(tag.trim_end_matches('_').len());

    let bytes = asm.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let prev_ok = |i: usize| {
        i == 0 || !is_ident(bytes[i - 1]) && bytes[i - 1] != b'$' && bytes[i - 1] != b'.'
    };
    // Byte-wise on purpose: the perl output carries comments in any encoding,
    // and only ASCII bytes can start a label.
    let bare_labels = collect_bare_labels(asm);
    let mut out: Vec<u8> = Vec::with_capacity(asm.len() + 2 * tag.len() + 16);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'.' && i + 1 < bytes.len() && bytes[i + 1] == b'L' {
            let mut j = i + 2;
            while j < bytes.len() && is_ident(bytes[j]) {
                j += 1;
            }
            let ident = &asm[i + 2..j];
            if prev_ok(i) && !ident.is_empty() && ident != "ong" {
                out.extend_from_slice(b".L");
                out.extend_from_slice(tag.as_bytes());
                out.push(b'_');
                out.extend_from_slice(ident.as_bytes());
                i = j;
                continue;
            }
        } else if bytes[i] == b'_' && prev_ok(i) {
            let mut j = i + 1;
            while j < bytes.len() && is_ident(bytes[j]) {
                j += 1;
            }
            let ident = &asm[i..j];
            if ident.ends_with("_shortcut") {
                out.push(b'_');
                out.extend_from_slice(tag.as_bytes());
                out.extend_from_slice(ident.as_bytes());
                i = j;
                continue;
            }
        } else if bytes[i] == b'L' && prev_ok(i) {
            let mut j = i + 1;
            while j < bytes.len() && is_ident(bytes[j]) {
                j += 1;
            }
            let ident = &asm[i..j];
            // The trailing boundary keeps a longer name intact when it starts
            // with a shorter one (`Lstep` vs `Lstep_zkbk`).
            let after_ok = j >= bytes.len() || !is_ident(bytes[j]);
            if after_ok && bare_labels.contains(ident) {
                out.push(b'L');
                out.extend_from_slice(tag.as_bytes());
                out.push(b'_');
                out.extend_from_slice(&bytes[i + 1..j]);
                i = j;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).expect("label tagging preserves UTF-8")
}

/// The `L...` names `asm` defines as labels at the start of a line (leading
/// blanks allowed), which is how perlasm writes them.
fn collect_bare_labels(asm: &str) -> std::collections::HashSet<&str> {
    let bytes = asm.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut labels = std::collections::HashSet::new();
    let mut at_line_start = true;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            at_line_start = true;
            i += 1;
            continue;
        }
        if at_line_start && (b == b' ' || b == b'\t') {
            i += 1;
            continue;
        }
        if at_line_start && b == b'L' {
            let mut j = i + 1;
            while j < bytes.len() && is_ident(bytes[j]) {
                j += 1;
            }
            if j > i + 1 && j < bytes.len() && bytes[j] == b':' {
                labels.insert(&asm[i..j]);
            }
        }
        at_line_start = false;
        i += 1;
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_local_labels() {
        let asm = "\t.Lloop:\n\tjmp\t.Lloop\n\tjmp\t_shaext_shortcut\n\
                   _shaext_shortcut:\n\t.long\t1\n\tjmp\t_avx2_shortcut\n\
                   _vpaes_encrypt_core:\n";
        let tagged = tag_local_labels("crown/src/hash/sha1/block/x86_64.ts", asm);
        assert!(tagged.contains(".Lcrown_src_hash_sha1_block_x86_64_ts_loop:"));
        assert!(tagged.contains("jmp\t.Lcrown_src_hash_sha1_block_x86_64_ts_loop"));
        assert!(tagged.contains("_crown_src_hash_sha1_block_x86_64_ts_shaext_shortcut:"));
        assert!(tagged.contains("jmp\t_crown_src_hash_sha1_block_x86_64_ts_avx2_shortcut"));
        // Underscore names that are not shortcut jump targets are left alone.
        assert!(tagged.contains("_vpaes_encrypt_core:"));
    }

    #[test]
    fn tags_local_labels_with_non_ascii_comments() {
        // The aarch64 GHASH output keeps a few `·` multiplication signs in
        // comments; they must survive byte-exact.
        let asm = "\tpmull\tv0.1q,v20.1d,v3.1d\t\t//H.lo·Xi.lo\n\tb\t.Lloop\n.Lloop:\n";
        let tagged = tag_local_labels("crown/src/block/aes/gcm/aarch64.ts", asm);
        assert!(tagged.contains("//H.lo·Xi.lo"));
        assert!(tagged.contains(".Lcrown_src_block_aes_gcm_aarch64_ts_loop:"));
    }

    #[test]
    fn tags_bare_riscv_labels() {
        // riscv.pm modules define `L...` labels at the start of a line and
        // jump to them; both the definition and every reference move.
        let asm = "Lstep:\n\taddi\tt0,t0,-1\n\tbnez\tt0,Lstep\n\
                   Lpolymod:\n\tj\tLstep\nK256:\n\t.word\t1\n\
                   \t# License terms, Lstep appears in prose\n";
        let tagged = tag_local_labels("crown/src/block/aes/gcm/riscv64_zbc.ts", asm);
        assert!(tagged.contains("Lcrown_src_block_aes_gcm_riscv64_zbc_ts_step:"));
        assert!(tagged.contains("bnez\tt0,Lcrown_src_block_aes_gcm_riscv64_zbc_ts_step"));
        assert!(tagged.contains("Lcrown_src_block_aes_gcm_riscv64_zbc_ts_polymod:"));
        assert!(tagged.contains("j\tLcrown_src_block_aes_gcm_riscv64_zbc_ts_step"));
        // Data labels shared by nothing are left alone, and prose is only
        // touched where it happens to name a label the module defines (the
        // `.L` rule rewrites occurrences in comments the same way).
        assert!(tagged.contains("K256:"));
        assert!(tagged.contains(
            "# License terms, Lcrown_src_block_aes_gcm_riscv64_zbc_ts_step appears in prose"
        ));
    }

    #[test]
    fn keeps_longer_bare_labels_intact() {
        // `Lstep` must not be rewritten inside `Lstep_zkbk`.
        let asm = "Lstep:\nLstep_zkbk:\n\tj\tLstep_zkbk\n\tj\tLstep\n";
        let tagged = tag_local_labels("m.ts", asm);
        assert!(tagged.contains("Lm_ts_step:"));
        assert!(tagged.contains("Lm_ts_step_zkbk:"));
        assert!(tagged.contains("j\tLm_ts_step_zkbk"));
        assert!(tagged.contains("j\tLm_ts_step\n"));
    }
}
