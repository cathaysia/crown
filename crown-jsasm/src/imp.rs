use anyhow::{anyhow, bail};
use rquickjs::{Context, Module, Runtime};

use crate::{
    quickjs_loader::{JsasmResolver, SwcLoader},
    transpile::transpile_ts,
};

pub fn execute_js_with_json_context(path: String) -> anyhow::Result<String> {
    let context_json = std::env::var("JSASM_VAR").map_err(|e| anyhow!("JSASM_VAR missing: {e}"))?;
    if context_json.is_empty() {
        bail!("JSASM_VAR empty");
    }

    let preload_js = transpile_ts(
        Some(include_str!("../preload/index.ts")),
        "preload/index.ts",
    )?;

    // Resolve user path to absolute for QuickJS import
    let user_path = {
        let p = std::path::Path::new(&path);
        if p.is_absolute() && p.exists() {
            p.to_string_lossy().to_string()
        } else {
            let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            let candidates = [
                manifest_dir.parent().unwrap().join(&path),
                manifest_dir.join(&path),
                std::path::Path::new(".").join(&path),
                p.to_path_buf(),
            ];
            let mut found = path.clone();
            for c in &candidates {
                if c.exists() {
                    found = c
                        .canonicalize()
                        .unwrap_or(c.clone())
                        .to_string_lossy()
                        .to_string();
                    break;
                }
            }
            found
        }
    };

    let rt = Runtime::new().map_err(|e| anyhow!("Runtime::new failed: {e}"))?;
    rt.set_loader(
        (
            JsasmResolver,
            rquickjs::loader::FileResolver::default().with_path("."),
        ),
        (SwcLoader, rquickjs::loader::ScriptLoader::default()),
    );

    let ctx = Context::full(&rt).map_err(|e| anyhow!("Context::full failed: {e}"))?;

    let result = ctx.with(|ctx| -> anyhow::Result<String> {
        ctx.eval::<(), _>(
            "globalThis.console = { log: (...a)=>{}, error: (...a)=>{}, warn: (...a)=>{}, info: (...a)=>{}, debug: (...a)=>{} };",
        )
        .map_err(|e| anyhow!("console stub failed: {e}"))?;

        let init_context = format!("globalThis.__CONTEXT = {:?};", context_json);
        ctx.eval::<(), _>(init_context.as_str())
            .map_err(|e| anyhow!("Failed to evaluate context: {e}"))?;

        ctx.eval::<(), _>(preload_js.as_str())
            .map_err(|e| anyhow!("Failed to evaluate preload script: {e}"))?;

        // Import user module via QuickJS's native import (triggers JsasmResolver/SwcLoader)
        let promise = Module::import(&ctx, user_path.clone())
            .map_err(|e| anyhow!("Failed to import user module {}: {e}", user_path))?;

        // Run pending jobs to settle the import promise
        while ctx.execute_pending_job() {}

        let ns: rquickjs::Object = promise
            .finish()
            .map_err(|e| anyhow!("Failed to finish import promise for {}: {:?}", user_path, e))?;

        let result_str: String = ns
            .get("default")
            .map_err(|e| anyhow!("Failed to get default export: {e}"))?;

        let result_str = result_str.trim_matches('"').to_string();

        Ok(result_str)
    })?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_md5() {
        std::env::set_var("JSASM_VAR", "{}");
        let result =
            execute_js_with_json_context("crown/src/hash/md5/block/x86_64.ts".into()).unwrap();
        assert!(result.contains("ossl_md5_block_asm_data_order"));
    }

    #[test]
    fn test_execute_rc4_with_import() {
        std::env::set_var("JSASM_VAR", "{}");
        let result =
            execute_js_with_json_context("crown/src/stream/rc4/xor_key_stream/x86_64.ts".into())
                .unwrap();
        assert!(result.contains("RC4:"));
    }
}
