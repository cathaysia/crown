use anyhow::{anyhow, bail};
use rquickjs::{Context, Runtime};

use crate::bundler::bundle_module;

pub fn execute_js_with_json_context(path: String) -> anyhow::Result<String> {
    let user_code = bundle_module(None, path.clone())?;

    let context_json =
        std::env::var("JSASM_VAR").map_err(|e| anyhow!("JSASM_VAR missing: {e}"))?;
    if context_json.is_empty() {
        bail!("JSASM_VAR empty");
    }

    let preload_code = bundle_module(
        Some(include_str!("../preload/index.ts").to_string()),
        "preload/index.ts".into(),
    )?;

    let rt = Runtime::new().map_err(|e| anyhow!("Runtime::new failed: {e}"))?;
    let ctx = Context::full(&rt).map_err(|e| anyhow!("Context::full failed: {e}"))?;

    let result = ctx.with(|ctx| -> anyhow::Result<String> {
        ctx.eval::<(), _>(
            "globalThis.console = { log: (...a)=>{}, error: (...a)=>{}, warn: (...a)=>{}, info: (...a)=>{}, debug: (...a)=>{} };",
        )
        .map_err(|e| anyhow!("console stub failed: {e}"))?;

        let init_context = format!("globalThis.__CONTEXT = {:?};", context_json);
        ctx.eval::<(), _>(init_context.as_str())
            .map_err(|e| anyhow!("Failed to evaluate context: {e}"))?;

        ctx.eval::<(), _>(preload_code.as_str())
            .map_err(|e| anyhow!("Failed to evaluate preload script: {e}"))?;

        let user_code_eval = if user_code.contains("export default") {
            user_code.replace("export default", "globalThis.__JSASM_RESULT =")
        } else {
            format!(
                "{user_code}\n; globalThis.__JSASM_RESULT = (typeof code !== 'undefined' ? code : (typeof generateAssembly !== 'undefined' ? generateAssembly() : undefined));"
            )
        };

        ctx.eval::<(), _>(user_code_eval.as_str())
            .map_err(|e| anyhow!("Failed to evaluate user module: {e}"))?;

        let result: String = ctx
            .eval::<String, _>("String(globalThis.__JSASM_RESULT)")
            .map_err(|e| anyhow!("Failed to get default export: {e}"))?;

        Ok(result)
    })?;

    Ok(result)
}
