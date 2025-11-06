use std::path::Path;

use anyhow::bail;
use boa_engine::{Context, Source};

pub fn execute_js_with_json_context(code: String, path: Option<String>) -> anyhow::Result<String> {
    let mut js_context = Context::default();
    let code = match path {
        Some(ref path) => std::fs::read_to_string(path)?,
        None => code,
    };

    {
        let context = std::env::var("JSASM_VAR").unwrap();
        let context = format!("globalThis.__CONTEXT = {:?};", context);
        if let Err(e) = js_context.eval(Source::from_bytes(&context)) {
            bail!("Failed to evaluate context: {}", e);
        }
    }

    let global = Source::from_bytes(include_bytes!("../preload/index.js"));
    if let Err(err) = js_context.eval(global) {
        bail!("Failed to evaluate global: {err}");
    }

    let mut source = Source::from_bytes(&code);
    let path = path.as_ref().map(Path::new);
    if let Some(path) = path {
        source = source.with_path(path);
    }
    let result = match js_context.eval(source) {
        Ok(result) => result,
        Err(e) => {
            bail!("Failed to evaluate JavaScript code: {}", e);
        }
    };
    let result = result.display().to_string();
    let result = result.trim_matches('"');

    Ok(result.to_string())
}
