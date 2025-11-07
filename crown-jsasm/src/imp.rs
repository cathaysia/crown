use std::path::Path;

use anyhow::anyhow;
use anyhow::bail;
use boa_engine::module::SimpleModuleLoader;
use boa_engine::Module;
use boa_engine::{property::Attribute, Context, Source};
use boa_runtime::Console;

use crate::bundler::bundle_module;

pub fn execute_js_with_json_context(path: String) -> anyhow::Result<String> {
    use boa_engine::{builtins::promise::PromiseState, JsError, JsValue, NativeFunction};

    let loader = std::rc::Rc::new(SimpleModuleLoader::new("./").map_err(|err| anyhow!("{err}"))?);
    let mut ctx = Context::builder()
        .module_loader(loader.clone())
        .build()
        .map_err(|err| anyhow!("{err}"))?;

    let user_code = bundle_module(None, path.clone())?;

    {
        let console = Console::init(&mut ctx);
        ctx.register_global_property(Console::NAME, console, Attribute::all())
            .expect("the console builtin shouldn't exist");
    }
    {
        let context = std::env::var("JSASM_VAR").unwrap();
        let context = format!("globalThis.__CONTEXT = {:?};", context);
        if let Err(e) = ctx.eval(Source::from_bytes(&context)) {
            bail!("Failed to evaluate context: {}", e);
        }
    }

    let global_code = include_str!("../preload/index.ts");
    let global_transpiled =
        bundle_module(Some(global_code.to_string()), "preload/index.ts".into())?;
    let global_source = Source::from_bytes(&global_transpiled);
    if let Err(e) = ctx.eval(global_source) {
        bail!("Failed to evaluate preload script: {}", e);
    }

    let user_source = Source::from_bytes(&user_code);
    let user_module = Module::parse(user_source, None, &mut ctx).map_err(|err| anyhow!("{err}"))?;

    let user_module_path = Path::new("./").canonicalize()?.join(path);

    loader.insert(user_module_path, user_module.clone());

    let promise_result = user_module
        .load(&mut ctx)
        .then(
            Some(
                NativeFunction::from_copy_closure_with_captures(
                    |_, _, module, context| {
                        module.link(context)?;
                        Ok(JsValue::undefined())
                    },
                    user_module.clone(),
                )
                .to_js_function(ctx.realm()),
            ),
            None,
            &mut ctx,
        )
        .then(
            Some(
                NativeFunction::from_copy_closure_with_captures(
                    |_, _, module, context| Ok(module.evaluate(context).into()),
                    user_module.clone(),
                )
                .to_js_function(ctx.realm()),
            ),
            None,
            &mut ctx,
        );

    ctx.run_jobs();

    match promise_result.state() {
        PromiseState::Pending => bail!("module didn't execute!"),
        PromiseState::Fulfilled(_) => {}
        PromiseState::Rejected(err) => {
            let js_error = JsError::from_opaque(err);
            match js_error.try_native(&mut ctx) {
                Ok(native_error) => bail!("module execution failed: {}", native_error),
                Err(_) => bail!("module execution failed: {js_error}"),
            }
        }
    }

    let namespace = user_module.namespace(&mut ctx);
    let default_export = namespace
        .get(boa_engine::js_string!("default"), &mut ctx)
        .map_err(|err| anyhow!("Failed to get default export: {err}"))?;

    let result = default_export.display().to_string();
    let result = result.trim_matches('"');

    Ok(result.to_string())
}
