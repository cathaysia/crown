use anyhow::anyhow;
use boa_engine::{
    builtins::promise::PromiseState, js_string, module::SimpleModuleLoader, Context, JsError,
    JsValue, Module, NativeFunction, Source,
};
use std::{path::Path, rc::Rc};

pub(super) fn render(
    src: &str,
    filepath: Option<&str>,
    root: Option<&str>,
) -> anyhow::Result<String> {
    const DEFAULT_PATH: &str = "./scripts/main.mjs";
    const DEFAULT_ROOT_PATH: &str = ".";

    let root = root
        .map(|v| v.to_string())
        .unwrap_or_else(|| match filepath {
            Some(path) => Path::new(path)
                .parent()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
            None => DEFAULT_ROOT_PATH.to_string(),
        });
    let path = filepath.unwrap_or(DEFAULT_PATH);
    // This can be overridden with any custom implementation of `ModuleLoader`.
    let loader = Rc::new(SimpleModuleLoader::new(root).map_err(|err| anyhow!("{err}"))?);

    // Just need to cast to a `ModuleLoader` before passing it to the builder.
    let context = &mut Context::builder()
        .module_loader(loader.clone())
        .build()
        .map_err(|err| anyhow!("{err}"))?;
    let source = Source::from_reader(src.as_bytes(), Some(Path::new(DEFAULT_PATH)));

    // Can also pass a `Some(realm)` if you need to execute the module in another realm.
    let module = Module::parse(source, None, context).map_err(|err| anyhow!("{err}"))?;

    // Don't forget to insert the parsed module into the loader itself, since the root module
    // is not automatically inserted by the `ModuleLoader::load_imported_module` impl.
    //
    // Simulate as if the "fake" module is located in the modules root, just to ensure that
    // the loader won't double load in case someone tries to import "./main.mjs".
    loader.insert(path.into(), module.clone());

    // The lifecycle of the module is tracked using promises which can be a bit cumbersome to use.
    // If you just want to directly execute a module, you can use the `Module::load_link_evaluate`
    // method to skip all the boilerplate.
    // This does the full version for demonstration purposes.
    //
    // parse -> load -> link -> evaluate
    let promise_result = module
        // Initial load that recursively loads the module's dependencies.
        // This returns a `JsPromise` that will be resolved when loading finishes,
        // which allows async loads and async fetches.
        .load(context)
        .then(
            Some(
                NativeFunction::from_copy_closure_with_captures(
                    |_, _, module, context| {
                        // After loading, link all modules by resolving the imports
                        // and exports on the full module graph, initializing module
                        // environments. This returns a plain `Err` since all modules
                        // must link at the same time.
                        module.link(context)?;
                        Ok(JsValue::undefined())
                    },
                    module.clone(),
                )
                .to_js_function(context.realm()),
            ),
            None,
            context,
        )
        .then(
            Some(
                NativeFunction::from_copy_closure_with_captures(
                    // Finally, evaluate the root module.
                    // This returns a `JsPromise` since a module could have
                    // top-level await statements, which defers module execution to the
                    // job queue.
                    |_, _, module, context| Ok(module.evaluate(context).into()),
                    module.clone(),
                )
                .to_js_function(context.realm()),
            ),
            None,
            context,
        );

    // Very important to push forward the job queue after queueing promises.
    context.run_jobs();

    // Checking if the final promise didn't return an error.
    match promise_result.state() {
        PromiseState::Pending => return Err(anyhow!("module didn't execute!")),
        PromiseState::Fulfilled(v) => {
            assert_eq!(v, JsValue::undefined());
        }
        PromiseState::Rejected(err) => {
            return JsError::from_opaque(err)
                .try_native(context)
                .map_err(|err| anyhow!("{err}"))
                .map(|_| "".into());
        }
    }

    // We can access the full namespace of the module with all its exports.
    let namespace = module.namespace(context);
    let result = namespace
        .get(js_string!("default"), context)
        .map_err(|err| anyhow!("{err}"))?;
    let result = result.to_string(context).map_err(|err| anyhow!("{err}"))?;

    Ok(format!("{}", result.display_lossy()))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_render() {
        let src = r#"
        const ret = "Hello World!";
        export default ret;
        "#;
        let result = render(src, None, None).unwrap();
        assert_eq!(result, "Hello World!");
    }
}
