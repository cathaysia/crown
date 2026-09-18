use std::path::Path;

use rquickjs::{
    loader::{Loader, Resolver},
    Ctx, Error, Module, Result,
};

use crate::transpile::transpile_ts;

pub struct JsasmResolver;

impl Resolver for JsasmResolver {
    fn resolve<'js>(
        &mut self,
        _ctx: &Ctx<'js>,
        base: &str,
        name: &str,
        _attrs: Option<rquickjs::loader::ImportAttributes<'js>>,
    ) -> Result<String> {
        let is_xlate = matches!(
            name,
            "jsasm/x86_64-xlate"
                | "jsasm/x86_64-xlate.ts"
                | "jsasm/x86_64-xlate.js"
                | "x86_64-xlate"
                | "x86_64-xlate.ts"
                | "x86_64-xlate.js"
        );
        if is_xlate {
            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            let p = manifest_dir.join("preload/x86_64-xlate.ts");
            if p.exists() {
                return Ok(p.to_string_lossy().to_string());
            }
            let fallback = manifest_dir
                .parent()
                .unwrap()
                .join("crown-jsasm/preload/x86_64-xlate.ts");
            return Ok(fallback.to_string_lossy().to_string());
        }

        if Path::new(name).is_absolute() {
            return Ok(name.to_string());
        }

        if name.starts_with('.') {
            let base_path = Path::new(base);
            let dir = base_path.parent().unwrap_or(Path::new("."));
            let joined = dir.join(name);
            return Ok(joined.to_string_lossy().to_string());
        }

        Err(Error::new_resolving(base, name))
    }
}

pub struct SwcLoader;

impl Loader for SwcLoader {
    fn load<'js>(
        &mut self,
        ctx: &Ctx<'js>,
        name: &str,
        _attrs: Option<rquickjs::loader::ImportAttributes<'js>>,
    ) -> Result<Module<'js>> {
        let js = transpile_ts(None, name)
            .map_err(|e| Error::new_loading_message(name, &e.to_string()))?;
        Module::declare(ctx.clone(), name, js)
    }
}
