mod loader;
use std::collections::HashMap;

use loader::Loader;

mod hook;
use hook::Hook;

use swc_bundler::Bundler;
use swc_common::{sync::Lrc, FileName, SourceMap};
use swc_ecma_codegen::{text_writer::JsWriter, Emitter};
use swc_ecma_loader::{
    resolvers::{lru::CachingResolver, node::NodeModulesResolver},
    TargetEnv,
};

pub(crate) fn bundle_module(code: Option<String>, file_path: String) -> anyhow::Result<String> {
    let globals = Box::leak(Box::default());
    let cm = Lrc::new(SourceMap::default());

    let mut bundler = Bundler::new(
        globals,
        cm.clone(),
        Loader { cm: cm.clone() },
        CachingResolver::new(
            4096,
            NodeModulesResolver::new(TargetEnv::Node, Default::default(), true),
        ),
        swc_bundler::Config {
            require: false,
            disable_inliner: false,
            external_modules: Default::default(),
            disable_fixer: false,
            disable_hygiene: false,
            disable_dce: false,
            module: Default::default(),
        },
        Box::new(Hook),
    );

    let file = match code {
        Some(code) => FileName::Custom(format!("{file_path}::{code}")),
        None => FileName::Real(file_path.clone().into()),
    };

    let mut files = HashMap::default();
    files.insert(file_path, file);

    let modules = bundler.bundle(files)?;
    let i: Vec<_> = modules
        .into_iter()
        .map(|module| {
            let mut buf = Vec::new();
            let mut emitter = Emitter {
                cm: cm.clone(),
                cfg: Default::default(),
                comments: None,
                wr: JsWriter::new(cm.clone(), "\n", &mut buf, None),
            };
            emitter.emit_module(&module.module).unwrap();
            let ret = String::from_utf8_lossy(&buf).to_string();
            buf.clear();
            ret
        })
        .collect();
    if i.is_empty() {
        panic!("no bundled module");
    }

    Ok(i.into_iter().next().unwrap())
}
