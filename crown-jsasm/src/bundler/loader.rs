use anyhow::Error;
use swc_bundler::{Load, ModuleData};
use swc_common::{
    comments::SingleThreadedComments,
    errors::{ColorConfig, Handler},
    sync::Lrc,
    FileName, Mark, SourceMap,
};
use swc_ecma_ast::*;
use swc_ecma_transforms::typescript::strip;

use swc_ecma_parser::Syntax;
use swc_ecma_transforms_base::{fixer::fixer, hygiene::hygiene, resolver};

pub struct Loader {
    pub cm: Lrc<SourceMap>,
}

impl Load for Loader {
    fn load(&self, f: &FileName) -> Result<ModuleData, Error> {
        let fm = match f {
            FileName::Real(path) => self.cm.load_file(path)?,
            FileName::Custom(content) => {
                let (filename, content) = content.split_once("::").unwrap();
                self.cm.new_source_file(
                    FileName::Real(filename.to_string().into()).into(),
                    content.to_string(),
                )
            }
            _ => unreachable!(),
        };

        let handler =
            Handler::with_tty_emitter(ColorConfig::Always, false, false, Some(self.cm.clone()));

        let module = swc_compiler_base::parse_js(
            self.cm.clone(),
            fm.clone(),
            &handler,
            EsVersion::Es2024,
            Syntax::Typescript(Default::default()),
            Default::default(),
            None,
        )?;
        let unresolved_mark = Mark::new();
        let top_level_mark = Mark::new();

        // Conduct identifier scope analysis
        let module = module.apply(resolver(unresolved_mark, top_level_mark, true));

        // Remove typescript types
        let module = module.apply(strip(unresolved_mark, top_level_mark));

        // Fix up any identifiers with the same name, but different contexts
        let module = module.apply(hygiene());

        // Ensure that we have enough parenthesis.
        let comments = SingleThreadedComments::default();
        let program = module.apply(fixer(Some(&comments)));

        let Program::Module(module) = program else {
            panic!("expected a module, but find a script.")
        };

        // let mut module = parse_file_as_module(
        //     &fm,
        //     Syntax::Typescript(Default::default()),
        //     EsVersion::Es2020,
        //     None,
        //     &mut Vec::new(),
        // )
        // .unwrap_or_else(|err| {
        //     let handler =
        //         Handler::with_tty_emitter(ColorConfig::Always, false, false, Some(self.cm.clone()));
        //     err.into_diagnostic(&handler).emit();
        //     panic!("failed to parse")
        // });

        Ok(ModuleData {
            fm,
            module,
            helpers: Default::default(),
        })
    }
}
