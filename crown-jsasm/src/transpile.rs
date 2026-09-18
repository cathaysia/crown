use anyhow::anyhow;
use swc_common::{comments::SingleThreadedComments, sync::Lrc, FileName, Mark, SourceMap};
use swc_ecma_ast::EsVersion;
use swc_ecma_codegen::{text_writer::JsWriter, Emitter};
use swc_ecma_parser::{Lexer, Parser, StringInput, TsSyntax};
use swc_ecma_transforms_base::{fixer::fixer, hygiene::hygiene, resolver};
use swc_ecma_transforms_typescript::strip;

pub(crate) fn transpile_ts(code: Option<&str>, file_path: &str) -> anyhow::Result<String> {
    let globals = swc_common::Globals::default();
    swc_common::GLOBALS.set(&globals, || {
        let cm = Lrc::new(SourceMap::default());
        let fm = match code {
            Some(content) => cm.new_source_file(
                FileName::Custom(file_path.to_string()).into(),
                content.to_string(),
            ),
            None => cm.load_file(std::path::Path::new(file_path))?,
        };

        let comments = SingleThreadedComments::default();

        let lexer = Lexer::new(
            swc_ecma_parser::Syntax::Typescript(TsSyntax::default()),
            EsVersion::Es2024,
            StringInput::from(&*fm),
            Some(&comments),
        );
        let mut parser = Parser::new_from(lexer);
        let program = parser
            .parse_program()
            .map_err(|e| anyhow!("Failed to parse {file_path}: {e:?}"))?;
        if let Some(err) = parser.take_errors().into_iter().next() {
            return Err(anyhow!("Failed to parse {file_path}: {err:?}"));
        }

        let unresolved_mark = Mark::new();
        let top_level_mark = Mark::new();

        // Conduct identifier scope analysis
        let program = program.apply(resolver(unresolved_mark, top_level_mark, true));

        // Remove typescript types
        let program = program.apply(strip(unresolved_mark, top_level_mark));

        // Fix up any identifiers with the same name, but different contexts
        let program = program.apply(hygiene());

        // Ensure that we have enough parenthesis.
        let program = program.apply(fixer(Some(&comments)));

        let mut buf = Vec::new();
        {
            let mut emitter = Emitter {
                cm: cm.clone(),
                cfg: Default::default(),
                comments: None,
                wr: JsWriter::new(cm.clone(), "\n", &mut buf, None),
            };
            emitter.emit_program(&program)?;
        }

        Ok(String::from_utf8(buf)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpile_simple() {
        let ts = "const x: number = 42; export default x;";
        let js = transpile_ts(Some(ts), "test.ts").unwrap();
        assert!(js.contains("const x = 42;"));
        assert!(js.contains("export default x;"));
    }
}
