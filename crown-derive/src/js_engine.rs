use boa_engine::{Context, Source};
use proc_macro::{Span, TokenStream};
use quote::{quote, ToTokens};
use syn::{parse::Parse, parse_macro_input, Error, LitStr, Token};

struct JinjaParam {
    code: String,
    context: String,
}

impl Parse for JinjaParam {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let code: LitStr = input.parse()?;
        let _: Token![,] = input.parse()?;
        let context: LitStr = input.parse()?;
        Ok(Self {
            code: code.to_token_stream().to_string(),
            context: context.to_token_stream().to_string(),
        })
    }
}

fn execute_js_with_context(js_code: &str, context: &str) -> Result<String, String> {
    let mut js_context = Context::default();

    if !context.is_empty() {
        let context_json = context.trim_matches('"');
        let context_js_code = format!("const CONTEXT = {};", context_json);
        if let Err(e) = js_context.eval(Source::from_bytes(&context_js_code)) {
            return Err(format!("Failed to evaluate context: {}", e));
        }
    }

    let result = match js_context.eval(Source::from_bytes(js_code)) {
        Ok(result) => result,
        Err(e) => {
            return Err(format!("Failed to evaluate JavaScript code: {}", e));
        }
    };

    Ok(result.display().to_string())
}

pub fn jsasm(input: TokenStream) -> TokenStream {
    let JinjaParam { code, context } = parse_macro_input!(input as JinjaParam);

    match execute_js_with_context(&code, &context) {
        Ok(result) => {
            let expr = LitStr::new(&result, Span::call_site().into());
            quote! { #expr }.into()
        }
        Err(error_msg) => Error::new(Span::call_site().into(), error_msg)
            .to_compile_error()
            .into(),
    }
}

pub fn jsasm_file(input: TokenStream) -> TokenStream {
    let JinjaParam { code, context } = parse_macro_input!(input as JinjaParam);

    let code_content = match std::fs::read_to_string(code.trim_matches('"')) {
        Ok(content) => content,
        Err(e) => {
            return Error::new(
                Span::call_site().into(),
                format!("Failed to read file: {}", e),
            )
            .to_compile_error()
            .into();
        }
    };

    match execute_js_with_context(&code_content, &context) {
        Ok(result) => {
            let expr = LitStr::new(&result, Span::call_site().into());
            quote! { #expr }.into()
        }
        Err(error_msg) => Error::new(Span::call_site().into(), error_msg)
            .to_compile_error()
            .into(),
    }
}
