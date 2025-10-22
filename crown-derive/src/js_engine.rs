use std::collections::HashMap;

use boa_engine::{Context, Source};
use proc_macro::{Span, TokenStream};
use quote::quote;
use serde_json::Value;
use syn::{parse::Parse, parse_macro_input, Error, Expr, LitStr, Token};

struct JinjaParam {
    code: String,
    context: HashMap<String, Value>,
}

impl Parse for JinjaParam {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let code: LitStr = input.parse()?;
        let _: Token![,] = input.parse()?;
        let context: LitStr = input.parse()?;
        Ok(Self {
            code: code.value(),
            context: {
                let mut map = HashMap::new();
                let context_str = context.value();
                if !context_str.is_empty() {
                    if let Ok(parsed) = serde_json::from_str::<HashMap<String, Value>>(&context_str)
                    {
                        map = parsed
                    }
                }
                map
            },
        })
    }
}

struct JinjaFileParam {
    path: String,
    context: HashMap<String, Value>,
}

impl Parse for JinjaFileParam {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let path: LitStr = input.parse()?;
        let mut context = HashMap::new();

        while !input.is_empty() {
            let _: Token![,] = input.parse()?;
            if input.is_empty() {
                break;
            }

            let key: LitStr = input.parse()?;
            let _: Token![,] = input.parse()?;
            let value: Expr = input.parse()?;

            let key_str = key.value();
            let value_json = expr_to_json_value(&value)?;
            context.insert(key_str, value_json);
        }

        Ok(Self {
            path: path.value(),
            context,
        })
    }
}

fn expr_to_json_value(expr: &Expr) -> syn::Result<Value> {
    match expr {
        Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Str(s) => Ok(Value::String(s.value())),
            syn::Lit::Int(i) => {
                if let Ok(val) = i.base10_parse::<i64>() {
                    Ok(Value::Number(serde_json::Number::from(val)))
                } else {
                    Err(Error::new_spanned(i, "Invalid integer"))
                }
            }
            syn::Lit::Float(f) => {
                if let Ok(val) = f.base10_parse::<f64>() {
                    Ok(Value::Number(serde_json::Number::from_f64(val).unwrap()))
                } else {
                    Err(Error::new_spanned(f, "Invalid float"))
                }
            }
            syn::Lit::Bool(b) => Ok(Value::Bool(b.value)),
            _ => Err(Error::new_spanned(lit, "Unsupported literal type")),
        },
        _ => Err(Error::new_spanned(
            expr,
            "Only literals are supported as values",
        )),
    }
}

fn execute_js_with_json_context(
    js_code: &str,
    context: &HashMap<String, Value>,
) -> Result<String, String> {
    let mut js_context = Context::default();

    if !context.is_empty() {
        let context_json = serde_json::to_string(context)
            .map_err(|e| format!("Failed to serialize context: {}", e))?;
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
    let result = result.display().to_string();
    let result = result.trim_matches('"');

    Ok(result.to_string())
}

pub fn jsasm(input: TokenStream) -> TokenStream {
    let JinjaParam { code, context } = parse_macro_input!(input as JinjaParam);

    match execute_js_with_json_context(&code, &context) {
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
    let JinjaFileParam { path, context } = parse_macro_input!(input as JinjaFileParam);

    let code_content = match std::fs::read_to_string(&path) {
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

    match execute_js_with_json_context(&code_content, &context) {
        Ok(result) => {
            let expr = LitStr::new(&result, Span::call_site().into());
            quote! { #expr }.into()
        }
        Err(error_msg) => Error::new(Span::call_site().into(), error_msg)
            .to_compile_error()
            .into(),
    }
}
