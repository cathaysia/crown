mod marshal;

use minijinja::{context, Environment};
use proc_macro::{Span, TokenStream};
use quote::quote;
use std::fs;
use syn::{parse_macro_input, LitStr};

#[proc_macro_derive(Marshal, attributes(marshal))]
pub fn marshal(input: TokenStream) -> TokenStream {
    marshal::marshal(input)
}

#[proc_macro]
pub fn jinja(input: TokenStream) -> TokenStream {
    let tmpl = parse_macro_input!(input as LitStr);

    let rendered = match render(&tmpl.value()) {
        Ok(result) => result,
        Err(err) => {
            return syn::Error::new(
                Span::call_site().into(),
                format!("Jinja rendering error: {}", err),
            )
            .to_compile_error()
            .into();
        }
    };

    let expr = LitStr::new(&rendered, Span::call_site().into());
    quote! { #expr }.into()
}

#[proc_macro]
pub fn jinja_file(input: TokenStream) -> TokenStream {
    let path = parse_macro_input!(input as LitStr).value();

    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            return syn::Error::new(
                Span::call_site().into(),
                format!("Failed to read file '{}': {}", path, err),
            )
            .to_compile_error()
            .into();
        }
    };

    let content = LitStr::new(&content, Span::call_site().into());
    jinja(
        quote! {
            #content
        }
        .into(),
    )
}

fn render(template: &str) -> Result<String, Box<dyn std::error::Error>> {
    let env = Environment::new();
    let tmpl = env.template_from_str(template)?;

    Ok(tmpl.render(context! {})?)
}
