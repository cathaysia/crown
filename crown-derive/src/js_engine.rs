use proc_macro::{Span, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Error, LitStr};

use crown_jsasm::execute_js_with_json_context;

pub fn jsasm_file(input: TokenStream) -> TokenStream {
    let path = parse_macro_input!(input as LitStr).value();

    match execute_js_with_json_context(path) {
        Ok(result) => {
            let expr = LitStr::new(&result, Span::call_site().into());
            quote! { #expr }.into()
        }
        Err(error_msg) => Error::new(Span::call_site().into(), error_msg)
            .to_compile_error()
            .into(),
    }
}
