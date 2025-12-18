#[cfg(feature = "jsasm")]
mod js_engine;
mod marshal;

use proc_macro::TokenStream;

#[proc_macro_derive(Marshal, attributes(marshal))]
pub fn marshal(input: TokenStream) -> TokenStream {
    marshal::marshal(input)
}

#[cfg(feature = "jsasm")]
#[proc_macro]
pub fn jsasm_file(input: TokenStream) -> TokenStream {
    js_engine::jsasm_file(input)
}
