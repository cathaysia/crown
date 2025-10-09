use darling::{FromDeriveInput, FromField};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{quote, ToTokens};
use syn::{parse_macro_input, LitByteStr};

#[derive(FromDeriveInput)]
#[darling(attributes(marshal), supports(struct_any))]
struct FromStruct {
    ident: syn::Ident,
    data: darling::ast::Data<(), DeriveField>,
    magic: Option<syn::LitByteStr>,
}

#[derive(FromField, Debug)]
#[darling(attributes(marshal))]
struct DeriveField {
    ident: Option<syn::Ident>,
    ty: syn::Type,
    #[darling(default)]
    skip: bool,
}

pub fn marshal(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    let FromStruct {
        ident: s_ident,
        data,
        magic,
    } = match FromStruct::from_derive_input(&input) {
        Ok(v) => v,
        Err(err) => return err.write_errors().into(),
    };
    let magic = magic.unwrap_or_else(|| {
        let x = s_ident.to_string().to_lowercase();
        let x = format!("{x}\x01");
        LitByteStr::new(x.as_bytes(), Span::call_site())
    });

    let darling::ast::Data::Struct(s) = data else {
        return syn::Error::new(proc_macro2::Span::call_site(), "only support struct")
            .into_compile_error()
            .into();
    };

    let mut gen_len = quote! { 0 };
    let mut gen_ser = quote! {};
    let mut gen_der = quote! {};
    for f in s {
        let DeriveField { ident, ty, skip } = f;
        if skip {
            continue;
        }
        let Some(ident) = ident else {
            return syn::Error::new(proc_macro2::Span::call_site(), "only support struct")
                .into_compile_error()
                .into();
        };
        if let syn::Type::Array(arr) = &ty {
            let len = arr.len.clone();
            let ty = arr.elem.to_token_stream().to_string();
            match ty.as_str() {
                "u8" => {
                    gen_ser.extend(quote! {
                        out.put_slice(&self.#ident);
                    });
                    gen_der.extend(quote! {
                        b.copy_to_slice(&mut self.#ident);
                    });
                    gen_len.extend(quote! {
                        + 1 * #len
                    });
                }
                "u32" => {
                    gen_ser.extend(quote! {
                        for i in &self.#ident {
                            out.put_u32(*i);
                        }
                    });
                    gen_der.extend(quote! {
                        for i in &mut self.#ident {
                            *i = b.get_u32();
                        }
                    });
                    gen_len.extend(quote! {
                        + 4 * #len
                    });
                }
                "u64" | "usize" => {
                    gen_ser.extend(quote! {
                        for i in &self.#ident {
                            out.put_u64(*i as u64);
                        }
                    });
                    gen_der.extend(quote! {
                        for i in &mut self.#ident {
                            *i = b.get_u64() as _;
                        }
                    });
                    gen_len.extend(quote! {
                        + 8 * #len
                    });
                }
                _ => {}
            }
        };
        let ty_s = ty.to_token_stream().to_string();
        match ty_s.as_str() {
            "u8" => {
                gen_ser.extend(quote! {
                    out.put_u8(self.#ident);
                });
                gen_der.extend(quote! {
                    self.#ident = b.get_u8();
                });
                gen_len.extend(quote! {
                    + 1
                });
            }
            "u32" => {
                gen_ser.extend(quote! {
                    out.put_u32(self.#ident);
                });
                gen_der.extend(quote! {
                    self.#ident = b.get_u32();
                });
                gen_len.extend(quote! {
                    + 4
                });
            }
            "u64" | "usize" => {
                gen_ser.extend(quote! {
                    out.put_u64(self.#ident as u64);
                });
                gen_der.extend(quote! {
                    self.#ident = b.get_u64() as _;
                });
                gen_len.extend(quote! {
                    + 8
                });
            }
            _ => {}
        }
    }

    let magic_len = magic.to_token_stream().to_string().len() - 3;

    quote! {
        impl #s_ident {
            const MAGIC: &'static [u8] = #magic;
            const MARSHALED_SIZE: usize = #magic_len + #gen_len;
        }
        impl crate::mac::hmac::Marshalable for #s_ident {
            fn marshal_size(&self) -> usize {
                Self::MARSHALED_SIZE
            }

            fn marshal_into(&self, mut out: &mut [u8]) -> crate::error::CryptoResult<usize> {
                use bytes::Buf;

                let len = out.len();
                {
                    out.put_slice(Self::MAGIC);
                    #gen_ser
                }

                Ok(len - out.len())
            }

            fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
                use bytes::Buf;

                if b.len() < Self::MAGIC.len() || &b[..Self::MAGIC.len()] != Self::MAGIC {
                    return Err(crate::error::CryptoError::InvalidHashIdentifier);
                }
                if b.len() != Self::MARSHALED_SIZE {
                    return Err(crate::error::CryptoError::InvalidHashState);
                }

                let mut b = &b[Self::MAGIC.len()..];

                #gen_der

                Ok(())
            }
        }
    }
    .into()
}
