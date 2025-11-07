fn main() {
    let ctx = crown_jsasm::JsasmContext::new().unwrap();
    let s = serde_json::to_string(&ctx).unwrap();
    println!("cargo:rustc-env=JSASM_VAR={}", s);
}
