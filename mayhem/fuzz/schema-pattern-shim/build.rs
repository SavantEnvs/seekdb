// Compiles upstream rust/json/src/schema_pattern.cpp plus the cxx thunks for the bridge
// in src/lib.rs. $CXX is the C++ compiler (cc crate); SEEKDB_CXX_SANITIZER_FLAGS (set by
// mayhem/build.sh) instruments the C++ the same way the Rust is.
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../../..").canonicalize().unwrap();
    let cpp = root.join("rust/json/src/schema_pattern.cpp");
    let mut build = cxx_build::bridge("src/lib.rs");
    build.file(&cpp).include(&root).std("c++17").flag("-gdwarf-3");
    if let Ok(flags) = std::env::var("SEEKDB_CXX_SANITIZER_FLAGS") {
        for flag in flags.split_whitespace() {
            build.flag(flag);
        }
    }
    build.compile("seekdb_schema_pattern");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed={}", cpp.display());
    println!("cargo:rerun-if-changed={}", root.join("rust/json/include/schema_pattern.h").display());
    println!("cargo:rerun-if-env-changed=SEEKDB_CXX_SANITIZER_FLAGS");
}
