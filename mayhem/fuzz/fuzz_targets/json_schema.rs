//! JSON Schema compile + validate (JSON_SCHEMA_VALID / JSON_SCHEMA_VALIDATION_REPORT).
//! Input: `<schema json>\n<document json>`. Schema `pattern`s go through the production
//! compiler, upstream's std::regex wrapper rust/json/src/schema_pattern.cpp, linked via the
//! schema-pattern-shim crate (same cxx bridge as rust/json/src/bridge.rs).
#![no_main]
use json::schema::{InputFormat, Schema};
use json::ParseOptions;
use libfuzzer_sys::fuzz_target;
use schema_pattern_shim::PlatformPatternCompiler;

fn cmp(_: json::BinaryValue<'_>, _: json::BinaryValue<'_>) -> json::schema::Result<std::cmp::Ordering> {
    Ok(std::cmp::Ordering::Equal)
}

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let schema_text = &data[..split];
    let doc_text = if split < data.len() { &data[split + 1..] } else { &[][..] };
    let compiler = PlatformPatternCompiler;
    let _ = Schema::decode(data, &compiler);
    let Ok(schema) = Schema::from_input(schema_text, InputFormat::Text, 100, &compiler, cmp) else { return };
    if let Ok(encoded) = schema.encode() {
        let _ = Schema::decode(&encoded, &compiler);
    }
    let Ok(bin) = json::parse_binary(doc_text, ParseOptions::default()) else { return };
    let Ok(doc) = json::BinaryDocument::new(bin.as_slice()) else { return };
    if let Ok(root) = doc.root() {
        if let Ok(validation) = schema.validate(root) {
            let _ = validation.is_valid();
            let _ = validation.report();
        }
    }
});
