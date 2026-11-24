//! JSON text -> document / binary JSON (rust/json: parse, validate, parse_binary),
//! then the binary form is read back and formatted (JSON_VALID / CAST(.. AS JSON)).
#![no_main]
use json::{DuplicatePolicy, ParseOptions, Query};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let policy = match data[0] & 3 {
        0 => DuplicatePolicy::Overwrite,
        1 => DuplicatePolicy::Preserve,
        2 => DuplicatePolicy::Reject,
        _ => DuplicatePolicy::KeepFirst,
    };
    let options = ParseOptions { duplicate_policy: policy, schema: data[0] & 4 != 0, ..ParseOptions::default() };
    let text = &data[1..];
    let _ = json::validate(text, options);
    let _ = json::parse(text, options);
    if let Ok(bin) = json::parse_binary(text, options) {
        if let Ok(query) = Query::from_binary(bin) {
            let _ = query.root_output(data[0] & 8 != 0);
            let _ = query.into_value();
        }
    }
});
