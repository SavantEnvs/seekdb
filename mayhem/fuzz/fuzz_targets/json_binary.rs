//! Untrusted binary JSON (the on-disk / wire JSON column encoding): open it,
//! walk it, format it and compare it (rust/json binary.rs reader).
#![no_main]
use json::{BinaryDocument, BinaryValue, Path, Query, QueryOptions};
use libfuzzer_sys::fuzz_target;

// Offsets may alias, so a binary of N bytes can describe an exponentially large tree;
// bound the harness's own walk by a node budget (the library's calls are not bounded).
fn walk(value: BinaryValue<'_>, depth: u32, budget: &mut u32) {
    if depth > 64 || *budget == 0 {
        return;
    }
    *budget -= 1;
    let _ = value.json_type();
    let Ok(len) = value.len() else { return };
    for i in 0..len.min(64) {
        let _ = value.key(i);
        if let Ok(child) = value.value(i) {
            walk(child, depth + 1, budget);
        }
    }
    let _ = value.boolean();
    let _ = value.number();
    let _ = value.decimal();
    let _ = value.string_bytes();
    let _ = value.opaque_bytes();
}

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = BinaryDocument::new(data) {
        let _ = doc.depth();
        if let Ok(root) = doc.root() {
            walk(root, 0, &mut 4096);
            let _ = json::binary::serialize_value(root);
        }
    }
    if let Ok(query) = Query::from_binary(data.to_vec()) {
        let _ = query.root_output(false);
        if let Ok(path) = Path::parse_mysql(b"$**[*]") {
            let _ = query.query(&path, QueryOptions::default());
        }
        let _ = query.overlaps(&query);
        let _ = query.into_value();
    }
});
