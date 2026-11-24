//! MySQL JSON path + SQL/JSON path parsing and evaluation over a JSON document
//! (JSON_EXTRACT / JSON_KEYS / JSON_CONTAINS / JSON_OVERLAPS family).
//! Input: `<path>\n<json document>`.
#![no_main]
use json::{ParseOptions, Path, Query, QueryOptions, SqlPath};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let path_text = &data[..split];
    let doc_text = if split < data.len() { &data[split + 1..] } else { &[][..] };
    let _ = SqlPath::parse(path_text);
    let path = Path::parse_mysql(path_text);
    if let Ok(path) = &path {
        let _ = path.to_mysql_string();
    }
    let Ok(query) = Query::from_text(doc_text, ParseOptions::default()) else { return };
    if let Ok(path) = path {
        let _ = query.query(&path, QueryOptions::default());
        let _ = query.query(&path, QueryOptions { auto_wrap: false, first_only: true });
        let _ = query.query_output(&path, true);
        let _ = query.first_value(&path, true);
        let _ = query.extract(std::slice::from_ref(&path));
        let _ = query.object_keys(Some(&path));
        let _ = query.contains(&query, Some(&path));
    }
    let _ = query.object_keys(None);
    let _ = query.overlaps(&query);
    let _ = query.member_of(&query);
});
