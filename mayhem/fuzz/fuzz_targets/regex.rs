//! REGEXP_LIKE / REGEXP_INSTR / REGEXP_SUBSTR / REGEXP_REPLACE engine (rust/regex-engine),
//! through the same bridge functions the C++ server calls.
//! Input: `<flags byte><pattern>\0<subject>\0<replacement>`; text is UTF-8, converted to the
//! UTF-16BE the bridge takes (that is what ObExprRegexContext hands it).
#![no_main]
use libfuzzer_sys::fuzz_target;
use regex_engine::{
    regex_buffer_free, regex_compile, regex_find, regex_free, regex_replace, RegexBuffer, RegexError, RegexMatch,
};

fn utf16be(bytes: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(bytes).encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let flags = u32::from(data[0] & 0x0f);
    let mut parts = data[1..].splitn(3, |&b| b == 0);
    let pattern = utf16be(parts.next().unwrap_or_default());
    let subject = utf16be(parts.next().unwrap_or_default());
    let replacement = utf16be(parts.next().unwrap_or_default());
    let start = i64::from(data[0] >> 4) + 1;
    unsafe {
        let mut error: RegexError = std::mem::zeroed();
        let mut engine = std::ptr::null_mut();
        // stack/time limits 0 = the engine's defaults (bounded backtracking).
        if regex_compile(pattern.as_ptr(), pattern.len(), flags, 0, 0, &mut engine, &mut error) != 0 {
            return;
        }
        let mut m = RegexMatch { matched: 0, start: -1, end: -1 };
        for (occurrence, group) in [(1, 0), (2, 1)] {
            let _ = regex_find(engine, subject.as_ptr(), subject.len(), start, occurrence, group, &mut m, &mut error);
        }
        for occurrence in [0, 1] {
            let mut out = RegexBuffer { data: std::ptr::null_mut(), len: 0 };
            if regex_replace(engine, subject.as_ptr(), subject.len(), replacement.as_ptr(), replacement.len(), start, occurrence, &mut out, &mut error) == 0 {
                regex_buffer_free(&mut out);
            }
        }
        regex_free(engine);
    }
});
