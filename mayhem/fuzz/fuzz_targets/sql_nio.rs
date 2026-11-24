//! MySQL wire-protocol parsers of rust/sql-nio — the code the server's network reactor runs on
//! raw client bytes before and after authentication (reached through the generated
//! sqlnio-shim crate, see mayhem/fuzz/sqlnio-shim/Cargo.toml).
//!
//! Input: byte 0 selects the parser, bytes 1..5 are capability flags (LE u32), the rest is the
//! packet body:
//!   0 → login::parse_login (HandshakeResponse41)        1 → command::parse_body (COM_*)
//!   2 → compress::deframe_step_limited loop (+ parse_body on each inflated packet)
//!   3 → stmt_execute::nio_parse_mysql_execute_params (COM_STMT_EXECUTE parameter block;
//!       the caps byte 0 is the parameter count)
//! Offsets the parsers hand back to C++ must lie inside the buffer they were parsed from.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sql_nio::fuzz_api::*;

fn in_bounds(off: i32, len: i32, total: usize) -> bool {
    off >= 0 && len >= 0 && (off as usize).checked_add(len as usize).is_some_and(|e| e <= total)
}

fn check_command(body: &[u8], caps: u32) {
    if let Some(v) = parse_body(body, caps) {
        for f in v.fields.iter() {
            if f.len > 0 {
                assert!(in_bounds(f.off, f.len, body.len()), "command field out of bounds: {:?}", v);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let caps = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let body = &data[5..];
    match data[0] % 4 {
        0 => {
            if let Some(l) = parse_login(body, caps | 0x0000_0200) {
                for (off, len) in [l.user, l.auth, l.db, l.plugin] {
                    // Absent db/plugin are (0, -1).
                    assert!(len <= 0 || in_bounds(off, len, body.len()), "login field out of bounds");
                }
                for a in &l.attrs {
                    assert!(in_bounds(a.key_off, a.key_len, body.len()), "attr key out of bounds");
                    assert!(in_bounds(a.value_off, a.value_len, body.len()), "attr value out of bounds");
                }
            }
        }
        1 => check_command(body, caps),
        2 => {
            let mut at = 0usize;
            while at < body.len() {
                match deframe_step_limited(body, at, 1 << 20) {
                    DeframeStep::Packet { consumed, plain, .. } => {
                        assert!(consumed > 0);
                        // Each inflated payload holds plain packets: 4-byte header + command.
                        if plain.len() > 4 {
                            check_command(&plain[4..], caps);
                        }
                        at += consumed;
                    }
                    _ => break,
                }
            }
        }
        _ => {
            let n = data[1] as usize;
            let mut params = vec![NioMysqlExecuteParam::default(); n];
            let mut result = NioMysqlExecuteParseResult::default();
            let rc = unsafe {
                nio_parse_mysql_execute_params(
                    body.as_ptr().cast(),
                    body.len() as i64,
                    n as i64,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    params.as_mut_ptr(),
                    n as i64,
                    &mut result,
                )
            };
            std::hint::black_box((rc, &params, result));
        }
    }
});
