#!/usr/bin/env bash
# Generate mayhem/fuzz/sqlnio-shim/gen/lib.rs from upstream rust/sql-nio/src/lib.rs (see
# sqlnio-shim/Cargo.toml). Called by mayhem/build.sh; idempotent.
set -euo pipefail
src="$1/rust/sql-nio/src"
out="$1/mayhem/fuzz/sqlnio-shim/gen"
mkdir -p "$out"
{
  # Crate-level #![...] attributes are kept (the generated file is the crate root).
  sed -E "s|^([[:space:]]*)mod ([a-z_0-9]+);|\1#[path = \"$src/\2.rs\"] mod \2;|" "$src/lib.rs"
  cat <<'RS'

/// Fuzzing entry points: the wire-protocol parsers the reactor runs on client bytes.
pub mod fuzz_api {
    pub use crate::bridge::ffi::{
        NioLoginAttr, NioMysqlCommandView, NioMysqlExecuteParam, NioMysqlExecuteParamMeta,
        NioMysqlExecuteParseResult,
    };
    pub use crate::command::parse_body;
    pub use crate::compress::{deframe_step_limited, DeframeStep};
    pub use crate::login::{parse_login, ParsedLogin};
    pub use crate::stmt_execute::nio_parse_mysql_execute_params;
}
RS
} > "$out/lib.rs.tmp"
mv "$out/lib.rs.tmp" "$out/lib.rs"
