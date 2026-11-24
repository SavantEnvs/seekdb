//! The production JSON Schema `pattern` compiler: upstream's std::regex wrapper
//! (rust/json/src/schema_pattern.cpp), exposed as a `json::schema::PatternCompiler`.
//! The bridge and the adapter mirror upstream's rust/json/src/bridge.rs
//! (`compile_schema_pattern` / `SchemaPattern::matches`, `PlatformPatternCompiler`), which is
//! private to the json crate.

#[cxx::bridge(namespace = "oceanbase::common::json")]
mod ffi {
    unsafe extern "C++" {
        include!("rust/json/include/schema_pattern.h");
        type SchemaPattern;
        fn compile_schema_pattern(pattern: &[u8]) -> Result<UniquePtr<SchemaPattern>>;
        fn matches(self: &SchemaPattern, text: &[u8]) -> Result<bool>;
    }
}

struct PlatformPattern(cxx::UniquePtr<ffi::SchemaPattern>);

impl json::schema::Pattern for PlatformPattern {
    fn is_match(&self, text: &[u8]) -> Result<bool, json::schema::Error> {
        self.0
            .matches(text)
            .map_err(|error| json::schema::Error::Pattern(error.to_string()))
    }
}

/// Same behavior as upstream's `PlatformPatternCompiler`.
pub struct PlatformPatternCompiler;

impl json::schema::PatternCompiler for PlatformPatternCompiler {
    fn compile(
        &self,
        text: &[u8],
    ) -> Result<Box<dyn json::schema::Pattern>, json::schema::PatternError> {
        let pattern = ffi::compile_schema_pattern(text)
            .map_err(|error| json::schema::PatternError::Resource(error.to_string()))?;
        if pattern.is_null() {
            Err(json::schema::PatternError::Invalid)
        } else {
            Ok(Box::new(PlatformPattern(pattern)))
        }
    }
}
