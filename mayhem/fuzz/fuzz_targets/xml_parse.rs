//! XML document / content parsing (rust/xml-parser, behind XMLPARSE / XMLTYPE and
//! ObXmlParser). First byte selects mode and options; the rest is the XML text.
#![no_main]
use libfuzzer_sys::fuzz_target;
use xml_parser::{Event, EventHandler, ParseMode, ParseOptions};

struct Count(usize);
impl EventHandler for Count {
    type Error = ();
    fn on_event(&mut self, event: Event<'_>) -> Result<(), ()> {
        // Touch the borrowed payloads so the parser's slices are read.
        self.0 += match event {
            Event::StartElement { name, attributes, .. } => name.len() + attributes.iter().map(|a| a.name.len() + a.value.len()).sum::<usize>(),
            Event::Text(t) | Event::Declaration(t) => t.len(),
            Event::CData(t) | Event::Comment(t) => t.len(),
            Event::ProcessingInstruction { target, value } => target.len() + value.len(),
            _ => 1,
        };
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let flags = data[0];
    let mode = if flags & 1 == 0 { ParseMode::Document } else { ParseMode::Content };
    let options = ParseOptions {
        recover: flags & 2 != 0,
        syntax_check: flags & 4 != 0,
        content_allow_xml_decl: flags & 8 != 0,
        preserve_entity_references: flags & 16 != 0,
    };
    let mut handler = Count(0);
    let _ = xml_parser::parse(&data[1..], mode, options, &mut handler);
});
