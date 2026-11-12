//! Format `plain` : une ligne = une entrée, sans préfixe. Sert aux tests des templates
//! abstraits et au bac à sable.

use super::{Format, FormatKind, Framed, LineClass};
use crate::entry::EntryKind;

pub struct Plain;

impl Format for Plain {
    fn kind(&self) -> FormatKind {
        FormatKind::Plain
    }

    fn frame<'a>(&self, line: &'a [u8]) -> Framed<'a> {
        Framed { source: b"", content: line }
    }

    fn classify(&self, content: &[u8]) -> LineClass {
        if content.iter().all(|b| b.is_ascii_whitespace()) {
            LineClass::Separator
        } else {
            LineClass::Standalone(EntryKind::Plain)
        }
    }

    fn message_start(&self, _header: &[u8]) -> usize {
        0
    }
}
