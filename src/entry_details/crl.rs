//! A certificate revocation list in the detail view, shown in place of a
//! hierarchy.
use ratatui::{text::Text, widgets::Row};

use super::{extensions_text, fingerprint_text, hierarchy_row, section_text};
use crate::{
    certificate::{details::time_text, extensions},
    revocation_list::List,
};

/// A revocation list, decoded once.
pub(super) struct CrlView {
    pub(super) der: Vec<u8>,
    /// `None` when the list cannot be decoded.
    list: Option<List>,
}

impl CrlView {
    pub(super) fn new(der: &[u8]) -> Self {
        Self {
            der: der.to_vec(),
            list: List::parse(der).ok(),
        }
    }

    /// The list's only hierarchy row. Its signature is not checked.
    pub(super) fn hierarchy_row(&self) -> Row<'static> {
        let label = self
            .list
            .as_ref()
            .map(|list| list.issuer.to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Revocation list (unreadable or unnamed)".into());
        hierarchy_row(label, false, None)
    }

    /// The detail text after the alias and type.
    pub(super) fn text(&self, mut text: String, sha1: bool) -> Text<'static> {
        let Some(list) = &self.list else {
            text.push_str("Revocation list could not be decoded.\n\n");
            text.push_str(&fingerprint_text(&self.der, sha1));
            return Text::from(text);
        };
        text.push_str(&format!(
            "Version: {}\n\nIssuer: {}\n\nThis Update: {}\n\nNext Update: {}\n\nSignature Algorithm: {}\nSignature: not checked (the issuer's certificate is not part of a revocation list).\n\n",
            list.version,
            list.issuer,
            time_text(&list.this_update),
            list.next_update
                .as_ref()
                .map_or_else(|| "None".into(), time_text),
            list.signature_algorithm,
        ));
        text.push_str(&fingerprint_text(&self.der, sha1));
        text.push_str(&extensions_text("Extensions", &list.extensions));
        let revoked: Vec<_> = list
            .revoked
            .iter()
            .map(|entry| {
                let mut lines = vec![format!("Revoked: {}", time_text(&entry.date))];
                lines.extend(entry.extensions.iter().map(|extension| {
                    let name = extension
                        .oid
                        .as_ref()
                        .and_then(extensions::name)
                        .map_or_else(|| extension.title(), Into::into);
                    format!("{name}: {}", extension.lines.join(", "))
                }));
                (format!("Serial Number: {}", entry.serial), lines)
            })
            .collect();
        text.push_str(&section_text(
            &format!("Revoked certificates ({})", revoked.len()),
            &revoked,
        ));
        text.push_str(
            "Whether the list is current, and whether its issuer is trusted, is not checked.",
        );
        Text::from(text)
    }
}
