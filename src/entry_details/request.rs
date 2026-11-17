//! A certificate request in the detail view, shown in place of a hierarchy.
use std::fmt::Write as _;

use ratatui::{text::Text, widgets::Row};

use super::{
    hierarchy_row, public_key_text, signature_line, weakness_lines, write_extensions, write_section,
};
use crate::{
    certificate::{
        Summary,
        signature::{self, Signature},
    },
    certificate_request::Request,
};

/// A certificate request, decoded and with its signature checked once.
pub(super) struct RequestView {
    pub(super) der: Vec<u8>,
    /// `None` when the request cannot be decoded.
    request: Option<Request>,
    /// Checked with the request's own key. Only a request whose details can be
    /// shown is checked, so the hierarchy tag and the details always agree.
    signature: Signature,
    /// The entry's summary of the request's subject and key.
    summary: Option<Summary>,
}

impl RequestView {
    pub(super) fn new(der: &[u8], summary: Option<Summary>) -> Self {
        let (request, signature) = match Request::parse(der) {
            Ok(request) => (Some(request), signature::verify_request(der)),
            Err(_) => (
                None,
                Signature::Unchecked("the request could not be decoded"),
            ),
        };
        Self {
            der: der.to_vec(),
            request,
            signature,
            summary,
        }
    }

    /// The request's only hierarchy row.
    pub(super) fn hierarchy_row(&self) -> Row<'static> {
        let label = self
            .request
            .as_ref()
            .map(|request| request.subject.to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Certificate request (unreadable or unnamed)".into());
        let weak = self
            .summary
            .as_ref()
            .is_some_and(|summary| !summary.weaknesses.is_empty());
        hierarchy_row(label, weak, Some(self.signature))
    }

    /// The detail text after the alias and type.
    pub(super) fn text(&self, mut text: String, fingerprint: &str) -> Text<'static> {
        let summary = self.summary.as_ref();
        let mut lines = Vec::new();
        if let Some(request) = &self.request {
            write!(
                text,
                "Version: {}\n\nSubject: {}\n\nPublic Key: {}\n\nSignature Algorithm: {}\n",
                request.version,
                request.subject,
                public_key_text(summary),
                request.signature_algorithm,
            )
            .unwrap();
            lines.extend(Text::from(text).lines);
            lines.extend(weakness_lines(summary));
            lines.push(signature_line(self.signature, "its own public key"));
            text = "\n".into();
        } else {
            text.push_str("Certificate request could not be decoded.\n\n");
        }
        text.push_str(fingerprint);
        if let Some(request) = &self.request {
            write_extensions(&mut text, "Requested extensions", &request.extensions);
            if !request.attributes.is_empty() {
                write_section(
                    &mut text,
                    "Attributes",
                    request
                        .attributes
                        .iter()
                        .map(|(title, lines)| (title, lines)),
                );
            }
        }
        text.push_str(
            "A request is not a certificate: it has no issuer or validity, and nothing in it is trusted.",
        );
        lines.extend(Text::from(text).lines);
        Text::from(lines)
    }
}
