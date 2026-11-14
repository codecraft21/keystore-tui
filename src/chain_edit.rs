//! Editing a private key's certificate chain by hand: appending an issuer
//! from a file, or removing the last certificate. The key's own
//! certificate stays.
use std::path::Path;

use crown::x509::cert::Certificate;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

use crate::{
    App, MAX_KEYSTORE_SIZE,
    certificate::signature::{self, Signature},
    certificate_file, editing,
    keystore::Kind,
    read_limited,
};

/// The name a certificate is called by in messages.
fn name(certificate: &[u8]) -> String {
    certificate_file::subject_name(certificate).unwrap_or_else(|| "a certificate".into())
}

/// `chain` with `issuer` after its last certificate, if `issuer` is named
/// as that certificate's issuer and its signature does not fail under it.
pub fn appended(chain: &[Vec<u8>], issuer: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let last = chain.last().ok_or("The chain is empty.")?;
    if chain.iter().any(|held| held == issuer) {
        return Err(format!("'{}' is already in the chain.", name(issuer)));
    }
    let names = |der: &[u8]| Certificate::parse(der).ok();
    let linked = names(last)
        .zip(names(issuer))
        .is_some_and(|(last, issuer)| last.issuer() == issuer.subject());
    if !linked || matches!(signature::verify(last, issuer), Signature::Failed(_)) {
        return Err(format!(
            "'{}' did not issue '{}', the last certificate of the chain.",
            name(issuer),
            name(last)
        ));
    }
    Ok(chain.iter().cloned().chain([issuer.to_vec()]).collect())
}

impl App {
    /// Asks what to do with the selected private key's chain.
    pub(crate) fn ask_chain(&mut self) {
        if !self.changeable() {
            return;
        }
        let Some(index) = self.selected_entry() else {
            return;
        };
        if self.entries[index].kind() == Kind::PrivateKey.label() {
            self.chain_menu = Some(index);
        } else {
            self.message = Some((
                "Only a private key has a certificate chain to edit.".into(),
                true,
            ));
        }
    }

    /// `a` chooses a certificate to append, `x` removes the last one, and
    /// `Esc` leaves the chain as it is.
    pub(crate) fn handle_chain(&mut self, key: KeyEvent) {
        let Some(index) = self.chain_menu else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.chain_menu = None,
            KeyCode::Char('a') if crate::is_text_input(key.modifiers) => {
                self.chain_menu = None;
                self.open_picker();
                self.appending = self.file_picker.is_some().then_some(index);
            }
            KeyCode::Char('x') if crate::is_text_input(key.modifiers) => {
                self.chain_menu = None;
                let chain = self.entries[index].certificates();
                let result = match chain.split_last() {
                    Some((last, rest)) if !rest.is_empty() => {
                        let message = format!(
                            "Removed '{}' from the chain of '{}'.",
                            name(last),
                            self.entries[index].alias
                        );
                        let rest = rest.to_vec();
                        self.set_chain(index, &rest).map(|()| message)
                    }
                    _ => Err("The chain holds only the key's own certificate, which stays.".into()),
                };
                self.report(result);
            }
            _ => {}
        }
    }

    /// Appends the single certificate in the file at `path` to the chain of
    /// the private key at `index`.
    pub(crate) fn append_to_chain(&mut self, index: usize, path: &Path) {
        let result = read_limited(path, MAX_KEYSTORE_SIZE)
            .map_err(|error| format!("Cannot read {}: {error}", path.display()))
            .and_then(|data| editing::read_certificate(path, &data))
            .and_then(|issuer| {
                let chain = appended(self.entries[index].certificates(), &issuer)?;
                let message = format!(
                    "Appended '{}' to the chain of '{}'.",
                    name(&issuer),
                    self.entries[index].alias
                );
                self.set_chain(index, &chain).map(|()| message)
            });
        self.report(result);
    }

    /// Gives the private key at `index` the chain `chain` and selects it.
    fn set_chain(&mut self, index: usize, chain: &[Vec<u8>]) -> Result<(), String> {
        let document = self.document.as_mut().ok_or("No keystore is open.")?;
        let to = document.replace_chain(&mut self.entries, index, chain)?;
        self.modified = true;
        self.select_changed(to);
        Ok(())
    }

    /// Shows what an edit did, in green, or why it did nothing, in red.
    fn report(&mut self, result: Result<String, String>) {
        self.message = Some(match result {
            Ok(message) => (message, false),
            Err(error) => (error, true),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ed25519_certificate;

    #[test]
    fn only_the_issuer_of_the_last_certificate_is_appended() {
        let leaf = ed25519_certificate("leaf", "ca", 7, 9);
        let ca = ed25519_certificate("ca", "ca", 9, 9);
        let chain = vec![leaf.clone()];
        assert_eq!(appended(&chain, &ca), Ok(vec![leaf.clone(), ca.clone()]));
        // Another certificate, one with the issuer's name but another key,
        // and one that is not a certificate.
        let other = ed25519_certificate("other", "other", 5, 5);
        let impostor = ed25519_certificate("ca", "ca", 5, 5);
        for wrong in [other, impostor, vec![0x30, 0]] {
            let error = appended(&chain, &wrong).unwrap_err();
            assert!(error.contains("did not issue 'leaf'"), "{error}");
        }
        // A certificate is in a chain once, and a chain has a certificate.
        let full = vec![leaf, ca.clone()];
        assert_eq!(
            appended(&full, &ca),
            Err("'ca' is already in the chain.".into())
        );
        assert_eq!(appended(&[], &ca), Err("The chain is empty.".into()));
    }
}
