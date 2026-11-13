//! Making a certificate request for a private-key entry: the form it
//! starts from, the name of the new file, and writing the signed request.
use std::path::Path;

use crown::x509::cert::Certificate;
use ratatui::crossterm::event::KeyEvent;

use crate::{
    App,
    certificate_form::{self, Form},
    export::{self, ExportPrompt, Scope},
    keystore::Kind,
    path_bar, save, signing,
};

/// A certificate request being made for the private key at `index` of the
/// app's entries.
pub struct NewRequest {
    index: usize,
    pub form: Form,
    /// What the form asked for and the file name being typed, once the form
    /// is filled in.
    pub naming: Option<(signing::Request, ExportPrompt)>,
}

impl App {
    /// Opens the form for a request signed with the selected private key,
    /// starting from its certificate's subject and alternative names.
    pub(crate) fn ask_request(&mut self) {
        if !self.editable() {
            return;
        }
        let (Some(index), Some(document)) = (self.selected_entry(), &self.document) else {
            return;
        };
        let entry = &self.entries[index];
        let form = if entry.kind() != Kind::PrivateKey.label() {
            Err("Only a private key can sign a certificate request.".into())
        } else {
            document
                .private_key(index)
                .map_err(|error| format!("No request made: the key '{}' {error}.", entry.alias))
                .and_then(|_| {
                    let certificate = entry
                        .certificates()
                        .first()
                        .and_then(|leaf| Certificate::parse(leaf).ok())
                        .ok_or("No request made: the key's certificate cannot be read.")?;
                    Ok(Form::for_request(
                        format!(" Certificate request for '{}' ", entry.alias),
                        certificate.subject(),
                        &certificate.tbs().subject_alt_names().unwrap_or_default(),
                    ))
                })
        };
        match form {
            Ok(form) => {
                self.requesting = Some(NewRequest {
                    index,
                    form,
                    naming: None,
                });
            }
            Err(error) => self.message = Some((error, true)),
        }
    }

    /// Fills in the form, then types the request's file name and writes it.
    pub(crate) fn handle_request(&mut self, key: KeyEvent) {
        let Some(request) = &mut self.requesting else {
            return;
        };
        let Some((_, prompt)) = &mut request.naming else {
            match request.form.handle_key(key) {
                certificate_form::Outcome::Editing => {}
                certificate_form::Outcome::Cancelled => self.requesting = None,
                certificate_form::Outcome::Submitted(_, asked) => {
                    let directory = self
                        .keystore_path
                        .as_deref()
                        .map(path_bar::directory)
                        .unwrap_or_default();
                    let alias = &self.entries[request.index].alias;
                    let prompt = ExportPrompt::new(Scope::Request, &directory, alias);
                    request.naming = Some((asked, prompt));
                }
            }
            return;
        };
        match prompt.handle_key(key) {
            export::Outcome::Editing => {}
            // Back to the form, as it was filled in.
            export::Outcome::Cancelled => request.naming = None,
            export::Outcome::Save(path) => {
                let index = request.index;
                match self.write_request(index, asked_request(&self.requesting), &path) {
                    Ok(message) => {
                        self.requesting = None;
                        self.message = Some((message, false));
                    }
                    Err(error) => self.message = Some((error, true)),
                }
            }
        }
    }

    /// Signs the request with the private key at `index` and writes it to
    /// the new file `path`: DER for a `.der` name, PEM otherwise.
    fn write_request(
        &self,
        index: usize,
        asked: Option<&signing::Request>,
        path: &Path,
    ) -> Result<String, String> {
        let (Some(document), Some(asked)) = (&self.document, asked) else {
            return Err("No keystore is open.".into());
        };
        let alias = &self.entries[index].alias;
        let key = document
            .private_key(index)
            .map_err(|error| format!("No request made: the key '{alias}' {error}."))?;
        save::OsRng::default().check()?;
        let mut rng = save::OsRng::default();
        let request = signing::request(&key, asked, &mut rng)?;
        rng.check()?;
        export::save(path, &[request], Scope::Request.pem_label())?;
        Ok(format!(
            "Saved a certificate request for '{alias}' to '{}'.",
            path.display()
        ))
    }
}

/// What the filled-in form of the request being made asked for.
fn asked_request(requesting: &Option<NewRequest>) -> Option<&signing::Request> {
    let (asked, _) = requesting.as_ref()?.naming.as_ref()?;
    Some(asked)
}
