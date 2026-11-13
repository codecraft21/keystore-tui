//! Signing with a private-key entry as a certificate authority: the menu
//! of what to sign, and signing a certificate request from a file into a
//! new certificate file.
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ratatui::crossterm::event::{KeyCode, KeyEvent};

use crate::{
    App, MAX_KEYSTORE_SIZE,
    certificate::{self, signature},
    certificate_file, certificate_form, certificate_request,
    export::{self, ExportPrompt, Scope},
    key_import,
    keystore::{Content, Kind},
    path_bar, read_limited, save,
    sign_form::{self, SignForm},
    signing,
};

/// A certificate request being signed with the private key at `signer` of
/// the app's entries.
pub struct Signing {
    signer: usize,
    /// The request's file name, and its DER.
    file: String,
    request: Vec<u8>,
    pub form: SignForm,
    /// What the form asked for, whether the file also holds the signer's
    /// chain, and the file name being typed, once the form is filled in.
    pub naming: Option<(signing::Terms, bool, ExportPrompt)>,
}

/// The single certificate request in the content `data` of the file named
/// `file`, once its own signature is verified.
fn verified_request(file: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut requests: Vec<_> = certificate_file::parse(data)
        .map(|parsed| parsed.entries)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| match entry.content {
            Content::Request(request) => Some(request),
            Content::Certificates { .. } => None,
        })
        .collect();
    let request = match requests.len() {
        1 => requests.remove(0),
        0 => return Err(format!("'{file}' holds no certificate request.")),
        count => {
            return Err(format!(
                "'{file}' holds {count} certificate requests; sign a file with a single request."
            ));
        }
    };
    // Only who holds the private key can have made the request.
    match signature::verify_request(&request) {
        signature::Signature::Verified => Ok(request),
        signature::Signature::Failed(reason) => Err(format!(
            "Not signed: the request in '{file}' does not verify with its own public key: {reason}."
        )),
        signature::Signature::Unchecked(reason) => Err(format!(
            "Not signed: the signature of the request in '{file}' was not checked ({reason})."
        )),
    }
}

/// The form titled `title` for signing the request `request`, showing its
/// subject, its public key, and the extensions it asks for. `None` for a
/// request that cannot be read.
fn request_form(title: String, request: &[u8]) -> Option<SignForm> {
    let parsed = certificate_request::Request::parse(request).ok()?;
    // The certificate gets the request's key as it is.
    let public = crown::x509::csr::CertificationRequest::parse(request)
        .ok()?
        .info()
        .subject_public_key_info
        .encode();
    let public_key = certificate::public_key(&public)
        .map(|(algorithm, size)| match size {
            Some(bits) => format!("{algorithm} {bits} bits"),
            None => algorithm,
        })
        .unwrap_or_default();
    Some(SignForm::new(
        title,
        certificate::subject_text(&parsed.subject.encode()),
        public_key,
        &parsed.extensions,
    ))
}

impl App {
    /// Asks what to sign with the selected private key.
    pub(crate) fn ask_sign(&mut self) {
        if !self.editable() {
            return;
        }
        let (Some(index), Some(document)) = (self.selected_entry(), &self.document) else {
            return;
        };
        let entry = &self.entries[index];
        let usable = if entry.kind() != Kind::PrivateKey.label() {
            Err("Only a private key can sign certificates.".into())
        } else {
            document
                .private_key(index)
                .map_err(|error| format!("Nothing signed: the key '{}' {error}.", entry.alias))
                .and_then(|_| {
                    let readable = entry
                        .certificates()
                        .first()
                        .is_some_and(|leaf| crown::x509::cert::Certificate::parse(leaf).is_ok());
                    if readable {
                        Ok(())
                    } else {
                        Err("Nothing signed: the key's certificate cannot be read.".into())
                    }
                })
        };
        match usable {
            Ok(()) => self.sign_menu = Some(index),
            Err(error) => self.message = Some((error, true)),
        }
    }

    /// Why what the private key at `index` signs may be rejected.
    pub(crate) fn sign_warning(&self, index: usize) -> Option<&'static str> {
        signing::ca_warning(self.entries[index].certificates().first()?)
    }

    /// `r` chooses a certificate request to sign, `g` fills in the form of a
    /// new key pair to sign, and `Esc` signs nothing.
    pub(crate) fn handle_sign_menu(&mut self, key: KeyEvent) {
        let Some(index) = self.sign_menu else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.sign_menu = None,
            KeyCode::Char('r') if crate::is_text_input(key.modifiers) => {
                self.sign_menu = None;
                self.open_picker();
                self.signing_request = self.file_picker.is_some().then_some(index);
            }
            KeyCode::Char('g') if crate::is_text_input(key.modifiers) => {
                self.sign_menu = None;
                let title = format!(
                    " Generate key pair signed by '{}' ",
                    self.entries[index].alias
                );
                self.generating = Some(certificate_form::Form::signed_by(title, index));
            }
            _ => {}
        }
    }

    /// Opens the form for signing the request in the file at `path` with
    /// the private key at `signer`.
    pub(crate) fn sign_request_file(&mut self, signer: usize, path: &Path) {
        let file = key_import::name(path);
        let form = read_limited(path, MAX_KEYSTORE_SIZE)
            .map_err(|error| format!("Cannot read {}: {error}", path.display()))
            .and_then(|data| verified_request(&file, &data))
            .and_then(|request| {
                let title = format!(" Sign request with '{}' ", self.entries[signer].alias);
                let unreadable = format!("Not signed: the request in '{file}' cannot be read.");
                let form = request_form(title, &request).ok_or(unreadable)?;
                Ok((request, form))
            });
        match form {
            Ok((request, form)) => {
                self.signing = Some(Signing {
                    signer,
                    file,
                    request,
                    form,
                    naming: None,
                });
            }
            Err(error) => self.message = Some((error, true)),
        }
    }

    /// Fills in the form, then types the certificate's file name and writes
    /// it.
    pub(crate) fn handle_signing(&mut self, key: KeyEvent) {
        let Some(signing) = &mut self.signing else {
            return;
        };
        let Some((_, _, prompt)) = &mut signing.naming else {
            match signing.form.handle_key(key) {
                sign_form::Outcome::Editing => {}
                sign_form::Outcome::Cancelled => self.signing = None,
                sign_form::Outcome::Submitted(terms, with_chain) => {
                    let directory = self
                        .keystore_path
                        .as_deref()
                        .map(path_bar::directory)
                        .unwrap_or_default();
                    // Named after the request's file, without its extension.
                    let stem = Path::new(&signing.file)
                        .file_stem()
                        .map(|stem| stem.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let prompt = ExportPrompt::new(Scope::Certificate, &directory, &stem);
                    signing.naming = Some((terms, with_chain, prompt));
                }
            }
            return;
        };
        match prompt.handle_key(key) {
            export::Outcome::Editing => {}
            // Back to the form, as it was filled in.
            export::Outcome::Cancelled => signing.naming = None,
            export::Outcome::Save(path) => {
                if let Some(signing) = self.signing.take() {
                    match self.write_signed(&signing, &path) {
                        Ok(message) => self.message = Some((message, false)),
                        Err(error) => {
                            self.message = Some((error, true));
                            self.signing = Some(signing);
                        }
                    }
                }
            }
        }
    }

    /// Signs the request and writes its certificate to the new file `path`,
    /// followed by the signer's chain when that was asked for.
    fn write_signed(&self, signing: &Signing, path: &Path) -> Result<String, String> {
        let (Some(document), Some((terms, with_chain, _))) = (&self.document, &signing.naming)
        else {
            return Err("No keystore is open.".into());
        };
        let entry = &self.entries[signing.signer];
        let alias = &entry.alias;
        let key = document
            .private_key(signing.signer)
            .map_err(|error| format!("Nothing signed: the key '{alias}' {error}."))?;
        let issuer = signing::Issuer {
            key: &key,
            certificate: entry
                .certificates()
                .first()
                .ok_or("The signing key has no certificate.")?,
        };
        save::OsRng::default().check()?;
        let mut rng = save::OsRng::default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as i64);
        let certificate =
            signing::request_certificate(&signing.request, terms.clone(), &issuer, now, &mut rng)?;
        rng.check()?;
        let mut items = vec![certificate];
        if *with_chain {
            items.extend_from_slice(entry.certificates());
        }
        export::save(path, &items, Scope::Certificate.pem_label())?;
        Ok(format!(
            "Signed the request in '{}' with '{alias}' and saved the certificate to '{}'.",
            signing.file,
            path.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{KEYTOOL_REQUEST, ed25519_certificate, ed25519_request};

    #[test]
    fn a_form_needs_a_request_that_can_be_read() {
        assert!(request_form(" Sign ".into(), &ed25519_request("device", &[])).is_some());
        assert!(request_form(" Sign ".into(), KEYTOOL_REQUEST).is_none());
        let fixture = crown::asn1::pem::parse(std::str::from_utf8(KEYTOOL_REQUEST).unwrap());
        assert!(request_form(" Sign ".into(), &fixture.unwrap()[0].data).is_some());
        assert!(request_form(" Sign ".into(), b"junk").is_none());
    }

    #[test]
    fn only_a_single_verified_request_is_signed() {
        let request = ed25519_request("device", &[]);
        let pem = |der: &[u8]| crown::asn1::pem::encode("CERTIFICATE REQUEST", der);
        assert_eq!(
            verified_request("a.csr", pem(&request).as_bytes()),
            Ok(request.clone())
        );
        assert!(verified_request("a.csr", KEYTOOL_REQUEST).is_ok());

        let none = ed25519_certificate("leaf", "leaf", 3, 3);
        for data in [&none[..], b"junk"] {
            assert_eq!(
                verified_request("a.csr", data),
                Err("'a.csr' holds no certificate request.".into())
            );
        }
        let two = [pem(&request), pem(&request)].concat();
        assert!(
            verified_request("a.csr", two.as_bytes())
                .unwrap_err()
                .contains("holds 2 certificate requests")
        );

        // A request changed after it was signed, and one whose signature
        // algorithm is not known.
        let mut altered = request.clone();
        let at = altered.windows(6).position(|w| w == b"device").unwrap();
        altered[at] = b'D';
        assert!(
            verified_request("a.csr", &altered)
                .unwrap_err()
                .contains("does not verify with its own public key: the signature does not match.")
        );
        let mut unknown = request;
        let last = unknown
            .windows(3)
            .rposition(|w| w == [0x2b, 0x65, 0x70])
            .unwrap();
        unknown[last + 2] = 0x7f;
        assert!(
            verified_request("a.csr", &unknown)
                .unwrap_err()
                .contains("was not checked (")
        );
    }
}
