//! Importing a certificate authority's reply: the issued chain replaces the
//! certificate chain of the private key it was issued for.
use std::path::Path;

use zeroize::Zeroizing;

use crate::{
    App, MAX_KEYSTORE_SIZE, certificate::details, key_import, keystore::Kind, read_limited,
};

/// The chain a reply gives the PKCS #8 private key `key`: the certificate
/// among the reply's `chains` that holds the key's public key, then its
/// issuers. Where the reply stops short of a self-issued certificate, the
/// chain goes on with the certificates in `held`. `None` when no
/// certificate of the reply holds the key.
pub fn issued_chain(
    key: &[u8],
    chains: &[Vec<Vec<u8>>],
    held: &[&[u8]],
) -> Result<Option<Vec<Vec<u8>>>, &'static str> {
    let Some(leaf) =
        key_import::matching_chain(key, chains)?.and_then(|chain| chain.into_iter().next())
    else {
        return Ok(None);
    };
    // The reply's own certificates come first; the keystore's only continue
    // from where they end.
    let reply: Vec<&[u8]> = chains.iter().flatten().map(Vec::as_slice).collect();
    let (mut chain, _) = details::chain(&leaf, &reply);
    if let Some(last) = chain.pop() {
        let (rest, _) = details::chain(&last, held);
        chain.extend(rest);
    }
    Ok(Some(chain))
}

impl App {
    /// Opens the file browser to choose the reply for the selected private
    /// key.
    pub(crate) fn ask_reply(&mut self) {
        if !self.changeable() {
            return;
        }
        let (Some(index), Some(document)) = (self.selected_entry(), &self.document) else {
            return;
        };
        let entry = &self.entries[index];
        let readable = if entry.kind() == Kind::PrivateKey.label() {
            document
                .private_key(index)
                .map(drop)
                .map_err(|error| format!("No reply imported: the key '{}' {error}.", entry.alias))
        } else {
            Err("Only a private key takes a CA reply; import other certificates with i.".into())
        };
        match readable {
            Ok(()) => {
                self.open_picker();
                self.reply = self.file_picker.is_some().then_some(index);
            }
            Err(error) => self.message = Some((error, true)),
        }
    }

    /// Replaces the chain of the private key at `index` with the one the
    /// reply file at `path` holds for it.
    pub(crate) fn import_reply(&mut self, index: usize, path: &Path) {
        let result = self.replace_with_reply(index, path);
        self.message = Some(match result {
            Ok(message) => (message, false),
            Err(error) => (error, true),
        });
    }

    fn replace_with_reply(&mut self, index: usize, path: &Path) -> Result<String, String> {
        let data = read_limited(path, MAX_KEYSTORE_SIZE)
            .map(Zeroizing::new)
            .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
        let file = key_import::name(path);
        let chains = key_import::chains(&data);
        if chains.is_empty() {
            return Err(format!("'{file}' holds no certificate."));
        }
        let document = self.document.as_mut().ok_or("No keystore is open.")?;
        let alias = self.entries[index].alias.clone();
        let failed = |error: &str| format!("No reply imported: {error}.");
        let key = document
            .private_key(index)
            .map_err(|error| failed(&format!("the key '{alias}' {error}")))?;
        let held: Vec<&[u8]> = self
            .entries
            .iter()
            .flat_map(|entry| entry.certificates())
            .map(Vec::as_slice)
            .collect();
        let chain = issued_chain(&key, &chains, &held)
            .map_err(failed)?
            .ok_or_else(|| {
                failed(&format!(
                    "no certificate in '{file}' holds the public key of '{alias}'"
                ))
            })?;
        if self.entries[index].certificates() == chain {
            return Ok(format!(
                "'{alias}' already has the chain in '{file}'; nothing changed."
            ));
        }
        let to = document.replace_chain(&mut self.entries, index, &chain)?;
        self.modified = true;
        self.select_changed(to);
        Ok(format!(
            "Replaced the certificate chain of '{alias}' with the {} from '{file}'.",
            match chain.len() {
                1 => "certificate".into(),
                count => format!("{count} certificates"),
            }
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ed25519_certificate, ed25519_pkcs8, synthetic_pkcs8};

    #[test]
    fn the_issued_chain_continues_with_held_certificates_where_the_reply_ends() {
        let key = ed25519_pkcs8(7);
        let leaf = ed25519_certificate("leaf", "issuing", 7, 8);
        let issuing = ed25519_certificate("issuing", "root", 8, 9);
        let root = ed25519_certificate("root", "root", 9, 9);
        let other = ed25519_certificate("other", "other", 5, 5);
        let issued = |chains: &[Vec<Vec<u8>>], held: &[&[u8]]| issued_chain(&key, chains, held);

        // A complete reply, whatever order its certificates come in.
        let whole = [
            vec![root.clone()],
            vec![leaf.clone(), issuing.clone(), root.clone()],
        ];
        let chain = vec![leaf.clone(), issuing.clone(), root.clone()];
        assert_eq!(issued(&whole, &[]), Ok(Some(chain.clone())));
        // A reply that stops short goes on with what the keystore holds.
        let short = [vec![leaf.clone(), issuing.clone()]];
        assert_eq!(issued(&short, &[&other, &root]), Ok(Some(chain.clone())));
        let bare = [vec![leaf.clone()]];
        assert_eq!(issued(&bare, &[&root, &issuing]), Ok(Some(chain)));
        assert_eq!(issued(&bare, &[&root]), Ok(Some(vec![leaf.clone()])));
        assert_eq!(issued(&bare, &[]), Ok(Some(vec![leaf])));
        // A reply for another key, and a key that cannot be matched.
        assert_eq!(issued(&[vec![other.clone()]], &[&root]), Ok(None));
        assert!(issued_chain(&synthetic_pkcs8(&[1]), &[vec![other]], &[]).is_err());
    }
}
