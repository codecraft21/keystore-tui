//! Canonical paths in the form users type. On Windows, `fs::canonicalize`
//! returns verbatim paths such as `\\?\C:\certs`; the app shows these paths
//! in the file browser, the path bar, and the export prompt, so the verbatim
//! prefix is removed when the plain path means the same file.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// `fs::canonicalize`, without the Windows verbatim prefix where possible.
pub fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    if cfg!(windows)
        && let Some(plain) = canonical.to_str().and_then(without_verbatim_prefix)
    {
        return Ok(PathBuf::from(plain));
    }
    Ok(canonical)
}

/// `\\?\C:\dir` as `C:\dir` and `\\?\UNC\server\share` as `\\server\share`,
/// or `None` when the plain form would mean another file or be too long.
fn without_verbatim_prefix(path: &str) -> Option<String> {
    let rest = path.strip_prefix(r"\\?\")?;
    let (plain, components) = if let Some(unc) = rest.strip_prefix(r"UNC\") {
        (format!(r"\\{unc}"), unc)
    } else {
        let bytes = rest.as_bytes();
        if !(bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == br":\") {
            return None;
        }
        (rest.to_owned(), &rest[3..])
    };
    // Plain paths are limited to `MAX_PATH`, and Windows normalizes names
    // that end in a dot or a space or are reserved device names.
    let plain_means_the_same = plain.len() < 260
        && components
            .split('\\')
            .filter(|name| !name.is_empty())
            .all(|name| {
                !name.ends_with(['.', ' ']) && !name.contains('/') && !is_reserved_name(name)
            });
    plain_means_the_same.then_some(plain)
}

fn is_reserved_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    let stem = stem.to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|device| {
        stem.strip_prefix(device).is_some_and(|digit| {
            matches!(
                digit,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_drive_and_unc_paths_become_plain() {
        assert_eq!(
            without_verbatim_prefix(r"\\?\C:\Users\me\certs").as_deref(),
            Some(r"C:\Users\me\certs")
        );
        assert_eq!(without_verbatim_prefix(r"\\?\D:\").as_deref(), Some(r"D:\"));
        assert_eq!(
            without_verbatim_prefix(r"\\?\UNC\server\share\certs").as_deref(),
            Some(r"\\server\share\certs")
        );
    }

    #[test]
    fn paths_that_need_the_verbatim_prefix_keep_it() {
        for path in [
            r"C:\already\plain",
            r"\\?\Volume{0123}\certs",
            r"\\?\C:\trailing.\name",
            r"\\?\C:\trailing \name",
            r"\\?\C:\certs\nul",
            r"\\?\C:\certs\COM1.pem",
            r"\\?\C:\certs\a/b",
        ] {
            assert_eq!(without_verbatim_prefix(path), None, "{path}");
        }
        let long = format!(r"\\?\C:\{}", "a".repeat(300));
        assert_eq!(without_verbatim_prefix(&long), None);
    }

    #[test]
    fn canonicalize_resolves_parent_components() {
        let directory = crate::test_support::TestDirectory::new();
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).unwrap();
        assert_eq!(
            canonicalize(&nested.join("..").join("nested")).unwrap(),
            canonicalize(&nested).unwrap()
        );
    }
}
