//! The opened file's path, shown below the entry table and the detail view,
//! and the directory it is in.

use std::path::{self, Path, PathBuf};

use ratatui::{style::Stylize, text::Line};

/// The status bar's `Path: '<path>'`, with the path itself in blue.
pub fn line(path: &Path) -> Line<'static> {
    Line::from(vec![
        "Path: '".into(),
        path.display().to_string().blue(),
        "'".into(),
    ])
}

/// The absolute directory of the opened file `path`. A bare file name, whose
/// parent is empty, is in the working directory. If the working directory
/// cannot be read, the directory is returned as it is, relative.
pub fn directory(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    path::absolute(parent).unwrap_or_else(|_| parent.to_path_buf())
}
