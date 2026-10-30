//! The opened file's path, shown below the entry table and the detail view.

use std::path::Path;

use ratatui::{style::Stylize, text::Line};

/// The status bar's `Path: '<path>'`, with the path itself in blue.
pub fn line(path: &Path) -> Line<'static> {
    Line::from(vec![
        "Path: '".into(),
        path.display().to_string().blue(),
        "'".into(),
    ])
}
