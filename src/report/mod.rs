//! Render a [`ScanResult`] as text, JSON, SARIF 2.1.0 or Markdown.

use crate::model::ScanResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Sarif,
    Markdown,
}

/// `color` only affects `Text` (ANSI colours for a terminal).
pub fn render(_result: &ScanResult, _format: Format, _color: bool) -> String {
    String::new()
}
