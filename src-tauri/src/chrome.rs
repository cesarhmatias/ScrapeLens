//! Detection and manual selection of an external Chrome. The implementation lives in
//! the `scrapelens-capture` crate (no Tauri); this module only re-exports it for the App.

pub use scrapelens_capture::chrome::*;
