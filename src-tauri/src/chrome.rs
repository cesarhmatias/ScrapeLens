//! Detecção e seleção manual do Chrome externo. A implementação vive na crate
//! `scrapelens-capture` (sem Tauri); este módulo só a reexporta para o App.

pub use scrapelens_capture::chrome::*;
