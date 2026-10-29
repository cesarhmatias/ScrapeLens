//! Adaptador Natural for Ajax do ScrapeLens.
//!
//! [`grammar`] não depende do core; [`NaturalAjax`] implementa o
//! `ProtocolAdapter`; [`PYTHON_ENCODER`] é o codificador Python equivalente ao
//! `encode`, que o script de priming inclui.

pub mod adapter;
pub mod grammar;
pub mod python;

pub use adapter::{NaturalAjax, ADAPTER_ID};
pub use python::{PYTHON_DECODER, PYTHON_ENCODER, PYTHON_FUNCTION};
