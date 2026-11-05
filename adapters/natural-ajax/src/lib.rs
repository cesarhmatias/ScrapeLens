//! Natural for Ajax adapter of ScrapeLens.
//!
//! [`grammar`] does not depend on the core; [`NaturalAjax`] implements the
//! `ProtocolAdapter`; [`PYTHON_ENCODER`] is the Python encoder equivalent to the
//! `encode`, which the priming script includes.

pub mod adapter;
pub mod extract;
pub mod grammar;
pub mod python;

pub use adapter::{NaturalAjax, ADAPTER_ID};
pub use python::{PYTHON_DECODER, PYTHON_ENCODER, PYTHON_FUNCTION};
