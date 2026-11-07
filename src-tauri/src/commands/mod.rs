//! Commands for the UI ↔ shell bridge. Contract v1: docs/03-contracts.md.
//!
//! Integration note: `start_session`, `import_har` and `import_netlog` call
//! `scrapelens-core` (a crate dependency, no sidecar) and operate on real data. The
//! capture opens the external Chrome in `capture.rs`; the `SessionPayload` envelope
//! stays stable for the UI.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use scrapelens_core::{store, ImportedSession};

use crate::capture::{self, CaptureConfig, CaptureSession, CaptureStatus};
use crate::chrome::{self, ChromeInfo};
use crate::cli;
#[cfg(feature = "test-hooks")]
use crate::cli_test::CliAction;
use crate::grants;
use crate::prefs;
use crate::AppState;

mod app;
mod browser;
mod compare;
mod dialog;
mod export;
mod live;
mod session;
mod validate;
#[cfg(test)]
mod tests;

pub(crate) use app::*;
pub(crate) use browser::*;
pub(crate) use compare::*;
pub(crate) use dialog::*;
pub(crate) use export::*;
pub(crate) use live::*;
pub(crate) use session::*;
pub(crate) use validate::*;
