//! Implementation of the core's `ProtocolAdapter` for the Connector's `XML` field.
//!
//! Parts model (original order, not reordered):
//! - `op` (Structure): the raw operation (`v`, `i`, `p`+name, `q`+key,
//!   `s`+key, `b`+scope, `c`, `l`, `k`+name);
//! - header: `sid`, `pid`, `model`, `page`, `event` (Value) and `empty`,
//!   `dummy`, `flag` (Structure), right after the `op` `v`/`i`;
//! - `p.<name>` (Value): value of a property, with the name resolved through the
//!   scopes and the dictionary; it comes right after its `op`;
//! - `s.<key>` (Name): the name defined by an `s` operation;
//! - `delta` (Delta).
//!
//! Length prefixes are never parts: `encode` recalculates them.

use scrapelens_core::adapter::{AdapterContext, AdapterPart, Decoded, PartRole, ProtocolAdapter};
use scrapelens_core::error::{CoreError, Result};

use crate::grammar::{self, Op};

pub const ADAPTER_ID: &str = "natural-ajax";

/// Names of the 8 header parts, in protocol order.
pub const HEAD_NAMES: [(&str, bool); 8] = [
    ("sid", true),
    ("pid", true),
    ("empty", false),
    ("model", true),
    ("dummy", false),
    ("page", true),
    ("event", true),
    ("flag", false),
];

#[derive(Debug, Default, Clone, Copy)]
pub struct NaturalAjax;

fn export_error(error: grammar::Error) -> CoreError {
    CoreError::Export {
        message: format!("Natural for Ajax protocol: {error}"),
    }
}

fn part(name: &str, value: &str, offset: usize, len: usize, role: PartRole) -> AdapterPart {
    AdapterPart {
        name: name.to_string(),
        value: value.to_string(),
        offset,
        len,
        role,
    }
}

impl ProtocolAdapter for NaturalAjax {
    fn id(&self) -> &str {
        ADAPTER_ID
    }

    fn detect(&self, field: &str, value: &str, _ctx: &AdapterContext<'_>) -> bool {
        // Cheap: header only; `decode` validates the rest (and the core falls back
        // to the no-adapter behaviour if it fails).
        field == "XML" && grammar::quick_check(value)
    }

    fn decode(&self, value: &str) -> Result<Decoded> {
        let items = grammar::parse(value).map_err(export_error)?;
        let mut parts: Vec<AdapterPart> = Vec::new();
        for item in &items {
            let raw_len = item.end - item.start;
            match &item.op {
                Op::Head { init, fields } => {
                    parts.push(part(
                        "op",
                        if *init { "i" } else { "v" },
                        0,
                        1,
                        PartRole::Structure,
                    ));
                    // Field offsets: rebuilt from the end.
                    let widths_total: usize = grammar::HEAD_WIDTHS.iter().sum();
                    let mut at = 1 + widths_total;
                    for ((name, is_value), field) in HEAD_NAMES.iter().zip(fields) {
                        let len = field.len();
                        parts.push(part(
                            name,
                            field,
                            at,
                            len,
                            if *is_value {
                                PartRole::Value
                            } else {
                                PartRole::Structure
                            },
                        ));
                        at += len;
                    }
                }
                Op::Lit { op, key, value: v } | Op::Ref { op, key, value: v } => {
                    parts.push(part(
                        "op",
                        &format!("{op}{key}"),
                        item.start,
                        raw_len,
                        PartRole::Structure,
                    ));
                    let path = item.path.as_deref().unwrap_or(key);
                    parts.push(part(
                        &format!("p.{path}"),
                        v,
                        item.value_start,
                        item.value_end - item.value_start,
                        PartRole::Value,
                    ));
                }
                Op::Dict { key, name } => {
                    parts.push(part(
                        "op",
                        &format!("s{key}"),
                        item.start,
                        raw_len,
                        PartRole::Structure,
                    ));
                    parts.push(part(
                        &format!("s.{key}"),
                        name,
                        item.value_start,
                        item.value_end - item.value_start,
                        PartRole::Name,
                    ));
                }
                Op::Begin(scope) => parts.push(part(
                    "op",
                    &format!("b{scope}"),
                    item.start,
                    raw_len,
                    PartRole::Structure,
                )),
                Op::End => parts.push(part("op", "c", item.start, raw_len, PartRole::Structure)),
                Op::Clear => parts.push(part("op", "l", item.start, raw_len, PartRole::Structure)),
                Op::Delete(name) => parts.push(part(
                    "op",
                    &format!("k{name}"),
                    item.start,
                    raw_len,
                    PartRole::Structure,
                )),
                Op::Delta(delta) => parts.push(part(
                    "delta",
                    delta,
                    item.value_start,
                    item.value_end - item.value_start,
                    PartRole::Delta,
                )),
            }
        }
        Ok(Decoded { parts })
    }

    /// Operation `i` (initialization) → "init"; in all other cases no label
    /// (the timeline uses the `event`).
    fn label_hint(&self, decoded: &Decoded) -> Option<String> {
        let op = decoded.parts.iter().find(|p| p.name == "op")?;
        (op.value == "i").then(|| "init".to_string())
    }

    fn encode(&self, decoded: &Decoded) -> Result<String> {
        let parts = &decoded.parts;
        let mut ops: Vec<Op> = Vec::new();
        let mut i = 0;
        let bad = |what: &str| CoreError::Export {
            message: format!("Natural for Ajax protocol: invalid structure ({what})"),
        };
        while i < parts.len() {
            let current = &parts[i];
            if current.role == PartRole::Delta {
                ops.push(Op::Delta(current.value.clone()));
                i += 1;
                continue;
            }
            if current.name != "op" || current.role != PartRole::Structure {
                return Err(bad("expected an operation"));
            }
            let mut chars = current.value.chars();
            let op = chars.next().ok_or_else(|| bad("empty operation"))?;
            let rest: String = chars.collect();
            match op {
                'i' | 'v' => {
                    let head = parts
                        .get(i + 1..i + 9)
                        .ok_or_else(|| bad("header too short"))?;
                    let mut fields: [String; 8] = Default::default();
                    for (field, p) in fields.iter_mut().zip(head) {
                        *field = p.value.clone();
                    }
                    ops.push(Op::Head {
                        init: op == 'i',
                        fields,
                    });
                    i += 9;
                }
                'p' | 'z' | 'q' | 'w' => {
                    let value = parts.get(i + 1).ok_or_else(|| bad("missing value"))?;
                    ops.push(if matches!(op, 'q' | 'w') {
                        Op::Ref {
                            op,
                            key: rest,
                            value: value.value.clone(),
                        }
                    } else {
                        Op::Lit {
                            op,
                            key: rest,
                            value: value.value.clone(),
                        }
                    });
                    i += 2;
                }
                's' => {
                    let name = parts.get(i + 1).ok_or_else(|| bad("missing name"))?;
                    ops.push(Op::Dict {
                        key: rest,
                        name: name.value.clone(),
                    });
                    i += 2;
                }
                'b' => {
                    ops.push(Op::Begin(rest));
                    i += 1;
                }
                'c' => {
                    ops.push(Op::End);
                    i += 1;
                }
                'l' => {
                    ops.push(Op::Clear);
                    i += 1;
                }
                'k' => {
                    ops.push(Op::Delete(rest));
                    i += 1;
                }
                other => return Err(bad(&format!("operation {other:?}"))),
            }
        }
        grammar::serialize(&ops).map_err(export_error)
    }
}
