//! Grammar of the `XML` field of the Connector Natural for Ajax, without
//! depending on the core. Lengths in UTF-16 units (JS `String.length`); parsing
//! is linear and any invalid input becomes an [`Error`], never a panic.
//!
//! Request: `i`/`v` + fixed widths (2,2,2,2,2,3,5,1) + 8 fields, then
//! operations `p` (name 2, value 5) and `x` (delta 2). Response: `l`, `s`, `p`,
//! `q`, `z`, `w`, `b`, `c`, `k`, `x`.

use std::fmt;

/// Widths of the 8 fields of the request header.
pub const HEAD_WIDTHS: [usize; 8] = [2, 2, 2, 2, 2, 3, 5, 1];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    InvalidLength,
    UnknownOp(char),
    UnbalancedScope,
    /// Cut in the middle of a UTF-16 surrogate pair.
    SplitSurrogate,
    /// Value larger than the prefix width can hold.
    TooLong {
        what: &'static str,
        max: usize,
    },
    /// Operation out of place (header not at the start).
    Misplaced(char),
    /// Scopes nested too deeply, path too long or dictionary too large.
    Limit(&'static str),
}

/// Maximum scope depth.
pub const MAX_DEPTH: usize = 32;
/// Maximum distinct keys in the dictionary (`s`).
pub const MAX_KEYS: usize = 10_000;
/// Maximum length (in `char`) of a property's scope path.
pub const MAX_PATH: usize = 512;
/// Maximum size of the claimed/decoded text (bytes).
pub const MAX_INPUT: usize = 8 * 1024 * 1024;
/// Maximum operations per field.
pub const MAX_OPS: usize = 200_000;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "message truncated"),
            Error::InvalidLength => write!(f, "invalid length"),
            Error::UnknownOp(c) => write!(f, "unsupported opcode: {c:?}"),
            Error::UnbalancedScope => write!(f, "invalid scope"),
            Error::SplitSurrogate => write!(f, "length cuts a UTF-16 surrogate pair"),
            Error::TooLong { what, max } => {
                write!(f, "{what} exceeds the maximum of {max} UTF-16 units")
            }
            Error::Misplaced(c) => write!(f, "operation out of place: {c:?}"),
            Error::Limit(what) => write!(f, "limit exceeded: {what}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// `i`/`v` + 8 fields (sid, pid, empty, model, dummy, page, event, flag).
    Head {
        init: bool,
        fields: [String; 8],
    },
    /// `p` (value 5) / `z` (value 10): literal name.
    Lit {
        op: char,
        key: String,
        value: String,
    },
    /// `q` (value 5) / `w` (value 10): name by reference to the `s` dictionary.
    Ref {
        op: char,
        key: String,
        value: String,
    },
    /// `s`: defines `key` → `name`.
    Dict {
        key: String,
        name: String,
    },
    Begin(String),
    End,
    Clear,
    Delete(String),
    Delta(String),
}

/// Operation with its positions (UTF-8 bytes in the original text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub op: Op,
    pub start: usize,
    pub end: usize,
    /// Position of the value (or of the delta / scope name) in the original.
    pub value_start: usize,
    pub value_end: usize,
    /// Full resolved name (scopes + key) for `Lit`/`Ref`.
    pub path: Option<String>,
}

/// Text in UTF-16 units with the unit → byte map of the original.
struct Units {
    units: Vec<u16>,
    /// `byte[i]` = byte of the original where unit `i` starts;
    /// `u32::MAX` marks the second half of a surrogate pair.
    byte: Vec<u32>,
}

impl Units {
    fn new(text: &str) -> Self {
        let mut units = Vec::with_capacity(text.len());
        let mut byte = Vec::with_capacity(text.len() + 1);
        let mut buf = [0u16; 2];
        for (at, c) in text.char_indices() {
            let encoded = c.encode_utf16(&mut buf);
            for (i, u) in encoded.iter().enumerate() {
                units.push(*u);
                byte.push(if i == 0 { at as u32 } else { u32::MAX });
            }
        }
        byte.push(text.len() as u32);
        Units { units, byte }
    }
}

struct Cursor<'a> {
    u: &'a Units,
    pos: usize,
}

impl Cursor<'_> {
    fn byte_at(&self, unit: usize) -> usize {
        match self.u.byte[unit] {
            u32::MAX => usize::MAX,
            b => b as usize,
        }
    }

    /// Consumes `n` units; returns the text and the bytes (start, end).
    fn take(&mut self, n: usize) -> Result<(String, usize, usize), Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.u.units.len() {
            return Err(Error::Truncated);
        }
        let (b0, b1) = (self.byte_at(self.pos), self.byte_at(end));
        if b0 == usize::MAX || b1 == usize::MAX {
            return Err(Error::SplitSurrogate);
        }
        let text =
            String::from_utf16(&self.u.units[self.pos..end]).map_err(|_| Error::SplitSurrogate)?;
        self.pos = end;
        Ok((text, b0, b1))
    }

    fn number(&mut self, width: usize) -> Result<usize, Error> {
        let (text, _, _) = self.take(width)?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidLength);
        }
        text.parse().map_err(|_| Error::InvalidLength)
    }
}

/// Length in UTF-16 units (`jslen`).
pub fn jslen(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Cheap check for `detect`: only the first operation's header,
/// without walking the message.
pub fn quick_check(text: &str) -> bool {
    let b = text.as_bytes();
    if b.is_empty() || b.len() > MAX_INPUT {
        return false;
    }
    let digits = |from: usize, n: usize| {
        b.len() >= from + n && b[from..from + n].iter().all(u8::is_ascii_digit)
    };
    match b[0] {
        b'i' | b'v' => digits(1, HEAD_WIDTHS.iter().sum()),
        b'l' | b'c' => true,
        b's' => digits(1, 3),
        b'p' | b'q' => digits(1, 7),
        b'z' | b'w' => digits(1, 12),
        b'b' | b'k' | b'x' => digits(1, 2),
        _ => false,
    }
}

/// Decodes the message into operations. Cost is linear in the text length.
pub fn parse(text: &str) -> Result<Vec<Item>, Error> {
    let units = Units::new(text);
    let mut cur = Cursor { u: &units, pos: 0 };
    let mut out: Vec<Item> = Vec::new();
    if text.len() > MAX_INPUT {
        return Err(Error::Limit("message too large"));
    }
    // Scope stack: `prefix` holds "a.b." and `marks` the length before
    // each scope, so a property's path costs O(|path|).
    let mut prefix = String::new();
    let mut marks: Vec<usize> = Vec::new();
    let mut names: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    if let Some(&first) = units.units.first() {
        if first == u16::from(b'i') || first == u16::from(b'v') {
            let init = first == u16::from(b'i');
            cur.pos = 1;
            let mut lens = [0usize; 8];
            for (len, width) in lens.iter_mut().zip(HEAD_WIDTHS) {
                *len = cur.number(width)?;
            }
            let mut fields: [String; 8] = Default::default();
            let mut head_end = 0;
            for (field, len) in fields.iter_mut().zip(lens) {
                let (value, _, b1) = cur.take(len)?;
                *field = value;
                head_end = b1;
            }
            out.push(Item {
                op: Op::Head { init, fields },
                start: 0,
                end: head_end,
                value_start: 1,
                value_end: head_end,
                path: None,
            });
        }
    }

    while cur.pos < units.units.len() {
        if out.len() >= MAX_OPS {
            return Err(Error::Limit("too many operations"));
        }
        let start = cur.byte_at(cur.pos);
        let (op_text, _, _) = cur.take(1)?;
        let op = op_text.chars().next().ok_or(Error::Truncated)?;
        let item = match op {
            'l' => (Op::Clear, None, start, start + 1),
            's' => {
                let n = cur.number(1)?;
                let m = cur.number(2)?;
                let (key, _, _) = cur.take(n)?;
                let (name, v0, v1) = cur.take(m)?;
                if names.len() >= MAX_KEYS && !names.contains_key(&key) {
                    return Err(Error::Limit("too many dictionary keys"));
                }
                names.insert(key.clone(), name.clone());
                (Op::Dict { key, name }, None, v0, v1)
            }
            'p' | 'q' | 'z' | 'w' => {
                let n = cur.number(2)?;
                let m = cur.number(if matches!(op, 'z' | 'w') { 10 } else { 5 })?;
                let (key, _, _) = cur.take(n)?;
                let (value, v0, v1) = cur.take(m)?;
                let resolved = if matches!(op, 'q' | 'w') {
                    names.get(&key).cloned().ok_or(Error::InvalidLength)?
                } else {
                    key.clone()
                };
                let mut path = String::with_capacity(prefix.len() + resolved.len());
                path.push_str(&prefix);
                path.push_str(&resolved);
                let op = if matches!(op, 'q' | 'w') {
                    Op::Ref { op, key, value }
                } else {
                    Op::Lit { op, key, value }
                };
                (op, Some(path), v0, v1)
            }
            'b' => {
                let n = cur.number(2)?;
                let (scope, v0, v1) = cur.take(n)?;
                if marks.len() >= MAX_DEPTH {
                    return Err(Error::Limit("scopes nested too deeply"));
                }
                marks.push(prefix.len());
                prefix.push_str(&scope);
                prefix.push('.');
                if prefix.chars().count() > MAX_PATH {
                    return Err(Error::Limit("scope path too long"));
                }
                (Op::Begin(scope), None, v0, v1)
            }
            'c' => {
                match marks.pop() {
                    Some(mark) => prefix.truncate(mark),
                    None => return Err(Error::UnbalancedScope),
                }
                (Op::End, None, start, start + 1)
            }
            'x' => {
                let n = cur.number(2)?;
                let (delta, v0, v1) = cur.take(n)?;
                (Op::Delta(delta), None, v0, v1)
            }
            'k' => {
                let n = cur.number(2)?;
                let (name, v0, v1) = cur.take(n)?;
                (Op::Delete(name), None, v0, v1)
            }
            'i' | 'v' => return Err(Error::Misplaced(op)),
            other => return Err(Error::UnknownOp(other)),
        };
        let end = if cur.pos < units.units.len() {
            cur.byte_at(cur.pos)
        } else {
            text.len()
        };
        out.push(Item {
            op: item.0,
            start,
            end,
            value_start: item.2,
            value_end: item.3,
            path: item.1,
        });
    }
    if !marks.is_empty() {
        return Err(Error::UnbalancedScope);
    }
    Ok(out)
}

fn fit(value: usize, width: usize, what: &'static str) -> Result<String, Error> {
    let text = value.to_string();
    if text.len() > width {
        return Err(Error::TooLong {
            what,
            max: 10usize.pow(width as u32) - 1,
        });
    }
    Ok(format!("{text:0>width$}"))
}

/// Re-encodes the operations, recalculating all length prefixes.
pub fn serialize(ops: &[Op]) -> Result<String, Error> {
    let mut out = String::new();
    for op in ops {
        match op {
            Op::Head { init, fields } => {
                out.push(if *init { 'i' } else { 'v' });
                for (field, width) in fields.iter().zip(HEAD_WIDTHS) {
                    out.push_str(&fit(jslen(field), width, "header field")?);
                }
                for field in fields {
                    out.push_str(field);
                }
            }
            Op::Lit { op, key, value } | Op::Ref { op, key, value } => {
                let width = if matches!(op, 'z' | 'w') { 10 } else { 5 };
                out.push(*op);
                out.push_str(&fit(jslen(key), 2, "name")?);
                out.push_str(&fit(jslen(value), width, "value")?);
                out.push_str(key);
                out.push_str(value);
            }
            Op::Dict { key, name } => {
                out.push('s');
                out.push_str(&fit(jslen(key), 1, "dictionary key")?);
                out.push_str(&fit(jslen(name), 2, "dictionary name")?);
                out.push_str(key);
                out.push_str(name);
            }
            Op::Begin(scope) => {
                out.push('b');
                out.push_str(&fit(jslen(scope), 2, "scope")?);
                out.push_str(scope);
            }
            Op::End => out.push('c'),
            Op::Clear => out.push('l'),
            Op::Delete(name) => {
                out.push('k');
                out.push_str(&fit(jslen(name), 2, "removed name")?);
                out.push_str(name);
            }
            Op::Delta(delta) => {
                out.push('x');
                out.push_str(&fit(jslen(delta), 2, "delta")?);
                out.push_str(delta);
            }
        }
    }
    Ok(out)
}
