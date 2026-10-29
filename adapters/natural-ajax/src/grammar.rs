//! Gramática do campo `XML` do Connector Natural for Ajax, sem depender do
//! core. Comprimentos em unidades UTF-16 (`String.length` do JS); a análise é
//! linear e qualquer entrada inválida vira [`Error`], nunca panic.
//!
//! Requisição: `i`/`v` + larguras fixas (2,2,2,2,2,3,5,1) + 8 campos, depois
//! operações `p` (nome 2, valor 5) e `x` (delta 2). Resposta: `l`, `s`, `p`,
//! `q`, `z`, `w`, `b`, `c`, `k`, `x`.

use std::fmt;

/// Larguras dos 8 campos do cabeçalho de requisição.
pub const HEAD_WIDTHS: [usize; 8] = [2, 2, 2, 2, 2, 3, 5, 1];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    InvalidLength,
    UnknownOp(char),
    UnbalancedScope,
    /// Corte no meio de um par substituto UTF-16.
    SplitSurrogate,
    /// Valor maior do que a largura do prefixo comporta.
    TooLong {
        what: &'static str,
        max: usize,
    },
    /// Operação fora de lugar (cabeçalho fora do início).
    Misplaced(char),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "mensagem truncada"),
            Error::InvalidLength => write!(f, "comprimento inválido"),
            Error::UnknownOp(c) => write!(f, "opcode não suportado: {c:?}"),
            Error::UnbalancedScope => write!(f, "escopo inválido"),
            Error::SplitSurrogate => write!(f, "comprimento corta um par substituto UTF-16"),
            Error::TooLong { what, max } => {
                write!(f, "{what} excede o máximo de {max} unidades UTF-16")
            }
            Error::Misplaced(c) => write!(f, "operação fora de lugar: {c:?}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// `i`/`v` + 8 campos (sid, pid, vazio, modelo, dummy, página, evento, flag).
    Head {
        init: bool,
        fields: [String; 8],
    },
    /// `p` (valor 5) / `z` (valor 10): nome literal.
    Lit {
        op: char,
        key: String,
        value: String,
    },
    /// `q` (valor 5) / `w` (valor 10): nome por referência ao dicionário `s`.
    Ref {
        op: char,
        key: String,
        value: String,
    },
    /// `s`: define `key` → `name`.
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

/// Operação com as posições (bytes UTF-8 no texto original).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub op: Op,
    pub start: usize,
    pub end: usize,
    /// Posição do valor (ou do delta / nome do escopo) no original.
    pub value_start: usize,
    pub value_end: usize,
    /// Nome completo resolvido (escopos + chave) para `Lit`/`Ref`.
    pub path: Option<String>,
}

/// Texto em unidades UTF-16 com o mapa unidade → byte do original.
struct Units {
    units: Vec<u16>,
    /// `byte[i]` = byte do original em que a unidade `i` começa;
    /// `usize::MAX` marca a segunda metade de um par substituto.
    byte: Vec<usize>,
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
                byte.push(if i == 0 { at } else { usize::MAX });
            }
        }
        byte.push(text.len());
        Units { units, byte }
    }
}

struct Cursor<'a> {
    u: &'a Units,
    pos: usize,
}

impl Cursor<'_> {
    fn byte_at(&self, unit: usize) -> usize {
        self.u.byte[unit]
    }

    /// Consome `n` unidades; devolve o texto e os bytes (início, fim).
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

/// Comprimento em unidades UTF-16 (`jslen`).
pub fn jslen(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Decodifica a mensagem em operações. Custo linear no tamanho do texto.
pub fn parse(text: &str) -> Result<Vec<Item>, Error> {
    let units = Units::new(text);
    let mut cur = Cursor { u: &units, pos: 0 };
    let mut out: Vec<Item> = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut names: Vec<(String, String)> = Vec::new();

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
                names.retain(|(k, _)| k != &key);
                names.push((key.clone(), name.clone()));
                (Op::Dict { key, name }, None, v0, v1)
            }
            'p' | 'q' | 'z' | 'w' => {
                let n = cur.number(2)?;
                let m = cur.number(if matches!(op, 'z' | 'w') { 10 } else { 5 })?;
                let (key, _, _) = cur.take(n)?;
                let (value, v0, v1) = cur.take(m)?;
                let resolved = if matches!(op, 'q' | 'w') {
                    names
                        .iter()
                        .find(|(k, _)| k == &key)
                        .map(|(_, name)| name.clone())
                        .ok_or(Error::InvalidLength)?
                } else {
                    key.clone()
                };
                let mut path = stack.join(".");
                if !path.is_empty() {
                    path.push('.');
                }
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
                stack.push(scope.clone());
                (Op::Begin(scope), None, v0, v1)
            }
            'c' => {
                if stack.pop().is_none() {
                    return Err(Error::UnbalancedScope);
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
    if !stack.is_empty() {
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

/// Recodifica as operações recalculando todos os prefixos de comprimento.
pub fn serialize(ops: &[Op]) -> Result<String, Error> {
    let mut out = String::new();
    for op in ops {
        match op {
            Op::Head { init, fields } => {
                out.push(if *init { 'i' } else { 'v' });
                for (field, width) in fields.iter().zip(HEAD_WIDTHS) {
                    out.push_str(&fit(jslen(field), width, "campo do cabeçalho")?);
                }
                for field in fields {
                    out.push_str(field);
                }
            }
            Op::Lit { op, key, value } | Op::Ref { op, key, value } => {
                let width = if matches!(op, 'z' | 'w') { 10 } else { 5 };
                out.push(*op);
                out.push_str(&fit(jslen(key), 2, "nome")?);
                out.push_str(&fit(jslen(value), width, "valor")?);
                out.push_str(key);
                out.push_str(value);
            }
            Op::Dict { key, name } => {
                out.push('s');
                out.push_str(&fit(jslen(key), 1, "chave do dicionário")?);
                out.push_str(&fit(jslen(name), 2, "nome do dicionário")?);
                out.push_str(key);
                out.push_str(name);
            }
            Op::Begin(scope) => {
                out.push('b');
                out.push_str(&fit(jslen(scope), 2, "escopo")?);
                out.push_str(scope);
            }
            Op::End => out.push('c'),
            Op::Clear => out.push('l'),
            Op::Delete(name) => {
                out.push('k');
                out.push_str(&fit(jslen(name), 2, "nome removido")?);
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
