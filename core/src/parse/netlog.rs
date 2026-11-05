//! NetLog importer for Chrome.
//!
//! NetLog is the only source that proves transmission order (see
//! `docs/02-matrix-fidelity.md`). This module preserves:
//! - pairs in event order, with duplicates;
//! - pseudoheaders separados;
//! - repeats merged by `\x00` in h2/h3 session events (expanded);
//! - provenance per block and verification per D2;
//! - unknown events and malformed lines as warnings, never silence.
//!
//! NetLog IDs are not equivalent to CDP ones: here only the chain
//! `HTTP_STREAM_JOB_BOUND_TO_REQUEST` is used explicitly to link session headers to
//! `URL_REQUEST`; the correlation with CDP lives in [`crate::correlate`].

use std::collections::{BTreeMap, BTreeSet};

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

use crate::error::{CoreError, Result};
use crate::model::{
    policy, Attempt, AttemptOutcome, Body, BrowserInfo, Completeness, Connection, CookieField,
    HeaderEvidence, HeaderRole, HeaderView, LogicalRequest, OrderState, Protocol, Provenance,
    Redirect, SessionBundle, SessionMeta, SessionV1, Source, StreamSession, Timings, Verification,
    Warning,
};
use crate::parse::own::JsonShape;
use crate::parse::{ImportReport, ImportedSession, InputFormat};

const MAX_UNKNOWN_SAMPLES: usize = 8;

/// Unit of the NetLog `time` field.
///
/// The real Chrome observed in this project (captures in `experiments/results/`)
/// records `time` in **milliseconds** of ticks: `timeTickOffset` (ms) + `time`
/// lands on the wall clock. The synthetic `detran-pb` fixtures use
/// microseconds. The unit is decided once per capture in
/// [`detect_time_unit`] and applied by [`ticks_to_epoch_seconds`]; no other
/// point in the parser converts time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetlogTimeUnit {
    /// `time` in microseconds of process ticks.
    Microseconds,
    /// `time` in milliseconds of process ticks (real Chrome).
    #[default]
    Milliseconds,
}

impl NetlogTimeUnit {
    /// Divisor that converts `time` to milliseconds.
    fn per_millisecond(self) -> f64 {
        match self {
            NetlogTimeUnit::Microseconds => 1_000.0,
            NetlogTimeUnit::Milliseconds => 1.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetlogTimeUnit::Microseconds => "microseconds",
            NetlogTimeUnit::Milliseconds => "milliseconds",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetlogCapture {
    pub browser: BrowserInfo,
    pub started_at: Option<String>,
    /// Unit used to convert `time` in this capture.
    pub time_unit: NetlogTimeUnit,
    pub time_tick_offset_ms: Option<f64>,
    pub events_total: usize,
    pub events_used: usize,
    pub events_unknown: usize,
    pub unknown_event_samples: Vec<String>,
    pub requests: Vec<NetlogUrlRequest>,
    pub warnings: Vec<Warning>,
    pub unlinked_session_events: usize,
}

#[derive(Debug, Clone, Default)]
pub struct NetlogUrlRequest {
    pub source_id: u32,
    pub url: String,
    pub method: String,
    pub request_type: Option<String>,
    pub started_at: Option<f64>,
    pub ended_at: Option<f64>,
    pub net_error: Option<i32>,
    pub attempts: Vec<NetlogAttempt>,
    pub redirects: Vec<NetlogRedirect>,
}

#[derive(Debug, Clone, Default)]
pub struct NetlogAttempt {
    pub url: String,
    pub method: String,
    pub started_at: Option<f64>,
    pub ended_at: Option<f64>,
    pub protocol: Protocol,
    pub status: Option<u16>,
    pub outcome: AttemptOutcome,
    pub send_transaction: Option<NetlogHeaderEvent>,
    pub send_session: Option<NetlogHeaderEvent>,
    pub recv_transaction: Option<NetlogHeaderEvent>,
    pub recv_session: Option<NetlogHeaderEvent>,
    pub redirect_to: Option<String>,
    pub net_error: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct NetlogHeaderEvent {
    pub event_name: String,
    pub event_index: usize,
    pub time: Option<f64>,
    pub source_id: Option<u32>,
    pub stream_id: Option<u32>,
    pub dependency_id: Option<u32>,
    pub protocol: Protocol,
    pub role: HeaderRole,
    pub view: HeaderView,
    pub nul_expanded: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NetlogRedirect {
    pub location: String,
    pub time: Option<f64>,
    pub from_url: String,
}

#[derive(Debug)]
enum Atom {
    Send(NetlogHeaderEvent),
    Recv(NetlogHeaderEvent),
    Redirect {
        location: String,
        time: Option<f64>,
        index: usize,
    },
    End {
        time: Option<f64>,
        net_error: Option<i32>,
        index: usize,
    },
}

#[derive(Debug)]
struct Builder {
    source_id: u32,
    url: String,
    method: String,
    request_type: Option<String>,
    started_at: Option<f64>,
    atoms: Vec<Atom>,
    net_error: Option<i32>,
    ended_at: Option<f64>,
}

impl Builder {
    fn new(source_id: u32) -> Self {
        Self {
            source_id,
            url: String::new(),
            method: "GET".to_string(),
            request_type: None,
            started_at: None,
            atoms: Vec::new(),
            net_error: None,
            ended_at: None,
        }
    }
}

// ---------------------------------------------------------------------------
// P4 (docs/18 §5): streaming read.
//
// A NetLog of 20 thousand requests is ~313 MiB; deserializing it whole into
// `serde_json::Value` cost ~3.15 GiB of DOM (10×). From here on the file
// is walked as a stream: `constants` goes into a small struct, each event of the
// `events` array is extracted to the few fields the parser uses, then discarded.
// Unknown fields are skipped with `JsonShape` (same recursion limit of
// 128 levels as `Value`), so the verdict on invalid/truncated JSON does not change.
//
// Duplicate top-level key: `events` twice follows the `Value` semantics
// of before (the last one wins; the earlier one is discarded in both passes).
// `events` before `constants` falls back to the in-memory path below: the events are
// buffered and processed at the end, to use the file's `constants`.
// ---------------------------------------------------------------------------

/// Information the import uses from `constants`.
#[derive(Debug, Default)]
struct ConstantsInfo {
    event_names: BTreeMap<u32, String>,
    client: Option<ClientFields>,
    tick_offset_ms: Option<f64>,
}

#[derive(Debug, Default)]
struct ClientFields {
    name: Option<String>,
    version: Option<String>,
    platform: Option<String>,
}

impl ConstantsInfo {
    fn browser(&self) -> BrowserInfo {
        match &self.client {
            Some(client) => BrowserInfo {
                name: client.name.clone().unwrap_or_else(|| "Chrome".to_string()),
                version: client.version.clone(),
                platform: client.platform.clone(),
                user_agent: None,
            },
            None => BrowserInfo::default(),
        }
    }
}

/// JSON number preserved across the three reads the parser uses (`as_u64`,
/// `as_i64`, `as_f64`), without keeping the `Value`. `Text` covers `time` as a string
/// that real Chrome writes.
#[derive(Debug, Clone)]
enum JsonNum {
    U64(u64),
    I64(i64),
    F64(f64),
    Text(String),
    Other,
}

impl JsonNum {
    fn as_u64(&self) -> Option<u64> {
        match self {
            JsonNum::U64(value) => Some(*value),
            JsonNum::I64(value) if *value >= 0 => Some(*value as u64),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            JsonNum::I64(value) => Some(*value),
            JsonNum::U64(value) if *value <= i64::MAX as u64 => Some(*value as i64),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            JsonNum::U64(value) => Some(*value as f64),
            JsonNum::I64(value) => Some(*value as f64),
            JsonNum::F64(value) => Some(*value),
            JsonNum::Text(value) => value.parse().ok(),
            JsonNum::Other => None,
        }
    }
}

fn drain_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> std::result::Result<(), A::Error> {
    while seq.next_element::<JsonShape>()?.is_some() {}
    Ok(())
}

fn drain_map<'de, A: MapAccess<'de>>(mut map: A) -> std::result::Result<(), A::Error> {
    while map.next_entry::<JsonShape, JsonShape>()?.is_some() {}
    Ok(())
}

struct NumVisitor;

impl<'de> Visitor<'de> for NumVisitor {
    type Value = JsonNum;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a number or a numeric string")
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<JsonNum, E> {
        Ok(JsonNum::U64(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<JsonNum, E> {
        Ok(JsonNum::I64(value))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<JsonNum, E> {
        Ok(JsonNum::F64(value))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<JsonNum, E> {
        Ok(JsonNum::Text(value.to_string()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> std::result::Result<JsonNum, E> {
        Ok(JsonNum::Text(value))
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<JsonNum, E> {
        Ok(JsonNum::Other)
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<JsonNum, E> {
        Ok(JsonNum::Other)
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<JsonNum, E> {
        Ok(JsonNum::Other)
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<JsonNum, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<JsonNum, A::Error> {
        drain_seq(seq)?;
        Ok(JsonNum::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<JsonNum, A::Error> {
        drain_map(map)?;
        Ok(JsonNum::Other)
    }
}

impl<'de> Deserialize<'de> for JsonNum {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(NumVisitor)
    }
}

/// JSON string; any other value becomes `None` (the earlier `Value::as_str`).
#[derive(Debug, Default)]
struct LooseStr(Option<String>);

struct StrVisitor;

impl<'de> Visitor<'de> for StrVisitor {
    type Value = LooseStr;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<LooseStr, E> {
        Ok(LooseStr(Some(value.to_string())))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> std::result::Result<LooseStr, E> {
        Ok(LooseStr(Some(value)))
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<LooseStr, E> {
        Ok(LooseStr(None))
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<LooseStr, E> {
        Ok(LooseStr(None))
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<LooseStr, E> {
        Ok(LooseStr(None))
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<LooseStr, E> {
        Ok(LooseStr(None))
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<LooseStr, E> {
        Ok(LooseStr(None))
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<LooseStr, E> {
        Ok(LooseStr(None))
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<LooseStr, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<LooseStr, A::Error> {
        drain_seq(seq)?;
        Ok(LooseStr(None))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<LooseStr, A::Error> {
        drain_map(map)?;
        Ok(LooseStr(None))
    }
}

impl<'de> Deserialize<'de> for LooseStr {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(StrVisitor)
    }
}

/// Tolerant `{ "id": N }` (used by `source` and `source_dependency`).
#[derive(Debug, Default)]
struct IdValue(Option<u32>);

struct IdVisitor;

impl<'de> Visitor<'de> for IdVisitor {
    type Value = IdValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an object with id")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<IdValue, A::Error> {
        let mut id = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == "id" {
                id = map
                    .next_value::<JsonNum>()?
                    .as_u64()
                    .map(|value| value as u32);
            } else {
                map.next_value::<JsonShape>()?;
            }
        }
        Ok(IdValue(id))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<IdValue, A::Error> {
        drain_seq(seq)?;
        Ok(IdValue(None))
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<IdValue, E> {
        Ok(IdValue(None))
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<IdValue, E> {
        Ok(IdValue(None))
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<IdValue, E> {
        Ok(IdValue(None))
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<IdValue, E> {
        Ok(IdValue(None))
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<IdValue, E> {
        Ok(IdValue(None))
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<IdValue, E> {
        Ok(IdValue(None))
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<IdValue, E> {
        Ok(IdValue(None))
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<IdValue, E> {
        Ok(IdValue(None))
    }
}

impl<'de> Deserialize<'de> for IdValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(IdVisitor)
    }
}

/// An item of `params.headers` (string or `{name, value}`).
#[derive(Debug)]
enum HeaderLine {
    Line(String),
    Pair {
        name: Option<String>,
        value: Option<String>,
    },
    Other,
}

struct HeaderLineVisitor;

impl<'de> Visitor<'de> for HeaderLineVisitor {
    type Value = HeaderLine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a header line")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<HeaderLine, E> {
        Ok(HeaderLine::Line(value.to_string()))
    }

    fn visit_string<E: serde::de::Error>(
        self,
        value: String,
    ) -> std::result::Result<HeaderLine, E> {
        Ok(HeaderLine::Line(value))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<HeaderLine, A::Error> {
        let mut name = None;
        let mut value = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "name" => name = map.next_value::<LooseStr>()?.0,
                "value" => value = map.next_value::<LooseStr>()?.0,
                _ => {
                    map.next_value::<JsonShape>()?;
                }
            }
        }
        Ok(HeaderLine::Pair { name, value })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<HeaderLine, A::Error> {
        drain_seq(seq)?;
        Ok(HeaderLine::Other)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<HeaderLine, E> {
        Ok(HeaderLine::Other)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<HeaderLine, E> {
        Ok(HeaderLine::Other)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<HeaderLine, E> {
        Ok(HeaderLine::Other)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<HeaderLine, E> {
        Ok(HeaderLine::Other)
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<HeaderLine, E> {
        Ok(HeaderLine::Other)
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<HeaderLine, E> {
        Ok(HeaderLine::Other)
    }
}

impl<'de> Deserialize<'de> for HeaderLine {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(HeaderLineVisitor)
    }
}

/// `params.headers`: array, text or unexpected format (`null` falls into `Other`,
/// like `Value::as_array`/`as_str` falling to `false`).
#[derive(Debug)]
enum HeadersValue {
    Lines(Vec<HeaderLine>),
    Text(String),
    Other,
}

struct HeadersVisitor;

impl<'de> Visitor<'de> for HeadersVisitor {
    type Value = HeadersValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("headers as array or text")
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<HeadersValue, A::Error> {
        let mut lines = Vec::new();
        while let Some(line) = seq.next_element::<HeaderLine>()? {
            lines.push(line);
        }
        Ok(HeadersValue::Lines(lines))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<HeadersValue, E> {
        Ok(HeadersValue::Text(value.to_string()))
    }

    fn visit_string<E: serde::de::Error>(
        self,
        value: String,
    ) -> std::result::Result<HeadersValue, E> {
        Ok(HeadersValue::Text(value))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<HeadersValue, A::Error> {
        drain_map(map)?;
        Ok(HeadersValue::Other)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<HeadersValue, E> {
        Ok(HeadersValue::Other)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<HeadersValue, E> {
        Ok(HeadersValue::Other)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<HeadersValue, E> {
        Ok(HeadersValue::Other)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<HeadersValue, E> {
        Ok(HeadersValue::Other)
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<HeadersValue, E> {
        Ok(HeadersValue::Other)
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<HeadersValue, E> {
        Ok(HeadersValue::Other)
    }
}

impl<'de> Deserialize<'de> for HeadersValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(HeadersVisitor)
    }
}

#[derive(Debug, Default)]
enum HeadersOpt {
    #[default]
    Missing,
    Lines(Vec<String>),
    Text(String),
    Other,
}

impl HeadersOpt {
    fn from_value(value: HeadersValue) -> Self {
        match value {
            HeadersValue::Lines(entries) => HeadersOpt::Lines(
                entries
                    .into_iter()
                    .filter_map(|entry| match entry {
                        HeaderLine::Line(line) => Some(line),
                        HeaderLine::Pair {
                            name: Some(name),
                            value: Some(value),
                        } => Some(format!("{name}: {value}")),
                        _ => None,
                    })
                    .collect(),
            ),
            HeadersValue::Text(text) => HeadersOpt::Text(text),
            HeadersValue::Other => HeadersOpt::Other,
        }
    }
}

/// The few `params` fields the parser uses.
#[derive(Debug, Default)]
struct RawParams {
    url: Option<String>,
    method: Option<String>,
    request_type: Option<String>,
    net_error: Option<i64>,
    location: Option<String>,
    line: Option<String>,
    headers: HeadersOpt,
    source_dependency_id: Option<u32>,
    stream_id: Option<JsonNum>,
    quic_stream_id: Option<JsonNum>,
}

struct ParamsVisitor;

impl<'de> Visitor<'de> for ParamsVisitor {
    type Value = Option<RawParams>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a params object")
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut params = RawParams::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "url" => params.url = map.next_value::<LooseStr>()?.0,
                "method" => params.method = map.next_value::<LooseStr>()?.0,
                "request_type" => params.request_type = map.next_value::<LooseStr>()?.0,
                "net_error" => {
                    params.net_error = map.next_value::<JsonNum>()?.as_i64();
                }
                "location" => params.location = map.next_value::<LooseStr>()?.0,
                "line" => params.line = map.next_value::<LooseStr>()?.0,
                "headers" => {
                    params.headers = HeadersOpt::from_value(map.next_value::<HeadersValue>()?)
                }
                "source_dependency" => params.source_dependency_id = map.next_value::<IdValue>()?.0,
                "stream_id" => {
                    params.stream_id = Some(map.next_value::<JsonNum>()?);
                }
                "quic_stream_id" => {
                    params.quic_stream_id = Some(map.next_value::<JsonNum>()?);
                }
                _ => {
                    map.next_value::<JsonShape>()?;
                }
            }
        }
        Ok(Some(params))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<Self::Value, A::Error> {
        drain_seq(seq)?;
        Ok(None)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }
}

struct ParamsHolder(Option<RawParams>);

impl<'de> Deserialize<'de> for ParamsHolder {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Ok(ParamsHolder(deserializer.deserialize_any(ParamsVisitor)?))
    }
}

/// An event reduced to what the parser uses.
#[derive(Debug, Default)]
struct RawEventObject {
    type_id: Option<u64>,
    phase: Option<i64>,
    time: Option<JsonNum>,
    source_id: Option<u32>,
    source_dependency_present: bool,
    source_dependency_id: Option<u32>,
    params: Option<RawParams>,
}

impl RawEventObject {
    fn dependency_id(&self) -> Option<u32> {
        if self.source_dependency_present {
            self.source_dependency_id
        } else {
            self.params
                .as_ref()
                .and_then(|params| params.source_dependency_id)
        }
    }
}

struct RawEventVisitor;

impl<'de> Visitor<'de> for RawEventVisitor {
    type Value = Option<RawEventObject>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a NetLog event")
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut event = RawEventObject::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "type" => event.type_id = map.next_value::<JsonNum>()?.as_u64(),
                "phase" => event.phase = map.next_value::<JsonNum>()?.as_i64(),
                "time" => event.time = Some(map.next_value::<JsonNum>()?),
                "source" => event.source_id = map.next_value::<IdValue>()?.0,
                "source_dependency" => {
                    let id = map.next_value::<IdValue>()?.0;
                    event.source_dependency_present = true;
                    event.source_dependency_id = id;
                }
                "params" => event.params = map.next_value::<ParamsHolder>()?.0,
                _ => {
                    map.next_value::<JsonShape>()?;
                }
            }
        }
        Ok(Some(event))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<Self::Value, A::Error> {
        drain_seq(seq)?;
        Ok(None)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<Self::Value, E> {
        Ok(None)
    }
}

struct RawEventSeed;

impl<'de> DeserializeSeed<'de> for RawEventSeed {
    type Value = Option<RawEventObject>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_any(RawEventVisitor)
    }
}

/// `constants.logEventTypes` as pairs in file order.
#[derive(Debug, Default)]
struct EventTypes(Vec<(String, u64)>);

struct EventTypesVisitor;

impl<'de> Visitor<'de> for EventTypesVisitor {
    type Value = EventTypes;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a map of event names")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<EventTypes, A::Error> {
        let mut pairs = Vec::new();
        while let Some(name) = map.next_key::<String>()? {
            if let Some(id) = map.next_value::<JsonNum>()?.as_u64() {
                pairs.push((name, id));
            }
        }
        Ok(EventTypes(pairs))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<EventTypes, A::Error> {
        drain_seq(seq)?;
        Ok(EventTypes::default())
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<EventTypes, E> {
        Ok(EventTypes::default())
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<EventTypes, E> {
        Ok(EventTypes::default())
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<EventTypes, E> {
        Ok(EventTypes::default())
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<EventTypes, E> {
        Ok(EventTypes::default())
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<EventTypes, E> {
        Ok(EventTypes::default())
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<EventTypes, E> {
        Ok(EventTypes::default())
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<EventTypes, E> {
        Ok(EventTypes::default())
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<EventTypes, E> {
        Ok(EventTypes::default())
    }
}

impl<'de> Deserialize<'de> for EventTypes {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(EventTypesVisitor)
    }
}

#[derive(Debug, Default)]
struct ClientInfoValue(Option<ClientFields>);

struct ClientInfoVisitor;

impl<'de> Visitor<'de> for ClientInfoVisitor {
    type Value = ClientInfoValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a clientInfo object")
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<ClientInfoValue, A::Error> {
        let mut client = ClientFields::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "name" => client.name = map.next_value::<LooseStr>()?.0,
                "version" => client.version = map.next_value::<LooseStr>()?.0,
                "os_type" => client.platform = map.next_value::<LooseStr>()?.0,
                _ => {
                    map.next_value::<JsonShape>()?;
                }
            }
        }
        Ok(ClientInfoValue(Some(client)))
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        seq: A,
    ) -> std::result::Result<ClientInfoValue, A::Error> {
        drain_seq(seq)?;
        Ok(ClientInfoValue(None))
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<ClientInfoValue, E> {
        Ok(ClientInfoValue(None))
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<ClientInfoValue, E> {
        Ok(ClientInfoValue(None))
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<ClientInfoValue, E> {
        Ok(ClientInfoValue(None))
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<ClientInfoValue, E> {
        Ok(ClientInfoValue(None))
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<ClientInfoValue, E> {
        Ok(ClientInfoValue(None))
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<ClientInfoValue, E> {
        Ok(ClientInfoValue(None))
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<ClientInfoValue, E> {
        Ok(ClientInfoValue(None))
    }

    fn visit_string<E: serde::de::Error>(
        self,
        _: String,
    ) -> std::result::Result<ClientInfoValue, E> {
        Ok(ClientInfoValue(None))
    }
}

impl<'de> Deserialize<'de> for ClientInfoValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(ClientInfoVisitor)
    }
}

#[derive(Debug, Default)]
struct ConstantsValue(Option<ConstantsInfo>);

struct ConstantsVisitor;

impl<'de> Visitor<'de> for ConstantsVisitor {
    type Value = ConstantsValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a constants object")
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<ConstantsValue, A::Error> {
        let mut info = ConstantsInfo::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "logEventTypes" => {
                    for (name, id) in map.next_value::<EventTypes>()?.0 {
                        info.event_names.insert(id as u32, name);
                    }
                }
                "clientInfo" => info.client = map.next_value::<ClientInfoValue>()?.0,
                "timeTickOffset" => {
                    info.tick_offset_ms = map.next_value::<JsonNum>()?.as_f64();
                }
                _ => {
                    map.next_value::<JsonShape>()?;
                }
            }
        }
        Ok(ConstantsValue(Some(info)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<ConstantsValue, A::Error> {
        drain_seq(seq)?;
        Ok(ConstantsValue(None))
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<ConstantsValue, E> {
        Ok(ConstantsValue(None))
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<ConstantsValue, E> {
        Ok(ConstantsValue(None))
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<ConstantsValue, E> {
        Ok(ConstantsValue(None))
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<ConstantsValue, E> {
        Ok(ConstantsValue(None))
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<ConstantsValue, E> {
        Ok(ConstantsValue(None))
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<ConstantsValue, E> {
        Ok(ConstantsValue(None))
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<ConstantsValue, E> {
        Ok(ConstantsValue(None))
    }

    fn visit_string<E: serde::de::Error>(
        self,
        _: String,
    ) -> std::result::Result<ConstantsValue, E> {
        Ok(ConstantsValue(None))
    }
}

impl<'de> Deserialize<'de> for ConstantsValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(ConstantsVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootKind {
    Object,
    Array,
    Unsupported,
}

#[derive(Debug, Default)]
struct ScanCtx {
    constants: Option<ConstantsInfo>,
    constants_seen: bool,
    saw_events: bool,
    events_is_array: bool,
    buffering: bool,
    buffered: Vec<RawEventObject>,
    events_total: usize,
    first_ticks: Option<f64>,
    bound_to_request: BTreeMap<u32, u32>,
    quic_stream_requests: BTreeMap<u32, BTreeSet<u32>>,
    unknown_counts: BTreeMap<u32, usize>,
    not_object_count: usize,
    not_object_warnings: Vec<Warning>,
}

impl ScanCtx {
    fn record(&mut self, event: Option<RawEventObject>) {
        let index = self.events_total;
        self.events_total += 1;
        let Some(event) = event else {
            self.not_object_count += 1;
            self.not_object_warnings.push(Warning::new(
                "netlog.event_not_object",
                format!("event {index} is not an object; skipped"),
            ));
            return;
        };
        if let Some(ticks) = event.time.as_ref().and_then(JsonNum::as_f64) {
            self.first_ticks = Some(match self.first_ticks {
                Some(current) => current.min(ticks),
                None => ticks,
            });
        }
        if self.buffering || !self.constants_seen {
            // `events` before `constants` (order not used by Chrome): keep and
            // process later, preserving the file order.
            self.buffering = true;
            self.buffered.push(event);
        } else {
            self.absorb(event);
        }
    }

    /// `Value` semantics: the last `events` key of the root object wins.
    /// A second occurrence discards everything that came from the earlier array.
    fn reset_events(&mut self) {
        self.buffered.clear();
        self.events_total = 0;
        self.first_ticks = None;
        self.bound_to_request.clear();
        self.quic_stream_requests.clear();
        self.unknown_counts.clear();
        self.not_object_count = 0;
        self.not_object_warnings.clear();
    }

    fn absorb(&mut self, event: RawEventObject) {
        let event_type = event.type_id;
        let name = match self
            .constants
            .as_ref()
            .and_then(|constants| event_type.and_then(|id| constants.event_names.get(&(id as u32))))
            .cloned()
        {
            Some(name) => name,
            None => {
                let id = event_type.unwrap_or(0);
                *self.unknown_counts.entry(id as u32).or_default() += 1;
                format!("unknown:{id}")
            }
        };
        if name == "HTTP_STREAM_JOB_BOUND_TO_REQUEST" {
            let source = event.source_id;
            let dependency = event
                .params
                .as_ref()
                .and_then(|params| params.source_dependency_id);
            if let (Some(source_id), Some(dep_id)) = (source, dependency) {
                self.bound_to_request.insert(source_id, dep_id);
            }
        } else if name == "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS" {
            if let (Some(request_id), Some(stream_id)) = (
                event.source_id,
                event.params.as_ref().and_then(stream_id_of),
            ) {
                self.quic_stream_requests
                    .entry(stream_id)
                    .or_default()
                    .insert(request_id);
            }
        }
    }

    fn finish(mut self, root: RootKind) -> Result<ScanOutcome> {
        for event in std::mem::take(&mut self.buffered) {
            self.absorb(event);
        }
        match root {
            RootKind::Unsupported => Err(CoreError::UnsupportedFormat {
                message: "NetLog must be an object with {constants,events}".to_string(),
            }),
            RootKind::Object if !self.saw_events || !self.events_is_array => {
                Err(CoreError::MissingField {
                    field: "events".to_string(),
                })
            }
            _ => Ok(ScanOutcome {
                constants: self.constants,
                events_total: self.events_total,
                first_ticks: self.first_ticks,
                bound_to_request: self.bound_to_request,
                quic_stream_requests: self.quic_stream_requests,
                unknown_counts: self.unknown_counts,
                not_object_warnings: self.not_object_warnings,
                not_object_count: self.not_object_count,
            }),
        }
    }
}

struct ScanOutcome {
    constants: Option<ConstantsInfo>,
    events_total: usize,
    first_ticks: Option<f64>,
    bound_to_request: BTreeMap<u32, u32>,
    quic_stream_requests: BTreeMap<u32, BTreeSet<u32>>,
    unknown_counts: BTreeMap<u32, usize>,
    not_object_warnings: Vec<Warning>,
    not_object_count: usize,
}

struct ScanRoot<'a> {
    ctx: &'a mut ScanCtx,
}

impl<'de> DeserializeSeed<'de> for ScanRoot<'_> {
    type Value = RootKind;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_any(ScanRootVisitor { ctx: self.ctx })
    }
}

struct ScanRootVisitor<'a> {
    ctx: &'a mut ScanCtx,
}

fn scan_events_seq<'de, A: SeqAccess<'de>>(
    mut seq: A,
    ctx: &mut ScanCtx,
) -> std::result::Result<(), A::Error> {
    while let Some(event) = seq.next_element_seed(RawEventSeed)? {
        ctx.record(event);
    }
    Ok(())
}

struct ScanEvents<'a> {
    ctx: &'a mut ScanCtx,
}

impl<'de> DeserializeSeed<'de> for ScanEvents<'_> {
    type Value = bool;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_any(ScanEventsVisitor { ctx: self.ctx })
    }
}

struct ScanEventsVisitor<'a> {
    ctx: &'a mut ScanCtx,
}

impl<'de> Visitor<'de> for ScanEventsVisitor<'_> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an array of events")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<bool, A::Error> {
        scan_events_seq(seq, self.ctx)?;
        Ok(true)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<bool, A::Error> {
        drain_map(map)?;
        Ok(false)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<bool, E> {
        Ok(false)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<bool, E> {
        Ok(false)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<bool, E> {
        Ok(false)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<bool, E> {
        Ok(false)
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<bool, E> {
        Ok(false)
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<bool, E> {
        Ok(false)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<bool, E> {
        Ok(false)
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<bool, E> {
        Ok(false)
    }
}

impl<'de> Visitor<'de> for ScanRootVisitor<'_> {
    type Value = RootKind;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a NetLog object or an array of events")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<RootKind, A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "constants" => {
                    self.ctx.constants_seen = true;
                    self.ctx.constants = map.next_value::<ConstantsValue>()?.0;
                }
                "events" => {
                    if self.ctx.saw_events {
                        self.ctx.reset_events();
                    } else {
                        self.ctx.saw_events = true;
                    }
                    let is_array = map.next_value_seed(ScanEvents {
                        ctx: &mut *self.ctx,
                    })?;
                    // Last key wins, even if not an array (like `Value`).
                    self.ctx.events_is_array = is_array;
                }
                _ => {
                    map.next_value::<JsonShape>()?;
                }
            }
        }
        Ok(RootKind::Object)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<RootKind, A::Error> {
        self.ctx.saw_events = true;
        self.ctx.events_is_array = true;
        scan_events_seq(seq, self.ctx)?;
        Ok(RootKind::Array)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<RootKind, E> {
        Ok(RootKind::Unsupported)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<RootKind, E> {
        Ok(RootKind::Unsupported)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<RootKind, E> {
        Ok(RootKind::Unsupported)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<RootKind, E> {
        Ok(RootKind::Unsupported)
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<RootKind, E> {
        Ok(RootKind::Unsupported)
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<RootKind, E> {
        Ok(RootKind::Unsupported)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<RootKind, E> {
        Ok(RootKind::Unsupported)
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<RootKind, E> {
        Ok(RootKind::Unsupported)
    }
}

fn scan_netlog(json: &[u8]) -> Result<ScanOutcome> {
    let mut ctx = ScanCtx::default();
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let root = ScanRoot { ctx: &mut ctx }
        .deserialize(&mut deserializer)
        .map_err(|error| CoreError::json("NetLog", error))?;
    deserializer
        .end()
        .map_err(|error| CoreError::json("NetLog", error))?;
    ctx.finish(root)
}

struct BuildCtx {
    names: BTreeMap<u32, String>,
    tick_offset_ms: Option<f64>,
    time_unit: NetlogTimeUnit,
    browser_version: Option<String>,
    builders: BTreeMap<u32, Builder>,
    pending_session: Vec<(NetlogHeaderEvent, Option<u32>)>,
    events_used: usize,
    index: usize,
    saw_events: bool,
    warnings: Vec<Warning>,
}

struct BuiltEvents {
    builders: BTreeMap<u32, Builder>,
    pending_session: Vec<(NetlogHeaderEvent, Option<u32>)>,
    events_used: usize,
}

impl BuildCtx {
    /// Same `Value` semantics: the last `events` key of the root object wins.
    fn reset_events(&mut self) {
        self.builders.clear();
        self.pending_session.clear();
        self.events_used = 0;
        self.index = 0;
        self.warnings.clear();
    }

    fn process(&mut self, index: usize, event: RawEventObject) {
        let name = match event
            .type_id
            .and_then(|id| self.names.get(&(id as u32)))
            .cloned()
        {
            Some(name) => name,
            None => "unknown:0".to_string(),
        };
        let source_id = event.source_id;
        // A single conversion for the whole capture (see `ticks_to_epoch_seconds`).
        let time = event
            .time
            .as_ref()
            .and_then(JsonNum::as_f64)
            .map(|ticks| ticks_to_epoch_seconds(ticks, self.tick_offset_ms, self.time_unit));
        let phase = event.phase.unwrap_or(0);

        match name.as_str() {
            "URL_REQUEST_START_JOB" => {
                let Some(source_id) = source_id else { return };
                if phase == 1 {
                    let builder = self
                        .builders
                        .entry(source_id)
                        .or_insert_with(|| Builder::new(source_id));
                    if let Some(params) = event.params.as_ref() {
                        if let Some(url) = params.url.as_deref() {
                            if builder.url.is_empty() {
                                builder.url = url.to_string();
                            }
                            if builder.started_at.is_none() {
                                builder.started_at = time;
                            }
                        }
                        if let Some(method) = params.method.as_deref() {
                            builder.method = method.to_string();
                        }
                        if let Some(request_type) = params.request_type.as_deref() {
                            builder.request_type = Some(request_type.to_string());
                        }
                    }
                    self.events_used += 1;
                } else if phase == 2 {
                    let builder = self
                        .builders
                        .entry(source_id)
                        .or_insert_with(|| Builder::new(source_id));
                    let net_error = event
                        .params
                        .as_ref()
                        .and_then(|params| params.net_error)
                        .map(|value| value as i32)
                        .filter(|value| *value != 0);
                    if let Some(net_error) = net_error {
                        builder.net_error = Some(net_error);
                    }
                    builder.ended_at = time;
                    builder.atoms.push(Atom::End {
                        time,
                        net_error,
                        index,
                    });
                    self.events_used += 1;
                }
            }
            "URL_REQUEST_REDIRECTED" => {
                let Some(source_id) = source_id else { return };
                let builder = self
                    .builders
                    .entry(source_id)
                    .or_insert_with(|| Builder::new(source_id));
                if let Some(location) = event
                    .params
                    .as_ref()
                    .and_then(|params| params.location.as_deref())
                {
                    builder.atoms.push(Atom::Redirect {
                        location: location.to_string(),
                        time,
                        index,
                    });
                    self.events_used += 1;
                }
            }
            _ => {
                if is_header_event(&name) {
                    let Some(source_id) = source_id else { return };
                    let role = if is_request_headers(&name) {
                        HeaderRole::Request
                    } else {
                        HeaderRole::Response
                    };
                    let protocol = protocol_for_event(&name);
                    let dependency_id = event.dependency_id();
                    let stream_id = event.params.as_ref().and_then(stream_id_of);
                    let (view, nul_expanded, issues) = match parse_headers(
                        event.params,
                        &name,
                        index,
                        role,
                        protocol,
                        self.browser_version.as_deref(),
                        time,
                    ) {
                        Ok(parsed) => parsed,
                        Err(warning) => {
                            self.warnings.push(warning);
                            return;
                        }
                    };
                    if !issues.is_empty() {
                        self.warnings.push(
                            Warning::new(
                                "netlog.header_line_invalid",
                                format!(
                                    "{} (event {index}): {} header line(s) without ':' separator",
                                    name,
                                    issues.len()
                                ),
                            )
                            .with_detail(serde_json::json!({ "lines": issues })),
                        );
                    }
                    let header_event = NetlogHeaderEvent {
                        event_name: name.clone(),
                        event_index: index,
                        time,
                        source_id: Some(source_id),
                        stream_id,
                        dependency_id,
                        protocol,
                        role,
                        view,
                        nul_expanded,
                    };
                    self.events_used += 1;

                    if is_transaction_event(&name) {
                        let builder = self
                            .builders
                            .entry(source_id)
                            .or_insert_with(|| Builder::new(source_id));
                        match role {
                            HeaderRole::Request => builder.atoms.push(Atom::Send(header_event)),
                            HeaderRole::Response => builder.atoms.push(Atom::Recv(header_event)),
                        }
                    } else {
                        self.pending_session.push((header_event, None));
                    }
                }
            }
        }
    }
}

struct BuildRoot<'a> {
    ctx: &'a mut BuildCtx,
}

impl<'de> DeserializeSeed<'de> for BuildRoot<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_any(BuildRootVisitor { ctx: self.ctx })
    }
}

struct BuildRootVisitor<'a> {
    ctx: &'a mut BuildCtx,
}

struct BuildEvents<'a> {
    ctx: &'a mut BuildCtx,
}

impl<'de> DeserializeSeed<'de> for BuildEvents<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_any(BuildEventsVisitor { ctx: self.ctx })
    }
}

struct BuildEventsVisitor<'a> {
    ctx: &'a mut BuildCtx,
}

fn build_events_seq<'de, A: SeqAccess<'de>>(
    mut seq: A,
    ctx: &mut BuildCtx,
) -> std::result::Result<(), A::Error> {
    while let Some(event) = seq.next_element_seed(RawEventSeed)? {
        let index = ctx.index;
        ctx.index += 1;
        if let Some(event) = event {
            ctx.process(index, event);
        }
    }
    Ok(())
}

impl<'de> Visitor<'de> for BuildEventsVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an array of events")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<(), A::Error> {
        build_events_seq(seq, self.ctx)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<(), A::Error> {
        drain_map(map)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<(), E> {
        Ok(())
    }
}

impl<'de> Visitor<'de> for BuildRootVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a NetLog object or an array of events")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "events" => {
                    if self.ctx.saw_events {
                        self.ctx.reset_events();
                    } else {
                        self.ctx.saw_events = true;
                    }
                    map.next_value_seed(BuildEvents {
                        ctx: &mut *self.ctx,
                    })?;
                }
                _ => {
                    map.next_value::<JsonShape>()?;
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> std::result::Result<(), A::Error> {
        build_events_seq(seq, self.ctx)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<(), E> {
        Ok(())
    }
}

fn build_events(
    json: &[u8],
    names: &BTreeMap<u32, String>,
    tick_offset_ms: Option<f64>,
    time_unit: NetlogTimeUnit,
    browser_version: Option<&str>,
    warnings: &mut Vec<Warning>,
) -> Result<BuiltEvents> {
    let mut ctx = BuildCtx {
        names: names.clone(),
        tick_offset_ms,
        time_unit,
        browser_version: browser_version.map(str::to_string),
        builders: BTreeMap::new(),
        pending_session: Vec::new(),
        events_used: 0,
        index: 0,
        saw_events: false,
        warnings: Vec::new(),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    BuildRoot { ctx: &mut ctx }
        .deserialize(&mut deserializer)
        .map_err(|error| CoreError::json("NetLog", error))?;
    deserializer
        .end()
        .map_err(|error| CoreError::json("NetLog", error))?;
    warnings.append(&mut ctx.warnings);
    Ok(BuiltEvents {
        builders: ctx.builders,
        pending_session: ctx.pending_session,
        events_used: ctx.events_used,
    })
}

/// Imports NetLog without a wall-clock reference.
///
/// Without a reference (CDP), the unit is assumed to be milliseconds — what the
/// real Chrome writes — and the capture receives the `netlog.time_unit_assumed` warning.
pub fn parse_netlog(json: &[u8]) -> Result<NetlogCapture> {
    parse_netlog_with_wall_clock(json, None)
}

/// Imports NetLog using a reference wall clock (epoch in seconds,
/// usually the median of the CDP `wallTime`s of the same capture) to decide the
/// unit of `time`. It does not associate requests: it only calibrates the clock.
pub fn parse_netlog_with_wall_clock(
    json: &[u8],
    wall_clock_s: Option<f64>,
) -> Result<NetlogCapture> {
    let scan = scan_netlog(json)?;
    let ScanOutcome {
        mut constants,
        events_total,
        first_ticks,
        bound_to_request,
        quic_stream_requests,
        unknown_counts,
        not_object_warnings,
        not_object_count,
    } = scan;

    let mut capture = NetlogCapture {
        events_total,
        events_unknown: not_object_count,
        ..Default::default()
    };
    if constants.is_none() {
        capture.warnings.push(Warning::new(
            "netlog.constants_missing",
            "NetLog has no constants object; event types cannot be decoded by name",
        ));
    }
    let event_names = constants
        .as_mut()
        .map(|info| std::mem::take(&mut info.event_names))
        .unwrap_or_default();
    let tick_offset_ms = constants.as_ref().and_then(|info| info.tick_offset_ms);
    capture.browser = match constants.as_ref() {
        Some(info) => info.browser(),
        None => BrowserInfo::default(),
    };

    // The clock is decided once per capture; every event uses the same base.
    let time_unit = match (first_ticks, tick_offset_ms) {
        (Some(ticks), Some(offset)) => {
            detect_time_unit(ticks, offset, wall_clock_s, &mut capture.warnings)
        }
        _ => {
            if tick_offset_ms.is_none() {
                capture.warnings.push(Warning::new(
                    "netlog.time_unit_assumed",
                    "NetLog has no timeTickOffset; `time` unit assumed to be milliseconds and clock relative",
                ));
            }
            NetlogTimeUnit::default()
        }
    };
    capture.time_unit = time_unit;
    capture.time_tick_offset_ms = tick_offset_ms;

    if let (Some(ticks), Some(offset)) = (first_ticks, tick_offset_ms) {
        let first_ms = offset + ticks / time_unit.per_millisecond();
        capture.started_at = Some(epoch_ms_to_iso(first_ms as i64));
    }
    if capture.started_at.is_none() {
        capture.started_at = Some("1970-01-01T00:00:00Z".to_string());
        capture.warnings.push(Warning::new(
            "netlog.no_wall_clock",
            "NetLog has no timeTickOffset; startedAt uses the Unix epoch as an explicit marker",
        ));
    }

    // Non-object event warnings were collected in file order.
    capture.warnings.extend(not_object_warnings);

    capture.events_unknown += unknown_counts.values().sum::<usize>();
    for (id, count) in unknown_counts {
        if capture.unknown_event_samples.len() < MAX_UNKNOWN_SAMPLES {
            capture
                .unknown_event_samples
                .push(format!("type {id} × {count}"));
        }
    }
    if capture.events_unknown > 0 {
        capture.warnings.push(
            Warning::new(
                "netlog.unknown_event_type",
                format!(
                    "{} event(s) of unknown type; preserved in the raw file and counted",
                    capture.events_unknown
                ),
            )
            .with_detail(serde_json::json!({
                "samples": capture.unknown_event_samples,
            })),
        );
    }

    let built = build_events(
        json,
        &event_names,
        tick_offset_ms,
        time_unit,
        capture.browser.version.as_deref(),
        &mut capture.warnings,
    )?;
    capture.events_used += built.events_used;
    let mut builders = built.builders;
    let mut pending_session = built.pending_session;

    // Links session events to URL_REQUEST through the explicit chain
    // HTTP_STREAM_JOB_BOUND_TO_REQUEST.
    let mut session_resolution: BTreeMap<(u32, u32), u32> = BTreeMap::new();
    for (event, resolution) in &mut pending_session {
        if event.role == HeaderRole::Request {
            let linked = event
                .dependency_id
                .and_then(|id| bound_to_request.get(&id).copied())
                .or_else(|| {
                    event.stream_id.and_then(|stream_id| {
                        quic_stream_requests.get(&stream_id).and_then(|requests| {
                            if requests.len() == 1 {
                                requests.iter().next().copied()
                            } else {
                                None
                            }
                        })
                    })
                })
                .or_else(|| event.dependency_id.filter(|id| builders.contains_key(id)));
            if let Some(request_id) = linked {
                *resolution = Some(request_id);
                if let Some(stream_id) = event.stream_id {
                    session_resolution
                        .insert((event.source_id.unwrap_or(0), stream_id), request_id);
                }
                let builder = builders
                    .entry(request_id)
                    .or_insert_with(|| Builder::new(request_id));
                builder.atoms.push(Atom::Send(event.clone()));
            } else {
                capture.unlinked_session_events += 1;
            }
        }
    }
    for (event, resolution) in &mut pending_session {
        if event.role == HeaderRole::Response {
            let linked = event.stream_id.and_then(|stream_id| {
                session_resolution
                    .get(&(event.source_id.unwrap_or(0), stream_id))
                    .copied()
            });
            if let Some(request_id) = linked {
                *resolution = Some(request_id);
                let builder = builders
                    .entry(request_id)
                    .or_insert_with(|| Builder::new(request_id));
                builder.atoms.push(Atom::Recv(event.clone()));
            } else {
                capture.unlinked_session_events += 1;
            }
        }
    }
    if capture.unlinked_session_events > 0 {
        capture.warnings.push(Warning::new(
            "netlog.session_headers_unlinked",
            format!(
                "{} h2/h3 session header event(s) without an explicit chain to a URL_REQUEST; not associated",
                capture.unlinked_session_events
            ),
        ));
    }

    for (_, mut builder) in builders {
        builder.atoms.sort_by(|left, right| {
            atom_time(left)
                .partial_cmp(&atom_time(right))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| atom_index(left).cmp(&atom_index(right)))
        });
        let request = build_request(builder);
        if request.url.is_empty() {
            capture.warnings.push(Warning::new(
                "netlog.request_without_url",
                format!(
                    "URL_REQUEST {} has no URL in URL_REQUEST_START_JOB; not imported",
                    request.source_id
                ),
            ));
            continue;
        }
        capture.requests.push(request);
    }

    if capture.requests.is_empty() {
        capture.warnings.push(Warning::error(
            "netlog.no_requests",
            "NetLog produced no usable request",
        ));
    }
    Ok(capture)
}

fn stream_id_of(params: &RawParams) -> Option<u32> {
    params
        .stream_id
        .as_ref()
        .or(params.quic_stream_id.as_ref())
        .and_then(JsonNum::as_u64)
        .map(|value| value as u32)
}

fn is_header_event(name: &str) -> bool {
    is_request_headers(name)
        || matches!(
            name,
            "HTTP_TRANSACTION_READ_RESPONSE_HEADERS"
                | "HTTP2_SESSION_RECV_HEADERS"
                | "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS"
        )
}

fn is_request_headers(name: &str) -> bool {
    matches!(
        name,
        "HTTP_TRANSACTION_SEND_REQUEST_HEADERS"
            | "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"
            | "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"
            | "HTTP2_SESSION_SEND_HEADERS"
            | "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS"
    )
}

fn is_transaction_event(name: &str) -> bool {
    name.starts_with("HTTP_TRANSACTION_")
}

fn protocol_for_event(name: &str) -> Protocol {
    match name {
        "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"
        | "HTTP2_SESSION_SEND_HEADERS"
        | "HTTP2_SESSION_RECV_HEADERS" => Protocol::H2,
        "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"
        | "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS"
        | "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS" => Protocol::H3,
        "HTTP_TRANSACTION_SEND_REQUEST_HEADERS" | "HTTP_TRANSACTION_READ_RESPONSE_HEADERS" => {
            Protocol::H1
        }
        _ => Protocol::Unknown,
    }
}

// The error is a rich `Warning` (code, message and detail), which the caller stacks
// as a warning; boxing would only move the allocation to the success path.
#[allow(clippy::result_large_err)]
fn parse_headers(
    params: Option<RawParams>,
    event_name: &str,
    index: usize,
    role: HeaderRole,
    protocol: Protocol,
    browser_version: Option<&str>,
    timestamp: Option<f64>,
) -> std::result::Result<(HeaderView, bool, Vec<String>), Warning> {
    let params = params.ok_or_else(|| {
        Warning::new(
            "netlog.header_event_without_params",
            format!("{event_name} (event {index}) has no params; skipped"),
        )
    })?;
    let RawParams { line, headers, .. } = params;
    let lines: Vec<String> = match headers {
        HeadersOpt::Missing => {
            return Err(Warning::new(
                "netlog.header_event_without_headers",
                format!("{event_name} (event {index}) has no params.headers; skipped"),
            ))
        }
        HeadersOpt::Other => {
            return Err(Warning::new(
                "netlog.headers_not_array",
                format!("{event_name} (event {index}) has params.headers in an unexpected format"),
            ))
        }
        HeadersOpt::Text(text) => text.lines().map(str::to_string).collect(),
        HeadersOpt::Lines(lines) => lines,
    };
    let (expanded, nul_expanded) = expand_nul_duplicates(&lines);
    let direction = match role {
        HeaderRole::Request => policy::Direction::Request,
        HeaderRole::Response => policy::Direction::Response,
    };
    let wire_protocol = match protocol {
        Protocol::H1 => policy::WireProtocol::H1,
        Protocol::H2 => policy::WireProtocol::H2,
        Protocol::H3 => policy::WireProtocol::H3,
        Protocol::Unknown => policy::WireProtocol::Unknown,
    };
    let provenance = policy::provenance_for(
        Source::NetLog,
        Some(event_name),
        direction,
        wire_protocol,
        if is_transaction_event(event_name) {
            "netlog.headers"
        } else {
            "netlog.session.headers"
        },
        browser_version,
    )
    .with_source_id(index.to_string());
    let provenance = match timestamp {
        Some(timestamp) => provenance.with_timestamp(timestamp),
        None => provenance,
    };

    let (mut view, _issues, unparsed) =
        HeaderView::from_header_lines(&expanded, &provenance, OrderState::SourceOrder);
    let request_line = line.map(|line| line.trim_end_matches(['\r', '\n']).to_string());
    if let Some(line) = &request_line {
        view.start_line = Some(line.clone());
        view.raw_block = Some(format!("{line}\n{}", lines.join("\n")));
    }
    // For header events, the ordered pairs are already the original; we do not
    // duplicate every line into `rawBlock` (high cost on large captures).
    if request_line.is_none() {
        view.raw_block = None;
    }
    if nul_expanded {
        view.notes.push(
            "repeats merged by \\x00 in the session event were expanded into distinct pairs"
                .to_string(),
        );
        for entry in view
            .pseudo_headers
            .iter_mut()
            .chain(view.headers.iter_mut())
        {
            entry.provenance.notes.push("expanded from NUL".to_string());
        }
    }
    if !unparsed.is_empty() {
        view.notes.push(format!(
            "{} line(s) without ':' preserved in raw_block and reported",
            unparsed.len()
        ));
    }
    Ok((view, nul_expanded, unparsed))
}

/// Expands `"x-resp-order: 1\x002"` into `"x-resp-order: 1"` and
/// `"x-resp-order: 2"` at the same position. Pseudoheaders (`:status: 1\x002`)
/// are also supported.
pub fn expand_nul_duplicates(lines: &[String]) -> (Vec<String>, bool) {
    let mut expanded = Vec::new();
    let mut changed = false;
    for line in lines {
        if !line.contains('\0') {
            expanded.push(line.clone());
            continue;
        }
        match line.find(": ") {
            Some(sep) => {
                let name = &line[..sep];
                let rest = &line[sep + 2..];
                for part in rest.split('\0') {
                    expanded.push(format!("{name}: {part}"));
                    changed = true;
                }
            }
            None => expanded.push(line.clone()),
        }
    }
    (expanded, changed)
}

fn build_request(builder: Builder) -> NetlogUrlRequest {
    let mut attempts: Vec<NetlogAttempt> = Vec::new();
    let mut current = NetlogAttempt {
        url: builder.url.clone(),
        method: builder.method.clone(),
        started_at: builder.started_at,
        ..Default::default()
    };
    let mut redirects: Vec<NetlogRedirect> = Vec::new();
    let mut current_has_data = false;

    for atom in builder.atoms {
        match atom {
            Atom::Send(event) => {
                if event.role != HeaderRole::Request {
                    continue;
                }
                current.protocol = if current.protocol == Protocol::Unknown {
                    event.protocol
                } else {
                    current.protocol
                };
                if is_transaction_event(&event.event_name) {
                    if current.send_transaction.is_some() || current.recv_transaction.is_some() {
                        flush_attempt(&mut current, &mut attempts);
                        current = NetlogAttempt {
                            url: attempts.last().map(|a| a.url.clone()).unwrap_or_default(),
                            method: builder.method.clone(),
                            started_at: event.time,
                            protocol: event.protocol,
                            ..Default::default()
                        };
                    }
                    current.send_transaction = Some(event);
                } else if current.send_session.is_none() {
                    current.send_session = Some(event);
                } else {
                    // Second session event for the same attempt: kept
                    // as additional evidence only if it is the same stream.
                }
                current_has_data = true;
            }
            Atom::Recv(event) => {
                if event.role != HeaderRole::Response {
                    continue;
                }
                if is_transaction_event(&event.event_name) {
                    if current.recv_transaction.is_some() {
                        flush_attempt(&mut current, &mut attempts);
                        current = NetlogAttempt {
                            url: attempts.last().map(|a| a.url.clone()).unwrap_or_default(),
                            method: builder.method.clone(),
                            started_at: event.time,
                            protocol: current.protocol,
                            ..Default::default()
                        };
                    }
                    current.recv_transaction = Some(event);
                } else if current.recv_session.is_none() {
                    // A session event is parallel evidence, not a new attempt.
                    current.recv_session = Some(event);
                }
                current_has_data = true;
            }
            Atom::Redirect {
                location,
                time,
                index: _,
            } => {
                current.redirect_to = Some(location.clone());
                current.ended_at = time.or(current.ended_at);
                flush_attempt(&mut current, &mut attempts);
                redirects.push(NetlogRedirect {
                    location: location.clone(),
                    time,
                    from_url: attempts.last().map(|a| a.url.clone()).unwrap_or_default(),
                });
                current = NetlogAttempt {
                    url: location,
                    method: builder.method.clone(),
                    started_at: time,
                    ..Default::default()
                };
                current_has_data = false;
            }
            Atom::End {
                time,
                net_error,
                index: _,
            } => {
                current.ended_at = time.or(current.ended_at);
                if net_error.is_some() {
                    current.net_error = net_error;
                }
            }
        }
    }
    if current_has_data || attempts.is_empty() {
        flush_attempt(&mut current, &mut attempts);
    }

    // Links redirects to the following attempts.
    for index in 0..attempts.len().saturating_sub(1) {
        if attempts[index].redirect_to.is_some() {
            attempts[index].ended_at = attempts[index]
                .ended_at
                .or_else(|| attempts[index + 1].started_at);
        }
    }

    for attempt in &mut attempts {
        if attempt.outcome == AttemptOutcome::Unknown {
            attempt.outcome = if attempt.net_error.is_some() {
                AttemptOutcome::Failed
            } else if attempt.status.is_some() {
                AttemptOutcome::Completed
            } else {
                AttemptOutcome::Unknown
            };
        }
    }
    NetlogUrlRequest {
        source_id: builder.source_id,
        url: builder.url,
        method: builder.method,
        request_type: builder.request_type,
        started_at: builder.started_at,
        ended_at: builder.ended_at,
        net_error: builder.net_error,
        attempts,
        redirects,
    }
}

fn flush_attempt(current: &mut NetlogAttempt, attempts: &mut Vec<NetlogAttempt>) {
    if current.send_transaction.is_none()
        && current.send_session.is_none()
        && current.recv_transaction.is_none()
        && current.recv_session.is_none()
        && current.redirect_to.is_none()
        && current.net_error.is_none()
    {
        return;
    }
    if current.ended_at.is_none() {
        current.ended_at = current
            .recv_session
            .as_ref()
            .and_then(|event| event.time)
            .or_else(|| {
                current
                    .recv_transaction
                    .as_ref()
                    .and_then(|event| event.time)
            });
    }
    if current.protocol == Protocol::Unknown {
        current.protocol = current
            .send_transaction
            .as_ref()
            .map(|event| event.protocol)
            .or_else(|| current.send_session.as_ref().map(|event| event.protocol))
            .or_else(|| current.recv_session.as_ref().map(|event| event.protocol))
            .unwrap_or(Protocol::Unknown);
    }
    current.status = status_of(current);
    current.outcome = if current.net_error.is_some() {
        AttemptOutcome::Failed
    } else if current.status.is_some() {
        AttemptOutcome::Completed
    } else {
        AttemptOutcome::Unknown
    };
    attempts.push(std::mem::take(current));
    current.method = attempts
        .last()
        .map(|attempt| attempt.method.clone())
        .unwrap_or_else(|| "GET".to_string());
}

fn status_of(attempt: &NetlogAttempt) -> Option<u16> {
    attempt
        .recv_session
        .as_ref()
        .and_then(|event| header_status(&event.view))
        .or_else(|| {
            attempt
                .recv_transaction
                .as_ref()
                .and_then(|event| header_status(&event.view))
        })
}

fn header_status(view: &HeaderView) -> Option<u16> {
    if let Some(status) = view.first_value(":status") {
        return status.trim().parse().ok();
    }
    let line = view.start_line.as_deref()?;
    let mut parts = line.split_whitespace();
    let _ = parts.next()?;
    parts.next()?.parse().ok()
}

fn atom_time(atom: &Atom) -> Option<f64> {
    match atom {
        Atom::Send(event) | Atom::Recv(event) => event.time,
        Atom::Redirect { time, .. } | Atom::End { time, .. } => *time,
    }
}

fn atom_index(atom: &Atom) -> usize {
    match atom {
        Atom::Send(event) | Atom::Recv(event) => event.event_index,
        Atom::Redirect { index, .. } | Atom::End { index, .. } => *index,
    }
}

/// Converts NetLog `time` (process ticks) to Unix seconds.
///
/// Single formula of the module: `ms = timeTickOffset + time / factor`, where `factor`
/// is 1 for milliseconds and 1000 for microseconds. Without `timeTickOffset`, the
/// result is relative to the start of the ticks (and the caller records the warning).
pub fn ticks_to_epoch_seconds(
    ticks: f64,
    tick_offset_ms: Option<f64>,
    unit: NetlogTimeUnit,
) -> f64 {
    let millis = ticks / unit.per_millisecond();
    match tick_offset_ms {
        Some(offset) => (offset + millis) / 1000.0,
        None => millis / 1000.0,
    }
}

/// Decides the unit of `time` by comparing the two possible readings with a
/// reference wall clock (median of the CDP `wallTime`s of the same
/// capture). Without a reference, it keeps milliseconds — the behavior of real
/// Chrome — and records that the unit was assumed.
///
/// The readings differ by ~1000× in the ticks part, so the one that falls near the
/// reference wins without a URL/method heuristic. The decision is recorded as
/// an informational warning, with the deviation of both hypotheses.
fn detect_time_unit(
    first_ticks: f64,
    tick_offset_ms: f64,
    wall_clock_s: Option<f64>,
    warnings: &mut Vec<Warning>,
) -> NetlogTimeUnit {
    let Some(reference) = wall_clock_s else {
        warnings.push(Warning::new(
            "netlog.time_unit_assumed",
            "no reference wall clock (CDP); `time` unit assumed to be milliseconds",
        ));
        return NetlogTimeUnit::default();
    };
    let as_ms = ticks_to_epoch_seconds(
        first_ticks,
        Some(tick_offset_ms),
        NetlogTimeUnit::Milliseconds,
    );
    let as_us = ticks_to_epoch_seconds(
        first_ticks,
        Some(tick_offset_ms),
        NetlogTimeUnit::Microseconds,
    );
    let error_ms = (as_ms - reference).abs();
    let error_us = (as_us - reference).abs();
    let (unit, error) = if error_us < error_ms {
        (NetlogTimeUnit::Microseconds, error_us)
    } else {
        (NetlogTimeUnit::Milliseconds, error_ms)
    };
    warnings.push(
        Warning::info(
            "netlog.time_unit_detected",
            format!(
                "`time` unit calibrated as {} by the CDP clock (deviation {:.3}s)",
                unit.as_str(),
                error
            ),
        )
        .with_detail(serde_json::json!({
            "unit": unit.as_str(),
            "referenceWallClock": reference,
            "firstTickAsMilliseconds": as_ms,
            "firstTickAsMicroseconds": as_us,
            "errorSeconds": error,
        })),
    );
    unit
}

/// Converts Unix milliseconds to RFC 3339 UTC without a date dependency.
pub fn epoch_ms_to_iso(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600_000;
    let minute = (rem % 3_600_000) / 60_000;
    let second = (rem % 60_000) / 1000;
    let millis = rem % 1000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (mp + if mp < 10 { 3 } else { -9 }) as u32;
    let year = year + i64::from(month <= 2);
    (year, month, day)
}

/// Builds a v1 session with only the NetLog (no CDP).
pub fn build_netlog_session(capture: &NetlogCapture) -> (SessionV1, ImportReport) {
    let mut report = ImportReport::new(InputFormat::NetLog);
    report.source_events = capture.events_total;
    report.source_events_used = capture.events_total.saturating_sub(capture.events_unknown);
    report.source_events_unknown = capture.events_unknown;

    let mut meta = SessionMeta::new(
        format!("netlog-{}", crate::parse::har::stable_id(b"netlog")),
        capture
            .started_at
            .clone()
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string()),
        capture.browser.clone(),
    );
    meta.capture = Some(crate::model::CaptureMeta {
        mode: Some("netlog-import".to_string()),
        headless: None,
        browser_binary: None,
        chrome_args: None,
        notes: Some("imported without CDP; association between sources was not attempted".to_string()),
    });
    meta.labels.push("netlog-import".to_string());
    meta.completeness = Completeness::partial(
        "NetLog does not declare a CDP capture; request coverage not confirmed",
    );
    let mut session = SessionV1::new(meta);

    for warning in &capture.warnings {
        session.add_warning(warning.clone());
        report.warn(warning.clone());
    }

    let mut connections: BTreeMap<String, String> = BTreeMap::new();
    let mut request_number = 0usize;

    for request in &capture.requests {
        request_number += 1;
        let logical_id = format!("netlog-r{request_number:04}");
        let mut logical = LogicalRequest::new(&logical_id, &request.url, &request.method);
        logical.resource_type = request.request_type.clone();
        logical.cdp = None;
        logical.netlog.source_ids.push(request.source_id);
        logical.provenance = Provenance::new(
            Source::NetLog,
            "URL_REQUEST_START_JOB",
            Verification::Partial,
        )
        .with_source_id(request.source_id.to_string())
          .with_note("request read only from the NetLog");
        if let Some(version) = &capture.browser.version {
            logical.provenance = logical.provenance.clone().with_browser_version(version);
        }
        if let Some(started_at) = request.started_at {
            logical.provenance = logical.provenance.clone().with_timestamp(started_at);
        }

        if request.attempts.is_empty() {
            session.add_warning(Warning::new(
                "netlog.request_without_headers",
                format!("URL_REQUEST {} has no header events", request.source_id),
            ));
        }

        for (index, parsed) in request.attempts.iter().enumerate() {
            let attempt_id = format!("{logical_id}-a{}", index + 1);
            let mut attempt = Attempt::new(
                &attempt_id,
                &logical_id,
                index as u32,
                &parsed.url,
                &parsed.method,
            );
            attempt.protocol = parsed.protocol;
            attempt.status = parsed.status;
            attempt.outcome = parsed.outcome;
            attempt.started_at = parsed.started_at;
            attempt.ended_at = parsed.ended_at;
            attempt.net_error_to_failure(parsed.net_error);
            attempt.netlog.source_ids.push(request.source_id);

            let primary_request = parsed
                .send_transaction
                .as_ref()
                .or(parsed.send_session.as_ref());
            if let Some(evidence) = primary_request {
                attempt.request_headers = evidence.view.clone();
                attempt.cookie = CookieField::from_header_values(
                    &evidence.view.cookie_field_values(),
                    &evidence
                        .view
                        .first("cookie")
                        .map(|entry| entry.provenance.clone())
                        .unwrap_or_default(),
                );
                if let Some(session_headers) = parsed.send_session.as_ref() {
                    if parsed.send_transaction.is_some() {
                        attempt.cookie.wire_lines = session_headers.view.cookie_field_values();
                        attempt.cookie.notes.push(
                            "wire lines read from the session event; NetLog may show a merged Cookie"
                                .to_string(),
                        );
                    }
                }
                if attempt.cookie.wire_lines.is_empty() && !attempt.cookie.raw.is_empty() {
                    attempt.cookie.wire_lines = attempt.cookie.raw.clone();
                    attempt.cookie.notes.push(
                        "h1: a single Cookie field observed in the transactional source".to_string(),
                    );
                }
            }
            if let Some(evidence) = parsed
                .recv_transaction
                .as_ref()
                .or(parsed.recv_session.as_ref())
            {
                attempt.response_headers = evidence.view.clone();
                for header in evidence.view.get_all("set-cookie") {
                    attempt
                        .set_cookies
                        .push(crate::model::SetCookieRecord::from_raw(
                            &header.value,
                            &header.provenance,
                        ));
                }
            }
            attempt.request_body = Body::unavailable("NetLog has no request body");
            attempt.response_body = Body::unavailable("NetLog has no response body");

            // Original evidence preserved per source.
            for (role, evidence) in [
                (HeaderRole::Request, parsed.send_transaction.as_ref()),
                (HeaderRole::Request, parsed.send_session.as_ref()),
                (HeaderRole::Response, parsed.recv_transaction.as_ref()),
                (HeaderRole::Response, parsed.recv_session.as_ref()),
            ] {
                if let Some(evidence) = evidence {
                    let header_id = format!("{attempt_id}-h{}", attempt.header_evidence.len() + 1);
                    if let Some(stream_id) = evidence.stream_id {
                        attempt.netlog.stream_ids.push(stream_id);
                    }
                    if let Some(dependency_id) = evidence.dependency_id {
                        attempt.netlog.dependency_ids.push(dependency_id);
                    }
                    let evidence_protocol = if evidence.protocol == Protocol::H1
                        && evidence.event_name == "HTTP_TRANSACTION_READ_RESPONSE_HEADERS"
                        && parsed.protocol != Protocol::Unknown
                    {
                        parsed.protocol
                    } else {
                        evidence.protocol
                    };
                    attempt.header_evidence.push(HeaderEvidence {
                        id: header_id,
                        role,
                        protocol: evidence_protocol,
                        event: evidence.event_name.clone(),
                        source_id: evidence.source_id,
                        stream_id: evidence.stream_id,
                        view: evidence.view.clone(),
                    });
                }
            }

            if let Some(status) = attempt.status {
                logical.status = Some(status);
            }
            attempt.provenance = Provenance::new(
                Source::NetLog,
                "netlog.attempt",
                attempt.request_headers.verification(),
            )
            .with_source_id(request.source_id.to_string())
            .with_optional_timestamp(parsed.started_at);
            if let Some(version) = &capture.browser.version {
                attempt.provenance = attempt.provenance.clone().with_browser_version(version);
            }

            let total = match (parsed.started_at, parsed.ended_at) {
                (Some(start), Some(end)) => Some(((end - start).max(0.0)) * 1000.0),
                _ => None,
            };
            attempt.timings = Timings {
                request_time: parsed.started_at,
                total_ms: total,
                estimated: total.is_some(),
                ..Default::default()
            };

            // Connection: derived from the URL; NetLog does not provide a stable id here.
            let connection_key = connection_key(&parsed.url, parsed.protocol);
            if let Some((host, port)) = host_port(&parsed.url) {
                let connection_id = connections
                    .entry(connection_key.clone())
                    .or_insert_with(|| {
                        let id = format!(
                            "netlog-conn-{}",
                            crate::parse::har::stable_id(connection_key.as_bytes())
                        );
                        session.connections.push(Connection {
                            id: id.clone(),
                            netlog_id: None,
                            protocol: parsed.protocol,
                            host: Some(host),
                            port: Some(port),
                            ip: None,
                            alpn: None,
                            tls_version: None,
                            reused: None,
                            provenance: Provenance::new(
                                Source::NetLog,
                                "derived:url",
                                Verification::Partial,
                            )
                              .with_note("connection derived from the URL; not the stream job id"),
                        });
                        id
                    })
                    .clone();
                attempt.connection_id = Some(connection_id);
            }

            // StreamSession: only when there is an h2/h3 session event with a stream id.
            if let Some(session_event) = parsed
                .send_session
                .as_ref()
                .or(parsed.recv_session.as_ref())
            {
                if let Some(stream_id) = session_event.stream_id {
                    let stream_id_str = format!("{logical_id}-s{}", stream_id);
                    if !session
                        .stream_sessions
                        .iter()
                        .any(|stream| stream.id == stream_id_str)
                    {
                        session.stream_sessions.push(StreamSession {
                            id: stream_id_str.clone(),
                            connection_id: attempt.connection_id.clone(),
                            protocol: parsed.protocol,
                            stream_id: Some(stream_id),
                            attempt_id: Some(attempt_id.clone()),
                            netlog_session_id: session_event.source_id,
                            provenance: Provenance::new(
                                Source::NetLog,
                                "netlog.stream_headers",
                                Verification::Partial,
                            )
                            .with_source_id(
                                session_event.source_id.unwrap_or_default().to_string(),
                            ),
                        });
                    }
                    attempt.stream_session_id = Some(stream_id_str);
                }
            }

            logical.attempts.push(attempt);
        }

        // Redirects linking consecutive attempts.
        for (index, redirect) in request.redirects.iter().enumerate() {
            let from_attempt = logical
                .attempts
                .get(index)
                .map(|attempt| attempt.id.clone())
                .unwrap_or_else(|| format!("{logical_id}-a{}", index + 1));
            let to_attempt = logical
                .attempts
                .get(index + 1)
                .map(|attempt| attempt.id.clone());
            if to_attempt.is_none() {
                session.add_warning(Warning::new(
                    "netlog.redirect_without_attempt",
                    format!("redirect to {} has no following attempt", redirect.location),
                ));
            }
            logical.redirects.push(Redirect {
                id: format!("{logical_id}-r{}", index + 1),
                logical_id: logical_id.clone(),
                from_attempt_id: from_attempt,
                to_attempt_id: to_attempt,
                status: logical
                    .attempts
                    .get(index)
                    .and_then(|attempt| attempt.status),
                location: Some(redirect.location.clone()),
                from_url: redirect.from_url.clone(),
                to_url: logical
                    .attempts
                    .get(index + 1)
                    .map(|attempt| attempt.url.clone())
                    .or_else(|| Some(redirect.location.clone())),
                provenance: Provenance::new(
                    Source::NetLog,
                    "URL_REQUEST_REDIRECTED",
                    Verification::Verified,
                ),
            });
        }

        logical.timings = logical
            .attempts
            .last()
            .map(|attempt| attempt.timings.clone())
            .unwrap_or_default();
        for attempt in &logical.attempts {
            for stream_id in &attempt.netlog.stream_ids {
                if !logical.netlog.stream_ids.contains(stream_id) {
                    logical.netlog.stream_ids.push(*stream_id);
                }
            }
            for dependency_id in &attempt.netlog.dependency_ids {
                if !logical.netlog.dependency_ids.contains(dependency_id) {
                    logical.netlog.dependency_ids.push(*dependency_id);
                }
            }
        }
        logical.refresh_primary_from_attempt();
        if logical.protocol == Protocol::H1 {
            for entry in logical
                .response_headers
                .headers
                .iter_mut()
                .chain(logical.response_headers.pseudo_headers.iter_mut())
            {
                entry
                    .provenance
                    .notes
                      .push("transactional event in h1".to_string());
            }
        }
        session.requests.push(logical);
    }

    for warning in &capture.warnings {
        if !session
            .warnings
            .iter()
            .any(|existing| existing.code == warning.code)
        {
            session.add_warning(warning.clone());
        }
    }
    session.session.completeness.counts.source_events = report.source_events;
    session.session.completeness.counts.source_events_used = report.source_events_used;
    session.session.completeness.counts.source_events_unknown = report.source_events_unknown;
    session.recompute_completeness();
    for warning in &session.warnings {
        if !report
            .warnings
            .iter()
            .any(|existing| existing.code == warning.code)
        {
            report.warn(warning.clone());
        }
    }
    report.attachments_missing = 0;
    (session, report)
}

/// Importa NetLog isolado.
pub fn import_netlog(json: &[u8]) -> Result<ImportedSession> {
    let capture = parse_netlog(json)?;
    let (mut session, mut report) = build_netlog_session(&capture);
    session.session.id = format!("netlog-{}", crate::parse::har::stable_id(json));
    report.bytes_read = json.len();
    let bundle = SessionBundle {
        session,
        cdp_events_jsonl: None,
        netlog_json: Some(json.to_vec()),
        attachments: Default::default(),
    };
    Ok(ImportedSession::new(bundle, report))
}

fn connection_key(url: &str, protocol: Protocol) -> String {
    match host_port(url) {
        Some((host, port)) => format!("{host}:{port}|{}", protocol.as_str()),
        None => format!("{url}|{}", protocol.as_str()),
    }
}

fn host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => 0,
    };
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, remainder) = stripped.split_once(']')?;
        let port = remainder
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .unwrap_or(default_port);
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host.to_string(), port.parse().ok()?)),
        _ => Some((authority.to_string(), default_port)),
    }
}

trait AttemptFailureExt {
    fn net_error_to_failure(&mut self, net_error: Option<i32>);
}
impl AttemptFailureExt for Attempt {
    fn net_error_to_failure(&mut self, net_error: Option<i32>) {
        if let Some(error) = net_error {
            self.failure = Some(format!("net_error {error}"));
        }
    }
}
