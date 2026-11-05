# Session contract — DRAFT (provisional, not official)

> **REPLACED in wave 2.** The official contract is `docs/03-contratos.md`
> (session format v1), with decisions in `docs/01-decisoes.md`. The UI has
> consumed `src/v1/types.ts` + `src/v1/adapter.ts` since the wave 2 commit. This
> file is kept only as the history of wave 1.

Status: **provisional**, written by the owner of `app/` to unblock the UI slice.
It replaces nothing: the official contract will be `docs/03-contratos.md` (owner:
leader). Once the official one exists, this file is discarded and the adapter in
`src/demo/adapter.ts` is the only place to rewrite.

Rule this draft protects: **the UI never sorts, deduplicates or merges headers on
its own.** It receives pairs in the order of the source, with duplicates, and only
the "normalized" panel derives another view, which is labeled as such.

## 1. Units

```ts
type SourceId = "cdp" | "netlog" | "har" | "session";      // session = own format
type Protocol = "HTTP/1.1" | "HTTP/2" | "HTTP/3";
type ResourceType = "document" | "stylesheet" | "script" | "xhr" | "fetch" | "image" | "font" | "other";

/** Header pair in the order the source delivered it. `index` is the 0-based position. */
interface HeaderPair {
  index: number;                 // position in the source sequence (never reordered in the UI)
  name: string;                  // keeps the original casing when the source keeps it
  value: string;
  kind: "pseudo" | "regular";    // ":method", ":path" etc. are pseudo
  note?: string;                 // e.g. "duplicate", "value concatenated by the source"
}
```

Headers are **arrays**, not maps: `x-cache` can appear twice, `accept` too, and
`set-cookie` almost always. HTTP/2/3 pseudoheaders go into the same array, with
`kind: "pseudo"` and before the regular ones — the UI shows them, it does not fix them.

```ts
interface CookiePair { name: string; value: string; index: number; }

interface ReceivedCookie extends CookiePair {
  attributes: { name: string; value?: string }[];  // Path, Domain, HttpOnly, SameSite...
  raw: string;                                     // full Set-Cookie line
}

interface BodyInfo {
  availability: "available" | "truncated" | "discarded" | "omitted" | "unavailable";
  contentType?: string;
  encodedSize?: number;
  decodedSize?: number;
  preview?: string;              // text/JSON only; HTML is never rendered as UI
  truncatedAt?: number;
  reason?: string;               // why it is unavailable/truncated/discarded
  captureRef?: string;           // event/file it came from
}

interface RedirectHop {
  index: number;
  url: string;
  status: number;
  location?: string;
  protocol: Protocol;
}

interface EvidenceRef {
  source: SourceId;
  event: string;                 // e.g. "Network.responseReceivedExtraInfo"
  timestamp: string;             // ISO 8601 with ms
  method: string;                // how the data was obtained (e.g. "raw CDP event")
  eventRef?: string;             // id/handle to open the original event
}

/** Verification state PER PIECE OF INFORMATION, not per request. */
type Verification =
  | { status: "verified"; evidence: EvidenceRef }
  | { status: "partial"; evidence: EvidenceRef; missing: string }
  | { status: "unverified"; reason: string };   // no evidence → UI shows "not verified"
```

```ts
interface RequestRecord {
  id: string;
  url: string;
  method: string;
  domain: string;
  path: string;
  status: number;
  statusText?: string;
  protocol: Protocol;
  type: ResourceType;
  startedAt: string;             // ISO 8601
  durationMs: number;
  initiator?: string;
  requestHeaders: HeaderPair[];
  responseHeaders: HeaderPair[];
  cookiesSent: CookiePair[];
  cookiesReceived: ReceivedCookie[];
  payload: BodyInfo;
  responseBody: BodyInfo;
  redirects: RedirectHop[];
  primarySource: SourceId;
  verification: {
    requestHeaders: Verification;
    responseHeaders: Verification;
    normalizedHeaders: Verification;   // derived: never "verified" on its own
    cookies: Verification;
    payload: Verification;
    responseBody: Verification;
    protocol: Verification;
    timings: Verification;
  };
}

interface SessionRecord {
  id: string;
  label: string;
  synthetic: boolean;            // true → the UI must show "DEMO"
  createdAt: string;
  chromeVersion?: string;
  capture: { cdpEvents: number; netlogBytes?: number; status: "closed" | "partial" | "open" };
  requests: RequestRecord[];
  sources: SourceId[];
  notes?: string[];
}
```

## 2. Display rules the UI assumes

1. `requestHeaders`/`responseHeaders` are rendered in `index` order, duplicates
   included; no `sort()`.
2. The normalized view is derived and labeled: it groups by name, sorts by name,
   keeps all values, and states the number of duplicates.
3. Every piece of information carries a badge: **verified**, **partial** or **not
   verified**. Without an `EvidenceRef`, the UI cannot write "verified".
4. A body with `availability != "available"` is shown with the reason, never as a
   silent empty value.
5. Captured HTML is shown as text (source), never injected as UI.
6. Comparison matches repeated pairs by value within the same name (multiset), not
   by index; "reordered" only when the pair exists on both sides with the same value
   and a different position in the sequence.
7. `synthetic: true` pins the badge "DEMO — synthetic session" at the top and the bottom.

## 3. What this draft does not decide (left for the official contract)

- Canonical form of timestamps (ISO with ms here) and the origin of the clock.
- How the parser marks a header concatenated by the source vs. a real duplicate.
- Stable request identity between CDP and NetLog.
- Persistence (`.scrapelens`), versioning and migration.
- Incremental streaming/import (this slice uses an in-memory session).
