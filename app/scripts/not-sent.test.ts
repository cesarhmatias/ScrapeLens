// Requests cancelled before any bytes reached the network (`networkState: "not-sent"`).
// Sessions saved without the field must keep their previous output.
// Run: npm run test:not-sent
import assert from "node:assert/strict";
import { adaptSession, protocolText, summaryFromRaw } from "../src/v1/adapter";
import type { LogicalRequest, RawRequestSummary, SessionV1 } from "../src/v1/types";

const session = (request: Partial<LogicalRequest>): SessionV1 =>
  ({
    schemaVersion: 1,
    session: { id: "s", startedAt: "2026-11-05T12:00:00Z", labels: [], completeness: { state: "complete", counts: {} } },
    requests: [
      {
        id: "cdp-r0066",
        url: "https://app.example.invalid/cancelled",
        method: "GET",
        protocol: "unknown",
        status: 0,
        requestHeaders: { headers: [{ name: "accept", value: "*/*", verification: "verified", provenance: {} }] },
        responseHeaders: { headers: [] },
        timings: { estimated: true },
        attempts: [
          {
            id: "cdp-r0066-a0",
            logicalId: "cdp-r0066",
            index: 0,
            url: "https://app.example.invalid/cancelled",
            method: "GET",
            protocol: "unknown",
            outcome: "aborted",
            requestHeaders: { headers: [] },
            responseHeaders: { headers: [] },
            cookie: { pairs: [] },
            requestBody: { availability: "unavailable" },
            responseBody: { availability: "unavailable" },
            provenance: {
              source: "netlog",
              verification: "partial",
              notes: ["NetLog source 4411; cancelled at 12:00:02.004; no HTTP_TRANSACTION_SEND_REQUEST"],
            },
          },
        ],
        provenance: { source: "cdp", verification: "partial" },
        ...request,
      },
    ],
    streamSessions: [],
  }) as unknown as SessionV1;

// --- With networkState: not-sent ---
const notSent = adaptSession(session({ networkState: "not-sent" })).session.requests[0];
assert.equal(notSent.networkState, "not-sent");
assert.equal(notSent.protocol, "unknown", "the protocol is never inferred");
assert.equal(protocolText(notSent.protocol, notSent.networkState), "not sent");
assert.equal(notSent.verification.protocol.status, "verified", "the NetLog proves the cancel");
const protocolEvidence = notSent.verification.protocol;
if (protocolEvidence.status !== "verified") throw new Error("expected verified protocol evidence");
assert.match(protocolEvidence.evidence.method, /no protocol: the request never reached the network/);
assert.match(protocolEvidence.evidence.method, /NetLog source 4411/, "the core note is shown");
assert.doesNotMatch(JSON.stringify(notSent.verification.protocol), /StreamSession|Missing/, "no capture-failure wording");
assert.equal(notSent.verification.requestHeaders.status, "unverified");
const headerReason = notSent.verification.requestHeaders.status === "unverified" ? notSent.verification.requestHeaders.reason : "";
assert.match(headerReason, /never transmitted/, "headers came from CDP and were never sent");
assert.equal(notSent.attempts[0].networkState, undefined, "attempt without the field keeps the old shape");
assert.equal(notSent.verification.timings.status, "unverified", "estimated timing is not a measured network time");

// Attempt-level flag alone also marks the request (the core sets both, this covers either).
const attemptOnly = adaptSession(
  session({ attempts: [{ ...session({}).requests[0].attempts[0], networkState: "not-sent" }] as LogicalRequest["attempts"] }),
).session.requests[0];
assert.equal(attemptOnly.networkState, "not-sent");
assert.equal(attemptOnly.attempts[0].networkState, "not-sent");

// Only some attempts not sent: the request is not marked (same rule as the core).
const someAttempts = session({
  attempts: [
    { ...session({}).requests[0].attempts[0], id: "a0", networkState: "not-sent" },
    { ...session({}).requests[0].attempts[0], id: "a1" },
  ] as LogicalRequest["attempts"],
}).requests[0];
const partlyNotSent = adaptSession(session({ attempts: someAttempts.attempts as unknown as LogicalRequest["attempts"] })).session.requests[0];
assert.equal(partlyNotSent.networkState, undefined, "one not-sent attempt out of two does not mark the request");
assert.equal(partlyNotSent.attempts[0].networkState, "not-sent");

// --- Without the field: unchanged behaviour ---
const plain = adaptSession(session({})).session.requests[0];
assert.equal(plain.networkState, undefined);
assert.equal(protocolText(plain.protocol, plain.networkState), "unknown");
assert.equal(plain.verification.protocol.status, "partial");
if (plain.verification.protocol.status !== "partial") throw new Error("expected partial protocol");
assert.equal(plain.verification.protocol.missing, "no NetLog StreamSession associated with this attempt");
const plainHeaders = plain.verification.requestHeaders;
assert.doesNotMatch(plainHeaders.status === "unverified" ? plainHeaders.reason : "", /never transmitted/);

// --- List summary (paginated DTO from src-tauri/src/listing.rs) ---
const raw = (networkState?: "not-sent"): RawRequestSummary =>
  ({
    id: "cdp-r0066",
    url: "https://app.example.invalid/cancelled",
    method: "GET",
    protocol: "unknown",
    source: "cdp",
    warningCount: 0,
    networkState,
  }) as RawRequestSummary;
const listNotSent = summaryFromRaw(raw("not-sent"), "2026-11-05T12:00:00Z");
assert.equal(listNotSent.networkState, "not-sent");
assert.equal(protocolText(listNotSent.protocol, listNotSent.networkState), "not sent");
const listPlain = summaryFromRaw(raw(), "2026-11-05T12:00:00Z");
assert.equal(listPlain.networkState, undefined);
assert.equal(protocolText(listPlain.protocol, listPlain.networkState), "unknown");

console.log("not-sent ok");
