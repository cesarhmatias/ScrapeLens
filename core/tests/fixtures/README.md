# Core synthetic fixtures

Every file here is **synthetic** and marked as such (`_comment` or
`comment`). There is no real traffic, real cookies or registrable domains:
only `.invalid` (RFC 2606) and documentation addresses.

- `har-minimal.json` — HAR 1.2 with duplicate headers, Cookie, Set-Cookie,
  request/response body and timings.
- `netlog-h2.json` — reduced h2 NetLog with:
  - explicit chain `HTTP_STREAM_JOB_BOUND_TO_REQUEST`;
  - pseudoheaders;
  - header duplicates;
  - repetitions merged by `\x00` (expanded by the parser);
  - one unknown event type and one invalid header line.

The tests also read, **without modifying**, the real captures in
`../experiments/results/h1-page` and `h2-page` to validate fidelity against the
matrix.
- `old-live-session-id.jsonl` — excerpt (2 requests) of a live raw capture
  from before round 10: `sessionId` on every line and no `Target.*` event.
  It comes from a local test server (127.0.0.1), with no real data.
