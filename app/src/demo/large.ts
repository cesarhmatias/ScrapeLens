// Generates a large synthetic v1 session to measure the virtualized list.
// synthetic-fixture label kept; nothing here is a real capture.

import base from "./session.v1.json";
import type { LogicalRequest, SessionV1 } from "../v1/types";

export function buildLargeSession(count = 12000): SessionV1 {
  const source = base as unknown as SessionV1;
  const seeds = source.requests;
  const requests: LogicalRequest[] = [];

  for (let i = 0; i < count; i += 1) {
    const seed = seeds[i % seeds.length];
    const id = `req-${String(i + 1).padStart(6, "0")}`;
    const suffix = `/item/${i}?batch=${i % 97}`;
    const url = `https://api.demo-shop.invalid/api/v1/products${suffix}`;
    const attempt = seed.attempts[0];
    requests.push({
      ...seed,
      id,
      url,
      status: i % 11 === 0 ? 403 : 200,
      timings: { ...seed.timings, totalMs: 20 + (i % 380), wallTime: new Date(Date.UTC(2026, 9, 26, 18, 0, 0, i % 60000)).toISOString() },
      attempts: attempt
        ? [
            {
              ...attempt,
              id: `${id}-a0`,
              logicalId: id,
              url,
              provenance: { ...attempt.provenance, sourceId: `stress-${i}` },
            },
          ]
        : [],
      redirects: [],
      provenance: { ...seed.provenance, sourceId: `stress-${i}` },
    } as LogicalRequest);
  }

  return {
    ...source,
    requests,
    session: {
      ...source.session,
      id: "demo-stress-12000",
      notes: ["Synthetic stress session to measure virtualization; no real bytes."],
      completeness: {
        ...source.session.completeness,
        counts: { ...(source.session.completeness.counts ?? {}), requests: count },
      },
    },
  };
}
