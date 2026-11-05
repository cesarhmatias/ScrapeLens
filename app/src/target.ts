// Labels and filters for the CDP target (docs/14-multi-target-capture.md). The UI only
// shows what the core writes to `target`/`links`; it does not invent provenance.

import type { RequestLinkView, RequestSummary, TargetKind, TargetView } from "./types";

/** Fields used by the target rules (list summary or full record). */
export type TargetRow = Pick<RequestSummary, "id" | "url" | "domain" | "target" | "links" | "netlogOnlyUnknownTarget">;

export const TARGET_KIND_LABELS: Record<TargetKind, string> = {
  page: "page",
  iframe: "iframe",
  worker: "worker",
  service_worker: "service worker",
  shared_worker: "shared worker",
  other: "other",
};

/** List filters: real types + NetLog-only. */
export type TargetFilter =
  | "all"
  | TargetKind
  | "popup"
  | "netlog_unknown";

export const TARGET_FILTERS: { id: TargetFilter; label: string }[] = [
  { id: "all", label: "all targets" },
  { id: "page", label: "page" },
  { id: "popup", label: "popup" },
  { id: "iframe", label: "iframe" },
  { id: "worker", label: "worker" },
  { id: "service_worker", label: "service worker" },
  { id: "shared_worker", label: "shared worker" },
  { id: "other", label: "other" },
  { id: "netlog_unknown", label: "NetLog only" },
];

/** Page with an opener = popup/`_blank` (Chrome types both as `page`). */
export function isPopupTarget(target: TargetView | undefined): boolean {
  return Boolean(target && target.kind === "page" && target.openerId);
}

/** Multi-target session: has provenance or an attach warning; otherwise, implicit legacy. */
export function sessionShowsTargets(
  requests: TargetRow[],
  warnings: { code: string }[],
): boolean {
  if (
    warnings.some((w) =>
      /target_attach|target_unknown|target_setup|service_worker/.test(w.code),
    )
  ) {
    return true;
  }
  return requests.some((r) => r.target || r.netlogOnlyUnknownTarget || r.links.length > 0);
}

export function shortTargetUrl(url: string | undefined): string {
  if (!url) return "";
  try {
    const parsed = new URL(url);
    const path = `${parsed.pathname}${parsed.search}`;
    if (path && path !== "/") {
      const clipped = path.length > 48 ? `${path.slice(0, 45)}…` : path;
      return clipped;
    }
    return parsed.host || url;
  } catch {
    return url.length > 48 ? `${url.slice(0, 45)}…` : url;
  }
}

/** Displayed type: popup when page+openerId. */
export function targetKindLabel(target: TargetView): string {
  if (isPopupTarget(target)) return "popup";
  return TARGET_KIND_LABELS[target.kind] ?? target.kind;
}

/**
 * Short list badge. `null` = do not show (implicit main page in an
 * old session, or a page without an opener when the column is already hidden).
 */
export function targetBadge(req: TargetRow): string | null {
  if (req.netlogOnlyUnknownTarget) return "unknown target (NetLog only)";
  if (!req.target) return null;
  const kind = targetKindLabel(req.target);
  const url =
    shortTargetUrl(req.target.url) || shortTargetUrl(req.url) || req.domain || "";
  return url ? `${kind} · ${url}` : kind;
}

/** In the timeline: only when it is not the main page (no opener). */
export function timelineTargetBadge(req: TargetRow | undefined): string | null {
  if (!req) return null;
  if (req.netlogOnlyUnknownTarget) return "unknown target (NetLog only)";
  if (!req.target) return null;
  if (req.target.kind === "page" && !req.target.openerId) return null;
  return targetBadge(req);
}

export function matchesTargetFilter(req: TargetRow, filter: TargetFilter): boolean {
  if (filter === "all") return true;
  if (filter === "netlog_unknown") return req.netlogOnlyUnknownTarget;
  if (filter === "popup") return isPopupTarget(req.target);
  if (filter === "page") {
    return Boolean(req.target && req.target.kind === "page" && !req.target.openerId);
  }
  return req.target?.kind === filter;
}

export function targetFilterCount(requests: TargetRow[], filter: TargetFilter): number {
  return requests.filter((r) => matchesTargetFilter(r, filter)).length;
}

export interface CaptureTargetRow {
  kind: string;
  url: string;
  attached: boolean | null;
  count: number;
}

/** Distinct targets seen in the requests (tracked). */
export function captureTargets(requests: TargetRow[]): CaptureTargetRow[] {
  const map = new Map<string, CaptureTargetRow>();
  for (const req of requests) {
    if (!req.target) continue;
    const kind = targetKindLabel(req.target);
    // No URL in Target.*: use the request's host/path (e.g. blank/_blank).
    const url =
      req.target.url ||
      shortTargetUrl(req.url) ||
      req.domain ||
      "(target URL not provided)";
    // Group by targetId when present, otherwise by kind+url.
    const key = req.target.targetId
      ? `id:${req.target.targetId}`
      : `${kind}\0${url}`;
    const row = map.get(key);
    if (row) {
      row.count += 1;
      if (req.target.attached === false) row.attached = false;
      // Prefer the Target.* URL when it shows up later.
      if (req.target.url && row.url !== req.target.url) row.url = req.target.url;
    } else {
      map.set(key, {
        kind,
        url,
        attached: req.target.attached ?? null,
        count: 1,
      });
    }
  }
  return [...map.values()].sort((a, b) => a.kind.localeCompare(b.kind) || a.url.localeCompare(b.url));
}

export function attachFailureWarnings(
  warnings: { code: string; message: string }[],
): { code: string; message: string }[] {
  return warnings.filter(
    (w) =>
      w.code === "cdp.target_attach_failed" ||
      w.code === "capture.target_attach" ||
      w.code.includes("target_attach"),
  );
}

/** Target CDP setup timeout and error — same block as in Limits. */
export function targetSetupWarnings(
  warnings: { code: string; message: string }[],
): { code: string; message: string }[] {
  return warnings.filter(
    (w) => w.code === "cdp.target_setup_timeout" || w.code === "cdp.target_setup_error",
  );
}

export function linkResolutionLabel(link: RequestLinkView): string {
  if (link.resolution === "linked") return "linked";
  if (link.resolution === "ambiguous") return "ambiguous";
  return link.resolution || "no resolution";
}
