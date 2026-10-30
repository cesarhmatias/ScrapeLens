// Rótulos e filtros do alvo CDP (docs/14-captura-multi-alvo.md). A UI só
// apresenta o que o core grava em `target`/`links`; não inventa proveniência.

import type { RequestLinkView, RequestRecord, TargetKind, TargetView } from "./types";

export const TARGET_KIND_LABELS: Record<TargetKind, string> = {
  page: "página",
  iframe: "iframe",
  worker: "worker",
  service_worker: "service worker",
  shared_worker: "shared worker",
  other: "outro",
};

/** Filtros da lista: tipos reais + só-NetLog. */
export type TargetFilter =
  | "all"
  | TargetKind
  | "popup"
  | "netlog_unknown";

export const TARGET_FILTERS: { id: TargetFilter; label: string }[] = [
  { id: "all", label: "todos os alvos" },
  { id: "page", label: "página" },
  { id: "popup", label: "popup" },
  { id: "iframe", label: "iframe" },
  { id: "worker", label: "worker" },
  { id: "service_worker", label: "service worker" },
  { id: "shared_worker", label: "shared worker" },
  { id: "other", label: "outro" },
  { id: "netlog_unknown", label: "só NetLog" },
];

/** Página com opener = popup/`_blank` (Chrome tipa ambos como `page`). */
export function isPopupTarget(target: TargetView | undefined): boolean {
  return Boolean(target && target.kind === "page" && target.openerId);
}

/** Sessão multi-alvo: há proveniência ou aviso de attach; senão, legado implícito. */
export function sessionShowsTargets(
  requests: RequestRecord[],
  warnings: { code: string }[],
): boolean {
  if (warnings.some((w) => /target_attach|target_unknown|service_worker/.test(w.code))) {
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

/** Tipo exibido: popup quando page+openerId. */
export function targetKindLabel(target: TargetView): string {
  if (isPopupTarget(target)) return "popup";
  return TARGET_KIND_LABELS[target.kind] ?? target.kind;
}

/**
 * Selo curto da lista. `null` = não mostrar (página principal implícita em
 * sessão antiga, ou page sem opener quando a coluna já está oculta).
 */
export function targetBadge(req: RequestRecord): string | null {
  if (req.netlogOnlyUnknownTarget) return "alvo desconhecido (só NetLog)";
  if (!req.target) return null;
  const kind = targetKindLabel(req.target);
  const url =
    shortTargetUrl(req.target.url) || shortTargetUrl(req.url) || req.domain || "";
  return url ? `${kind} · ${url}` : kind;
}

/** Na timeline: só quando não for a página principal (sem opener). */
export function timelineTargetBadge(req: RequestRecord | undefined): string | null {
  if (!req) return null;
  if (req.netlogOnlyUnknownTarget) return "alvo desconhecido (só NetLog)";
  if (!req.target) return null;
  if (req.target.kind === "page" && !req.target.openerId) return null;
  return targetBadge(req);
}

export function matchesTargetFilter(req: RequestRecord, filter: TargetFilter): boolean {
  if (filter === "all") return true;
  if (filter === "netlog_unknown") return req.netlogOnlyUnknownTarget;
  if (filter === "popup") return isPopupTarget(req.target);
  if (filter === "page") {
    return Boolean(req.target && req.target.kind === "page" && !req.target.openerId);
  }
  return req.target?.kind === filter;
}

export function targetFilterCount(requests: RequestRecord[], filter: TargetFilter): number {
  return requests.filter((r) => matchesTargetFilter(r, filter)).length;
}

export interface CaptureTargetRow {
  kind: string;
  url: string;
  attached: boolean | null;
  count: number;
}

/** Alvos distintos vistos nas requisições (acompanhados). */
export function captureTargets(requests: RequestRecord[]): CaptureTargetRow[] {
  const map = new Map<string, CaptureTargetRow>();
  for (const req of requests) {
    if (!req.target) continue;
    const kind = targetKindLabel(req.target);
    // Sem URL no Target.*: usa o host/caminho da requisição (ex.: blank/_blank).
    const url =
      req.target.url ||
      shortTargetUrl(req.url) ||
      req.domain ||
      "(URL do alvo não informada)";
    // Agrupa pelo targetId quando existe, senão por kind+url.
    const key = req.target.targetId
      ? `id:${req.target.targetId}`
      : `${kind}\0${url}`;
    const row = map.get(key);
    if (row) {
      row.count += 1;
      if (req.target.attached === false) row.attached = false;
      // Prefere URL do Target.* quando aparecer depois.
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

export function linkResolutionLabel(link: RequestLinkView): string {
  if (link.resolution === "linked") return "ligada";
  if (link.resolution === "ambiguous") return "ambígua";
  return link.resolution || "sem resolução";
}
