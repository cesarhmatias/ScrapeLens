// TypeScript projection of the core's output: flow::value_origins, flow::priming_chain
// and compare::compare_sessions (docs/09-cadeia-comparacao.md). The UI only shows what
// the core returns; "value-match" is never presented as certainty.

export type EvidenceKind = "cookie-jar" | "same-field" | "value-match" | "initiator" | string;
export type Strength = "strong" | "medium" | "weak" | string;

export interface Evidence {
  kind: EvidenceKind;
  strength: Strength;
  /** produced = 1st producer; reissued = appears again later. */
  role: string;
  producerRequestId: string;
  producerAttemptId: string;
  scope: string;
  field: string | null;
  producerOffset: number | null;
  consumedOffset: number | null;
  consumedLength: number | null;
  /** The producer is an HTML form control (input/textarea/select). */
  htmlControl?: boolean;
}

export interface Unobservable {
  requestId: string;
  state: string;
  reason?: string;
  /** Equivalent occurrence (same model) later on with an observable body. */
  suggestion?: string | null;
}

export interface ContextNote {
  requestId: string;
  field: string | null;
  note: string;
}

/** Value of a producer at the edge of the field; the rest has no observed source. */
export interface PartialComposition {
  producerRequestId: string;
  field?: string | null;
  start: number;
  length: number;
}

export interface ValueOrigin {
  scope: string;
  field: string;
  occurrence: number;
  value: string;
  length: number;
  /** origin | ambiguous | repeated | none | composite | redacted ... */
  status: string;
  /** `strong` | `possible` | null (core ≥ revision 5); absent in old schemas. */
  confidence?: "strong" | "possible" | string | null;
  label: string;
  offset: number | null;
  /** Index, in `evidences`, of the oldest producer (if any). */
  oldest: number | null;
  evidences: Evidence[];
  repeatedFrom: string[];
  unobservable?: Unobservable[];
  parent: string | null;
  note: string | null;
  /** Value also present in a static resource: likely a protocol constant. */
  context?: ContextNote[];
  /** Partial composition (core ≥ 6b): part with a source + part without a source. */
  partialComposition?: PartialComposition[] | string | null;
}

export interface ValueOrigins {
  requestId: string;
  attemptId: string;
  values: ValueOrigin[];
  redactedValues: number;
  ties: string[];
  warnings: string[];
}

export interface StepReason {
  provides: string;
  field: string;
  kind: EvidenceKind;
  strength: Strength;
  consumedBy: string;
}

export interface ChainStep {
  /** `strong` | `possible` (core ≥ revision 5); absent in old schemas. */
  confidence?: "strong" | "possible" | string;
  requestId: string;
  attemptId: string;
  method: string;
  url: string;
  startedAt: number | null;
  class: "application" | "protection" | string;
  reason: string;
  reasons: StepReason[];
}

export interface UnresolvedValue {
  label: string;
  unobservable?: Unobservable[];
  requestId: string;
  scope: string;
  field: string;
  status: string;
}

export interface PrimingChain {
  requestId: string;
  steps: ChainStep[];
  protection: ChainStep[];
  /** Context pages (Referer): never producers. */
  pages?: ChainStep[];
  /** Auxiliary frames loaded by a parser (outside `pages`). */
  auxiliaryPages?: ChainStep[];
  unresolved: UnresolvedValue[];
  redactedValues: number;
  warnings: string[];
}

export interface RequestRef {
  /** Optional core marker: a single request that was reordered (name not yet fixed). */
  reordered?: boolean;
  outOfOrder?: boolean;
  requestId: string;
  method: string;
  url: string;
}

export interface PartDiff {
  class: string;
  label: string;
  aOffset: number | null;
  bOffset: number | null;
  a: string | null;
  b: string | null;
  dynamicKind: string | null;
  originLabel: string | null;
  origin: OriginSummary | null;
}

export interface OriginSummary {
  kind: EvidenceKind;
  requestId: string;
  scope: string;
  field: string | null;
  ambiguous: boolean;
}

export interface FieldDiff {
  scope: string;
  field: string;
  occurrence: number;
  /** static | dynamic | onlyA | onlyB | redacted ... */
  class: string;
  label: string;
  dynamicKind: "runtime" | "noOrigin" | "repeated" | "composite" | null;
  originLabel: string | null;
  a: string | null;
  b: string | null;
  origin: OriginSummary | null;
  parts: PartDiff[];
}

export interface PairCounts {
  static: number;
  dynamic: number;
  runtime: number;
  noOrigin: number;
  onlyA: number;
  onlyB: number;
  redacted: number;
}

export interface PartsCounts {
  static: number;
  dynamic: number;
  runtime: number;
  noOrigin: number;
}

export interface RoundInfo {
  aRound: number;
  bRound: number;
  score: number;
  aRequests: number;
  bRequests: number;
}

export interface UnpairedRound {
  side: "A" | "B" | string;
  round: number;
  requests: number;
  first: RequestRef;
  last: RequestRef;
}

export interface GroupSummary {
  kind: "protection" | "static" | string;
  a: RequestRef[];
  aTotal: number;
  b: RequestRef[];
  bTotal: number;
}

export interface PairComparison {
  round?: number;
  partsCounts?: PartsCounts;
  a: RequestRef;
  b: RequestRef;
  alignedBy: string;
  outOfOrder: boolean;
  fields: FieldDiff[];
  counts: PairCounts;
}

export interface SessionComparison {
  reordered?: ReorderedPair[];
  partsCounts?: PartsCounts;
  pairs: PairComparison[];
  onlyInA: RequestRef[];
  onlyInB: RequestRef[];
  ambiguities: string[];
  counts: PairCounts;
  redactedFields: number;
  warnings: string[];
}

export const evidenceLabels: Record<string, string> = {
  "cookie-jar": "cookie-jar (earlier Set-Cookie with the same name and value)",
  "same-field": "same-field (same field name and value)",
  "value-match": "value-match (value found, no guarantee of cause)",
  initiator: "initiator (supplementary; does not prove origin)",
};

export const strengthLabels: Record<string, string> = { strong: "strong", medium: "medium", weak: "weak" };

/** Status label; "no observed origin" is neutral, never an error. */
export function originStatusLabel(value: ValueOrigin): string {
  const confidence = originConfidence(value);
  // Core label, when it reports confidence (keeps the exact same texts as the core).
  if ((value.status === "origin" || value.status === "ambiguous") && value.confidence && value.label) return value.label;
  const kind = (oldestEvidence(value) ?? value.evidences[0])?.kind;
  switch (value.status) {
    case "repeated":
      return "no observed origin (already circulating)";
    case "composite":
      return "composite (see excerpts)";
    case "redacted":
      return "redacted (not traceable)";
    case "none":
      return "no observed origin";
    default:
      break;
  }
  if (value.status === "ambiguous") return confidence === "possible" ? "ambiguous (possible origin)" : "ambiguous";
  if (confidence === "possible") return `possible origin (${kind ?? "medium evidence"})`;
  if (confidence === "strong") return "observed origin";
  return "no observed origin";
}

/** Evidence of the oldest producer, when `oldest` points to one. */
export function oldestEvidence(value: ValueOrigin): Evidence | undefined {
  return value.oldest === null ? undefined : value.evidences[value.oldest];
}

/** Excerpt values (children of an opaque field) grouped under their parent. */
export function groupOrigins(values: ValueOrigin[]): { top: ValueOrigin; parts: ValueOrigin[] }[] {
  const groups: { top: ValueOrigin; parts: ValueOrigin[] }[] = [];
  for (const value of values) {
    if (value.parent !== null) {
      const owner = [...groups].reverse().find((group) => group.top.field === value.parent && group.top.scope === value.scope);
      if (owner) {
        owner.parts.push(value);
        continue;
      }
    }
    groups.push({ top: value, parts: [] });
  }
  return groups;
}

/** "Dynamic only" filter: pairs without dynamic fields disappear; fields keep the source order. */
export function dynamicOnly(pairs: PairComparison[]): PairComparison[] {
  return pairs
    .map((pair) => ({ ...pair, fields: pair.fields.filter((field) => field.class !== "static") }))
    .filter((pair) => pair.fields.length > 0);
}

export function fieldClassLabel(field: FieldDiff): string {
  if (field.class === "static") return "static";
  if (field.dynamicKind === "runtime") return field.originLabel || "obtain at runtime";
  if (field.dynamicKind === "noOrigin") return "dynamic, no origin";
  if (field.dynamicKind === "repeated") return "dynamic (already circulating, no observed producer)";
  if (field.dynamicKind === "composite") return "dynamic composite (see excerpts)";
  return field.label;
}

// ---- Paged comparison (commands compare_open / compare_page / compare_fields) ----

export interface ReorderedPair {
  a: RequestRef;
  b: RequestRef;
}

export interface CompareSummary {
  rounds?: RoundInfo[];
  unpairedRounds?: UnpairedRound[];
  entryRequest?: string | null;
  groups?: GroupSummary[];
  includeAll?: boolean;
  reordered?: ReorderedPair[];
  reorderedTotal?: number;
  handle: number;
  pairs: number;
  dynamicPairs: number;
  counts: PairCounts;
  partsCounts?: PartsCounts;
  redactedFields: number;
  ambiguities: string[];
  warnings: string[];
  onlyInA: RequestRef[];
  onlyInATotal: number;
  onlyInB: RequestRef[];
  onlyInBTotal: number;
}

export interface PairSummary {
  index: number;
  /** Index into `rounds`. */
  round?: number;
  a: RequestRef;
  b: RequestRef;
  alignedBy: string;
  outOfOrder: boolean;
  counts: PairCounts;
  partsCounts?: PartsCounts;
  fieldCount: number;
}

export interface ComparePage {
  total: number;
  items: PairSummary[];
}

/** Above this number of pairs, "dynamic only" starts on. */
export const DYNAMIC_ONLY_THRESHOLD = 500;

export function visibleFields(fields: FieldDiff[], onlyDynamic: boolean): FieldDiff[] {
  return onlyDynamic ? fields.filter((field) => field.class !== "static") : fields;
}

/** "N dynamic, M of them in excerpts of composite fields" (only with partsCounts). */
export function dynamicSummary(counts: PairCounts, parts?: PartsCounts): string {
  const base = `${counts.dynamic} dynamic`;
  return parts ? `${base}, ${parts.dynamic} in excerpts of composite fields` : base;
}

// ---- Origin confidence ("possible origin" × "observed origin") ----

export type OriginConfidence = "strong" | "possible" | "none";

/** "Observed origin" requires strong evidence; only medium = "possible origin". */
export function originConfidence(value: ValueOrigin): OriginConfidence {
  if (value.confidence === "strong" || value.confidence === "possible") return value.confidence;
  if (value.status.startsWith("possible")) return "possible";
  if (value.status === "origin" || value.status === "ambiguous") {
    if (value.evidences.length === 0) return value.status === "origin" ? "strong" : "none";
    return value.evidences.some((ev) => ev.strength === "strong") ? "strong" : "possible";
  }
  return "none";
}

export function stepConfidence(step: ChainStep): "strong" | "possible" {
  if (step.confidence === "strong" || step.confidence === "possible") return step.confidence;
  return step.reasons.some((reason) => reason.strength === "strong") ? "strong" : step.reasons.length === 0 ? "strong" : "possible";
}

// ---- Round 6: HTML controls, static context, suggestion, partial composition ----

/** Producer label: HTML form control, when applicable. */
export function producerKindLabel(ev: Evidence): string | null {
  return ev.htmlControl ? `HTML form control (${ev.field ?? "?"})` : null;
}

export const CONTEXT_LABEL = "also present in a static resource: likely a protocol constant";

export function partialCompositionText(value: ValueOrigin): string | null {
  const pc = value.partialComposition;
  if (!pc || (Array.isArray(pc) && pc.length === 0)) return null;
  if (typeof pc === "string") return pc;
  // The core already writes the label ("no observed origin; contains the value of <field> from <producer> …").
  // The legacy Portuguese label ("sem origem observada … composição …") is still accepted.
  if (value.label.includes("composition") || value.label.includes("composição")) return value.label;
  const first = pc[0];
  return `no observed origin; contains ${first.field ?? "a field"} from ${first.producerRequestId} + part with no observed source — probable composition in the client`;
}

/** Warnings worth highlighting (missing cookies in the HAR, etc.), without repeats. */
export function highlightedWarnings(...lists: (string[] | undefined)[]): string[] {
  const seen = new Set<string>();
  for (const list of lists) for (const text of list ?? []) seen.add(text);
  return [...seen].sort((a, b) => Number(isCookiesAbsent(b)) - Number(isCookiesAbsent(a)));
}

export function isCookiesAbsent(text: string): boolean {
  return text.includes("har.cookies_absent") || text.includes("does not contain cookies") || text.includes("não contém cookies");
}

/** Groups a page's pairs by round: header when the round changes. */
export function roundHeader(round: number | undefined, previous: number | undefined, rounds?: RoundInfo[]): string | null {
  if (round === undefined || round === previous) return null;
  const info = rounds?.[round];
  return info
    ? `Round ${round + 1}: A#${info.aRound + 1} ↔ B#${info.bRound + 1} · ${info.aRequests} × ${info.bRequests} requests · ${info.score} model(s) in common`
    : `Round ${round + 1}`;
}
