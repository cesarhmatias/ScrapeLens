// Projeção TypeScript da saída do core: flow::value_origins, flow::priming_chain
// e compare::compare_sessions (docs/09-cadeia-comparacao.md). A UI só exibe o
// que o core devolve; "value-match" nunca é apresentado como certeza.

export type EvidenceKind = "cookie-jar" | "same-field" | "value-match" | "initiator" | string;
export type Strength = "strong" | "medium" | "weak" | string;

export interface Evidence {
  kind: EvidenceKind;
  strength: Strength;
  /** produced = 1º produtor; reissued = reaparece depois. */
  role: string;
  producerRequestId: string;
  producerAttemptId: string;
  scope: string;
  field: string | null;
  producerOffset: number | null;
  consumedOffset: number | null;
  consumedLength: number | null;
  /** O produtor é um controle de formulário HTML (input/textarea/select). */
  htmlControl?: boolean;
}

export interface Unobservable {
  requestId: string;
  state: string;
  reason?: string;
  /** Ocorrência equivalente (mesmo modelo) mais adiante com corpo observável. */
  suggestion?: string | null;
}

export interface ContextNote {
  requestId: string;
  field: string | null;
  note: string;
}

/** Valor de um produtor à borda do campo; o resto não tem fonte observada. */
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
  /** `strong` | `possible` | null (core ≥ revisão 5); ausente em esquemas antigos. */
  confidence?: "strong" | "possible" | string | null;
  label: string;
  offset: number | null;
  /** Índice, em `evidences`, do produtor mais antigo (se houver). */
  oldest: number | null;
  evidences: Evidence[];
  repeatedFrom: string[];
  unobservable?: Unobservable[];
  parent: string | null;
  note: string | null;
  /** Valor também presente em recurso estático: provável constante do protocolo. */
  context?: ContextNote[];
  /** Composição parcial (core ≥ 6b): parte com fonte + parte sem fonte. */
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
  /** `strong` | `possible` (core ≥ revisão 5); ausente em esquemas antigos. */
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
  /** Páginas de contexto (Referer): nunca produtoras. */
  pages?: ChainStep[];
  /** Frames auxiliares carregados por parser (fora de `pages`). */
  auxiliaryPages?: ChainStep[];
  unresolved: UnresolvedValue[];
  redactedValues: number;
  warnings: string[];
}

export interface RequestRef {
  /** Marca opcional do core: requisição única reordenada (nome ainda não fixado). */
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
  "cookie-jar": "cookie-jar (Set-Cookie anterior com o mesmo nome e valor)",
  "same-field": "same-field (mesmo nome de campo e valor)",
  "value-match": "value-match (valor encontrado, sem garantia de causa)",
  initiator: "initiator (complementar; não prova origem)",
};

export const strengthLabels: Record<string, string> = { strong: "forte", medium: "média", weak: "fraca" };

/** Rótulo de status em português; "sem origem observada" é neutro, nunca erro. */
export function originStatusLabel(value: ValueOrigin): string {
  const confidence = originConfidence(value);
  // Rótulo do core, quando informa a confiança (garante os mesmos textos do core).
  if ((value.status === "origin" || value.status === "ambiguous") && value.confidence && value.label) return value.label;
  const kind = (oldestEvidence(value) ?? value.evidences[0])?.kind;
  switch (value.status) {
    case "repeated":
      return "sem origem observada (já circulava)";
    case "composite":
      return "composto (ver trechos)";
    case "redacted":
      return "redigido (não rastreável)";
    case "none":
      return "sem origem observada";
    default:
      break;
  }
  if (value.status === "ambiguous") return confidence === "possible" ? "ambíguo (possível origem)" : "ambíguo";
  if (confidence === "possible") return `possível origem (${kind ?? "evidência média"})`;
  if (confidence === "strong") return "origem observada";
  return "sem origem observada";
}

/** Evidência do produtor mais antigo, quando `oldest` aponta para uma. */
export function oldestEvidence(value: ValueOrigin): Evidence | undefined {
  return value.oldest === null ? undefined : value.evidences[value.oldest];
}

/** Valores de trecho (filhos de um campo opaco) agrupados sob o pai. */
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

/** Filtro "só dinâmicos": pares sem campos dinâmicos somem; campos ficam na ordem da fonte. */
export function dynamicOnly(pairs: PairComparison[]): PairComparison[] {
  return pairs
    .map((pair) => ({ ...pair, fields: pair.fields.filter((field) => field.class !== "static") }))
    .filter((pair) => pair.fields.length > 0);
}

export function fieldClassLabel(field: FieldDiff): string {
  if (field.class === "static") return "estático";
  if (field.dynamicKind === "runtime") return field.originLabel || "obter em runtime";
  if (field.dynamicKind === "noOrigin") return "dinâmico sem origem";
  if (field.dynamicKind === "repeated") return "dinâmico (já circulava, sem produtor observado)";
  if (field.dynamicKind === "composite") return "dinâmico composto (ver trechos)";
  return field.label;
}

// ---- Comparação paginada (commands compare_open / compare_page / compare_fields) ----

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
  /** Índice em `rounds`. */
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

/** Acima deste número de pares, "só dinâmicos" começa ligado. */
export const DYNAMIC_ONLY_THRESHOLD = 500;

export function visibleFields(fields: FieldDiff[], onlyDynamic: boolean): FieldDiff[] {
  return onlyDynamic ? fields.filter((field) => field.class !== "static") : fields;
}

/** "N dinâmicos, sendo M em trechos de campos compostos" (só com partsCounts). */
export function dynamicSummary(counts: PairCounts, parts?: PartsCounts): string {
  const base = `${counts.dynamic} dinâmico(s)`;
  return parts ? `${base}, sendo ${parts.dynamic} em trechos de campos compostos` : base;
}

// ---- Confiança da origem ("possível origem" × "origem observada") ----

export type OriginConfidence = "strong" | "possible" | "none";

/** "Origem observada" exige evidência forte; só média = "possível origem". */
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

// ---- Rodada 6: controles HTML, contexto estático, sugestão, composição parcial ----

/** Rótulo do produtor: controle de formulário HTML, quando aplicável. */
export function producerKindLabel(ev: Evidence): string | null {
  return ev.htmlControl ? `controle de formulário HTML (${ev.field ?? "?"})` : null;
}

export const CONTEXT_LABEL = "também presente em recurso estático: provável constante do protocolo";

export function partialCompositionText(value: ValueOrigin): string | null {
  const pc = value.partialComposition;
  if (!pc || (Array.isArray(pc) && pc.length === 0)) return null;
  if (typeof pc === "string") return pc;
  // O core já escreve o rótulo ("sem origem observada; contém o valor de <campo> de <produtor> …").
  if (value.label.includes("composição")) return value.label;
  const first = pc[0];
  return `sem origem observada; contém ${first.field ?? "um campo"} de ${first.producerRequestId} + parte sem fonte — provável composição no cliente`;
}

/** Avisos que merecem destaque (cookies ausentes no HAR etc.), sem repetir. */
export function highlightedWarnings(...lists: (string[] | undefined)[]): string[] {
  const seen = new Set<string>();
  for (const list of lists) for (const text of list ?? []) seen.add(text);
  return [...seen].sort((a, b) => Number(isCookiesAbsent(b)) - Number(isCookiesAbsent(a)));
}

export function isCookiesAbsent(text: string): boolean {
  return text.includes("har.cookies_absent") || text.includes("não contém cookies");
}

/** Agrupa pares de uma página por rodada: cabeçalho quando a rodada muda. */
export function roundHeader(round: number | undefined, previous: number | undefined, rounds?: RoundInfo[]): string | null {
  if (round === undefined || round === previous) return null;
  const info = rounds?.[round];
  return info
    ? `Rodada ${round + 1}: A#${info.aRound + 1} ↔ B#${info.bRound + 1} · ${info.aRequests} × ${info.bRequests} requisições · ${info.score} modelo(s) em comum`
    : `Rodada ${round + 1}`;
}
