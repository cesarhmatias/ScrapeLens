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
}

export interface Unobservable {
  requestId: string;
  state: string;
  reason?: string;
}

export interface ValueOrigin {
  scope: string;
  field: string;
  occurrence: number;
  value: string;
  length: number;
  /** origin | ambiguous | repeated | none | composite | redacted ... */
  status: string;
  label: string;
  offset: number | null;
  /** Índice, em `evidences`, do produtor mais antigo (se houver). */
  oldest: number | null;
  evidences: Evidence[];
  repeatedFrom: string[];
  unobservable?: Unobservable[];
  parent: string | null;
  note: string | null;
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
  unresolved: UnresolvedValue[];
  redactedValues: number;
  warnings: string[];
}

export interface RequestRef {
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

export interface PairComparison {
  a: RequestRef;
  b: RequestRef;
  alignedBy: string;
  outOfOrder: boolean;
  fields: FieldDiff[];
  counts: PairCounts;
}

export interface SessionComparison {
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
  switch (value.status) {
    case "origin":
      return "origem observada";
    case "ambiguous":
      return "ambíguo";
    case "repeated":
      return "sem origem observada (já circulava)";
    case "composite":
      return "composto (ver trechos)";
    case "redacted":
      return "redigido (não rastreável)";
    default:
      return "sem origem observada";
  }
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
