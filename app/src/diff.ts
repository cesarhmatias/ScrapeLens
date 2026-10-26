import type { CookiePair, HeaderPair } from "./types";

export type DiffKind = "same" | "added" | "removed" | "changed" | "reordered";

export interface HeaderDiffRow {
  key: string;
  name: string;
  a?: HeaderPair;
  b?: HeaderPair;
  kind: DiffKind;
}

export interface HeaderDiff {
  rows: HeaderDiffRow[];
  counts: Record<Exclude<DiffKind, "same">, number>;
}

/**
 * Diff de headers por NOME, com pares repetidos casados por VALOR (multiconjunto),
 * nunca por posição. "reordenado" = mesmo par presente nos dois lados, com a
 * ordem relativa invertida em relação a outro par estável.
 */
export function diffHeaders(a: HeaderPair[], b: HeaderPair[]): HeaderDiff {
  const names: string[] = [];
  const seen = new Set<string>();
  for (const h of [...a, ...b]) {
    if (!seen.has(h.name)) {
      seen.add(h.name);
      names.push(h.name);
    }
  }

  const rows: HeaderDiffRow[] = [];
  let r = 0;

  for (const name of names) {
    const aList = a.filter((h) => h.name === name);
    const bList = b.filter((h) => h.name === name);
    const usedB = new Set<number>();

    // 1. casamento exato nome+valor (preserva duplicatas legítimas)
    const matched: { a: HeaderPair; b: HeaderPair }[] = [];
    const restA: HeaderPair[] = [];
    for (const ah of aList) {
      const idx = bList.findIndex((bh, i) => !usedB.has(i) && bh.value === ah.value);
      if (idx >= 0) {
        usedB.add(idx);
        matched.push({ a: ah, b: bList[idx] });
      } else {
        restA.push(ah);
      }
    }
    const restB = bList.filter((_, i) => !usedB.has(i));

    const rowsForName: HeaderDiffRow[] = [];
    for (const m of matched) {
      rowsForName.push({ key: `${name}-${r++}`, name, a: m.a, b: m.b, kind: "same" });
    }
    // 2. sobras: mesmo nome nos dois lados = valor alterado; senão adicionado/removido
    const maxRest = Math.max(restA.length, restB.length);
    for (let i = 0; i < maxRest; i += 1) {
      const ah = restA[i];
      const bh = restB[i];
      const kind: DiffKind = ah && bh ? "changed" : ah ? "removed" : "added";
      rowsForName.push({ key: `${name}-${r++}`, name, a: ah, b: bh, kind });
    }
    rows.push(...rowsForName);
  }

  // 3. reordenação por ordem relativa entre pares iguais
  const sameRows = rows.filter((row) => row.kind === "same" && row.a && row.b);
  for (const p of sameRows) {
    for (const q of sameRows) {
      if (p === q || !p.a || !p.b || !q.a || !q.b) continue;
      const aDelta = p.a.index - q.a.index;
      const bDelta = p.b.index - q.b.index;
      if (aDelta * bDelta < 0) {
        p.kind = "reordered";
        q.kind = "reordered";
      }
    }
  }

  const counts = { added: 0, removed: 0, changed: 0, reordered: 0 };
  for (const row of rows) {
    if (row.kind !== "same") counts[row.kind] += 1;
  }
  return { rows, counts };
}

export interface CookieDiffRow {
  key: string;
  name: string;
  a?: CookiePair;
  b?: CookiePair;
  kind: DiffKind;
}

export function diffCookies(a: CookiePair[], b: CookiePair[]): CookieDiffRow[] {
  const names: string[] = [];
  for (const c of [...a, ...b]) if (!names.includes(c.name)) names.push(c.name);
  const rows: CookieDiffRow[] = [];
  for (const name of names) {
    const aList = a.filter((c) => c.name === name);
    const bList = b.filter((c) => c.name === name);
    const used = new Set<number>();
    const remnantsA: CookiePair[] = [];
    for (const ac of aList) {
      const i = bList.findIndex((bc, idx) => !used.has(idx) && bc.value === ac.value);
      if (i >= 0) {
        used.add(i);
        rows.push({ key: `${name}-${rows.length}`, name, a: ac, b: bList[i], kind: "same" });
      } else {
        remnantsA.push(ac);
      }
    }
    const remnantsB = bList.filter((_, i) => !used.has(i));
    for (let i = 0; i < Math.max(remnantsA.length, remnantsB.length); i += 1) {
      const ac = remnantsA[i];
      const bc = remnantsB[i];
      rows.push({
        key: `${name}-${rows.length}`,
        name,
        a: ac,
        b: bc,
        kind: ac && bc ? "changed" : ac ? "removed" : "added",
      });
    }
  }
  return rows;
}

export interface NormalizedHeader {
  name: string;
  values: string[];
  count: number;
}

/** Visão derivada: agrupada por nome, ordenada, duplicatas preservadas e contadas. */
export function normalizeHeaders(pairs: HeaderPair[]): NormalizedHeader[] {
  const map = new Map<string, string[]>();
  for (const p of pairs) {
    const list = map.get(p.name) ?? [];
    list.push(p.value);
    map.set(p.name, list);
  }
  return [...map.entries()]
    .map(([name, values]) => ({ name, values, count: values.length }))
    .sort((x, y) => x.name.localeCompare(y.name));
}

export const kindLabel: Record<DiffKind, string> = {
  same: "igual",
  added: "adicionado",
  removed: "removido",
  changed: "alterado",
  reordered: "reordenado",
};
