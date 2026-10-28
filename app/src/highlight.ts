// Intervalos de realce a partir dos achados do core. O core informa bytes UTF-8
// no original; o texto exibido é uma string JS (UTF-16), então convertemos.

export interface RangeMatch {
  byteOffset: number | null;
  byteLength?: number;
  decoded: boolean;
  exact?: boolean;
}

export interface TextRange {
  start: number;
  end: number;
  decoded: boolean;
}

/**
 * Realce tracejado (derivado) só quando o intervalo não é um trecho literal:
 * `exact === false`, ou o texto no intervalo difere do texto buscado (ex.:
 * percent-encoded). Com `exact === true` e trecho igual, o realce é sólido.
 */
function isDerived(match: RangeMatch, slice: string, needle: string | undefined, caseSensitive: boolean): boolean {
  if (match.exact === false) return true;
  if (match.exact === undefined) return match.decoded;
  if (needle === undefined) return false;
  return caseSensitive ? slice !== needle : slice.toLowerCase() !== needle.toLowerCase();
}

/** Sem `byteLength` não há intervalo confiável: o achado não é realçado. */
export function matchRanges(
  text: string,
  matches: RangeMatch[],
  needle?: string,
  caseSensitive = false,
): { ranges: TextRange[]; beyond: number } {
  const bytes = new TextEncoder().encode(text);
  const decoder = new TextDecoder();
  const ranges: TextRange[] = [];
  let beyond = 0;
  for (const match of matches) {
    if (match.byteOffset === null || match.byteLength === undefined) continue;
    const end = match.byteOffset + match.byteLength;
    if (end > bytes.length) {
      beyond += 1;
      continue;
    }
    const start = decoder.decode(bytes.subarray(0, match.byteOffset)).length;
    const endIdx = decoder.decode(bytes.subarray(0, end)).length;
    ranges.push({
      start,
      end: endIdx,
      decoded: isDerived(match, text.slice(start, endIdx), needle, caseSensitive),
    });
  }
  ranges.sort((a, b) => a.start - b.start);
  return { ranges, beyond };
}
