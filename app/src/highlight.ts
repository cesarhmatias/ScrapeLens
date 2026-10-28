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

/** Sem `byteLength` não há intervalo confiável: o achado não é realçado. */
export function matchRanges(text: string, matches: RangeMatch[]): { ranges: TextRange[]; beyond: number } {
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
    ranges.push({
      start: decoder.decode(bytes.subarray(0, match.byteOffset)).length,
      end: decoder.decode(bytes.subarray(0, end)).length,
      decoded: match.decoded || match.exact === false,
    });
  }
  ranges.sort((a, b) => a.start - b.start);
  return { ranges, beyond };
}
