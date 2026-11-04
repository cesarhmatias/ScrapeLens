// Highlight ranges derived from the core's findings. The core reports UTF-8 bytes
// in the original; the displayed text is a JS string (UTF-16), so we convert.

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
 * Dashed (derived) highlight only when the range is not a literal excerpt:
 * `exact === false`, or the text in the range differs from the searched text (e.g.
 * percent-encoded). With `exact === true` and an identical excerpt, the highlight is solid.
 */
function isDerived(match: RangeMatch, slice: string, needle: string | undefined, caseSensitive: boolean): boolean {
  if (match.exact === false) return true;
  if (match.exact === undefined) return match.decoded;
  if (needle === undefined) return false;
  return caseSensitive ? slice !== needle : slice.toLowerCase() !== needle.toLowerCase();
}

/** Without `byteLength` there is no reliable range: the finding is not highlighted. */
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
