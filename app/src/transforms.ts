// Body transformations (Body.transformed). `chrome-decoded` is universal in
// text responses (CDP delivers the body already decoded): it becomes just a note.
// Any other (charset:*, lossy-postData, unknown) is a warning.

export interface TransformView {
  /** Transformations that make the body meaningfully different from the wire bytes. */
  warn: string[];
  /** true if `chrome-decoded` was present. */
  chromeDecoded: boolean;
}

export function classifyTransforms(transformed: string[] | undefined): TransformView {
  const list = transformed ?? [];
  return { warn: list.filter((item) => item !== "chrome-decoded"), chromeDecoded: list.includes("chrome-decoded") };
}
