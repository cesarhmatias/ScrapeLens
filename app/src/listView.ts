// Pure rules for the list and the session bar (tested in scripts/list-view.test.ts).

export type FilterState = {
  query: string;
  typeFilter: string;
  targetFilter: string;
  protocol: string;
  failFilter: boolean;
  blockFilter: boolean;
};

/** Verdict filter chip: with a count of 0 and inactive, it is disabled (it would only empty the list). */
export function outcomeChipDisabled(count: number, active: boolean): boolean {
  return count === 0 && !active;
}

/** Names of the active filters, so the empty state can say why the list is empty. */
export function activeFilterLabels(f: FilterState): string[] {
  const out: string[] = [];
  if (f.query.trim()) out.push(`search “${f.query.trim()}”`);
  if (f.typeFilter !== "all") out.push(`type ${f.typeFilter}`);
  if (f.targetFilter !== "all") out.push(`target ${f.targetFilter}`);
  if (f.protocol !== "all") out.push(`protocol ${f.protocol}`);
  if (f.failFilter) out.push("Application failures");
  if (f.blockFilter) out.push("Possible blocks?");
  return out;
}

/**
 * The "recording" badge belongs to the capture, not to the displayed session: it only appears
 * next to the title when the displayed session is the folder of the recording in progress.
 */
export function sessionIsRecording(
  displayed: { sourcePath?: string; synthetic?: boolean },
  recording: { sessionDir: string } | null,
): boolean {
  if (!recording || displayed.synthetic || !displayed.sourcePath) return false;
  const norm = (p: string) => p.replace(/\/+$/, "");
  return norm(displayed.sourcePath) === norm(recording.sessionDir);
}

/**
 * `list_requests` pages needed to show rows [start, end) plus one spare page.
 * Without a known `matched` (before the first response), only page 0.
 */
export function pagesFor(start: number, end: number, matched: number | undefined, pageSize: number): number[] {
  if (matched === undefined) return [0];
  if (matched === 0) return [];
  const first = Math.floor(Math.max(0, start) / pageSize);
  const last = Math.floor(Math.max(start, end - 1, 0) / pageSize) + 1;
  const out: number[] = [];
  for (let p = first; p <= last && p * pageSize < matched; p++) out.push(p);
  return out;
}

/** On-demand paged list for a fixed filter: fetches only the requested pages, once each. */
export class PagedList<Row, Meta extends { matched: number }> {
  readonly pages = new Map<number, Row[]>();
  private readonly inflight = new Set<number>();
  meta?: Meta;
  error?: string;
  calls = 0;
  private dead = false;

  constructor(
    private readonly fetchPage: (offset: number, limit: number) => Promise<{ meta: Meta; rows: Row[] }>,
    readonly pageSize: number,
    private readonly onChange: () => void,
  ) {}

  get length(): number {
    return this.meta?.matched ?? 0;
  }

  row(index: number): Row | undefined {
    return this.pages.get(Math.floor(index / this.pageSize))?.[index % this.pageSize];
  }

  /** Rows already loaded, in order. */
  loadedRows(): Row[] {
    return [...this.pages.keys()].sort((a, b) => a - b).flatMap((p) => this.pages.get(p) ?? []);
  }

  ensure(start: number, end: number): void {
    if (this.dead || this.error) return;
    // Before the first response only page 0 exists; do not blindly fire page 1.
    if (this.meta === undefined && this.inflight.size > 0) return;
    for (const page of pagesFor(start, end, this.meta?.matched, this.pageSize)) {
      if (this.pages.has(page) || this.inflight.has(page)) continue;
      this.inflight.add(page);
      this.calls++;
      this.fetchPage(page * this.pageSize, this.pageSize).then(
        ({ meta, rows }) => {
          this.inflight.delete(page);
          if (this.dead) return;
          this.meta = meta;
          this.pages.set(page, rows);
          this.onChange();
        },
        (error) => {
          this.inflight.delete(page);
          if (this.dead) return;
          this.error = String(error);
          this.onChange();
        },
      );
    }
  }

  dispose(): void {
    this.dead = true;
  }
}

/** macOS shows ⌘/⇧; Linux and Windows show Ctrl+/Shift+. */
export const IS_MAC = typeof navigator !== "undefined" && /Mac/i.test(navigator.platform || navigator.userAgent);

/** Shortcut label from "⌘⇧R" (the canonical form used in the code). */
export function shortcutLabel(mac: string, isMac: boolean = IS_MAC): string {
  if (isMac) return mac;
  return mac.replace(/⌘/g, "Ctrl+").replace(/⇧/g, "Shift+");
}

/** Name of the platform's file manager. */
export const FILE_MANAGER = IS_MAC ? "Finder" : "file manager";
