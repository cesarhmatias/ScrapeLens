// Regras puras da lista e da barra de sessão (testadas em scripts/list-view.test.ts).

export type FilterState = {
  query: string;
  typeFilter: string;
  targetFilter: string;
  protocol: string;
  failFilter: boolean;
  blockFilter: boolean;
};

/** Chip de filtro por avaliação: com contagem 0 e inativo, fica desabilitado (só esvaziaria a lista). */
export function outcomeChipDisabled(count: number, active: boolean): boolean {
  return count === 0 && !active;
}

/** Nomes dos filtros ativos, para o estado vazio dizer por que a lista está vazia. */
export function activeFilterLabels(f: FilterState): string[] {
  const out: string[] = [];
  if (f.query.trim()) out.push(`busca “${f.query.trim()}”`);
  if (f.typeFilter !== "all") out.push(`tipo ${f.typeFilter}`);
  if (f.targetFilter !== "all") out.push(`alvo ${f.targetFilter}`);
  if (f.protocol !== "all") out.push(`protocolo ${f.protocol}`);
  if (f.failFilter) out.push("Falhas da aplicação");
  if (f.blockFilter) out.push("Possíveis bloqueios?");
  return out;
}

/**
 * O selo "gravando" pertence à captura, não à sessão exibida: só aparece junto do título
 * quando a sessão exibida é a pasta da gravação em andamento.
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
 * Páginas de `list_requests` necessárias para mostrar as linhas [start, end) e mais uma de folga.
 * Sem `matched` conhecido (antes da primeira resposta), só a página 0.
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

/** Lista paginada sob demanda para um filtro fixo: busca só as páginas pedidas, uma vez cada. */
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

  /** Linhas já carregadas, em ordem. */
  loadedRows(): Row[] {
    return [...this.pages.keys()].sort((a, b) => a - b).flatMap((p) => this.pages.get(p) ?? []);
  }

  ensure(start: number, end: number): void {
    if (this.dead || this.error) return;
    // Antes da primeira resposta só existe a página 0; não dispara a 1 às cegas.
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
