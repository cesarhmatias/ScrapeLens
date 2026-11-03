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
