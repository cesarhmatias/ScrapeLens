/** Validação da URL inicial de captura (espelha src-tauri/src/cli.rs). */

export type CaptureUrlResult =
  | { ok: true; url: string }
  | { ok: false; error: string };

/** Vazio → about:blank; senão só http/https. */
export function resolveCaptureStartUrl(input: string | null | undefined): CaptureUrlResult {
  const trimmed = (input ?? "").trim();
  if (!trimmed) return { ok: true, url: "about:blank" };
  const check = validateHttpUrl(trimmed);
  if (!check.ok) return check;
  return { ok: true, url: trimmed };
}

export function validateHttpUrl(raw: string): CaptureUrlResult {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, error: "URL vazia" };
  if (/\s/.test(trimmed)) return { ok: false, error: "URL não pode conter espaços" };
  const lower = trimmed.toLowerCase();
  if (!(lower.startsWith("http://") || lower.startsWith("https://"))) {
    return { ok: false, error: "a URL inicial aceita só http:// ou https://" };
  }
  if (trimmed.length <= "http://".length || (lower.startsWith("https://") && trimmed.length <= "https://".length)) {
    return { ok: false, error: "URL incompleta" };
  }
  return { ok: true, url: trimmed };
}
