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

export const MAX_URL_LEN = 2048;

/** Caracteres Unicode Cf recusados; mesma lista de `is_invisible_format` em src-tauri/src/cli.rs (autoridade). */
export function isInvisibleFormat(cp: number): boolean {
  const ranges: Array<[number, number]> = [
    [0x00ad, 0x00ad], [0x0600, 0x0605], [0x061c, 0x061c], [0x06dd, 0x06dd], [0x070f, 0x070f],
    [0x0890, 0x0891], [0x08e2, 0x08e2], [0x180e, 0x180e], [0x200b, 0x200f], [0x202a, 0x202e],
    [0x2060, 0x2064], [0x2066, 0x206f], [0xfeff, 0xfeff], [0xfff9, 0xfffb], [0x110bd, 0x110bd],
    [0x110cd, 0x110cd], [0x13430, 0x1343f], [0x1bca0, 0x1bca3], [0x1d173, 0x1d17a],
    [0xe0001, 0xe0001], [0xe0020, 0xe007f],
  ];
  return ranges.some(([a, b]) => cp >= a && cp <= b);
}

/** Controle Unicode (Cc), como `char::is_control` do Rust. */
function isControl(cp: number): boolean {
  return cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f);
}

function splitHttpUrl(trimmed: string): { scheme: string; authority: string; path: string } | null {
  const lower = trimmed.toLowerCase();
  const schemeLen = lower.startsWith("http://") ? 7 : lower.startsWith("https://") ? 8 : 0;
  if (!schemeLen) return null;
  const rest = trimmed.slice(schemeLen);
  const authEnd = rest.search(/[/?#]/);
  const authority = authEnd < 0 ? rest : rest.slice(0, authEnd);
  const after = authEnd < 0 ? "" : rest.slice(authEnd);
  const pathEnd = after.search(/[?#]/);
  return { scheme: trimmed.slice(0, schemeLen), authority, path: pathEnd < 0 ? after : after.slice(0, pathEnd) };
}

function validPort(port: string | undefined): boolean {
  if (port === undefined) return true;
  return /^\d{1,5}$/.test(port) && Number(port) <= 65535;
}

export function validateHttpUrl(raw: string): CaptureUrlResult {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, error: "URL vazia" };
  const cps = Array.from(trimmed, (c) => c.codePointAt(0) ?? 0);
  if (cps.length > MAX_URL_LEN) return { ok: false, error: `URL maior que ${MAX_URL_LEN} caracteres` };
  if (cps.some(isControl)) return { ok: false, error: "URL não pode conter caracteres de controle" };
  if (/\s/u.test(trimmed) || cps.some((cp) => cp === 0x85 || cp === 0x1680 || (cp >= 0x2000 && cp <= 0x200a) || cp === 0x2028 || cp === 0x2029 || cp === 0x202f || cp === 0x205f || cp === 0x3000)) {
    return { ok: false, error: "URL não pode conter espaços" };
  }
  if (cps.some(isInvisibleFormat)) return { ok: false, error: "URL não pode conter caracteres invisíveis" };
  const parts = splitHttpUrl(trimmed);
  if (!parts) return { ok: false, error: "a URL inicial aceita só http:// ou https://" };
  if (parts.authority.includes("@")) return { ok: false, error: "URL com usuário/senha (user@host) não é aceita" };
  let host: string;
  if (parts.authority.startsWith("[")) {
    const close = parts.authority.indexOf("]");
    if (close < 0) return { ok: false, error: "host IPv6 malformado" };
    const tail = parts.authority.slice(close + 1);
    if (!(tail === "" || tail.startsWith(":"))) return { ok: false, error: "host IPv6 malformado" };
    if (!validPort(tail.startsWith(":") ? tail.slice(1) : undefined)) return { ok: false, error: "porta inválida na URL" };
    host = parts.authority.slice(1, close);
  } else {
    const colon = parts.authority.lastIndexOf(":");
    const port = colon < 0 ? undefined : parts.authority.slice(colon + 1);
    if (!validPort(port)) return { ok: false, error: "porta inválida na URL" };
    host = colon < 0 ? parts.authority : parts.authority.slice(0, colon);
  }
  if (!host) return { ok: false, error: "URL sem host" };
  return { ok: true, url: trimmed };
}

/** Forma persistida: só esquema, host, porta e caminho (sem query/fragmento). */
export function persistableUrl(raw: string): CaptureUrlResult {
  const check = validateHttpUrl(raw);
  if (!check.ok) return check;
  const parts = splitHttpUrl(check.url)!;
  return { ok: true, url: parts.scheme + parts.authority + parts.path };
}
