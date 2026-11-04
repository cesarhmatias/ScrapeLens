import * as React from "react";
import type { CookieSourceDto } from "./bridge";

export function CookieSourceSelect({ sources, value, startUrl, disabled, onChange }: {
  sources: CookieSourceDto[];
  value: string;
  startUrl: string;
  disabled: boolean;
  onChange: (value: string) => void;
}): React.ReactElement {
  const needsUrl = !!value && !startUrl.trim();
  const hint = needsUrl
    ? "Informe a URL inicial (https://…) para importar os cookies do site. Com URL vazia, a captura usa sessão limpa."
    : "Importar apenas os cookies do site da URL inicial a partir deste perfil de navegador.";
  return (
    <label className="cookie-source-field" title={hint}>
      <span className="start-url-label">Cookies</span>
      <select className="cookie-source-select" aria-label="Importar cookies do navegador"
        value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}
        aria-describedby={needsUrl ? "cookie-source-hint" : undefined}>
        <option value="">Sem cookies (sessão limpa)</option>
        {sources.map((source) => <option key={source.id} value={source.id}>{source.label}</option>)}
      </select>
      {needsUrl && <span id="cookie-source-hint" className="cookie-source-hint">Informe a URL inicial para importar cookies.</span>}
    </label>
  );
}
