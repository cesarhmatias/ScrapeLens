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
    ? "Enter the start URL (https://…) to import the site's cookies. With an empty URL, capture uses a clean session."
    : "Import only the cookies for the start URL's site from this browser profile.";
  return (
    <label className="cookie-source-field" title={hint}>
      <span className="start-url-label">Cookies</span>
      <select className="cookie-source-select" aria-label="Import cookies from browser"
        value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}
        aria-describedby={needsUrl ? "cookie-source-hint" : undefined}>
        <option value="">No cookies (clean session)</option>
        {sources.map((source) => <option key={source.id} value={source.id}>{source.label}</option>)}
      </select>
      {needsUrl && <span id="cookie-source-hint" className="cookie-source-hint">Enter the start URL to import cookies.</span>}
    </label>
  );
}
