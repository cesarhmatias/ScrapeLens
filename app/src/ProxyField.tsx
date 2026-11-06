import * as React from "react";
import { PROXY_PLACEHOLDER, proxyFieldView, type ProxyState } from "./proxyRules";

/**
 * The Proxy field next to Start URL and Cookies. The typed text lives only in `draft`
 * until the backend accepts it; then the backend keeps the credentials and the field
 * shows the server address only.
 */
export function ProxyField({ state, draft, error, disabled, onDraftChange, onApply, onClear }: {
  state: ProxyState | null;
  draft: string;
  error: string | null;
  disabled: boolean;
  onDraftChange: (value: string) => void;
  onApply: () => void;
  onClear: () => void;
}): React.ReactElement {
  const view = proxyFieldView(state);
  const hasDraft = draft.trim().length > 0;
  const placeholder =
    view.kind === "empty" ? PROXY_PLACEHOLDER : view.serverUrl;
  const hint =
    view.kind === "active"
      ? view.authenticated
        ? "Credentials kept in memory until the app closes."
        : "No credentials. Enter a link to change it."
      : view.kind === "needs-link"
        ? "Saved address. Enter the full link again: the password is not kept."
        : "Optional: HTTP, HTTPS, SOCKS5 or host:port:user:password.";
  return (
    <div className="proxy-field">
      <label className="start-url-label" htmlFor="scrapelens-proxy">Proxy</label>
      <div className="proxy-row">
        <input
          id="scrapelens-proxy"
          className="proxy-input mono"
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder={placeholder}
          value={draft}
          disabled={disabled}
          aria-label="Capture proxy link"
          aria-invalid={!!error}
          aria-describedby="scrapelens-proxy-hint"
          onChange={(event) => onDraftChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && hasDraft) {
              event.preventDefault();
              onApply();
            }
          }}
        />
        <button
          type="button"
          className="ghost-btn small"
          disabled={disabled || !hasDraft}
          onClick={onApply}
          aria-label="Use this proxy"
        >
          Use
        </button>
        {view.kind !== "empty" && (
          <button
            type="button"
            className="ghost-btn small"
            disabled={disabled}
            onClick={onClear}
            aria-label="Clear the proxy"
          >
            Clear
          </button>
        )}
      </div>
      <span id="scrapelens-proxy-hint" className={`proxy-hint${view.kind === "needs-link" ? " proxy-hint-warn" : ""}`}>
        {error ? <span className="proxy-error">{error}</span> : hint}
      </span>
    </div>
  );
}
