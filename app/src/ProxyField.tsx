import * as React from "react";
import { PROXY_PLACEHOLDER, proxyFieldView, proxyStatusText, type ProxyState } from "./proxyRules";

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
  const status = proxyStatusText(state);
  const hasDraft = draft.trim().length > 0;
  // The input is for a NEW link only: the state is stated on the status line, not in the placeholder.
  const placeholder = view.kind === "empty" ? PROXY_PLACEHOLDER : "Type a new link to replace it";
  return (
    <div className="proxy-field">
      <div className="proxy-label-row">
        <label className="start-url-label" htmlFor="scrapelens-proxy">Proxy</label>
        {view.kind !== "empty" && (
          <button
            type="button"
            className="proxy-clear"
            disabled={disabled}
            onClick={onClear}
            aria-label="Clear the proxy"
          >
            Clear
          </button>
        )}
      </div>
      <span
        id="scrapelens-proxy-status"
        className={`proxy-status proxy-status-${status.tone}`}
        data-testid="proxy-status"
        role="status"
      >
        <span className="proxy-dot" aria-hidden="true" />
        <span className="proxy-status-text">{status.text}</span>
      </span>
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
          aria-describedby="scrapelens-proxy-status scrapelens-proxy-hint"
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
      </div>
      <span id="scrapelens-proxy-hint" className="proxy-hint">
        {error ? (
          <span className="proxy-error">{error}</span>
        ) : view.kind === "empty" ? (
          "Optional: HTTP, HTTPS, SOCKS5 or host:port:user:password."
        ) : null}
      </span>
    </div>
  );
}
