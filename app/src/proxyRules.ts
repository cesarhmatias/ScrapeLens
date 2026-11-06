// Proxy field and session header rules (no credentials ever reach this module: the backend
// returns only the server address and whether the link is authenticated).
// Design notes: docs/22-proxy.md.

export interface ProxyInfo {
  serverUrl: string;
  scheme: string;
  host: string;
  port: number;
  authenticated: boolean;
}

export interface ProxyState {
  /** Server address saved in the preferences (`scheme://host:port`), if any. */
  saved: string | null;
  /** The link kept in memory for this run, if any. */
  active: ProxyInfo | null;
  /** Saved, but the password is not kept: the user types the link again. */
  needsLink: boolean;
}

/** Example only: the placeholder never holds a real host or credential. */
export const PROXY_PLACEHOLDER = "http://user:password@proxy.example:8080";

export type ProxyFieldView =
  | { kind: "empty" }
  | { kind: "active"; serverUrl: string; authenticated: boolean }
  | { kind: "needs-link"; serverUrl: string };

export function proxyFieldView(state: ProxyState | null): ProxyFieldView {
  if (!state) return { kind: "empty" };
  if (state.active) {
    return { kind: "active", serverUrl: state.active.serverUrl, authenticated: state.active.authenticated };
  }
  if (state.saved) return { kind: "needs-link", serverUrl: state.saved };
  return { kind: "empty" };
}

/**
 * The status line above the Proxy input: what is in use, stated in full (no placeholder).
 * Credentials are only mentioned as a fact, never shown.
 */
export function proxyStatusText(state: ProxyState | null): { tone: "on" | "warn" | "off"; text: string } {
  const view = proxyFieldView(state);
  if (view.kind === "active") {
    return {
      tone: "on",
      text: `Using ${view.serverUrl} · ${
        view.authenticated ? "with credentials (kept in memory until the app closes)" : "no credentials"
      }`,
    };
  }
  if (view.kind === "needs-link") {
    return {
      tone: "warn",
      text: `Saved ${view.serverUrl}. Enter the full link again to use it: the password is not kept.`,
    };
  }
  return { tone: "off", text: "No proxy: the capture connects directly." };
}

/** Why Start is blocked by the proxy, or `null` when it is not. */
export function proxyStartBlock(state: ProxyState | null, recording: boolean): string | null {
  if (recording || !state) return null;
  if (state.needsLink && state.saved) {
    return `The proxy ${state.saved} is saved, but its password is not kept between runs. Enter the link again first.`;
  }
  return null;
}

export interface ProxyRecordView {
  scheme: string;
  host?: string;
  port?: number;
  authenticated: boolean;
  route?: "direct" | "relay";
}

export interface ProxyHeaderView {
  /** `scheme://host:port` when the record has the address; otherwise only the scheme. */
  address: string;
  authenticated: boolean;
  routeText: string;
  /** Shown in every proxied session: a proxied capture never uses HTTP/3. */
  http3Note: string;
}

/**
 * Header of a session captured through a proxy. Sessions without `capture.proxy` (all
 * older sessions and every capture without a proxy) get `null` and show nothing new.
 */
export function proxyHeaderView(proxy: ProxyRecordView | null | undefined): ProxyHeaderView | null {
  if (!proxy) return null;
  const address = proxy.host && proxy.port !== undefined ? `${proxy.scheme}://${formatHost(proxy.host)}:${proxy.port}` : proxy.scheme;
  const routeText =
    proxy.route === "relay"
      ? "route: local relay (the app adds the credentials and the allowlist)"
      : proxy.route === "direct"
        ? "route: direct to the proxy"
        : "route: not recorded (sanitized export)";
  return {
    address,
    authenticated: proxy.authenticated,
    routeText,
    http3Note: "HTTP/3 is not used through a proxy, so the absence of h3 in this capture is not evidence.",
  };
}

function formatHost(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

/**
 * Export notice for a session captured through a proxy. The generated cURL, Python and
 * priming scripts do not use that proxy. The text never names the host or a credential.
 * Sessions without `capture.proxy` get `null`: their export is unchanged.
 */
export function scriptProxyNotice(proxy: ProxyRecordView | null | undefined): string | null {
  if (!proxy) return null;
  return "This session was captured through a proxy. The generated script does not use it: the request may leave from another IP and behave differently. Run it only if that is what you want.";
}

/** Notice in the Export / Sanitize dialog. The sanitized copy keeps the proxy only as recorded. */
export function sessionExportProxyNotice(proxy: ProxyRecordView | null | undefined): string | null {
  if (!proxy) return null;
  return "This session was captured through a proxy. Scripts made from this export (cURL, Python, priming) do not use that proxy.";
}
