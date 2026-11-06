// Proxy field and session header rules (no credentials ever reach this module: the backend
// returns only the server address and whether the link is authenticated).
// Contract: /Users/cesar/OpenBot/Shared/sl-proxy-contract.md, section App.

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
