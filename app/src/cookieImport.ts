// Cookie import of a live capture (`Capture.cookiesImported`, read by src-tauri/src/cookie_import.rs).
// Only counts and the reason come from the capture; cookie values are never shown here.

export interface CookieImportReport {
  /** `initialCookies` when given in code; otherwise the browser label. */
  source: string;
  domain: string;
  importedCount: number;
  skippedCount: number;
  undecryptableCount: number;
  undecryptableReason?: string;
}

export interface CookieImportNotice {
  tone: "warning" | "info";
  title: string;
  detail: string;
  action?: string;
}

/**
 * What the user must see about the cookie import, or `null` when there is nothing to say.
 * Sessions from older captures have no report at all, so they show nothing new.
 */
export function cookieImportNotice(report: CookieImportReport | null | undefined): CookieImportNotice | null {
  if (!report) return null;
  if (report.undecryptableCount > 0) {
    return {
      tone: "warning",
      title: `${report.undecryptableCount} cookie(s) from ${report.source} could not be decrypted`,
      detail: `${report.importedCount} imported. ${report.undecryptableReason ?? "The capture gave no reason."}`,
      action: "Unlock the browser's keyring or profile, then capture again. This session may be logged out because of it.",
    };
  }
  if (report.source !== "initialCookies" && report.importedCount === 0) {
    return {
      tone: "info",
      title: `No cookies for ${report.domain} in ${report.source}`,
      detail: "The browser has no cookies for this site, so the session starts logged out. This is not an error.",
    };
  }
  return null;
}
