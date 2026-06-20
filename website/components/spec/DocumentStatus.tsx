import type { Locale } from "@/lib/i18n";
import { t } from "@/lib/i18n";
import { getSpecMeta, formatSpecDate } from "@/lib/spec-meta";

interface DocumentStatusProps {
  locale: Locale;
  /**
   * If this status block lives on a non-canonical page (e.g. /governance),
   * pass the section anchor so readers know they're reading the version
   * applicable to that page (W3C does this on TR/* pages).
   */
  sectionHref?: string;
  /** Override the status (e.g. "Editor's Draft" on a preview page). */
  statusOverride?: string;
}

/**
 * Standards-document banner. Appears at the top of every spec-bearing page.
 * Pattern after W3C "Status of This Document" header strip.
 *
 *   [Working Draft · 3.5.0 · 26 May 2026 · /spec · Editor: Adam Lin]
 */
export function DocumentStatus({
  locale,
  sectionHref,
  statusOverride,
}: DocumentStatusProps) {
  const meta = getSpecMeta();
  const status = statusOverride ?? meta.status;
  const date = formatSpecDate(meta.lastModified);
  const canonicalLabel = t(locale, "spec.canonical");
  const versionLabel = t(locale, "spec.version");
  const dateLabel = t(locale, "spec.date");
  const editorLabel = t(locale, "spec.editor");

  return (
    <div className="doc-status not-prose" role="note" aria-label={t(locale, "spec.status_aria")}>
      <strong>{status}</strong>
      <span className="pipe">·</span>
      <span>
        <span className="opacity-70">{versionLabel}</span>{" "}
        <span className="tnum">{meta.version}</span>
      </span>
      <span className="pipe">·</span>
      <span>
        <span className="opacity-70">{dateLabel}</span> {date}
      </span>
      <span className="pipe">·</span>
      <span>
        <span className="opacity-70">{canonicalLabel}</span>{" "}
        <a href={`/${locale}/spec${sectionHref ?? ""}`}>
          /spec{sectionHref ?? ""}
        </a>
      </span>
      <span className="pipe">·</span>
      <span>
        <span className="opacity-70">{editorLabel}</span> {meta.editors[0].name}
      </span>
    </div>
  );
}
