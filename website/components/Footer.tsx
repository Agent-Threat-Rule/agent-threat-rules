import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import { getSpecMeta } from "@/lib/spec-meta";
import { loadVersionLabels, NPM_PACKAGE_URL } from "@/lib/versions";
import { FOOTER_EXTRA, NAV_GROUPS, pick } from "@/lib/site-nav";
import { Meander } from "@/components/classical/Emblem";

const REPO = "https://github.com/Agent-Threat-Rule/agent-threat-rules";

/**
 * Site index footer: the same five groups as the header, plus pages kept out
 * of the header, plus contact. The bottom row carries the three version labels
 * and the rule counts with what each counts.
 */
export async function Footer({ locale }: { locale: Locale }) {
  const prefix = `/${locale}`;
  const zh = locale === "zh";
  const stats = loadSiteStats();
  const specVersion = getSpecMeta().specVersion;
  const versions = await loadVersionLabels();
  const linkClass = "text-[13px] text-stone hover:text-ink transition-colors";

  return (
    <footer>
      <div className="sheet sheet-row px-8 md:px-12 pt-12 pb-8">
        <Meander className="text-fog mb-10" height={12} />
        <span className="corner-mark corner-mark-l" aria-hidden="true" />
        <span className="corner-mark corner-mark-r" aria-hidden="true" />
        <div className="font-data text-[10.5px] uppercase tracking-[0.12em] text-stone mb-10 leading-tight">
          <div>FIG. A</div>
          <div className="text-ink">{zh ? "網站索引" : "Site index"}</div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-x-8 gap-y-10">
          {NAV_GROUPS.map((group) => (
            <div key={group.key}>
              <div className="text-[13px] text-ink mb-3">{pick(group.label, locale)}</div>
              <ul className="flex flex-col gap-2">
                {group.links.map((link) => (
                  <li key={link.path}>
                    <Link href={`${prefix}${link.path}`} className={linkClass}>
                      {pick(link.label, locale)}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <div>
            <div className="text-[13px] text-ink mb-3">{zh ? "更多" : "More"}</div>
            <ul className="flex flex-col gap-2">
              {FOOTER_EXTRA.map((link) => (
                <li key={link.path}>
                  <Link href={`${prefix}${link.path}`} className={linkClass}>
                    {pick(link.label, locale)}
                  </Link>
                </li>
              ))}
              <li><a href={REPO} className={linkClass}>GitHub</a></li>
              <li><a href={NPM_PACKAGE_URL} className={linkClass}>npm</a></li>
              <li><a href="mailto:contact@agentthreatrule.org" className={linkClass}>contact@agentthreatrule.org</a></li>
            </ul>
          </div>
        </div>

        <div className="mt-12 pt-6 border-t border-fog flex flex-col md:flex-row md:items-center md:justify-between gap-3 font-data text-[11px] text-stone">
          <div className="flex items-center gap-3">
            <img src="/atr-logo-ink.png" alt="ATR" className="h-6 w-auto opacity-80" />
            <span>{zh ? "MIT 授權 · 開放標準" : "MIT licensed · Open standard"}</span>
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            <Link href={`${prefix}/spec`} className="hover:text-ink">{zh ? "規格" : "Spec"} {specVersion}</Link>
            <a href={NPM_PACKAGE_URL} className="hover:text-ink">{versions.npmVerified ? "npm" : "package.json"} {versions.npm}</a>
            <Link href={`${prefix}/rules`} className="hover:text-ink">
              {zh
                ? `${stats.ruleCount} 條生效規則，main 上共 ${stats.ruleFileCount} 個檔，${stats.ruleInertCount} 條 inert`
                : `${stats.ruleCount} effective rules, ${stats.ruleFileCount} files on main, ${stats.ruleInertCount} inert`}
            </Link>
            <Link href={`${prefix}/citations`} className="hover:text-ink">DOI 10.5281/zenodo.19178002</Link>
            <span>{zh ? "頁面產生於" : "Page generated"} {versions.generatedAt}</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
