import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { t } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";

/** Build-time date stamp — safe for all environments */
const BUILD_DATE = new Date().toISOString().slice(0, 10);

export function Footer({ locale }: { locale: Locale }) {
  const prefix = `/${locale}`;
  const zh = locale === "zh";
  const stats = loadSiteStats();
  const lastUpdated = BUILD_DATE;

  return (
    <footer className="border-t border-fog py-12 px-6">
      <div className="max-w-[1120px] mx-auto">
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-8 mb-10">
          {/* Project */}
          <div>
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">
              {zh ? "專案" : "Project"}
            </div>
            <div className="flex flex-col gap-2">
              <Link href={`${prefix}/rules`} className="text-sm text-stone hover:text-ink transition-colors">
                {zh ? "規則庫" : "Rules"}
              </Link>
              <Link href={`${prefix}/coverage`} className="text-sm text-stone hover:text-ink transition-colors">
                {zh ? "覆蓋範圍" : "Coverage"}
              </Link>
              <Link href={`${prefix}/research`} className="text-sm text-stone hover:text-ink transition-colors">
                {zh ? "研究" : "Research"}
              </Link>
            </div>
          </div>

          {/* Developers */}
          <div>
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">
              {zh ? "開發者" : "Developers"}
            </div>
            <div className="flex flex-col gap-2">
              <Link href={`${prefix}/integrate`} className="text-sm text-stone hover:text-ink transition-colors">
                {zh ? "整合" : "Integrate"}
              </Link>
              <a href="https://www.npmjs.com/package/agent-threat-rules" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                npm
              </a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                GitHub
              </a>
            </div>
          </div>

          {/* Community */}
          <div>
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">
              {zh ? "社群" : "Community"}
            </div>
            <div className="flex flex-col gap-2">
              <Link href={`${prefix}/contribute`} className="text-sm text-stone hover:text-ink transition-colors">
                {zh ? "參與貢獻" : "Contribute"}
              </Link>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                Governance
              </a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CONTRIBUTORS.md" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                Contributors
              </a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/discussions" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                Discussions
              </a>
            </div>
          </div>

          {/* Research */}
          <div>
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">
              {zh ? "研究" : "Research"}
            </div>
            <div className="flex flex-col gap-2">
              <a href="https://doi.org/10.5281/zenodo.19178002" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                Paper (Zenodo)
              </a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/LIMITATIONS.md" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                Limitations
              </a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SECURITY.md" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                Security Policy
              </a>
            </div>
          </div>

          {/* Contact */}
          <div>
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">
              {zh ? "聯絡" : "Contact"}
            </div>
            <div className="flex flex-col gap-2">
              <a href="mailto:contact@agentthreatrule.org" className="text-sm text-stone hover:text-ink transition-colors break-all sm:break-normal">
                contact@agentthreatrule.org
              </a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues" target="_blank" rel="noopener noreferrer" className="text-sm text-stone hover:text-ink transition-colors">
                {zh ? "回報問題" : "Report an Issue"}
              </a>
            </div>
          </div>
        </div>

        {/* License + static description */}
        <div className="border-t border-fog pt-6 pb-4 flex flex-wrap items-center gap-3">
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">
            <img src="https://img.shields.io/badge/license-MIT-E8E8E5?style=flat&labelColor=FAFAF8" alt="MIT License" className="h-5" />
          </a>
          <span className="font-data text-xs text-stone">
            {zh ? "MIT 授權 · npm 可安裝 · 開源" : "MIT Licensed · Available on npm · Open Source"}
          </span>
        </div>

        {/* Bottom bar */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-3 pt-4">
          <div className="flex items-center gap-3">
            <img src="/atr-logo-black.png" alt="ATR" className="h-5 opacity-40" />
            <span className="text-xs text-mist">
              {t(locale, "footer.note")}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-data text-xs text-mist">
            <span>ATR v2.0.17 · {stats.ruleCount} {zh ? "條規則" : "rules"}</span>
            <span className="text-fog hidden sm:inline">|</span>
            <span>{zh ? "更新於" : "Updated"} {lastUpdated}</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
