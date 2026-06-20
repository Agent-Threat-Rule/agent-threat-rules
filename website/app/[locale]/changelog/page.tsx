import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadChangelog } from "@/lib/changelog";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Changelog — ATR",
  description:
    "Version history for Agent Threat Rules (ATR). Detection rules, engine changes, and ecosystem milestones.",
};

const SECTION_ACCENT: Record<string, string> = {
  BREAKING: "text-critical border-critical",
  Added: "text-ink border-ink",
  Changed: "text-high border-high",
  Fixed: "text-blue border-blue",
  Metrics: "text-stone border-stone",
  Ecosystem: "text-blue border-blue",
  Stats: "text-stone border-stone",
};

export default async function ChangelogPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";
  const entries = loadChangelog();

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[860px] mx-auto">
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3">
          {zh ? "版本歷程" : "Changelog"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="font-display text-[clamp(32px,5vw,56px)] font-extrabold tracking-[-2px] md:tracking-[-3px] leading-[1.05] text-ink">
          {zh ? "每一次發布。" : "Every release."}
          <br />
          {zh ? "可追溯。" : "On the record."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-sm md:text-base text-graphite max-w-[640px] mt-5 md:mt-6 leading-[1.8]">
          {zh ? (
            <>
              從 <code className="font-data text-xs bg-ash px-1.5 py-0.5">CHANGELOG.md</code> 於建置時自動產生——這頁就是那份檔案。規則 ID 一經發布永不改號；rule_version 可升，ID 穩定，外部論文、CI 腳本、稽核軌跡都能安全引用。版號跟著 npm 釋出線走（目前 <code className="font-data text-xs bg-ash px-1.5 py-0.5">v3.5.0</code>），書面規範以同一版號發布、狀態為 Working Draft。完整 commit 歷史在 GitHub。
            </>
          ) : (
            <>
              Generated from <code className="font-data text-xs bg-ash px-1.5 py-0.5">CHANGELOG.md</code> at build time — this page is that file. Rule IDs are permanent once published; <code className="font-data text-xs bg-ash px-1.5 py-0.5">rule_version</code> may bump, but the ID stays stable, safe for papers, CI scripts, and audit trails to cite. Version numbers track the npm release line (currently <code className="font-data text-xs bg-ash px-1.5 py-0.5">v3.5.0</code>); the written specification ships at the same version with Working Draft status. Full commit history is on GitHub.
            </>
          )}
        </p>
      </Reveal>
      <Reveal delay={0.15}>
        <a
          href="https://github.com/Agent-Threat-Rule/agent-threat-rules/releases"
          target="_blank"
          rel="noopener noreferrer"
          className="font-data text-xs md:text-sm text-blue hover:underline inline-block mt-4"
        >
          {zh ? "在 GitHub 查看完整 release 歷史 →" : "View full release history on GitHub →"}
        </a>
      </Reveal>

      {entries.length === 0 ? (
        <Reveal delay={0.2}>
          <p className="text-sm text-mist mt-10">
            {zh ? "尚無版本資料。" : "No changelog entries available."}
          </p>
        </Reveal>
      ) : (
        <div className="mt-12 md:mt-16 space-y-12 md:space-y-16">
          {entries.map((entry, i) => (
            <Reveal key={entry.version} delay={0.2 + i * 0.03}>
              <article className="border-t border-fog pt-8">
                <div className="flex items-baseline justify-between gap-3 flex-wrap mb-6">
                  <h2 className="font-display text-[clamp(24px,3.5vw,36px)] font-extrabold tracking-[-1px] leading-[1.1] text-ink">
                    v{entry.version}
                  </h2>
                  {entry.date && (
                    <span className="font-data text-xs text-stone">{entry.date}</span>
                  )}
                </div>
                {entry.sections.map((section) => {
                  const accent = SECTION_ACCENT[section.heading] ?? "text-stone border-stone";
                  const [textClass, borderClass] = accent.split(" ");
                  return (
                    <div key={section.heading} className="mb-6 last:mb-0">
                      <div
                        className={`font-data text-[10px] md:text-[11px] font-medium tracking-[2px] uppercase inline-block border ${borderClass}/40 ${textClass} bg-ash/50 px-2 py-0.5 rounded-[2px] mb-3`}
                      >
                        {section.heading}
                      </div>
                      <ul className="space-y-2">
                        {section.items.map((item, idx) => (
                          <li
                            key={idx}
                            className="text-sm text-graphite leading-[1.7] flex items-start gap-2"
                          >
                            <span className="text-fog shrink-0 mt-1">▸</span>
                            <span>{renderInline(item)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  );
                })}
              </article>
            </Reveal>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Render a changelog bullet with minimal inline markdown: `code` spans + **bold**.
 */
function renderInline(text: string): React.ReactNode {
  const parts: React.ReactNode[] = [];
  const regex = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    const token = match[0];
    if (token.startsWith("`")) {
      parts.push(
        <code
          key={key++}
          className="font-data text-[11px] bg-ash px-1 py-0.5 rounded-[2px]"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else {
      parts.push(
        <strong key={key++} className="font-semibold text-ink">
          {token.slice(2, -2)}
        </strong>,
      );
    }
    lastIndex = match.index + token.length;
  }
  if (lastIndex < text.length) parts.push(text.slice(lastIndex));
  return <>{parts}</>;
}
