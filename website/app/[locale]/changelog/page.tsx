import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadChangelog } from "@/lib/changelog";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { getSpecMeta } from "@/lib/spec-meta";
import { loadVersionLabels } from "@/lib/versions";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/changelog",
    title: "Changelog",
    description:
      "Version history for Agent Threat Rules (ATR): detection rules, engine changes and ecosystem milestones.",
  });
}

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
  const specVersion = getSpecMeta().specVersion;
  const versions = await loadVersionLabels();
  const releaseLabel = versions.npmVerified ? `npm v${versions.npm}` : `package.json v${versions.npm}`;

  return (
    <div className="pt-20 pb-20 px-6 md:px-14 max-w-[972px]">
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "版本歷程" : "Changelog"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="text-[32px] md:text-[48px] leading-[1.06] tracking-[-0.01em] font-medium text-ink">
          {zh ? "每一次發布。" : "Every release."}
          <br />
          {zh ? "都查得到。" : "On the record."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-sm md:text-base text-graphite max-w-[640px] mt-5 md:mt-6 leading-[1.8]">
          {zh ? (
            <>
              這頁在建置時由 <code className="font-data text-xs bg-ash px-1.5 py-0.5">CHANGELOG.md</code> 自動產生，內容就是那份檔案。規則 ID 發布後不會改號。rule_version 可以往上升，ID 不動，所以論文、CI 腳本、稽核紀錄都能放心引用。版號跟著 npm 的發布走，目前是 <code className="font-data text-xs bg-ash px-1.5 py-0.5">{releaseLabel}</code>，本頁產生於 {versions.generatedAt}。書面的核心規格 SPEC.md 有自己的版號，目前是 <code className="font-data text-xs bg-ash px-1.5 py-0.5">{specVersion}</code>，狀態是 Working Draft。完整的 commit 歷史在 GitHub。
            </>
          ) : (
            <>
              This page is <code className="font-data text-xs bg-ash px-1.5 py-0.5">CHANGELOG.md</code>, generated from it at build time. Rule IDs are permanent once published. <code className="font-data text-xs bg-ash px-1.5 py-0.5">rule_version</code> may go up, but the ID stays the same, so papers, CI scripts and audit trails can cite it safely. Version numbers follow the npm release line, currently <code className="font-data text-xs bg-ash px-1.5 py-0.5">{releaseLabel}</code> as of {versions.generatedAt}. The written core specification, SPEC.md, has its own version, currently <code className="font-data text-xs bg-ash px-1.5 py-0.5">{specVersion}</code>, with Working Draft status. The full commit history is on GitHub.
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
          {zh ? "到 GitHub 看完整的 release 歷史 →" : "Full release history on GitHub →"}
        </a>
      </Reveal>

      {entries.length === 0 ? (
        <Reveal delay={0.2}>
          <p className="text-sm text-mist mt-10">
            {zh ? "還沒有版本資料。" : "No changelog entries available."}
          </p>
        </Reveal>
      ) : (
        <div className="mt-12 md:mt-16 space-y-12 md:space-y-16">
          {entries.map((entry, i) => (
            <Reveal key={entry.version} delay={0.2 + i * 0.03}>
              <article className="border-t border-fog pt-8">
                <div className="flex items-baseline justify-between gap-3 flex-wrap mb-6">
                  <h2 className="text-[26px] md:text-[34px] leading-[1.18] tracking-[-0.01em] font-medium text-ink">
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
