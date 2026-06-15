import { Reveal } from "@/components/Reveal";
import { loadContributors, getCountryStats } from "@/lib/contributors";
import { loadSiteStats } from "@/lib/stats";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Wall — ATR Community",
  description:
    "The people maintaining ATR — contributors, adopters, and researchers carrying an open detection standard toward universal. A standard is only as strong as the people who maintain it.",
};

const COUNTRY_NAMES: Record<string, { en: string; zh: string }> = {
  TW: { en: "Taiwan", zh: "台灣" },
  US: { en: "United States", zh: "美國" },
  DE: { en: "Germany", zh: "德國" },
  JP: { en: "Japan", zh: "日本" },
  IN: { en: "India", zh: "印度" },
  GB: { en: "United Kingdom", zh: "英國" },
  FR: { en: "France", zh: "法國" },
  KR: { en: "South Korea", zh: "韓國" },
  BR: { en: "Brazil", zh: "巴西" },
  CA: { en: "Canada", zh: "加拿大" },
  AU: { en: "Australia", zh: "澳洲" },
  SG: { en: "Singapore", zh: "新加坡" },
  IL: { en: "Israel", zh: "以色列" },
  CN: { en: "China", zh: "中國" },
};

const ROLE_LABELS: Record<string, { en: string; zh: string }> = {
  maintainer: { en: "Maintainer", zh: "維護者" },
  contributor: { en: "Contributor", zh: "貢獻者" },
  reporter: { en: "Reporter", zh: "回報者" },
};

const CONTRIBUTION_LABELS: Record<string, { en: string; zh: string }> = {
  rules: { en: "Rules", zh: "規則" },
  engine: { en: "Engine", zh: "引擎" },
  website: { en: "Website", zh: "網站" },
  benchmark: { en: "Benchmark", zh: "基準測試" },
  docs: { en: "Docs", zh: "文件" },
  "evasion-report": { en: "Evasion Report", zh: "繞過回報" },
  "fp-report": { en: "FP Report", zh: "誤報回報" },
  review: { en: "Review", zh: "審查" },
};

export default async function WallPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const contributors = loadContributors();
  const countries = getCountryStats(contributors);
  const stats = loadSiteStats();

  return (
    <div className="pt-20 pb-16 px-5 md:px-6 max-w-[860px] mx-auto">
      {/* Hero */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "社群" : "Community"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(26px,4vw,44px)] font-extrabold tracking-[-2px] leading-[1.2] mb-4 max-w-[600px]">
          {zh
            ? <>一個標準的強度，<br />等於貢獻它的人。</>
            : <>A standard is only as strong<br className="hidden sm:block" /> as the people who maintain it.</>}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-sm md:text-base text-stone font-light leading-[1.8] mb-10 max-w-[540px]">
          {zh
            ? "Sigma、CVE、YARA 之所以通用，不是因為某家公司擁有它們，而是因為夠多人選擇用同一套語言描述威脅。ATR 走的是同一條路——貢獻者寫規則、採用者把它接進產線、研究者回報繞過。每一筆都讓這套標準離「世界通用」近一點。一條在台北寫的規則，會擋下西雅圖首報的攻擊。"
            : "Sigma, CVE, and YARA became universal not because a company owned them, but because enough people chose to describe threats in one shared language. ATR follows the same path — contributors write rules, adopters wire them into production, researchers report the bypasses. Each one moves the standard a step closer to universal. A rule written in Taipei catches an attack first reported in Seattle."}
        </p>
      </Reveal>

      {/* Contributors — card style */}
      <Reveal delay={0.3}>
        <div className="mb-10">
          <div className="grid grid-cols-1 gap-px bg-fog border border-fog">
            {contributors.map((c) => {
              const country = countries.find((co) => co.code === c.country);
              const name = COUNTRY_NAMES[c.country]?.[zh ? "zh" : "en"] ?? c.country;
              const role = ROLE_LABELS[c.role]?.[zh ? "zh" : "en"] ?? c.role;

              return (
                <a
                  key={c.github}
                  href={`https://github.com/${c.github}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-paper p-5 md:p-6 flex items-start gap-4 hover:bg-ash/50 transition-colors"
                >
                  <img
                    src={`https://github.com/${c.github}.png?size=80`}
                    alt={c.github}
                    width={48}
                    height={48}
                    className="rounded-sm ring-1 ring-fog shrink-0"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="font-display text-base font-semibold text-ink">@{c.github}</span>
                      <span className="text-xl leading-none">{country?.flag}</span>
                      <span className="font-data text-xs text-stone">{name}</span>
                    </div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`font-data text-xs px-2 py-0.5 rounded-sm ${
                        c.role === "maintainer"
                          ? "bg-blue/10 text-blue"
                          : "bg-ash text-stone"
                      }`}>
                        {role}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {c.contributions.map((contrib: string) => (
                        <span
                          key={contrib}
                          className="font-data text-xs text-mist bg-ash px-2 py-0.5 rounded-sm"
                        >
                          {CONTRIBUTION_LABELS[contrib]?.[zh ? "zh" : "en"] ?? contrib}
                        </span>
                      ))}
                    </div>
                  </div>
                </a>
              );
            })}
          </div>
        </div>
      </Reveal>

      {/* What this project has shipped — context for why joining matters */}
      <Reveal>
        <div className="bg-ash border border-fog p-6 md:p-8 mb-10">
          <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-4">
            {zh ? "這個社群做了什麼" : "What this community has shipped"}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6">
            <div>
              <div className="font-data text-2xl md:text-3xl font-bold text-ink">{stats.ruleCount}</div>
              <div className="text-xs text-stone mt-1">{zh ? "偵測規則" : "detection rules"}</div>
            </div>
            <div>
              <div className="font-data text-2xl md:text-3xl font-bold text-ink">{Math.round(stats.megaScanTotal / 1000)}K+</div>
              <div className="text-xs text-stone mt-1">{zh ? "skills 已掃描" : "skills scanned"}</div>
            </div>
            <div>
              <div className="font-data text-2xl md:text-3xl font-bold text-ink">{stats.owaspAgentic}</div>
              <div className="text-xs text-stone mt-1">OWASP Agentic</div>
            </div>
            <div>
              <div className="font-data text-2xl md:text-3xl font-bold text-ink">{stats.ecosystemIntegrations.filter((e) => e.type === "merged").length}</div>
              <div className="text-xs text-stone mt-1">{zh ? "生態系整合" : "ecosystem integrations"}</div>
            </div>
          </div>
        </div>
      </Reveal>

      {/* How to contribute — the real CTA */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-4">
          {zh ? "加入方式" : "How to Contribute"}
        </div>
      </Reveal>

      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 gap-px bg-fog border border-fog mb-10">
          {[
            {
              en: "Report an Evasion",
              zh: "回報繞過方法",
              desc: zh
                ? "找到繞過某條 ATR 規則的方法？這是最有價值的貢獻。已知繞過手法是公開記錄的——回報一個，整個生態系一起補上，沒有人需要再各自踩同一個坑。"
                : "Found a way to bypass an ATR rule? This is the most valuable contribution there is. Known evasions are documented in the open — report one and the whole ecosystem closes the gap at once, so no one has to rediscover it.",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=evasion-report.yml",
              time: "15 min",
              impact: zh ? "最高" : "Highest",
            },
            {
              en: "Report a False Positive",
              zh: "回報誤判",
              desc: zh
                ? "ATR 規則標記了正常內容？一筆誤報回報就是一個我們公開揭露的最差數字——它直接讓對應車道的精確度更誠實。"
                : "An ATR rule flagged something benign? A false-positive report is one more worst-case figure we publish, not hide — it makes the precision we report, lane by lane, more honest.",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=false-positive.yml",
              time: "20 min",
              impact: zh ? "高" : "High",
            },
            {
              en: "Submit a Rule",
              zh: "提交新規則",
              desc: zh
                ? "用 YAML 寫一條偵測規則。必須附真實攻擊 payload 與真／假陽性 test case，不是文字描述——這樣它才能被 peer-review、被 conformance 測試、被任何引擎重現。"
                : "Write a detection rule in YAML. It must carry real attack payloads and true/false-positive test cases, not a prose description — so it can be peer-reviewed, conformance-tested, and reproduced by any engine.",
              href: `${prefix}/contribute`,
              time: "1-2 hr",
              impact: zh ? "高" : "High",
              internal: true,
            },
            {
              en: "Share Threat Intel",
              zh: "分享威脅情報",
              desc: zh
                ? "看到一種還沒人寫進規則的 AI agent 攻擊手法？在 Discussions 裡描述它。技法先被記錄，規則隨後跟上——知識層不必等偵測層就位。"
                : "Seen an AI agent attack technique no rule covers yet? Describe it in Discussions. The technique gets documented first; a rule follows — the knowledge layer doesn't wait on the detection layer.",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/discussions",
              time: "10 min",
              impact: zh ? "中" : "Medium",
            },
          ].map((item) => {
            const inner = (
              <div className="bg-paper p-5 md:p-6 hover:bg-ash/30 transition-colors">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="font-display text-sm font-semibold text-ink mb-1">
                      {zh ? item.zh : item.en}
                    </div>
                    <p className="text-sm text-stone leading-relaxed">{item.desc}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="font-data text-xs text-mist">{item.time}</div>
                    <div className="font-data text-xs text-blue mt-0.5">{item.impact}</div>
                  </div>
                </div>
              </div>
            );
            return item.internal ? (
              <Link key={item.en} href={item.href}>{inner}</Link>
            ) : (
              <a key={item.en} href={item.href} target="_blank" rel="noopener noreferrer">{inner}</a>
            );
          })}
        </div>
      </Reveal>

      {/* Add yourself */}
      <Reveal>
        <div className="border border-ink bg-ink text-white px-6 py-6 md:py-8 mb-10">
          <div className="font-display text-lg md:text-xl font-extrabold mb-2">
            {zh ? "把你的名字加上來。" : "Put your name on the wall."}
          </div>
          <p className="text-sm text-white/60 mb-5 max-w-[480px] leading-relaxed">
            {zh
              ? "在 contributors.yaml 加一行，提一個 PR。你的 GitHub 頭像、國家、貢獻類型會顯示在這裡——和那些把開放標準推向世界通用的人並列。這份名單是公開的，永久留存。"
              : "Add one line to contributors.yaml and open a PR. Your GitHub avatar, country, and contribution types appear here — alongside everyone carrying an open standard toward universal. The list is public, and it stays."}
          </p>
          <div className="flex flex-col sm:flex-row gap-3">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=add-contributor.md&title=Add+contributor:+MY_GITHUB_USERNAME"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-blue text-white px-6 py-3 rounded-sm text-sm font-semibold hover:bg-blue-hover transition-colors text-center"
            >
              {zh ? "加入社群 →" : "Add Yourself →"}
            </a>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules"
              target="_blank"
              rel="noopener noreferrer"
              className="border border-white/20 text-white px-6 py-3 rounded-sm text-sm font-medium hover:border-white/40 transition-colors text-center"
            >
              {zh ? "GitHub Star ★" : "Star on GitHub ★"}
            </a>
          </div>
        </div>
      </Reveal>

      {/* Country presence */}
      {countries.length > 0 && (
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-3">
            {zh ? "目前覆蓋" : "Current Reach"}
          </div>
          <div className="flex flex-wrap gap-3 mb-4">
            {countries.map((country) => {
              const name = COUNTRY_NAMES[country.code]?.[zh ? "zh" : "en"] ?? country.code;
              return (
                <div
                  key={country.code}
                  className="flex items-center gap-2 bg-ash px-3 py-2 rounded-sm"
                >
                  <span className="text-2xl leading-none">{country.flag}</span>
                  <div>
                    <div className="font-data text-xs font-semibold text-ink">{name}</div>
                    <div className="font-data text-xs text-mist">
                      {country.count} {zh ? "人" : (country.count === 1 ? "contributor" : "contributors")}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          <p className="text-xs text-mist">
            {zh
              ? `${countries.length} 個國家。一套通用標準的價值，正比於有多少地方在用同一套語言描述威脅。目標：每個運行 AI agent 的國家，都有人在這裡。`
              : `${countries.length} countries. A universal standard is worth as much as the number of places speaking the same language for threats. Goal: a contributor in every country running AI agents.`}
          </p>
        </Reveal>
      )}
    </div>
  );
}
