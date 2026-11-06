import { Reveal } from "@/components/Reveal";
import { loadSiteStats } from "@/lib/stats";
import { locales, type Locale } from "@/lib/i18n";
import { listActors } from "@/lib/actors";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import Link from "next/link";

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
    path: "/threats",
    title: "Threat Feed",
    description:
      "A public blacklist of flagged AI agent skills, built from open ATR ecosystem scans.",
  });
}

interface BlacklistData {
  generated: string;
  total_flagged: number;
  confirmed_malware: number;
  severity: { critical: number; high: number; medium: number };
  threat_actors: string[];
}

interface WhitelistEntry {
  skill: string;
  source: string;
  downloads: number;
  risk_score: number;
  verified: boolean;
}

interface WhitelistData {
  generated: string;
  total_verified: number;
  criteria: string;
  entries: WhitelistEntry[];
}

function loadBlacklist(): BlacklistData {
  try {
    const raw = readFileSync(join(process.cwd(), "..", "data", "public-blacklist.json"), "utf-8");
    const parsed = JSON.parse(raw);
    return {
      generated: parsed.generated,
      total_flagged: parsed.total_flagged,
      confirmed_malware: parsed.confirmed_malware,
      severity: parsed.severity,
      threat_actors: parsed.threat_actors,
    };
  } catch {
    return {
      generated: "N/A",
      total_flagged: 0,
      confirmed_malware: 0,
      severity: { critical: 0, high: 0, medium: 0 },
      threat_actors: [],
    };
  }
}

function loadWhitelist(): WhitelistData {
  try {
    const raw = readFileSync(join(process.cwd(), "..", "data", "public-whitelist.json"), "utf-8");
    return JSON.parse(raw);
  } catch {
    return { generated: "N/A", total_verified: 0, criteria: "", entries: [] };
  }
}

export default async function ThreatsPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const stats = loadSiteStats();
  const bl = loadBlacklist();
  const wl = loadWhitelist();
  const actors = listActors();

  return (
    <div className="pt-20 pb-16 px-5 md:px-6 max-w-[1120px] mx-auto">
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "公開威脅情報" : "Public Threat Feed"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.01em] font-medium mb-2">
          {zh ? "攻擊先發生在野外。" : "The attack happens in the wild first."}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-8 max-w-[560px] leading-[1.8]">
          {zh
            ? <>偵測標準如果只寫在規格書裡，就沒有意義。<br />ATR 在野外掃了 {stats.megaScanTotal.toLocaleString()} 個真實的 skill 和 MCP server 定義，標記出 {stats.megaScanFlagged.toLocaleString()} 個有風險（engine v2.0.0，{stats.megaScanDate}）。<br className="sm:hidden" />背後的行為者，也公開記錄下來。<br /><br className="sm:hidden" />名單和規則都用 MIT 授權公開。誰都可以查詢、引用，自己核對一遍。</>
            : <>A detection standard that only lives in a spec is worth nothing. ATR scanned {stats.megaScanTotal.toLocaleString()} real agent skills and MCP server definitions in the wild and flagged {stats.megaScanFlagged.toLocaleString()} of them (engine v2.0.0, {stats.megaScanDate}). It also documented the actors behind them.<br /><br className="sm:hidden" />The list and the rules are public under MIT. Anyone can query and cite them, and check the work.</>}
        </p>
      </Reveal>

      {/* Summary cards */}
      <Reveal delay={0.3}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog mb-8">
          <div className="bg-paper p-4 md:p-5">
            <div className="font-data text-2xl md:text-3xl font-bold text-critical">{bl.total_flagged.toLocaleString()}</div>
            <div className="font-data text-xs text-stone mt-1">{zh ? "這份檔案標記的" : "flagged in this file"}</div>
          </div>
          <div className="bg-paper p-4 md:p-5">
            <div className="font-data text-2xl md:text-3xl font-bold text-critical">{bl.threat_actors.length}</div>
            <div className="font-data text-xs text-stone mt-1">{zh ? "記錄在案的行為者" : "documented actors"}</div>
          </div>
          <div className="bg-paper p-4 md:p-5">
            <div className="font-data text-2xl md:text-3xl font-bold text-ink">{bl.severity.critical}</div>
            <div className="font-data text-xs text-stone mt-1">CRITICAL</div>
          </div>
          <div className="bg-paper p-4 md:p-5">
            <div className="font-data text-2xl md:text-3xl font-bold text-ink">{bl.severity.high}</div>
            <div className="font-data text-xs text-stone mt-1">HIGH</div>
          </div>
        </div>
        <p className="text-xs text-mist mb-8 leading-[1.7] max-w-[620px]">
          {zh
            ? `這些數字是這份公開黑名單檔案本身的統計，快照日期 ${bl.generated}。「已標記」代表規則命中，不是人判定的惡意。行為者是以整個帳號為單位、在發布者層級歸因的，不是逐檔分析。可以對外引用的野外掃描數字，是掃描 ${stats.megaScanTotal.toLocaleString()} 個、標記 ${stats.megaScanFlagged.toLocaleString()} 個（engine v2.0.0，${stats.megaScanDate}）。`
            : `These counts describe this public blacklist file itself, as of ${bl.generated}. "Flagged" means a rule matched. It is not a human verdict of malice. Actors are attributed at the publisher level, across the whole account, not file by file. The wild-scan figures cleared for external citation are ${stats.megaScanTotal.toLocaleString()} items scanned and ${stats.megaScanFlagged.toLocaleString()} flagged (engine v2.0.0, ${stats.megaScanDate}).`}
        </p>
      </Reveal>

      {/* Threat actors — clickable profile cards */}
      <Reveal delay={0.35}>
        <div className="mb-10 md:mb-12">
          <div className="mb-4 md:mb-5">
            <div className="flex items-baseline justify-between flex-wrap gap-2">
              <div className="font-data text-xs text-stone tracking-[2px] uppercase">
                {zh ? "已知威脅行為者" : "Known Threat Actors"}
              </div>
              <span className="font-data text-[11px] text-mist">
                {zh ? "點進去看完整檔案" : "Click for full profile"}
              </span>
            </div>
            <p className="text-sm text-graphite mt-3 max-w-[620px] leading-[1.7]">
              {zh
                ? `ATR 不只列規則，也追寫出這些攻擊的人。下面這 ${actors.length} 個行為者，是在同一次掃描裡找出來的。他們把惡意 skill 偽裝成錢包工具、圖像生成器、商業助手，放上公開的 registry 散布。每份檔案都附實際證據：C2 位址、壓縮檔密碼、命名模式，還有對應的 ATLAS 技法。在野外看到的手法，會寫成偵測規則，回到標準裡。`
                : `ATR tracks the people who write the attacks, not only the rules that catch them. The ${actors.length} actors below turned up in a single scan. They spread malicious skills across public registries, dressed up as wallet tools, image generators and business assistants. Each profile carries the actual evidence: C2 addresses, archive passwords, naming patterns and the mapped ATLAS technique. What shows up in the wild becomes a detection rule, and that rule goes back into the standard.`}
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog">
            {actors.map((a) => (
              <Link
                key={a.slug}
                href={`${prefix}/threats/${a.slug}`}
                className="group bg-paper p-6 md:p-8 hover:bg-ash/50 transition-colors"
              >
                <div className="flex items-baseline justify-between gap-2 flex-wrap">
                  <div className="font-data text-sm text-critical font-semibold break-all">
                    {a.name}
                  </div>
                  <span className="font-data text-[10px] text-critical bg-critical/10 px-2 py-0.5 rounded-[2px] uppercase tracking-wide">
                    {zh ? "活躍中" : "Active"}
                  </span>
                </div>
                <div className="font-data text-[clamp(28px,4vw,40px)] font-bold text-ink mt-3 leading-none">
                  {a.skillsMalicious}
                </div>
                <div className="font-data text-xs text-stone mt-2">
                  {zh
                    ? `個 skill 歸為惡意（帳號層級歸因，${a.malRatio}）`
                    : `skills attributed as malicious (publisher-level, ${a.malRatio})`}
                </div>
                <p className="text-sm text-graphite mt-4 leading-[1.7] line-clamp-3">
                  {zh ? a.summary.zh : a.summary.en}
                </p>
                <div className="font-data text-xs text-blue mt-4 group-hover:underline">
                  {zh ? "看完整檔案 →" : "View full profile →"}
                </div>
              </Link>
            ))}
          </div>
        </div>
      </Reveal>

      {/* ── Whitelist: ATR Verified ── */}
      <section className="py-10 md:py-14 px-5 md:px-6 bg-[#F0FAF0] border-y border-green/20 -mx-5 md:-mx-6">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="flex items-center gap-2 mb-4">
              <div className="font-data text-xs font-medium text-green tracking-[2px] uppercase">
                {zh ? "掃描沒有高風險發現的 skill" : "Skills with no high-risk findings"}
              </div>
              <span className="inline-flex items-center gap-1 bg-green/15 text-green text-[10px] font-bold px-2 py-0.5  tracking-wide uppercase">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="none" className="shrink-0">
                  <path d="M6.5 11.5L3 8l1-1 2.5 2.5L12 4l1 1-6.5 6.5z" fill="currentColor"/>
                </svg>
                {zh ? `${wl.generated} 掃描` : `Scanned ${wl.generated}`}
              </span>
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="text-sm text-graphite mb-6 max-w-[520px] leading-[1.8]">
              {zh
                ? <>同一套規則也掃過這些 skill。它們在 {wl.generated} 那次 ATR 掃描裡沒有任何 CRITICAL 或 HIGH 發現，下載也超過 100 次。這不是認證，只代表那次掃描沒有規則在高風險等級命中；之後的版本沒有重掃。</>
                : <>The same rules scanned these skills too. In the ATR scan of {wl.generated} they had no CRITICAL or HIGH findings, and each has more than 100 downloads. This is not a certification. It only means no rule matched at high severity in that scan, and later rule versions have not rescanned them.</>}
            </p>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {wl.entries.slice(0, 21).map((entry) => (
                <div key={entry.skill} className="bg-white border border-green/20  p-3 md:p-4">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="font-data text-xs font-medium text-ink truncate">{entry.skill}</div>
                    <span className="font-data text-[10px] text-stone shrink-0">{entry.downloads.toLocaleString()} {zh ? "下載" : "dl"}</span>
                  </div>
                  {/* ATR Official Badge */}
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src="/atr-badge-clean.svg"
                    alt="ATR Scanned - No Issues"
                    width={170}
                    height={20}
                    className="block"
                  />
                </div>
              ))}
            </div>
          </Reveal>
          {wl.entries.length > 20 && (
            <Reveal delay={0.3}>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/data/public-whitelist.json"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-green hover:underline inline-block mt-4"
              >
                {zh ? `看全部 ${wl.total_verified} 個已認證的 skill →` : `View all ${wl.total_verified} verified skills →`}
              </a>
            </Reveal>
          )}
        </div>
      </section>

      {/* Full blacklist — JSON download card */}
      <Reveal delay={0.4}>
        <div className="mb-4">
          <div className="text-[13px] text-stone mb-3">
            {zh ? "完整黑名單" : "Full Blacklist"}
          </div>
          <div className="bg-paper border border-fog p-5 md:p-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <div className="font-data text-2xl md:text-3xl font-bold text-ink leading-none">
                {bl.total_flagged.toLocaleString()}
              </div>
              <p className="text-sm text-graphite mt-2 leading-[1.7]">
                {zh
                  ? "每個被標記的 skill，都在同一份機器可讀的 blacklist.json 裡，每筆附上命中的規則和證據。任何 CI、registry 或 agent framework 都能直接拉。不用註冊，不用金鑰，也不收費。"
                  : "Every flagged skill is in one machine-readable blacklist.json. Each entry carries the rule it hit and the evidence behind it. Any CI, registry or agent framework can pull it directly. No signup, no key, no fee."}
              </p>
            </div>
            <div className="flex flex-col gap-2 md:shrink-0">
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/data/public-blacklist.json"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-ink text-paper font-data text-xs px-5 py-2.5 rounded-[2px] hover:bg-graphite transition-colors text-center whitespace-nowrap"
              >
                {zh ? "看完整的 blacklist.json →" : "View full blacklist.json →"}
              </a>
              <a
                href="https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/data/public-blacklist.json"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline text-center"
              >
                {zh ? "下載原始 JSON" : "Download raw JSON"}
              </a>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Footer note */}
      <Reveal delay={0.5}>
        <p className="text-xs text-mist mt-6 leading-[1.8] max-w-[480px]">
          {zh
            ? <>這份清單由公開的 ATR 生態掃描自動產生，<br className="sm:hidden" />依據的是 MIT 授權的規則。<br />被標記是一個訊號，不是定罪。<br className="sm:hidden" />請對照命中的規則，自己判斷。<br />覺得標錯了？開一個 GitHub Issue，審查過程公開。</>
            : <>This list is generated from open ATR ecosystem scans,<br className="sm:hidden" /> built on the MIT-licensed rules.<br />A flag is a signal, not a verdict.<br className="sm:hidden" /> Check the rule it hit and judge for yourself.<br />Think one is wrong? Open a GitHub Issue. The review happens in the open.</>}
        </p>
      </Reveal>

    </div>
  );
}
