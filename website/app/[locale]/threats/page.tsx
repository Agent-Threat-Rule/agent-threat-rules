import { Reveal } from "@/components/Reveal";
import { loadSiteStats } from "@/lib/stats";
import { locales, type Locale } from "@/lib/i18n";
import { listActors } from "@/lib/actors";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Metadata } from "next";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Threat Feed - ATR",
  description:
    "Public blacklist of flagged AI agent skills. 1,302 flagged, 552 confirmed malware. Generated from open ATR ecosystem scans; Threat Cloud is an optional reference service that can also feed reports.",
};

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
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "公開威脅情報" : "Public Threat Feed"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] mb-2">
          {zh ? "攻擊先發生在野外。" : "The attack happens in the wild first."}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-8 max-w-[560px] leading-[1.8]">
          {zh
            ? <>一個偵測標準若只活在規格書裡，就沒有意義。<br />ATR 掃描了 {stats.megaScanTotal.toLocaleString()} 個真實 skill，標記 {bl.total_flagged.toLocaleString()} 個有風險、確認 {bl.confirmed_malware} 個為惡意軟體，<br className="sm:hidden" />並把背後的行為者公開記錄下來。<br /><br className="sm:hidden" />名單與規則都以 MIT 授權公開——任何人都能查詢、引用、自行核對。</>
            : <>A detection standard that only lives in a spec is worth nothing. ATR scanned {stats.megaScanTotal.toLocaleString()} real skills, flagged {bl.total_flagged.toLocaleString()} as risky, confirmed {bl.confirmed_malware} as malware, and documented the actors behind them.<br /><br className="sm:hidden" />The list and the rules are public under MIT — anyone can query, cite, and verify them.</>}
        </p>
      </Reveal>

      {/* Summary cards */}
      <Reveal delay={0.3}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog mb-8">
          <div className="bg-paper p-4 md:p-5">
            <div className="font-data text-2xl md:text-3xl font-bold text-critical">{bl.total_flagged.toLocaleString()}</div>
            <div className="font-data text-xs text-stone mt-1">{zh ? "已標記" : "flagged"}</div>
          </div>
          <div className="bg-paper p-4 md:p-5">
            <div className="font-data text-2xl md:text-3xl font-bold text-critical">{bl.confirmed_malware}</div>
            <div className="font-data text-xs text-stone mt-1">{zh ? "確認惡意軟體" : "confirmed malware"}</div>
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
                {zh ? "點擊查看完整檔案" : "Click for full profile"}
              </span>
            </div>
            <p className="text-sm text-graphite mt-3 max-w-[620px] leading-[1.7]">
              {zh
                ? "ATR 不只列規則,也追蹤寫出這些攻擊的人。以下三個行為者在同一次掃描中被揪出——他們把惡意 skill 偽裝成錢包工具、圖像生成器、商業助手,散佈到公開 registry。每個檔案都附上實際證據:C2 位址、封存檔密碼、命名模式、對映的 ATLAS 技法。野外觀察到的手法,變成回流標準的偵測規則。"
                : "ATR tracks the people who write the attacks, not just the rules that catch them. The three actors below surfaced in a single scan — distributing malicious skills disguised as wallet tools, image generators, and business assistants across public registries. Each profile carries the actual evidence: C2 addresses, archive passwords, naming patterns, the mapped ATLAS technique. What is observed in the wild becomes a detection rule that flows back into the standard."}
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
                    ? `個惡意 skill (${a.malRatio})`
                    : `malicious skills (${a.malRatio})`}
                </div>
                <p className="text-sm text-graphite mt-4 leading-[1.7] line-clamp-3">
                  {zh ? a.summary.zh : a.summary.en}
                </p>
                <div className="font-data text-xs text-blue mt-4 group-hover:underline">
                  {zh ? "查看完整檔案 →" : "View full profile →"}
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
                {zh ? "ATR 認證白名單" : "ATR Verified Whitelist"}
              </div>
              <span className="inline-flex items-center gap-1 bg-green/15 text-green text-[10px] font-bold px-2 py-0.5 rounded-sm tracking-wide uppercase">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="none" className="shrink-0">
                  <path d="M6.5 11.5L3 8l1-1 2.5 2.5L12 4l1 1-6.5 6.5z" fill="currentColor"/>
                </svg>
                {zh ? "已驗證" : "VERIFIED"}
              </span>
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="text-sm text-graphite mb-6 max-w-[520px] leading-[1.8]">
              {zh
                ? <>同一套規則也用來證明乾淨。這些 skill 通過最新一次 ATR {stats.ruleCount} 條規則掃描,<br className="sm:hidden" />零 CRITICAL / HIGH 發現——同一個可稽核標準,既標記惡意,也背書良性。</>
                : <>The same ruleset proves what is clean. These skills passed the latest ATR {stats.ruleCount}-rule scan with zero CRITICAL / HIGH findings — one auditable standard that flags the malicious and vouches for the benign.</>}
            </p>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {wl.entries.slice(0, 21).map((entry) => (
                <div key={entry.skill} className="bg-white border border-green/20 rounded-sm p-3 md:p-4">
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
                {zh ? `查看全部 ${wl.total_verified} 個已認證 skill →` : `View all ${wl.total_verified} verified skills →`}
              </a>
            </Reveal>
          )}
        </div>
      </section>

      {/* Full blacklist — JSON download card */}
      <Reveal delay={0.4}>
        <div className="mb-4">
          <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">
            {zh ? "完整黑名單" : "Full Blacklist"}
          </div>
          <div className="bg-paper border border-fog p-5 md:p-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <div className="font-data text-2xl md:text-3xl font-bold text-ink leading-none">
                {bl.total_flagged.toLocaleString()}
              </div>
              <p className="text-sm text-graphite mt-2 leading-[1.7]">
                {zh
                  ? "所有被標記的 skill 都在一份機器可讀的 blacklist.json 裡——每筆都附上命中規則與證據。任何 CI、registry 或 agent framework 都能直接拉取,不需註冊、不需金鑰、不收過路費。"
                  : "Every flagged skill lives in one machine-readable blacklist.json — each entry carries the rule it hit and the evidence behind it. Any CI, registry, or agent framework can pull it directly: no signup, no key, no toll."}
              </p>
            </div>
            <div className="flex flex-col gap-2 md:shrink-0">
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/data/public-blacklist.json"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-ink text-paper font-data text-xs px-5 py-2.5 rounded-[2px] hover:bg-graphite transition-colors text-center whitespace-nowrap"
              >
                {zh ? "查看完整 blacklist.json →" : "View full blacklist.json →"}
              </a>
              <a
                href="https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/data/public-blacklist.json"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline text-center"
              >
                {zh ? "下載 raw JSON" : "Download raw JSON"}
              </a>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Footer note */}
      <Reveal delay={0.5}>
        <p className="text-xs text-mist mt-6 leading-[1.8] max-w-[480px]">
          {zh
            ? <>此清單由開放的 ATR 生態系掃描自動產生，<br className="sm:hidden" />並以 MIT 授權的規則為本體。<br />被標記是訊號,不是定罪 — <br className="sm:hidden" />請對照命中的規則自行判斷。<br />認為標錯了?開一個 GitHub Issue,我們公開審。</>
            : <>This list is generated from open ATR ecosystem scans,<br className="sm:hidden" /> built on the MIT-licensed rules.<br />A flag is a signal, not a verdict — <br className="sm:hidden" />check the rule it hit and judge for yourself.<br />Think we got one wrong? Open a GitHub Issue; we review it in the open.</>}
        </p>
      </Reveal>

      {/* Threat Cloud — optional reference service (not part of the standard) */}
      <Reveal delay={0.55}>
        <p className="text-xs text-mist mt-4 leading-[1.8] max-w-[480px]">
          {zh
            ? "Threat Cloud 是 ATR 維護者運營的選用參考服務，並非標準的一部分。標準本體是規格加上 MIT 授權的規則，透過 npm / PyPI / 純 YAML 完全可離線使用；Threat Cloud 只提供 hosted 便利（規則同步、威脅提交），不用它也能達到同樣結果。"
            : "Threat Cloud is an optional reference service operated by the ATR maintainers — not part of the standard. The standard is the spec plus the MIT-licensed rules, fully usable offline via npm / PyPI / raw YAML. Threat Cloud only adds hosted convenience (rule sync, threat submission); the same outcomes are reachable without it."}
        </p>
      </Reveal>
    </div>
  );
}
