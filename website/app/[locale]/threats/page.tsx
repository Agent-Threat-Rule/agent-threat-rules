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
    "Public blacklist of flagged AI agent skills. 1,302 flagged, 552 confirmed malware. Updated from ATR ecosystem scans and Threat Cloud reports.",
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
          {zh ? "AI Agent 黑名單" : "AI Agent Blacklist"}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-8 max-w-[560px] leading-[1.8]">
          {zh
            ? <>ATR 掃描 {stats.megaScanTotal.toLocaleString()} 個 skill 後，<br className="sm:hidden" />標記了 {bl.total_flagged.toLocaleString()} 個有風險的 skill。<br />其中 {bl.confirmed_malware} 個確認為惡意軟體。<br /><br className="sm:hidden" />這份清單完全公開。任何人都可以查詢。</>
            : <>After scanning {stats.megaScanTotal.toLocaleString()} skills,<br className="sm:hidden" /> ATR flagged {bl.total_flagged.toLocaleString()} with risks.<br />{bl.confirmed_malware} confirmed as malware.<br /><br className="sm:hidden" />This list is fully public. Anyone can check.</>}
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
          <div className="flex items-baseline justify-between flex-wrap gap-2 mb-4 md:mb-5">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase">
              {zh ? "已知威脅行為者" : "Known Threat Actors"}
            </div>
            <span className="font-data text-[11px] text-mist">
              {zh ? "點擊查看完整檔案" : "Click for full profile"}
            </span>
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
            <p className="text-sm text-graphite mb-6 max-w-[480px] leading-[1.8]">
              {zh
                ? <>這些 skill 通過 ATR {stats.ruleCount} 條規則掃描，<br className="sm:hidden" />零 CRITICAL / HIGH 發現。<br />安全使用。</>
                : <>These skills passed ATR&apos;s {stats.ruleCount}-rule scan<br className="sm:hidden" /> with zero CRITICAL / HIGH findings.<br />Safe to use.</>}
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
                  ? "所有被標記的 skill 都在公開的 blacklist.json。任何 CI、registry 或 agent framework 都可以直接拉取。"
                  : "Every flagged skill lives in the public blacklist.json. Any CI, registry, or agent framework can pull it directly."}
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
            ? <>此清單由 ATR 生態系掃描自動產生，<br className="sm:hidden" />並與 Threat Cloud 同步。<br />被標記不代表一定是惡意 — <br className="sm:hidden" />請查看具體規則判斷風險。<br />回報誤報：GitHub Issue。</>
            : <>This list is generated from ATR ecosystem scans<br className="sm:hidden" /> and synced with Threat Cloud.<br />Being flagged does not guarantee malice — <br className="sm:hidden" />check the specific rules for risk assessment.<br />Report false positives via GitHub Issues.</>}
        </p>
      </Reveal>
    </div>
  );
}
