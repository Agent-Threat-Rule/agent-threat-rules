"use client";

import Link from "next/link";
import { useRef, useState } from "react";
import { useSteps } from "@/lib/use-steps";

export interface BirthRule {
  id: string;
  title: string;
  severity: string;
  maturity: string;
  category: string;
  date: string;
  truePositives: number;
  trueNegatives: number;
  mappings: string[];
  npmVersion: string;
}

type B = { en: string; zh: string };

const STEPS: ReadonlyArray<{ key: string; label: B; head: B; body: B }> = [
  {
    key: "incident",
    label: { en: "Incident", zh: "事件" },
    head: { en: "Someone finds a new way in", zh: "有人找到新的入口" },
    body: {
      en: "July 2026: Manifold Security reports that an Azure DevOps MCP server hands pull-request descriptions to the agent untouched. An HTML comment in the description is invisible on the web page. The agent reads it and does what it says, with the reviewer's own access.",
      zh: "2026 年 7 月，Manifold Security 回報：Azure DevOps 的 MCP 伺服器把 PR 描述原封不動交給 agent。描述裡藏一段 HTML 註解，網頁上看不到，agent 卻讀得到，還會用審查者自己的權限照做。",
    },
  },
  {
    key: "rule",
    label: { en: "Rule", zh: "規則" },
    head: { en: "It is written down once", zh: "寫下來，一次就好" },
    body: {
      en: "The attack becomes a rule with a permanent ID. It describes the shape of the attack, not the vendor, so the same trick is caught wherever it shows up.",
      zh: "這一招被寫成一條規則，拿到永久編號。規則描述的是攻擊的樣子，不是某一家廠商，所以同一招換個地方出現，一樣認得出來。",
    },
  },
  {
    key: "tests",
    label: { en: "Tests", zh: "測試" },
    head: { en: "It has to prove both ways", zh: "該抓的抓，不該抓的放" },
    body: {
      en: "Every rule carries examples it must catch and examples it must leave alone. A named maintainer reviews it before it ships.",
      zh: "每條規則都附上必須抓到的例子，也附上必須放過的例子。放出去之前，由一位具名的維護者審過。",
    },
  },
  {
    key: "release",
    label: { en: "Release", zh: "發布" },
    head: { en: "Everyone gets it", zh: "所有人一起拿到" },
    body: {
      en: "It ships in the next numbered release. Every agent that updates ATR now knows this trick, and nobody had to sign anything or pay for it.",
      zh: "它跟著下一個版號發布。每一個更新了 ATR 的 agent，從此都認得這一招，沒有人需要簽約，也不用付錢。",
    },
  },
];

const DURATIONS = [5200, 5200, 5200, 5200];

export function RuleBirth({ locale, rule }: { locale: string; rule: BirthRule }) {
  const zh = locale === "zh";
  const pick = (b: B) => (zh ? b.zh : b.en);
  const rootRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState(false);
  const [step, setStep] = useSteps(rootRef, DURATIONS, hover);
  const current = STEPS[step];

  return (
    <div ref={rootRef} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
      <div className="grid grid-cols-4 border-b border-fog" role="tablist">
        {STEPS.map((s, i) => (
          <button key={s.key} role="tab" aria-selected={i === step} onClick={() => setStep(i)} className="relative text-left pb-3 pt-1 text-[13px] transition-colors">
            <span className={i === step ? "text-ink" : "text-mist hover:text-ink"}>{pick(s.label)}</span>
            <span className="absolute left-0 right-3 -bottom-px h-[2px] bg-fog overflow-hidden">
              <span
                key={`${step}-${i}`}
                className={`block h-full bg-brand ${i < step ? "w-full" : i === step ? "w-0 animate-[grow_5200ms_linear_forwards]" : "w-0"}`}
                style={i === step && hover ? { animationPlayState: "paused" } : undefined}
              />
            </span>
          </button>
        ))}
      </div>

      <div className="mt-10 grid lg:grid-cols-[1.15fr_1fr] gap-10 lg:gap-16 items-center">
        <div className="relative min-h-[320px] flex items-center justify-center py-8">
          <div className="absolute inset-0 grid-paper grid-paper-fade pointer-events-none" aria-hidden="true" />
          <div key={current.key} className="relative w-full max-w-[460px] animate-[fadein_450ms_ease-out]">
            {current.key === "incident" && <IncidentCard zh={zh} />}
            {current.key === "rule" && <RuleCard rule={rule} />}
            {current.key === "tests" && <TestsCard zh={zh} rule={rule} />}
            {current.key === "release" && <ReleaseCard zh={zh} rule={rule} />}
          </div>
        </div>
        <div key={`t-${current.key}`} className="animate-[fadein_450ms_ease-out]">
          <h3 className="text-[24px] md:text-[28px] leading-[1.25] tracking-[-0.02em] font-medium text-ink">{pick(current.head)}</h3>
          <p className="mt-4 text-[16px] leading-[1.8] text-graphite max-w-[480px]">{pick(current.body)}</p>
          <Link href={`/${locale}/rules/${rule.id}`} className="mt-6 inline-block text-[14px] text-ink underline underline-offset-[6px] decoration-brand decoration-2 hover:decoration-ink">
            {zh ? `看 ${rule.id} 全文` : `Read ${rule.id}`}
          </Link>
        </div>
      </div>
    </div>
  );
}

const CARD = "bg-white border border-fog shadow-[0_20px_50px_-30px_rgba(0,0,0,0.3)]";

function IncidentCard({ zh }: { zh: boolean }) {
  return (
    <div className={`${CARD} p-5`}>
      <div className="flex items-center justify-between font-data text-[10.5px] text-stone">
        <span>{zh ? "事件回報" : "Incident report"}</span>
        <span>2026-07-22</span>
      </div>
      <div className="mt-3 text-[15px] leading-snug text-ink">Azure DevOps MCP · repo_get_pull_request_by_id</div>
      <div className="mt-4 border border-fog bg-ash/40 p-3 font-data text-[11px] leading-[1.7] text-graphite">
        <div className="text-mist">PR #4021 · Fix typo in README</div>
        <div>Small docs fix.</div>
        <div className="mt-1 text-alert-ink bg-alert/10 px-1 -mx-1">&lt;!-- {zh ? "網頁上看不到的指令" : "an instruction the web page hides"} --&gt;</div>
      </div>
      <div className="mt-3 flex gap-2 text-[11px] font-data">
        <span className="px-1.5 py-0.5 border border-fog text-stone">{zh ? "回報者 Manifold Security" : "Reported by Manifold Security"}</span>
      </div>
    </div>
  );
}

function RuleCard({ rule }: { rule: BirthRule }) {
  const rows: Array<[string, string]> = [
    ["id", rule.id],
    ["severity", rule.severity],
    ["maturity", rule.maturity],
    ["category", rule.category],
    ["date", rule.date],
  ];
  return (
    <div className={`${CARD} font-data text-[11.5px] leading-[1.9]`}>
      <div className="px-5 py-2.5 border-b border-fog text-stone">{rule.id}.yaml</div>
      <div className="px-5 py-4">
        <div className="text-ink">title: <span className="text-graphite">&quot;{rule.title}&quot;</span></div>
        {rows.map(([k, v]) => (
          <div key={k} className="text-ink">
            {k}: <span className={k === "id" ? "text-brand-ink" : "text-graphite"}>{v}</span>
          </div>
        ))}
        <div className="text-ink">references:</div>
        {rule.mappings.slice(0, 4).map((m) => (
          <div key={m} className="pl-4 text-graphite">- {m}</div>
        ))}
      </div>
    </div>
  );
}

function TestsCard({ zh, rule }: { zh: boolean; rule: BirthRule }) {
  return (
    <div className={`${CARD} p-5`}>
      <div className="flex items-baseline justify-between text-[12px]">
        <span className="text-ink">{zh ? "必須抓到" : "Must catch"}</span>
        <span className="font-data text-stone">{rule.truePositives}</span>
      </div>
      <div className="mt-2 grid grid-cols-12 gap-1">
        {Array.from({ length: rule.truePositives }, (_, i) => (
          <span key={i} className="aspect-square bg-alert animate-[fadein_300ms_ease-out_both]" style={{ animationDelay: `${i * 70}ms` }} />
        ))}
      </div>
      <div className="mt-5 flex items-baseline justify-between text-[12px]">
        <span className="text-ink">{zh ? "必須放過" : "Must leave alone"}</span>
        <span className="font-data text-stone">{rule.trueNegatives}</span>
      </div>
      <div className="mt-2 grid grid-cols-12 gap-1">
        {Array.from({ length: rule.trueNegatives }, (_, i) => (
          <span key={i} className="aspect-square bg-brand animate-[fadein_300ms_ease-out_both]" style={{ animationDelay: `${(rule.truePositives + i) * 50}ms` }} />
        ))}
      </div>
      <div className="mt-5 pt-3 border-t border-fog text-[11.5px] text-stone">{zh ? "測試案例寫在規則檔裡，任何人都能重跑。" : "The test cases live in the rule file. Anyone can rerun them."}</div>
    </div>
  );
}

function ReleaseCard({ zh, rule }: { zh: boolean; rule: BirthRule }) {
  return (
    <div className={`${CARD} p-5`}>
      <div className="font-data text-[12px] text-stone">$ npm install agent-threat-rules@{rule.npmVersion}</div>
      <div className="mt-4 flex items-center gap-3">
        <span className="w-2 h-2 bg-brand" />
        <span className="font-data text-[12.5px] text-ink">{rule.id}</span>
        <span className="text-[12px] text-stone">{zh ? "已包含" : "included"}</span>
      </div>
      <div className="mt-5 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-[12.5px]">
        <span className="text-stone">{zh ? "事件回報" : "Reported"}</span>
        <span className="font-data text-ink">2026-07-22</span>
        <span className="text-stone">{zh ? "規則日期" : "Rule dated"}</span>
        <span className="font-data text-ink">{rule.date}</span>
      </div>
    </div>
  );
}
