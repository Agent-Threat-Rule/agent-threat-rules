"use client";

import Link from "next/link";
import { useRef } from "react";
import data from "@/data/scenarios.json";
import { useSteps } from "@/lib/use-steps";
import { Sign } from "@/components/Sign";

type Match = { id: string; title: string; severity: string; category: string | null };
type Step = { type: string; role: string; name: string | null; content: string; attack: string | null; matches: { hunt: Match[]; alert: Match[]; enforce: Match[] } };

const LABELS: Record<string, { en: string; zh: string }> = {
  coding: { en: "Coding agent", zh: "寫程式的 agent" },
  support: { en: "Support agent", zh: "客服 agent" },
  automation: { en: "Ops agent", zh: "維運 agent" },
};

// Per scenario: blank, task, tool call, tool result, scan, verdict.
const BEATS = [350, 800, 800, 900, 1100, 3800];
const DURATIONS = data.scenarios.flatMap(() => BEATS);

/**
 * The hero: three agent sessions, each with an attack hidden in what the
 * agent reads. ATR's verdict on every message is the published engine's
 * recorded output in the alert lane (data/scenarios.json).
 */
export function AgentConsole({ locale, ruleCount }: { locale: string; ruleCount: number }) {
  const zh = locale === "zh";
  const rootRef = useRef<HTMLDivElement>(null);
  // Server renders the first session complete; the loop starts from there.
  const [tick] = useSteps(rootRef, DURATIONS, false, BEATS.length - 1);
  const sIndex = Math.floor(tick / BEATS.length);
  const beat = tick % BEATS.length;
  const scenario = data.scenarios[sIndex];
  const [task, call, result] = scenario.steps as Step[];
  const verdict = result.matches.alert;
  const lead = verdict[0];

  const shown = (n: number) => (beat >= n ? "opacity-100 translate-y-0" : "opacity-0 translate-y-1.5");
  const attackOn = beat >= 5 && !!result.attack;
  const parts = result.attack ? result.content.split(result.attack) : [result.content];

  return (
    <div ref={rootRef} className="relative w-full min-w-0">

      <div className="mb-3 text-[12.5px] text-stone" aria-live="polite">
        {zh ? "例" : "Example"} · <span className="text-ink">{zh ? LABELS[scenario.key].zh : LABELS[scenario.key].en}</span>
      </div>

      <div className="relative bg-white border border-ink">
        <div className="flex items-center gap-3 px-4 h-10 border-b border-fog">
          <span className="font-data text-[11.5px] text-ink">{scenario.agent}</span>
          <span className="ml-auto font-data text-[10.5px] text-stone">ATR · alert lane</span>
        </div>

        <div className="px-4 py-4 space-y-3 h-[300px] sm:h-[280px] overflow-hidden font-data text-[11.5px] leading-[1.6]">
          <div className={`transition-all duration-500 ${shown(1)}`}>
            <span className="text-mist">{zh ? "使用者" : "user"}</span>
            <p className="mt-0.5 font-body text-[13px] text-ink">{task.content}</p>
          </div>
          <div className={`transition-all duration-500 ${shown(2)}`}>
            <span className="text-mist">→ {call.name}</span> <span className="text-stone">{call.content}</span>
          </div>
          <div className={`relative transition-all duration-500 ${shown(3)}`}>
            <span className="text-mist">← {result.name}</span>
            <div className="relative mt-1 border-l-2 border-fog pl-3 text-graphite whitespace-pre-wrap break-words">
              {parts[0]}
              {result.attack && (
                <>
                  <Sign name="obelos" size={12} className={`mr-1.5 align-[-1px] text-ink transition-opacity duration-500 ${attackOn ? "opacity-100" : "opacity-0"}`} label={zh ? "劍號：這一段不屬於原文" : "Obelos: this text does not belong"} />
                  <mark className={`transition-colors duration-500 ${attackOn ? "bg-alert/15 text-alert-ink" : "bg-transparent text-graphite"}`}>{result.attack}</mark>
                </>
              )}
              {parts[1]}
              {beat === 4 && <span className="absolute inset-x-0 h-6 -top-1 bg-gradient-to-b from-transparent via-ink/10 to-transparent animate-[scan_1.1s_ease-in-out]" aria-hidden="true" />}
            </div>
          </div>
        </div>

        <div className="border-t border-fog px-4 h-[92px] flex flex-col justify-center">
          {beat === 4 && (
            <div className="font-data text-[11.5px] text-stone">{zh ? `對照 ${ruleCount} 條規則…` : `Checking ${ruleCount} rules…`}</div>
          )}
          {beat >= 5 && lead && (
            <div className="animate-[fadein_350ms_ease-out]">
              <div className="flex items-center gap-2 flex-wrap">
                <Sign name="obelos" size={12} className="text-ink" />
                <Link href={`/${locale}/rules/${lead.id}`} className="font-data text-[12.5px] text-ink hover:underline underline-offset-2">{lead.id}</Link>
                <span className="font-data text-[10.5px] text-stone uppercase">{lead.severity}</span>
              </div>
              <div className="mt-1 pl-5 text-[13px] text-ink truncate">{lead.title}</div>
              <div className="mt-0.5 flex items-center gap-2 text-[11.5px] text-stone">
                {verdict.length > 1 && <Sign name="asteriskos" size={12} />}
                {verdict.length > 1
                  ? zh ? `另外 ${verdict.length - 1} 條規則也認出這一段` : `${verdict.length - 1} more rules flagged the same text`
                  : zh ? "其他 agent 動作：沒有命中" : "Other steps: no match"}
              </div>
            </div>
          )}
          {beat < 4 && <div className="font-data text-[11.5px] text-mist">{zh ? "每一則輸入，ATR 都會跑一遍" : "ATR runs on every message"}</div>}
        </div>
      </div>

      <p className="relative mt-3 text-[11.5px] text-stone">
        {zh
          ? `以上判定，是 agent-threat-rules ${data.engine} 實際跑出來的結果。攻擊內容取自規則的測試案例。`
          : `Verdicts are what agent-threat-rules ${data.engine} actually returned. Each attack is taken from a rule's test cases.`}
      </p>
    </div>
  );
}
