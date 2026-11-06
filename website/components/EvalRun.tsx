"use client";

import { useRef } from "react";
import { EXAMPLE_AGENT, ILLUSTRATIVE_HITS, SELECTED, TRIALS, wilson } from "@/lib/eval-demo";
import { useTimeline } from "@/lib/use-timeline";

// Timeline, in ms: controls, trials, receipt, signature, recompute.
const CTRL0 = 500;
const CTRL_STEP = 45;
const TRIAL0 = 2200;
const TRIAL_STEP = 105;
const ROWS = SELECTED.length;
const TRIALS_END = TRIAL0 + TRIALS * ROWS * TRIAL_STEP;
const RECEIPT0 = TRIALS_END + 900;
const SIGN = RECEIPT0 + 1900;
const VERIFY = SIGN + 1100;
const TOTAL = VERIFY + 4200;
const STILL = VERIFY + 2000;

const ROW = "grid grid-cols-[minmax(0,1fr)_200px_200px_120px] gap-x-6 items-center";
const DIGEST = "sha256:4be1c07a9e3f52d8b16a0c4e77f9d2a1";

// Which trials succeed in each row: spread out, fixed, so the loop looks the same each time.
const hitSet = (row: number) => {
  const hits = ILLUSTRATIVE_HITS[row] ?? 0;
  const order = [6, 2, 9, 4, 0, 7, 3, 8, 1, 5];
  return new Set(order.slice(0, hits).map((i) => (i + row * 3) % TRIALS));
};
// The no-attack twin finishes its task every time except once in row three.
const twinFails = (row: number, trial: number) => row === 2 && trial === 4;

function Cell({ state }: { state: "empty" | "hit" | "held" | "done" | "fail" }) {
  const cls = {
    empty: "border border-fog",
    hit: "bg-alert",
    held: "bg-ink",
    done: "bg-brand",
    fail: "border border-mist",
  }[state];
  return <span className={`block w-full aspect-square transition-colors duration-200 ${cls}`} />;
}

export function EvalRun({ locale }: { locale: string }) {
  const zh = locale === "zh";
  const pick = (b: { en: string; zh: string }) => (zh ? b.zh : b.en);
  const rootRef = useRef<HTMLDivElement>(null);
  const t = useTimeline(rootRef, TOTAL, STILL);

  const ctrlFilled = (i: number) => t >= CTRL0 + i * CTRL_STEP;
  const ctrlDone = t >= CTRL0 + 2 * TRIALS * CTRL_STEP + 300;
  const trialFilled = (row: number, trial: number) => t >= TRIAL0 + (trial * ROWS + row) * TRIAL_STEP;
  const rowDone = (row: number) => trialFilled(row, TRIALS - 1);
  const rescoring = t >= VERIFY && t < VERIFY + 1400;
  const digestChars = Math.max(0, Math.min(DIGEST.length, Math.floor((t - (RECEIPT0 + 900)) / 28)));
  const totalVerdicts = ROWS * TRIALS * 2;

  return (
    <div ref={rootRef} className="relative">
      <div className="absolute right-0 -top-8 text-[11.5px] text-mist">{zh ? "示意，不是實測結果" : "Illustration, not a measured result"}</div>

      {/* Controls */}
      <div className="overflow-x-auto">
        <div className="min-w-[640px]">
          <div className="pb-2 text-[12px] text-stone">{zh ? "開跑前，先確認檢查本身可靠" : "Before the run, the checks themselves are checked"}</div>
          {[
            { label: zh ? "什麼攻擊都照做的 agent" : "Agent that obeys every attack", state: "hit" as const, expect: "10 / 10" },
            { label: zh ? "什麼都不做的 agent" : "Agent that does nothing", state: "held" as const, expect: "0 / 10" },
          ].map((c, r) => (
            <div key={c.label} className={`${ROW} py-2.5 border-t border-fog`}>
              <span className="text-[12.5px] text-ink">{c.label}</span>
              <div className="grid grid-cols-10 gap-1">
                {Array.from({ length: TRIALS }, (_, i) => (
                  <Cell key={i} state={ctrlFilled(r * TRIALS + i) ? c.state : "empty"} />
                ))}
              </div>
              <span />
              <span className={`font-data text-[12px] transition-opacity duration-300 ${ctrlDone ? "opacity-100 text-brand-ink" : "opacity-0"}`}>
                {c.expect} ✓
              </span>
            </div>
          ))}
          <p className={`pt-3 border-t border-fog text-[12.5px] transition-colors duration-500 ${ctrlDone ? "text-brand-ink" : "text-transparent"}`}>
            {zh ? "檢查本身沒問題，開跑。" : "The checks hold. The run starts."}
          </p>
        </div>
      </div>

      {/* Trials */}
      <div className="mt-10 overflow-x-auto">
        <div className="min-w-[640px]">
          <div className={`${ROW} pb-2 text-[12px] text-stone`}>
            <span>{zh ? `${EXAMPLE_AGENT.name} ${EXAMPLE_AGENT.version}` : `${EXAMPLE_AGENT.name} ${EXAMPLE_AGENT.version}`}</span>
            <span>{zh ? "有攻擊，跑 10 次" : "With the attack, 10 runs"}</span>
            <span>{zh ? "沒有攻擊的雙胞胎" : "Twin, no attack"}</span>
            <span>{zh ? "得逞率，95% 區間" : "Success, 95% interval"}</span>
          </div>
          {SELECTED.map((a, row) => {
            const hits = hitSet(row);
            const k = hits.size;
            const [lo, hi] = wilson(k, TRIALS);
            return (
              <div key={a.id} className={`${ROW} py-3 border-t border-fog transition-colors duration-300 ${rescoring ? "bg-brand-tint" : ""}`}>
                <div className="min-w-0">
                  <div className="font-data text-[10.5px] text-mist">{a.id}</div>
                  <div className="text-[12.5px] leading-[1.4] text-ink truncate">{pick(a.title)}</div>
                </div>
                <div className="grid grid-cols-10 gap-1">
                  {Array.from({ length: TRIALS }, (_, i) => (
                    <Cell key={i} state={trialFilled(row, i) ? (hits.has(i) ? "hit" : "held") : "empty"} />
                  ))}
                </div>
                <div className="grid grid-cols-10 gap-1">
                  {Array.from({ length: TRIALS }, (_, i) => (
                    <Cell key={i} state={trialFilled(row, i) ? (twinFails(row, i) ? "fail" : "done") : "empty"} />
                  ))}
                </div>
                <div className={`transition-opacity duration-500 ${rowDone(row) ? "opacity-100" : "opacity-0"}`}>
                  <div className="font-data text-[12px] text-ink tabular-nums">{k} / {TRIALS}</div>
                  <div className="relative mt-1.5 h-[6px] bg-ash">
                    <span
                      className="absolute top-0 bottom-0 bg-alert/70 transition-[width] duration-700"
                      style={{ left: `${lo * 100}%`, width: rowDone(row) ? `${(hi - lo) * 100}%` : "0%" }}
                    />
                    <span className="absolute -top-[3px] -bottom-[3px] w-[2px] bg-ink" style={{ left: `calc(${(k / TRIALS) * 100}% - 1px)` }} />
                  </div>
                </div>
              </div>
            );
          })}
          <div className="flex flex-wrap gap-x-5 gap-y-1 pt-3 border-t border-fog text-[11.5px] text-stone">
            <span className="inline-flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-alert" />{zh ? "攻擊得逞" : "Attack succeeded"}</span>
            <span className="inline-flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-ink" />{zh ? "擋下了" : "Held"}</span>
            <span className="inline-flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-brand" />{zh ? "沒有攻擊時，任務完成" : "Task done, no attack"}</span>
          </div>
        </div>
      </div>

      {/* Receipt */}
      <div className={`mt-10 grid md:grid-cols-[1fr_auto] gap-6 items-end transition-all duration-700 ${t >= RECEIPT0 ? "opacity-100 translate-y-0" : "opacity-0 translate-y-3"}`}>
        <div className="relative border border-ink bg-white px-5 py-4 font-data text-[12px] leading-[1.9] max-w-[560px]">
          <div className="text-ink">receipt.dsse.json</div>
          <div className="grid grid-cols-[96px_1fr] text-stone">
            <span>subject</span><span className="text-ink">{EXAMPLE_AGENT.name} {EXAMPLE_AGENT.version}</span>
            <span>verdicts</span><span className="text-ink">{totalVerdicts}</span>
            <span>evidence</span><span className="text-ink truncate">{DIGEST.slice(0, digestChars)}<span className={digestChars < DIGEST.length && t >= RECEIPT0 + 900 ? "animate-pulse" : "opacity-0"}>▍</span></span>
            <span>signature</span>
            <span className={`transition-opacity duration-300 ${t >= SIGN ? "opacity-100 text-brand-ink" : "opacity-0"}`}>Ed25519 · in-toto / DSSE</span>
          </div>
          <span
            className={`absolute -right-4 -top-4 w-16 h-16 rounded-full border-2 border-brand text-brand-ink flex items-center justify-center text-[11px] font-data rotate-[-12deg] bg-white transition-all duration-300 ${t >= SIGN ? "opacity-100 scale-100" : "opacity-0 scale-150"}`}
            aria-hidden="true"
          >
            {zh ? "已簽" : "signed"}
          </span>
        </div>
        <div className={`font-data text-[12px] leading-[1.8] transition-opacity duration-500 ${t >= VERIFY ? "opacity-100" : "opacity-0"}`}>
          <div className="text-stone">$ atr-eval verify run --rescore</div>
          <div className={`transition-opacity duration-300 ${t >= VERIFY + 1400 ? "opacity-100 text-brand-ink" : "opacity-0"}`}>
            {zh ? `簽章有效。${totalVerdicts} 個判定重算，全部一致。` : `Signature valid. ${totalVerdicts} verdicts recomputed, all match.`}
          </div>
        </div>
      </div>
    </div>
  );
}
