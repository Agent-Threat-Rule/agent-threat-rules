"use client";

import { useEffect, useRef, useState } from "react";
import { ATOMICS, CHANNEL_LABEL, EFFECT_LABEL, EXAMPLE_AGENT, applies } from "@/lib/eval-demo";
import { useTimeline } from "@/lib/use-timeline";

// Timeline, in ms: read the tools, judge each test, run, deliver.
const SCAN0 = 600;
const SCAN_STEP = 420;
const PICK0 = 3300;
const PICK_STEP = 270;
const RUN0 = 6500;
const OUT0 = 9600;
const OUT_STEP = 520;
const TOTAL = 15500;
const STILL = 13000;

const OUTPUTS = [
  { name: "SARIF", to: { en: "for CI", zh: "給 CI" } },
  { name: "OSCAL", to: { en: "for GRC tools", zh: "給 GRC 工具" } },
  { name: "receipt.dsse.json", to: { en: "for auditors and insurers", zh: "給稽核與保險業者" } },
];
const ADAPTERS = ["agent.yaml", "Claude Code", "Grok Build"];

type Point = { x: number; y: number };
type Anchors = { agent: Point; tiles: Point[]; hub: Point; outs: Point[]; w: number; h: number };

const curve = (a: Point, b: Point) => {
  const mx = (a.x + b.x) / 2;
  return `M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`;
};

export function RouterFlow({ locale }: { locale: string }) {
  const zh = locale === "zh";
  const pick = (b: { en: string; zh: string }) => (zh ? b.zh : b.en);
  const rootRef = useRef<HTMLDivElement>(null);
  const agentRef = useRef<HTMLDivElement>(null);
  const tilesRef = useRef<HTMLDivElement>(null);
  const tileRefs = useRef<Array<HTMLDivElement | null>>([]);
  const outRefs = useRef<Array<HTMLDivElement | null>>([]);
  const [anchors, setAnchors] = useState<Anchors | null>(null);
  const t = useTimeline(rootRef, TOTAL, STILL);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const measure = () => {
      const base = root.getBoundingClientRect();
      const rel = (el: Element | null, side: "l" | "r"): Point => {
        if (!el) return { x: 0, y: 0 };
        const r = el.getBoundingClientRect();
        return { x: (side === "l" ? r.left : r.right) - base.left, y: r.top + r.height / 2 - base.top };
      };
      setAnchors({
        agent: rel(agentRef.current, "r"),
        tiles: tileRefs.current.map((el) => rel(el, "l")),
        hub: rel(tilesRef.current, "r"),
        outs: outRefs.current.map((el) => rel(el, "l")),
        w: base.width,
        h: base.height,
      });
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(root);
    return () => ro.disconnect();
  }, []);

  const tools = EXAMPLE_AGENT.tools;
  const scanned = (i: number) => t >= SCAN0 + i * SCAN_STEP;
  const scanning = (i: number) => scanned(i) && t < SCAN0 + (i + 1) * SCAN_STEP;
  const judged = (j: number) => t >= PICK0 + j * PICK_STEP;
  const fits = ATOMICS.map((a) => applies(a, tools, EXAMPLE_AGENT.persistentMemory));
  const running = t >= RUN0;
  const runOrder = (j: number) => fits.slice(0, j).filter(Boolean).length;
  const delivered = (k: number) => t >= OUT0 + k * OUT_STEP;
  const selectedCount = fits.filter(Boolean).length;

  return (
    <div ref={rootRef} className="relative">
      <div className="absolute right-0 -top-8 text-[11.5px] text-mist">{zh ? "示意，不是實測結果" : "Illustration, not a measured result"}</div>
      {anchors && anchors.w >= 900 && (
        <svg className="absolute inset-0 w-full h-full pointer-events-none hidden lg:block" viewBox={`0 0 ${anchors.w} ${anchors.h}`} aria-hidden="true">
          {ATOMICS.map((a, j) =>
            fits[j] ? (
              <path
                key={a.id}
                d={curve(anchors.agent, anchors.tiles[j])}
                pathLength={1}
                className="fill-none stroke-ink transition-[stroke-dashoffset] duration-700 ease-out"
                strokeWidth={1}
                strokeDasharray="1"
                strokeDashoffset={judged(j) ? 0 : 1}
              />
            ) : null,
          )}
          {running &&
            ATOMICS.map((a, j) =>
              fits[j] ? (
                <circle key={`run-${a.id}`} r={2.5} className="fill-ink">
                  <animateMotion dur="1.4s" repeatCount="indefinite" begin={`${runOrder(j) * 0.25}s`} path={curve(anchors.agent, anchors.tiles[j])} />
                </circle>
              ) : null,
            )}
          {OUTPUTS.map((o, k) =>
            delivered(k) ? (
              <circle key={`out-${o.name}`} r={3} className="fill-ink">
                <animateMotion dur="1.6s" repeatCount="indefinite" path={curve(anchors.hub, anchors.outs[k])} />
              </circle>
            ) : null,
          )}
          {OUTPUTS.map((o, k) => (
            <path
              key={o.name}
              d={curve(anchors.hub, anchors.outs[k])}
              pathLength={1}
              className="fill-none stroke-ink transition-[stroke-dashoffset] duration-700 ease-out"
              strokeWidth={1.5}
              strokeDasharray="1"
              strokeDashoffset={delivered(k) ? 0 : 1}
            />
          ))}
        </svg>
      )}

      <div className="relative grid lg:grid-cols-[0.95fr_1.35fr_0.8fr] gap-10 lg:gap-16">
        {/* What it can reach */}
        <div className="min-w-0">
          <div className="text-[13px] text-stone">{zh ? "它碰得到什麼" : "What it can reach"}</div>
          <div ref={agentRef} className="mt-4 border border-ink bg-white">
            <div className="flex items-baseline justify-between px-4 py-3 border-b border-fog">
              <span className="font-data text-[13px] text-ink">{EXAMPLE_AGENT.name}</span>
              <span className="font-data text-[11px] text-mist">{EXAMPLE_AGENT.version}</span>
            </div>
            <ul>
              {tools.map((tool, i) => (
                <li key={tool.name} className={`flex items-center justify-between gap-3 px-4 py-2.5 border-b border-fog last:border-b-0 transition-colors duration-300 ${scanning(i) ? "bg-ash" : ""}`}>
                  <span className="font-data text-[12px] text-ink truncate">{tool.name}</span>
                  <span className={`text-[11.5px] whitespace-nowrap transition-opacity duration-500 ${scanned(i) ? "opacity-100" : "opacity-0"}`}>
                    {tool.channel && <span className="text-stone">{pick(CHANNEL_LABEL[tool.channel])}</span>}
                    {tool.channel && tool.effect && <span className="text-mist"> · </span>}
                    {tool.effect && <span className="text-ink">{pick(EFFECT_LABEL[tool.effect])}</span>}
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <p className={`mt-3 text-[12px] text-stone transition-opacity duration-500 ${scanned(tools.length - 1) ? "opacity-100" : "opacity-0"}`}>
            {zh ? "沒有 skill、檔案、付款、程式執行或長期記憶。" : "No skills, files, payments, code execution or long-term memory."}
          </p>
        </div>

        {/* What to test */}
        <div className="min-w-0">
          <div className="flex items-baseline justify-between text-[13px] text-stone">
            <span>{zh ? "要測什麼" : "What to test"}</span>
            <span className={`tabular-nums transition-opacity duration-500 ${judged(ATOMICS.length - 1) ? "opacity-100" : "opacity-0"}`}>
              {zh ? `10 題裡 ${selectedCount} 題適用` : `${selectedCount} of 10 apply`}
            </span>
          </div>
          <div ref={tilesRef} className="mt-4 grid gap-1.5">
            {ATOMICS.map((a, j) => {
              const done = judged(j);
              const on = done && fits[j];
              const off = done && !fits[j];
              return (
                <div
                  key={a.id}
                  ref={(el) => {
                    tileRefs.current[j] = el;
                  }}
                  className={`relative overflow-hidden border px-3 py-2 transition-all duration-500 ${on ? "border-ink bg-white" : "border-fog"} ${off ? "opacity-60" : ""}`}
                >
                  <div className="flex items-baseline gap-3">
                    <span className={`font-data text-[10.5px] shrink-0 ${on ? "text-ink" : "text-mist"}`}>{a.id}</span>
                    <span className={`text-[12.5px] leading-[1.45] truncate ${on ? "text-ink" : "text-stone"}`}>{pick(a.title)}</span>
                    {off && <span className="ml-auto shrink-0 text-[11px] text-mist">{zh ? "不適用" : "n/a"}</span>}
                  </div>
                  {fits[j] && (
                    <span
                      className="absolute left-0 bottom-0 h-[2px] bg-ink transition-[width] ease-linear"
                      style={{ width: running ? "100%" : "0%", transitionDuration: running ? "1800ms" : "0ms", transitionDelay: running ? `${runOrder(j) * 260}ms` : "0ms" }}
                    />
                  )}
                </div>
              );
            })}
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2 text-[12px]">
            <span className="text-stone mr-1">{zh ? "怎麼跑" : "How it runs"}</span>
            {ADAPTERS.map((name, i) => (
              <span key={name} className={`font-data px-2 py-1 border transition-colors duration-500 ${running && i === 0 ? "border-ink text-ink bg-white" : "border-fog text-mist"}`}>
                {name}
              </span>
            ))}
          </div>
        </div>

        {/* Who gets it */}
        <div className="min-w-0">
          <div className="text-[13px] text-stone">{zh ? "交給誰" : "Who gets it"}</div>
          <div className="mt-4 space-y-3 lg:mt-16">
            {OUTPUTS.map((o, k) => (
              <div
                key={o.name}
                ref={(el) => {
                  outRefs.current[k] = el;
                }}
                className={`relative border px-4 py-3.5 transition-all duration-500 ${delivered(k) ? "border-ink bg-white translate-x-0" : "border-fog text-mist lg:translate-x-2"}`}
              >
                <span className="absolute right-0 top-0 w-3 h-3 border-l border-b border-inherit bg-paper" aria-hidden="true" />
                <div className={`font-data text-[12.5px] ${delivered(k) ? "text-ink" : "text-mist"}`}>{o.name}</div>
                <div className="mt-0.5 text-[12px] text-stone">{pick(o.to)}</div>
                <span className={`absolute right-4 bottom-3.5 w-2 h-2 bg-ink transition-opacity duration-300 ${delivered(k) ? "opacity-100" : "opacity-0"}`} aria-hidden="true" />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
