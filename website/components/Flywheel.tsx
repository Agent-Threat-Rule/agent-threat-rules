"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { motion, AnimatePresence, useInView } from "motion/react";

interface Step {
  label: string;
  labelZh: string;
  actor: string;
  actorZh: string;
  detail: string;
  detailZh: string;
}

const STEPS: Step[] = [
  {
    label: "Detect",
    labelZh: "偵測",
    actor: "Global Sensors",
    actorZh: "全球感測器",
    detail: "Endpoints report suspicious patterns via ATR Reporter",
    detailZh: "端點透過 ATR Reporter 回報可疑模式",
  },
  {
    label: "Analyze",
    labelZh: "分析",
    actor: "Threat Cloud LLM",
    actorZh: "Threat Cloud LLM",
    detail: "In the rule-authoring pipeline (not per-scan), the LLM analyzes attack structure, intent, and evasion techniques",
    detailZh: "在規則撰寫管線中(非每次掃描),LLM 分析攻擊結構、意圖、和繞過技術",
  },
  {
    label: "Crystallize",
    labelZh: "結晶",
    actor: "Auto-gen Engine",
    actorZh: "自動生成引擎",
    detail: "Generates YAML rule + test cases from attack analysis",
    detailZh: "從攻擊分析中生成 YAML 規則 + 測試案例",
  },
  {
    label: "Review",
    labelZh: "審查",
    actor: "Community",
    actorZh: "社群",
    detail: "Contributors review, precision gates must pass",
    detailZh: "貢獻者審查，精準度關卡必須通過",
  },
  {
    label: "Deploy",
    labelZh: "部署",
    actor: "All Platforms",
    actorZh: "所有平台",
    detail: "Merged into ATR, downstream auto-updates via npm",
    detailZh: "合併到 ATR，下游透過 npm 自動更新",
  },
];

const N = STEPS.length;
const EASE: [number, number, number, number] = [0.25, 0.1, 0.25, 1];

export function Flywheel({ locale = "en" }: { locale?: string }) {
  const zh = locale === "zh";
  const containerRef = useRef<HTMLDivElement>(null);
  const isInView = useInView(containerRef, { once: true, margin: "-80px" });
  const [active, setActive] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!isInView) return;

    timerRef.current = setInterval(() => {
      setActive((prev) => (prev + 1) % N);
    }, 3000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isInView]);

  const handleClick = useCallback((idx: number) => {
    setActive(idx);
    // Reset timer
    if (timerRef.current) clearInterval(timerRef.current);
    timerRef.current = setInterval(() => {
      setActive((prev) => (prev + 1) % N);
    }, 3000);
  }, []);

  return (
    <div ref={containerRef} className="max-w-[720px]">
      {/* Step indicators — horizontal row */}
      <div className="flex items-center mb-8">
        {STEPS.map((step, i) => {
          const isActive = i === active;
          const isPast = i < active;
          return (
            <div key={step.label} className="flex items-center flex-1 last:flex-none">
              {/* Node */}
              <button
                onClick={() => handleClick(i)}
                className={`relative shrink-0 w-10 h-10 rounded-sm flex items-center justify-center font-data text-xs font-bold transition-all duration-500 cursor-pointer ${
                  isActive
                    ? "bg-blue text-white"
                    : isPast
                    ? "bg-blue/10 text-blue"
                    : "bg-ash text-stone border border-fog"
                }`}
              >
                {i + 1}
                {isActive && (
                  <motion.div
                    className="absolute inset-0 rounded-sm border-2 border-blue"
                    layoutId="flywheel-ring"
                    transition={{ duration: 0.4, ease: EASE }}
                  />
                )}
              </button>
              {/* Connector line */}
              {i < N - 1 && (
                <div className="flex-1 h-px mx-1 relative overflow-hidden">
                  <div className="absolute inset-0 bg-fog" />
                  <motion.div
                    className="absolute top-0 left-0 h-full bg-blue origin-left"
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: isPast || isActive ? 1 : 0 }}
                    transition={{ duration: 0.5, ease: EASE }}
                  />
                </div>
              )}
            </div>
          );
        })}
        {/* Loop-back arrow */}
        <div className="ml-2 text-stone">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M17 1L21 5L17 9" />
            <path d="M21 5H7C4.23858 5 2 7.23858 2 10V11" />
          </svg>
        </div>
      </div>

      {/* Active step detail card */}
      <AnimatePresence mode="wait">
        <motion.div
          key={active}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.35, ease: EASE }}
          className="border border-fog p-6 md:p-8"
        >
          <div className="flex items-baseline gap-3 mb-2">
            <span className="font-data text-xs text-blue tracking-[2px] uppercase font-bold">
              {zh ? STEPS[active].labelZh : STEPS[active].label}
            </span>
            <span className="text-xs text-mist">
              {active + 1}/{N}
            </span>
          </div>
          <div className="font-display text-lg md:text-xl font-bold text-ink mb-2">
            {zh ? STEPS[active].actorZh : STEPS[active].actor}
          </div>
          <p className="text-sm text-stone leading-[1.7]">
            {zh ? STEPS[active].detailZh : STEPS[active].detail}
          </p>
        </motion.div>
      </AnimatePresence>

      {/* Loop annotation */}
      <div className="mt-4 md:flex md:items-center md:gap-2">
        <div className="h-px flex-1 bg-fog hidden md:block" />
        <span className="font-data text-[10px] md:text-xs text-mist tracking-[1px] uppercase block text-center">
          {zh ? "更多端點 = 更多資料 = 更強規則" : "More endpoints = more data = stronger rules"}
        </span>
        <div className="h-px flex-1 bg-fog hidden md:block" />
      </div>
    </div>
  );
}
