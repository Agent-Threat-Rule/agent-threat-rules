import { CountUp } from "@/components/CountUp";
import { pct } from "@/lib/recall";
import type { BenchmarkMeasurement } from "@/lib/stats";

/** CountUp shows one decimal; where that would read a rate as 0% or 100% when it is not, show the exact figure. */
function Rate({ value }: { value: number }) {
  const shown = Math.round(value * 1000) / 10;
  if ((shown === 100 && value !== 1) || (shown === 0 && value !== 0)) return <>{pct(value)}</>;
  return <CountUp target={shown} suffix="%" />;
}

/** A measured rate, as a percentage (or a plain score for F1), with its label. */
export function MetricCell({ value, label, plain = false }: { value: number; label: string; plain?: boolean }) {
  return (
    <div>
      <div className="font-data text-2xl font-bold text-ink">
        {plain ? <CountUp target={Math.round(value * 1000) / 10} /> : <Rate value={value} />}
      </div>
      <div className="text-xs text-stone">{label}</div>
    </div>
  );
}

/**
 * A recall with its lane: the hunt figure, and under it the enforce figure the
 * same measurement records (or a note that it records none).
 */
export function RecallCell({ m, label, zh }: { m: BenchmarkMeasurement; label: string; zh: boolean }) {
  return (
    <div>
      <div className="font-data text-2xl font-bold text-ink">
        <Rate value={m.recall} />
      </div>
      <div className="text-xs text-stone">{label} · hunt</div>
      <div className="font-data text-xs text-stone mt-1">
        {m.enforce
          ? `enforce ${pct(m.enforce.recall)}`
          : zh ? "enforce 未記錄" : "enforce not recorded"}
      </div>
    </div>
  );
}
