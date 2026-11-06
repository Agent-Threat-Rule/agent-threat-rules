import { EMBLEMS, type EmblemName, type Shape } from "@/lib/emblems";

/* Engraved line emblems (lib/emblems.ts) and the pieces built from them:
 * a beaded medallion and a meander band. Static SVG, no client code. */

const STROKE = { fill: "none", stroke: "currentColor", strokeLinecap: "round", strokeLinejoin: "round", vectorEffect: "non-scaling-stroke" } as const;

function Shapes({ shapes, color, width }: { shapes: ReadonlyArray<Shape>; color: string; width: number }) {
  return (
    <>
      {shapes.map((s, i) => {
        const style = { ...STROKE, stroke: color, strokeWidth: width, fill: s.fill ? color : "none" };
        return "c" in s ? <circle key={i} cx={s.c[0]} cy={s.c[1]} r={s.c[2]} {...style} /> : <path key={i} d={s.d} {...style} />;
      })}
    </>
  );
}

function Glyph({ name, width }: { name: EmblemName; width: number }) {
  const e = EMBLEMS[name];
  return (
    <>
      <Shapes shapes={e.base} color="currentColor" width={width} />
      {"accent" in e && e.accent && <Shapes shapes={e.accent} color="var(--alert)" width={width} />}
    </>
  );
}

export function Emblem({ name, size = 48, stroke = 1.25, className = "" }: { name: EmblemName; size?: number; stroke?: number; className?: string }) {
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} className={className} aria-hidden="true">
      <Glyph name={name} width={stroke} />
    </svg>
  );
}

const BEADS = Array.from({ length: 36 }, (_, i) => {
  const a = (i / 36) * Math.PI * 2;
  return [Math.round((60 + Math.cos(a) * 55.5) * 100) / 100, Math.round((60 + Math.sin(a) * 55.5) * 100) / 100];
});

/** An emblem struck inside a ring of beads, like the face of a coin. */
export function Medallion({ name, size = 96, className = "" }: { name: EmblemName; size?: number; className?: string }) {
  return (
    <svg viewBox="0 0 120 120" width={size} height={size} className={className} aria-hidden="true">
      <circle cx="60" cy="60" r="59" {...STROKE} strokeWidth={1} />
      <circle cx="60" cy="60" r="52" {...STROKE} strokeWidth={1} />
      {BEADS.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r={0.9} fill="currentColor" />
      ))}
      <g transform="translate(22 22) scale(1.1875)">
        <Glyph name={name} width={1.15} />
      </g>
    </svg>
  );
}

/** A running Greek key, drawn as a thin band across its container. */
export function Meander({ className = "", height = 14 }: { className?: string; height?: number }) {
  const unit = height;
  const s = (n: number) => Math.round((n * height) / 14 * 100) / 100;
  return (
    <svg width="100%" height={height + 2} className={className} aria-hidden="true">
      <defs>
        <pattern id={`atr-meander-${height}`} width={unit} height={height + 2} patternUnits="userSpaceOnUse">
          <path d={`M0 ${s(14)} V${s(2)} H${s(10)} V${s(10)} H${s(4)} V${s(6)} H${s(7)} M0 ${s(14)} H${unit}`} {...STROKE} strokeWidth={1} />
        </pattern>
      </defs>
      <rect width="100%" height={height + 2} fill={`url(#atr-meander-${height})`} />
    </svg>
  );
}

const SEAL_UNITS = 30;
const SEAL_KEY = (() => {
  const r = 64; // mid radius of the key band
  const w = (2 * Math.PI * r) / SEAL_UNITS;
  const k = w / 14;
  const q = (n: number) => Math.round(n * k * 100) / 100;
  return `M0 ${q(11)} V${q(1)} H${q(10)} V${q(8)} H${q(4)} V${q(4)} H${q(7)} M0 ${q(11)} H${q(14)}`;
})();

/**
 * A larger seal: an emblem inside a ring of running Greek key, between two
 * hairline circles. Used where one emblem stands for a whole page or tool.
 */
export function Seal({ name, size = 140, className = "" }: { name: EmblemName; size?: number; className?: string }) {
  const units = Array.from({ length: SEAL_UNITS }, (_, i) => (i * 360) / SEAL_UNITS);
  return (
    <svg viewBox="0 0 160 160" width={size} height={size} className={className} aria-hidden="true">
      <circle cx="80" cy="80" r="78" {...STROKE} strokeWidth={1} />
      <circle cx="80" cy="80" r="74.5" {...STROKE} strokeWidth={1} />
      <g transform="translate(80 80)">
        {units.map((deg) => (
          <path key={deg} d={SEAL_KEY} transform={`rotate(${deg}) translate(-6.7 -72)`} {...STROKE} strokeWidth={0.9} />
        ))}
      </g>
      <circle cx="80" cy="80" r="58" {...STROKE} strokeWidth={1} />
      <g transform="translate(36 36) scale(1.375)">
        <Glyph name={name} width={1.15} />
      </g>
    </svg>
  );
}
