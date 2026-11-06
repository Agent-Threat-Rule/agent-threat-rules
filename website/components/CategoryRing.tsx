import { FigureLabel } from "./Sheet";

/**
 * FIG. 02: the ten threat categories as a ring around the standard, with the
 * reference frameworks underneath. Static SVG drawn on a framed sheet.
 */
export function CategoryRing({
  categories,
  references,
  title,
  activeIndex = 0,
}: {
  /** Display names in order; letters A, B, C... are assigned by position. */
  categories: string[];
  references: string[];
  title: string;
  activeIndex?: number;
}) {
  const cx = 260;
  const cy = 250;
  const r = 132;
  const nodes = categories.map((name, i) => {
    const angle = (-90 + (360 / categories.length) * i) * (Math.PI / 180);
    return {
      name,
      letter: String.fromCharCode(65 + i),
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
      lx: cx + (r + 34) * Math.cos(angle),
      ly: cy + (r + 34) * Math.sin(angle),
      anchor: Math.abs(Math.cos(angle)) < 0.2 ? "middle" : Math.cos(angle) > 0 ? "start" : "end",
    };
  });

  return (
    <div className="border border-fog bg-paper p-3">
      <div className="border border-fog bg-white/50 p-4">
        <div className="border-b border-fog pb-3">
          <FigureLabel fig="02" title={title} />
        </div>
        <svg viewBox="0 0 520 500" className="w-full h-auto" role="img" aria-label={`${title}: ${categories.join(", ")}`}>
          <defs>
            <pattern id="ringgrid" width="26" height="26" patternUnits="userSpaceOnUse">
              <path d="M 26 0 L 0 0 0 26" fill="none" stroke="#DFDFDF" strokeWidth="0.6" />
            </pattern>
            <radialGradient id="ringfade">
              <stop offset="40%" stopColor="#fff" stopOpacity="1" />
              <stop offset="100%" stopColor="#fff" stopOpacity="0" />
            </radialGradient>
            <mask id="ringmask">
              <circle cx={cx} cy={cy} r="210" fill="url(#ringfade)" />
            </mask>
          </defs>
          <rect x="0" y="0" width="520" height="500" fill="url(#ringgrid)" mask="url(#ringmask)" />
          <circle cx={cx} cy={cy} r={r + 22} fill="none" stroke="#D2D2D2" strokeWidth="0.8" />
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="#C4C4C4" strokeWidth="0.8" strokeDasharray="2 4" />
          <circle cx={cx} cy={cy} r="62" fill="#F8F8F8" stroke="#1A1A1A" strokeWidth="1.2" />
          <circle cx={cx} cy={cy} r="55" fill="none" stroke="#1A1A1A" strokeWidth="0.8" />
          <text x={cx} y={cy + 9} textAnchor="middle" fontSize="26" fill="#1A1A1A" style={{ fontFamily: "var(--font-geist-sans)", letterSpacing: "0.04em" }}>ATR</text>
          {nodes.map((n, i) => (
            <g key={n.name}>
              <line x1={cx} y1={cy} x2={n.x} y2={n.y} stroke="#E4E4E4" strokeWidth="0.6" />
              <circle cx={n.x} cy={n.y} r="11" fill={i === activeIndex ? "#EAF6EE" : "#FFFFFF"} stroke={i === activeIndex ? "#2EA44F" : "#8C8C8C"} strokeWidth="0.9" />
              <text x={n.x} y={n.y + 3.5} textAnchor="middle" fontSize="9.5" fill="#1A1A1A" style={{ fontFamily: "var(--font-geist-mono)" }}>{n.letter}</text>
              <text x={n.lx} y={n.ly + 3} textAnchor={n.anchor as "start" | "middle" | "end"} fontSize="8.2" fill="#5F5F5F" style={{ fontFamily: "var(--font-geist-mono)", letterSpacing: "0.08em" }}>
                {n.name.toUpperCase()}
              </text>
            </g>
          ))}
          <line x1={cx} y1={cy + r + 44} x2={cx} y2="456" stroke="#2EA44F" strokeWidth="0.8" />
          <rect x={cx - 60} y="456" width="120" height="22" fill="#FFFFFF" stroke="#C4C4C4" strokeWidth="0.8" />
          <text x={cx} y="470.5" textAnchor="middle" fontSize="8" fill="#1A1A1A" style={{ fontFamily: "var(--font-geist-mono)", letterSpacing: "0.1em" }}>REF. STANDARDS</text>
        </svg>
        <div className="border-t border-fog pt-3 flex flex-wrap justify-center gap-x-4 gap-y-1 font-data text-[10px] tracking-[0.1em] text-stone uppercase">
          {references.map((ref) => <span key={ref}>{ref}</span>)}
        </div>
      </div>
    </div>
  );
}
