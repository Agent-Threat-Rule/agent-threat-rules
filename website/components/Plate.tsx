/**
 * The ATR plate: the standard rendered as an engraved metal plate. It is the
 * site's central object, the way a physical plaque anchors a certification
 * site, but it states only facts that are true of the standard itself.
 */
export function Plate({ specVersion, ruleCount }: { specVersion: string; ruleCount: number }) {
  return (
    <div className="[perspective:1400px]">
      <div
        className="plate w-[420px] max-w-full aspect-[1.62] px-9 py-8 flex flex-col justify-between [transform:rotateX(9deg)_rotateY(-16deg)_rotateZ(1.5deg)]"
        role="img"
        aria-label={`ATR, Agent Threat Rules, open standard, specification ${specVersion}`}
      >
        <span className="plate-screw left-3.5 top-3.5" />
        <span className="plate-screw right-3.5 top-3.5" />
        <span className="plate-screw left-3.5 bottom-3.5" />
        <span className="plate-screw right-3.5 bottom-3.5" />

        <div className="flex justify-between font-data text-[10px] tracking-[0.18em] plate-engrave">
          <span>OPEN STANDARD</span>
          <span>SPEC {specVersion}</span>
        </div>

        <div className="flex items-center gap-5">
          <div
            className="w-[86px] h-[78px] shrink-0"
            style={{
              background: "#A9A9A4",
              WebkitMaskImage: "url(/atr-mark-ink.png)",
              maskImage: "url(/atr-mark-ink.png)",
              WebkitMaskSize: "contain",
              maskSize: "contain",
              WebkitMaskRepeat: "no-repeat",
              maskRepeat: "no-repeat",
              filter: "drop-shadow(0 1px 0 rgba(255,255,255,0.85)) drop-shadow(0 -1px 0 rgba(0,0,0,0.25))",
            }}
            aria-hidden="true"
          />
          <div>
            <div className="text-[64px] leading-[0.9] font-semibold tracking-[0.04em] plate-engrave">ATR</div>
            <div className="mt-2 font-data text-[11px] tracking-[0.22em] plate-engrave">AGENT THREAT RULES</div>
          </div>
        </div>

        <div className="flex justify-between font-data text-[9.5px] tracking-[0.16em] plate-engrave">
          <span>MIT LICENSED</span>
          <span>{ruleCount} EFFECTIVE RULES</span>
        </div>
      </div>
    </div>
  );
}
