import Link from "next/link";
import type { ReactNode } from "react";

/**
 * Drawing-sheet primitives. Every redone page is one "sheet" between two
 * hairline rails; each row starts on a hairline with a mark at both corners.
 */

export function SheetRow({
  children,
  className = "",
  grid = false,
  id,
}: {
  children: ReactNode;
  className?: string;
  /** Faded grid paper behind the row. */
  grid?: boolean;
  id?: string;
}) {
  return (
    <section id={id} className={`sheet-row ${className}`}>
      <span className="corner-mark corner-mark-l" aria-hidden="true" />
      <span className="corner-mark corner-mark-r" aria-hidden="true" />
      {grid && <div className="absolute inset-0 grid-paper grid-paper-fade pointer-events-none" aria-hidden="true" />}
      <div className="relative">{children}</div>
    </section>
  );
}

/** "FIG. 02 — TITLE" label for drawings and diagrams. */
export function FigureLabel({ fig, title }: { fig: string; title: string }) {
  return (
    <div className="font-data text-[10.5px] uppercase tracking-[0.12em] text-stone leading-tight">
      <div>FIG. {fig}</div>
      <div className="text-ink">{title}</div>
    </div>
  );
}

/** Section eyebrow: a small square marker and a label, as on a drawing sheet. */
export function Eyebrow({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-[13px] text-stone">
      <span className="inline-block w-2 h-2 bg-brand" aria-hidden="true" />
      {children}
    </div>
  );
}

/** Small solid button with an arrow box, for "view" actions. */
export function ArrowButton({ href, children, external = false }: { href: string; children: ReactNode; external?: boolean }) {
  const cls = "inline-flex items-stretch bg-ink text-white text-[12.5px] leading-none hover:bg-black transition-colors";
  const inner = (
    <>
      <span className="px-3 py-2">{children}</span>
      <span className="px-2 py-2 border-l border-white/20" aria-hidden="true">↗</span>
    </>
  );
  return external ? (
    <a href={href} className={cls} target="_blank" rel="noopener noreferrer">{inner}</a>
  ) : (
    <Link href={href} className={cls}>{inner}</Link>
  );
}

/** Primary and secondary hero buttons, small and square-cornered. */
export function SolidButton({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className="inline-flex items-center bg-ink text-white text-[13px] px-3.5 py-2 hover:bg-black transition-colors">
      {children}
    </Link>
  );
}

export function OutlineButton({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className="inline-flex items-center bg-white text-ink text-[13px] px-3.5 py-2 border border-fog hover:border-ink transition-colors">
      {children}
    </Link>
  );
}
