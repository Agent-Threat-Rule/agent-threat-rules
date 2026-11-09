import type { ReactNode } from "react";

// The site's only symbols: the critical signs ancient editors wrote in the
// margin of a text (Zenodotus, Aristarchus, later Origen). The logo's bars are
// the first of them, the obelos. Drawing rules, taken from the logo: one stroke
// weight, flat line ends, diagonals at 30 or 60 degrees, square dots.
//
//   obelos      a line marked as not belonging to the text -> hunt lane: mark, do not block
//   enforce     obelos with a stop (our own derivation)    -> enforce lane: block
//   asteriskos  a line that also appears elsewhere         -> crosswalk to other frameworks
//   diple       a line worth a note                        -> link, read on
//   dipleDot    a reading that differs between editions    -> changed since the last version
//   stigme      a line suspected, not settled              -> draft / test maturity

export type SignName = "obelos" | "enforce" | "asteriskos" | "diple" | "dipleDot" | "stigme";

const dot = (x: number, y: number, s: number) => <rect x={x - s / 2} y={y - s / 2} width={s} height={s} stroke="none" />;

const PATHS: Record<SignName, ReactNode> = {
  obelos: <line x1="3" y1="12" x2="21" y2="12" />,
  enforce: (
    <>
      <line x1="3" y1="12" x2="17" y2="12" />
      <line x1="20" y1="4" x2="20" y2="20" />
    </>
  ),
  asteriskos: (
    <>
      <line x1="9" y1="6.8" x2="15" y2="17.2" />
      <line x1="15" y1="6.8" x2="9" y2="17.2" />
      {dot(4.5, 12, 2.6)}
      {dot(19.5, 12, 2.6)}
      {dot(12, 3, 2.6)}
      {dot(12, 21, 2.6)}
    </>
  ),
  diple: <polyline points="5,5 17,12 5,19" fill="none" />,
  dipleDot: (
    <>
      <polyline points="3,6 13.4,12 3,18" fill="none" />
      {dot(20, 12, 3.2)}
    </>
  ),
  stigme: dot(12, 12, 4),
};

export function Sign({ name, size = 16, className = "", label }: { name: SignName; size?: number; className?: string; label?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="currentColor"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="butt"
      className={`inline-block shrink-0 ${className}`}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      {PATHS[name]}
    </svg>
  );
}
