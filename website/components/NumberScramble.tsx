interface NumberScrambleProps {
  target: string;
  /** Kept for call-site compatibility; the text no longer animates. */
  duration?: number;
  className?: string;
  /** Kept for call-site compatibility; the text is not replaced after load. */
  liveKey?: string;
}

/** Static text. It used to scramble its digits on scroll; see CountUp for why it no longer moves. */
export function NumberScramble({ target, className = "" }: NumberScrambleProps) {
  return <span className={`tabular-nums ${className}`}>{target}</span>;
}
