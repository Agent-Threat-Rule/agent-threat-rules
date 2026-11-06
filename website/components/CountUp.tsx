interface CountUpProps {
  target: number;
  suffix?: string;
  prefix?: string;
  useComma?: boolean;
  /** Kept for call-site compatibility; numbers no longer animate. */
  duration?: number;
  className?: string;
  /** Kept for call-site compatibility; numbers are not replaced after load. */
  liveKey?: string;
}

/**
 * A number, printed as it was when the page was built. It used to count up
 * on scroll and could be swapped for a live value after load; a figure on
 * this site is true as of the page's generation date, so it now renders once
 * and stays put.
 */
export function CountUp({ target, suffix = "", prefix = "", useComma = false, className = "" }: CountUpProps) {
  const text = target % 1 !== 0 ? target.toFixed(1) : useComma ? target.toLocaleString("en-US") : String(target);
  return <span className={`tabular-nums ${className}`}>{prefix}{text}{suffix}</span>;
}
