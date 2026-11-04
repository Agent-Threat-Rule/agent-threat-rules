/**
 * binomial-ci.ts — exact (Clopper-Pearson) confidence intervals for a rate.
 *
 * Every rate the holdout evidence publishes carries its n and a 95% interval.
 * Clopper-Pearson rather than Wilson or the normal approximation because the
 * rates that matter here are rare events: a rule's false positives are usually
 * 0 or 1 out of thousands, and the normal approximation gives [0, 0] for 0/n,
 * which reads as certainty. Clopper-Pearson for 0/n gives an upper bound of
 * about 3.69/n at 95% — the "rule of three" a reader expects.
 *
 * Computed by bisection on the exact binomial CDF in log space, so it needs no
 * statistics dependency and is exact to well below the precision we print.
 */

/** Lanczos approximation of ln Γ(x), x > 0. Accurate to ~1e-13. */
function lnGamma(x: number): number {
  const g = 7;
  const c = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313,
    -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6,
    1.5056327351493116e-7,
  ];
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - lnGamma(1 - x);
  const xx = x - 1;
  let a = c[0]!;
  const t = xx + g + 0.5;
  for (let i = 1; i < g + 2; i++) a += c[i]! / (xx + i);
  return 0.5 * Math.log(2 * Math.PI) + (xx + 0.5) * Math.log(t) - t + Math.log(a);
}

function lnChoose(n: number, k: number): number {
  return lnGamma(n + 1) - lnGamma(k + 1) - lnGamma(n - k + 1);
}

/** P(X <= k) for X ~ Binomial(n, p). */
export function binomialCdf(k: number, n: number, p: number): number {
  if (k < 0) return 0;
  if (k >= n) return 1;
  if (p <= 0) return 1;
  if (p >= 1) return 0;
  const lp = Math.log(p);
  const lq = Math.log1p(-p);
  let sum = 0;
  for (let i = 0; i <= k; i++) sum += Math.exp(lnChoose(n, i) + i * lp + (n - i) * lq);
  return Math.min(1, sum);
}

/** p in [lo, hi] where the decreasing function f(p) crosses target. */
function bisect(f: (p: number) => number, target: number): number {
  let lo = 0;
  let hi = 1;
  for (let i = 0; i < 80; i++) {
    const mid = (lo + hi) / 2;
    if (f(mid) > target) lo = mid;
    else hi = mid;
  }
  return (lo + hi) / 2;
}

export interface RateWithCi {
  /** Events observed. */
  readonly k: number;
  /** Trials. */
  readonly n: number;
  /** k / n, or null when n is 0 (a rate over nothing is not 0). */
  readonly rate: number | null;
  /** Lower and upper bound of the two-sided Clopper-Pearson interval, or null when n is 0. */
  readonly ci95: readonly [number, number] | null;
}

/** k/n with its exact two-sided 95% interval. */
export function rateWithCi(k: number, n: number, alpha = 0.05): RateWithCi {
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 0 || n < 0 || k > n) {
    throw new Error(`rateWithCi: need integers 0 <= k <= n, got k=${k} n=${n}`);
  }
  if (n === 0) return Object.freeze({ k, n, rate: null, ci95: null });
  // Lower bound: P(X >= k) = alpha/2, i.e. P(X <= k-1) = 1 - alpha/2.
  // Upper bound: P(X <= k) = alpha/2. Both CDFs decrease in p.
  const lower = k === 0 ? 0 : bisect((p) => binomialCdf(k - 1, n, p), 1 - alpha / 2);
  const upper = k === n ? 1 : bisect((p) => binomialCdf(k, n, p), alpha / 2);
  return Object.freeze({ k, n, rate: k / n, ci95: Object.freeze([lower, upper] as const) });
}
