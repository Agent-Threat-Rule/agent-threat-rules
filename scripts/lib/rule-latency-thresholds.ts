/**
 * rule-latency-thresholds.ts -- every number the latency ratchet judges by, and
 * the measurement each one came from.
 *
 * Split out of scripts/gate-rule-latency.ts so that a pull request loosening a
 * threshold shows up as a diff to a file whose entire contents are the
 * justification. Nothing here imports anything: these are constants, and the
 * derivations beside them are the review.
 *
 * All figures below were measured on the platform the gate runs on
 * (ubuntu-latest x64) unless a line says otherwise, because relative regex cost
 * is not architecture-neutral -- see HOW MACHINE-INDEPENDENT IS IT, HONESTLY in
 * scripts/gate-rule-latency.ts.
 *
 * @module scripts/lib/rule-latency-thresholds
 */

/**
 * Rules at or above this many anchor medians are recorded in the baseline.
 *
 * Today's distribution over the 674 evaluable, corpus-covered rules, measured on
 * ubuntu-latest: p50 1.01x, p75 2.16x, p90 4.22x, p95 5.93x, p99 15.57x,
 * max 288.3x. Recording from 3x captures the whole tail worth watching (113
 * rules) while keeping the baseline diff small enough to read. It sits below
 * FAIL_FLOOR on purpose: a rule recorded at 5x cannot fail on its own, but its
 * growth is then bounded by TOLERANCE instead of only by FAIL_FLOOR.
 */
export const RECORD_FLOOR = 3;

/**
 * A rule outside the baseline fails the build at or above this many medians.
 *
 * This is the threshold with no tolerance behind it, so it is derived from what
 * an INNOCENT rule can read on its unluckiest run rather than from what a guilty
 * one reads on its luckiest. On the platform that enforces it, an ordinarily
 * thick new rule sits at p95 = 5.93x; the worst cross-run spread measured for
 * rules in that class is 1.316x, so an innocent p95 rule reads at most about
 * 7.8x. 14x is 1.8x above that.
 *
 * It sits far below the cheapest catastrophic construct measured -- a real
 * `(?:[a-z]+\s*){0,6}` rule injected into this corpus profiles at 50x-70x -- and
 * near the lower edge of the 7.8x <-> 50x decision band on purpose: surfacing a
 * merely wasteful rule early is cheap, missing a pathological one is not. The
 * cost of sitting low is that a rule authored above the corpus's own p99
 * (15.57x) has to be justified before it lands, which is a policy this project
 * can afford now that --changed-since means the bill goes to the author who
 * wrote it rather than to the next unrelated pull request.
 *
 * Ten rules are above it today, all baselined and reprinted every run under
 * ACCEPTED DEBT. One of them, ATR-2026-02300, reads 288x.
 */
export const FAIL_FLOOR = 14;

/**
 * A baselined rule fails only if it also grew past baseline * TOLERANCE.
 *
 * Sized against measured noise, not taste. The rules this clause can act on are
 * the ones at or above FAIL_FLOOR, and across the four profiles the worst spread
 * seen by any rule at or above 5x was 1.316x. 3.0 is 2.3x of headroom over that,
 * and 1.7x over the worst spread seen by ANY rule in the corpus (1.776x, on a
 * rule reading around 1x where this clause cannot fire).
 *
 * It used to be 2.5 against evidence of a 2.10x worst case -- 1.19x of headroom,
 * which is not headroom. Two changes bought the margin rather than the number
 * being talked up: PROFILE_PASSES (two independent sweeps, per-rule minimum),
 * because the variance was between processes rather than inside the timing loop;
 * and the anchor cohort, which removed the corpus-growth term the old derivation
 * had to reserve 1.11x for (see THE METRIC).
 *
 * What this costs: a baselined rule at 25.3x may reach 76x before failing.
 * Accepted, because the catastrophic constructs this gate exists for do not grow
 * by 3x, they grow by an order of magnitude per unit of quantifier bound
 * ({0,6} 58.5x, {0,8} 822.7x, {0,10} 10657x), and any rule crossing FAIL_FLOOR
 * for the first time is caught by the added-rule path with no tolerance at all.
 */
export const TOLERANCE = 3.0;

/**
 * Engine-wide p95/p50 must stay at or below baseline * SHAPE_HIGH.
 *
 * Over 14 real CI runs the shape was 1.8386..2.0506, mean 1.9144, sd 0.0526 --
 * a 2.75% coefficient of variation measured across runners that differed 2.716x
 * in absolute speed. Shape is far more stable than the absolute number it
 * replaces. But it is NOT ratio-immune the way relCost is: it is the one term in
 * this gate that machine load can push on. Across the four profiles it read
 * 1.928 and 1.972 quiet, 2.054 and 2.134 contended, and a single undefended raw
 * pass has been seen at 3.158 -- which is why measureShape() takes the median of
 * three. 2.5x of headroom over the recorded value keeps load comfortably green
 * while still catching the tail blow-ups this is for, which move it 5x-100x.
 *
 * There is deliberately no lower bound. Shape falls as the corpus grows -- 670,
 * 870 and 1170 rules measured 1.93, 1.88 and 1.67 on a quiet machine -- so a
 * band tight enough to be meaningful underneath would eventually fail on rule
 * growth alone, which is the exact failure mode this whole change exists to
 * remove. SHAPE_REPORT_LOW only annotates the output.
 */
export const SHAPE_HIGH = 2.5;
export const SHAPE_REPORT_LOW = 0.65;

/**
 * At least this fraction of the baseline's anchor cohort must still be present.
 *
 * The denominator is a median over named rules. Deleting them, or flipping them
 * to draft, shifts that median with nothing else changing -- the quiet way to
 * make every remaining rule look cheaper. Below this fraction the run is not
 * comparable to the baseline and must read as a broken gate (exit 2) rather than
 * a green one. 0.75 tolerates ordinary attrition (a handful of rules deprecated
 * between baseline refreshes) and stops a wholesale cull.
 */
export const ANCHOR_MIN_COVERAGE = 0.75;

