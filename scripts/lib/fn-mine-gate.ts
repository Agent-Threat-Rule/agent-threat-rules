/**
 * scripts/lib/fn-mine-gate.ts
 *
 * Decides which of this run's authored rules a failed safety gate rejected, for
 * the scheduled FN-mine lane (scripts/fn-mine-llm.ts).
 *
 * The lane resumes fn-mine/rolling, so scripts/check-rules-safety.ts sees two
 * kinds of new rule: the ones already waiting in the rolling PR and the ones
 * this run authored. Its Check 5 (cross-rule conflict) names the OFFENDER — the
 * rule whose regex matched — not the rule that owns the true-negative. When a
 * waiting rule matches a TN this run wrote, the failure line names the waiting
 * rule's file. The miner used to look only for its own files on failure lines,
 * found none, and dropped the whole batch behind a green "null result" without
 * saying why.
 *
 * Waiting rules pass the same gate on their own before anything is authored, so
 * a failure that names one can only come from this run's batch; its
 * `conflicts with <id>'s TN` entries say which authored rule to drop. A failure
 * that names nothing this run authored is something the miner cannot explain,
 * and it fails the run instead of being read as an empty week.
 */

export interface AuthoredRef {
  readonly id: string;
  readonly file: string;
}

export interface GateRun {
  readonly pass: boolean;
  readonly raw: string;
}

export interface GateAttribution {
  /** Authored rule file → the gate lines that blame it. */
  readonly blamed: ReadonlyMap<string, readonly string[]>;
  /** Failure lines that name nothing this run authored. */
  readonly unattributed: readonly string[];
}

export class GateAttributionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GateAttributionError';
  }
}

/** `  ✗ <file or id> — <reason>`, as check-rules-safety.ts prints a failure. */
const FAILURE_LINE = /^\s*✗\s+(\S+)(.*)$/;
const TN_OWNER = /conflicts with (\S+?)'s TN/g;
const GATE_TAIL_CHARS = 2000;

/** Authored files one failure line blames: the file it names, else the TN owners it lists. */
function filesBlamedBy(line: string, fileOf: ReadonlyMap<string, string>): readonly string[] {
  const m = FAILURE_LINE.exec(line);
  if (!m) return [];
  const named = fileOf.get(m[1]);
  if (named) return [named];
  const owners = [...m[2].matchAll(TN_OWNER)].map((o) => fileOf.get(o[1]));
  return [...new Set(owners.filter((f): f is string => Boolean(f)))];
}

export function attributeGateFailures(gateOutput: string, authored: readonly AuthoredRef[]): GateAttribution {
  const fileOf = new Map(authored.flatMap((a) => [[a.file, a.file] as const, [a.id, a.file] as const]));
  const verdicts = gateOutput
    .split('\n')
    .filter((line) => FAILURE_LINE.test(line))
    .map((line) => ({ line: line.trim(), files: filesBlamedBy(line, fileOf) }));
  const blamed = new Map<string, readonly string[]>(
    authored
      .map((a) => [a.file, verdicts.filter((v) => v.files.includes(a.file)).map((v) => v.line)] as const)
      .filter(([, lines]) => lines.length > 0),
  );
  return { blamed, unattributed: verdicts.filter((v) => v.files.length === 0).map((v) => v.line) };
}

function unattributableError(attribution: GateAttribution, raw: string): GateAttributionError {
  const named = attribution.unattributed.length > 0 ? attribution.unattributed.join(' | ') : '(the gate named no file)';
  return new GateAttributionError(
    `the safety gate failed on something this run did not author: ${named}. ` +
      `Nothing was dropped and nothing is pushed; fix the named rule or the gate input.\n${raw.slice(-GATE_TAIL_CHARS)}`,
  );
}

/**
 * Runs the gate until it passes, dropping the authored rules each failure
 * blames. Every round drops at least one rule or throws, so it ends. Throws
 * GateAttributionError when a failure names nothing this run authored — even
 * alongside failures it can attribute, since dropping the rest would turn an
 * unexplained failure back into a quiet null result.
 */
export function gateAuthoredBatch<T extends AuthoredRef>(
  authored: readonly T[],
  runGate: () => GateRun,
  discard: (rule: T, blamedBy: readonly string[]) => void,
): readonly T[] {
  let remaining = authored;
  while (remaining.length > 0) {
    const gate = runGate();
    if (gate.pass) return remaining;
    const attribution = attributeGateFailures(gate.raw, remaining);
    if (attribution.unattributed.length > 0 || attribution.blamed.size === 0) {
      throw unattributableError(attribution, gate.raw);
    }
    for (const rule of remaining) {
      const lines = attribution.blamed.get(rule.file);
      if (lines) discard(rule, lines);
    }
    remaining = remaining.filter((r) => !attribution.blamed.has(r.file));
  }
  return remaining;
}
