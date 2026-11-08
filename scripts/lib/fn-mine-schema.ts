/**
 * scripts/lib/fn-mine-schema.ts
 *
 * Reads the repo's schema validator (tests/validate-rules.ts, `npm run
 * validate`) for one rule the FN-mine lane authored.
 */
import path from 'node:path';

/**
 * The repo's schema validator (npm run validate) on the rule at `filePath`:
 * null when it passes, else its ERROR lines. The validator checks every rule
 * file, so only this file's block is read; one other rule failing elsewhere is
 * not this rule's problem. Run before the engine self-test because a rule the
 * engine runs can still be one validate refuses: on 2026-11-08 an authored
 * rule declared `block_tool_call`, which the eligibility filter keeps (an
 * unknown action ranks as observe) and validate rejects, and that one rule
 * failed the workflow's validate step for the whole batch of ten.
 */
export function schemaProblem(filePath: string, validatorOutput: string): string | null {
  const rel = path.relative('rules', filePath);
  const lines = validatorOutput.split('\n');
  const start = lines.findIndex((l) => l.startsWith(`[FAIL] ${rel} `));
  if (start < 0) return null;
  const errors: string[] = [];
  for (const l of lines.slice(start + 1)) {
    if (!/^\s+\S/.test(l)) break;
    if (/^\s+ERROR:/.test(l)) errors.push(l.trim());
  }
  return `npm run validate rejects ${rel}:\n${errors.join('\n') || lines[start]}`;
}

