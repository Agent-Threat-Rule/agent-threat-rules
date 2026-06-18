/**
 * NemoClaw / OpenShell supply-chain pre-flight scanner (ATR Seam B).
 *
 * Scans an agent bundle — SKILL.md skills and MCP server configs — BEFORE it is
 * provisioned into a NemoClaw/OpenShell sandbox, and returns a gate verdict:
 *   exit 0 = pass        (all targets scanned, nothing at/above threshold)
 *   exit 1 = block       (a rule at/above the threshold matched)
 *   exit 2 = incomplete  (could not fully scan — oversized/unreadable/symlink/
 *                         too many files) OR internal error
 *
 * It is FAIL-CLOSED: because this is the only pre-deployment barrier, an
 * incomplete scan is never reported as a pass. A skipped file (too large to
 * scan, unreadable, a symlink, or beyond the file cap) yields an "incomplete"
 * verdict the caller must treat as a gate failure, not a clean result.
 *
 * This is the pre-deployment counterpart to the runtime content filter
 * (openshell-filter): the filter inspects L7 traffic at run time; this inspects
 * the skill / MCP supply chain at provision time — a gap neither OpenShell's
 * capability policy nor a runtime guard covers.
 *
 * Why MCP configs specifically: OpenShell/NemoClaw run OpenClaw/Hermes agents
 * that load skills and register MCP servers (.mcp.json, .cursor/mcp.json,
 * .claude/settings.json, ...). Malicious server definitions (stdio RCE, unauth
 * registration, SymJack symlink-config redirection) are a content-level attack
 * surface ATR has rules for. The `atr scan` CLI treats .json as MCP *events*;
 * this scans MCP *config* files as content, which is the missing path.
 *
 * Symlinks are never followed (cycle-safe, version-consistent across the
 * supported Node range, and SymJack-safe); a symlink that would otherwise be a
 * scan target is recorded as skipped so it cannot pass silently.
 *
 * Findings use the canonical atr.* shape (matched values redacted by default per
 * the engine INTERFACE-CONTRACT), consistent with openshell-filter, so Seam A
 * (runtime) and Seam B (supply chain) feed the same OCSF detection_finding
 * audit stream. Reuses ATREngine in skill context; adds no dependency.
 *
 * @module agent-threat-rules/nemoclaw-preflight
 */

import { existsSync, lstatSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join, relative } from 'node:path';
import { ATREngine } from '../engine.js';
import type { AgentEvent, ATRMatch } from '../types.js';

export type Decision = 'pass' | 'block' | 'incomplete';

/** Reason a target could not be fully scanned (fail-closed signals). */
export type SkipReason = 'too_large' | 'unreadable' | 'symlink' | 'max_files_exceeded';

/** Severity ordering for the block threshold (ATR_MIN_SEVERITY). */
const SEVERITY_RANK: Readonly<Record<string, number>> = Object.freeze({
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

const DEFAULT_MIN_SEVERITY = 'high';
const DEFAULT_MAX_FILE_BYTES = 1024 * 1024; // 1 MB per file
const DEFAULT_MAX_FILES = 2000;
const REDACTED = '[REDACTED]';
const SKIP_DIRS: ReadonlySet<string> = new Set([
  '.git', 'node_modules', '.venv', 'venv', 'dist', 'build', '__pycache__', '.next',
]);

/** MCP config file basenames (exact) and path suffixes (agent-specific locations). */
const MCP_CONFIG_BASENAMES: ReadonlySet<string> = new Set(['.mcp.json', 'mcp.json']);
const MCP_CONFIG_SUFFIXES: readonly string[] = [
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  '.claude/settings.json',
  '.gemini/settings.json',
  '.codex/config.toml',
];

function severityRank(severity: string): number {
  return SEVERITY_RANK[severity.toLowerCase()] ?? 0;
}

export interface PreflightOptions {
  /** Block when a matched rule's severity is at or above this (default "high"). */
  readonly minSeverity: string;
  /** Directory of ATR rule YAML files. Omit to use the rules bundled with the package. */
  readonly rulesDir?: string;
  /** When true, include the raw matched value instead of redacting it. */
  readonly forensic: boolean;
  /** Skip files larger than this (default 1 MB) — skipped files block the gate. */
  readonly maxFileBytes?: number;
  /** Stop collecting after this many target files (default 2000) — truncation blocks the gate. */
  readonly maxFiles?: number;
}

/** A finding, in the canonical atr.* shape plus the source file that triggered it. */
export interface PreflightFinding {
  readonly 'atr.rule_id': string;
  readonly 'atr.severity': string;
  readonly 'atr.category': string;
  readonly 'atr.confidence': number;
  readonly 'atr.matched_value_redacted': string;
  readonly 'atr.source_path': string;
}

export interface SkippedFile {
  readonly path: string;
  readonly reason: SkipReason;
}

export interface PreflightResult {
  readonly decision: Decision;
  /** Number of files actually read and evaluated (not merely discovered). */
  readonly scanned: number;
  /** Targets that could not be fully scanned. Non-empty ⇒ verdict cannot be a clean pass. */
  readonly skipped: readonly SkippedFile[];
  readonly findings: readonly PreflightFinding[];
}

type TargetKind = 'skill' | 'mcp-config';
interface Target {
  readonly path: string;
  readonly kind: TargetKind;
}
interface CollectResult {
  readonly targets: readonly Target[];
  readonly skipped: readonly SkippedFile[];
  readonly truncated: boolean;
}

function isSkillFile(base: string): boolean {
  return base.toLowerCase() === 'skill.md';
}

function isMcpConfig(relPath: string, base: string): boolean {
  if (MCP_CONFIG_BASENAMES.has(base)) return true;
  const norm = relPath.split('\\').join('/');
  return MCP_CONFIG_SUFFIXES.some((suffix) => norm.endsWith(suffix));
}

/**
 * Recursively collect skill + MCP-config files under root (bounded, skipping
 * vendor dirs and never following symlinks). A symlink that would otherwise be a
 * target is reported as skipped; hitting maxFiles sets truncated.
 */
function collectTargets(root: string, maxFiles: number): CollectResult {
  // lstat (not stat) so a symlinked root is NOT silently followed — the
  // per-entry guard during traversal only covers symlinks found inside dirs,
  // not the root argument itself. Honors the module's "never follow symlinks".
  const rootStat = lstatSync(root);
  if (rootStat.isSymbolicLink()) {
    return { targets: [], skipped: [{ path: root, reason: 'symlink' }], truncated: false };
  }
  if (rootStat.isFile()) {
    const base = basename(root);
    const kind: TargetKind = isMcpConfig(root, base) ? 'mcp-config' : 'skill';
    return { targets: [{ path: root, kind }], skipped: [], truncated: false };
  }

  const targets: Target[] = [];
  const skipped: SkippedFile[] = [];
  const stack: string[] = [root];
  let truncated = false;

  while (stack.length > 0) {
    if (targets.length >= maxFiles) { truncated = true; break; }
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      skipped.push({ path: dir, reason: 'unreadable' });
      continue;
    }
    for (const entry of entries) {
      if (targets.length >= maxFiles) { truncated = true; break; }
      const full = join(dir, entry.name);
      const rel = relative(root, full);
      const wouldBeTarget = isSkillFile(entry.name) || isMcpConfig(rel, entry.name);

      // Never follow symlinks: avoids traversal cycles, is consistent across the
      // supported Node range (Dirent.isDirectory() follows links on some), and
      // refuses SymJack-style redirection. Surface link-targets as skipped.
      if (entry.isSymbolicLink()) {
        if (wouldBeTarget) skipped.push({ path: full, reason: 'symlink' });
        continue;
      }
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
        continue;
      }
      if (isSkillFile(entry.name)) targets.push({ path: full, kind: 'skill' });
      else if (isMcpConfig(rel, entry.name)) targets.push({ path: full, kind: 'mcp-config' });
    }
  }
  return { targets, skipped, truncated };
}

/** The supply-chain pre-flight scanner. Construct once, reuse across bundles. */
export class NemoClawPreflight {
  private readonly engine: ATREngine;
  private readonly blockRank: number;
  private readonly maxFileBytes: number;
  private readonly maxFiles: number;
  private loadPromise: Promise<number> | null = null;

  constructor(private readonly options: PreflightOptions) {
    this.engine = new ATREngine(options.rulesDir ? { rulesDir: options.rulesDir } : {});
    this.blockRank = severityRank(options.minSeverity);
    this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  }

  private ensureLoaded(): Promise<number> {
    if (this.loadPromise === null) this.loadPromise = this.engine.loadRules();
    return this.loadPromise;
  }

  /**
   * Scan one file's content in skill context. Returns the findings and a skip
   * reason (null if the file was actually read and evaluated). Oversized and
   * unreadable files are reported as skipped (fail-closed), never silently
   * treated as clean.
   */
  private scanFile(target: Target): { findings: PreflightFinding[]; skip: SkipReason | null } {
    let content: string;
    try {
      if (statSync(target.path).size > this.maxFileBytes) {
        return { findings: [], skip: 'too_large' };
      }
      content = readFileSync(target.path, 'utf8');
    } catch {
      return { findings: [], skip: 'unreadable' };
    }
    if (!content.trim()) return { findings: [], skip: null };

    // scanContext 'skill' makes every rule evaluate against the whole content,
    // with the engine's compound gating controlling false positives — correct
    // for both SKILL.md and MCP config text (exec commands, server
    // registrations, symlink targets are inspected as content).
    const event: AgentEvent = {
      type: 'tool_call',
      timestamp: new Date().toISOString(),
      content,
      scanContext: 'skill',
    };

    const findings = this.engine
      .evaluate(event)
      .filter((m) => severityRank(m.rule.severity) >= this.blockRank)
      .map((m) => this.toFinding(m, target.path));
    return { findings, skip: null };
  }

  private toFinding(match: ATRMatch, sourcePath: string): PreflightFinding {
    const matchedPattern = match.matchedPatterns?.[0];
    return {
      'atr.rule_id': match.rule.id,
      'atr.severity': match.rule.severity,
      'atr.category': match.rule.tags?.category ?? 'unknown',
      'atr.confidence': match.confidence,
      'atr.matched_value_redacted': this.options.forensic && matchedPattern ? matchedPattern : REDACTED,
      'atr.source_path': sourcePath,
    };
  }

  /**
   * Scan an agent bundle (directory or single file). Block on any finding at or
   * above the threshold; otherwise report incomplete if any target could not be
   * fully scanned (fail-closed); otherwise pass.
   */
  async scanBundle(root: string): Promise<PreflightResult> {
    await this.ensureLoaded();
    if (!existsSync(root)) {
      throw new Error(`path not found: ${root}`);
    }

    const collected = collectTargets(root, this.maxFiles);
    const skipped: SkippedFile[] = [...collected.skipped];
    const findings: PreflightFinding[] = [];
    let evaluated = 0;

    for (const target of collected.targets) {
      const { findings: f, skip } = this.scanFile(target);
      if (skip) skipped.push({ path: target.path, reason: skip });
      else evaluated++;
      findings.push(...f);
    }
    if (collected.truncated) {
      skipped.push({ path: root, reason: 'max_files_exceeded' });
    }

    const decision: Decision =
      findings.length > 0 ? 'block' : skipped.length > 0 ? 'incomplete' : 'pass';
    return { decision, scanned: evaluated, skipped, findings };
  }
}

// ── CLI wiring (provisioning gate the supervisor / CI runs) ──────────────────

/** Build options from the ATR_* environment contract. */
export function optionsFromEnv(): PreflightOptions {
  const minRaw = (process.env['ATR_MIN_SEVERITY'] ?? DEFAULT_MIN_SEVERITY).toLowerCase();
  const minSeverity = SEVERITY_RANK[minRaw] !== undefined ? minRaw : DEFAULT_MIN_SEVERITY;
  const forensicRaw = process.env['ATR_FORENSIC_MODE'];
  return {
    minSeverity,
    rulesDir: process.env['ATR_RULES_DIR'] ?? process.env['ATR_CORPUS_PATH'] ?? undefined,
    forensic: forensicRaw === '1' || forensicRaw === 'true',
  };
}

function exitCodeFor(decision: Decision): number {
  return decision === 'block' ? 1 : decision === 'incomplete' ? 2 : 0;
}

async function main(argv: readonly string[]): Promise<number> {
  const target = argv.find((a) => !a.startsWith('-'));
  if (!target) {
    process.stderr.write('usage: nemoclaw-preflight <agent-bundle-dir> [--json]\n');
    return 2;
  }
  const result = await new NemoClawPreflight(optionsFromEnv()).scanBundle(target);

  if (argv.includes('--json')) {
    process.stdout.write(JSON.stringify(result) + '\n');
    return exitCodeFor(result.decision);
  }

  if (result.decision === 'block') {
    process.stderr.write(`BLOCK: ${result.findings.length} finding(s) across ${result.scanned} file(s)\n`);
    for (const f of result.findings) {
      process.stderr.write(`  ${f['atr.severity']}  ${f['atr.rule_id']}  ${f['atr.category']}  ${f['atr.source_path']}\n`);
    }
  } else if (result.decision === 'incomplete') {
    process.stderr.write(`INCOMPLETE: scanned ${result.scanned} file(s); ${result.skipped.length} could not be scanned (treated as gate failure)\n`);
    for (const s of result.skipped) {
      process.stderr.write(`  ${s.reason}  ${s.path}\n`);
    }
  } else {
    process.stderr.write(`PASS: ${result.scanned} file(s) scanned, no findings at or above threshold\n`);
  }
  return exitCodeFor(result.decision);
}

const isDirectInvocation = Boolean(process.argv[1]) && import.meta.url === `file://${process.argv[1]}`;
if (isDirectInvocation) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`nemoclaw-preflight: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(2);
    });
}
