#!/usr/bin/env npx tsx
/**
 * probe-to-atr.ts
 *
 * Converts a red-team probe submission into an ATR rule proposal under
 * proposals/red-team-probes/<slug>.proposal.yaml.
 *
 * Two input modes:
 *
 *   1. --probe path/to/probe.yaml
 *      Local YAML file with the structured probe fields. Useful when a red
 *      team wants to dry-run the conversion before opening an issue.
 *
 *   2. --issue-body path/to/issue-body.txt
 *      Raw markdown body from a GitHub issue using the
 *      red-team-probe.yml form. The workflow writes the issue body to a
 *      tempfile and passes it via this flag.
 *
 * Both modes produce the same on-disk proposal. The proposal is a STUB:
 *   - detection.conditions is left empty with a TODO comment
 *   - test_cases.true_positives + true_negatives are populated from the
 *     submitter's examples
 *   - metadata_provenance.discovered_by + source URL are filled in
 *
 * The maintainer (or a follow-up workflow) fills in the regex. The
 * benign-corpus FP gate in check-rules-safety.ts still has to pass before
 * the proposal can be promoted to rules/.
 *
 * Usage:
 *   npx tsx scripts/probe-to-atr.ts --probe probes/dan-binding.yaml --write
 *   npx tsx scripts/probe-to-atr.ts --issue-body /tmp/issue.txt --write
 *   npx tsx scripts/probe-to-atr.ts --issue-body /tmp/issue.txt          # dry-run
 *
 * Exit codes:
 *   0 success
 *   1 fatal error (missing input, malformed body, schema mismatch)
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const OUT_DIR = resolve(REPO_ROOT, "proposals/red-team-probes");

const args = process.argv.slice(2);
const flag = (n: string): boolean => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const PROBE_FILE = opt("--probe");
const ISSUE_BODY_FILE = opt("--issue-body");
const FORCE = flag("--force");

const CATEGORY_ALLOW = new Set([
  "prompt-injection",
  "agent-manipulation",
  "tool-poisoning",
  "context-exfiltration",
  "credential-exfiltration",
  "model-abuse",
  "privilege-escalation",
  "data-poisoning",
  "supply-chain",
  "other",
]);

const SEVERITY_ALLOW = new Set(["critical", "high", "medium", "low"]);

interface Probe {
  name: string;
  category: string;
  severity: string;
  description: string;
  positive_examples: string[];
  negative_examples: string[];
  source_url?: string;
  discovered_by: string;
  cves?: string[];
  owasp_mapping?: string[];
  notes?: string;
}

function fail(msg: string): never {
  console.error(`error: ${msg}`);
  process.exit(1);
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

function splitList(s: string | undefined): string[] {
  if (!s) return [];
  return s
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

function splitCsv(s: string | undefined): string[] {
  if (!s) return [];
  return s
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
}

/**
 * Parse a GitHub issue body created by .github/ISSUE_TEMPLATE/red-team-probe.yml.
 * GitHub renders form fields as `### Field label` headers followed by the
 * user's content until the next `###` or end of file.
 */
function parseIssueBody(body: string): Probe {
  const sections = new Map<string, string>();
  const lines = body.replace(/\r\n/g, "\n").split("\n");
  let current: string | null = null;
  let buf: string[] = [];
  for (const line of lines) {
    const m = line.match(/^###\s+(.+?)\s*$/);
    if (m) {
      if (current) sections.set(current.toLowerCase(), buf.join("\n").trim());
      current = m[1];
      buf = [];
    } else if (current) {
      buf.push(line);
    }
  }
  if (current) sections.set(current.toLowerCase(), buf.join("\n").trim());

  const get = (label: string): string | undefined => {
    const v = sections.get(label.toLowerCase());
    if (!v) return undefined;
    if (v === "_No response_" || v === "_No response_\n") return undefined;
    return v;
  };

  const name = get("Probe name") ?? "";
  const category = (get("Attack category") ?? "other").trim();
  const severity = (get("Severity") ?? "medium").trim();
  const description = get("Attack description") ?? "";
  const positiveRaw =
    get("Positive examples (attack payloads — one per line)") ?? "";
  const negativeRaw =
    get(
      "Negative examples (benign strings that must NOT trigger — one per line)",
    ) ?? "";
  const sourceUrl = get("Source paper / blog / repo URL");
  const discoveredBy = get("Discovered by (your name + handle)") ?? "anonymous";
  const cvesRaw = get("Related CVE IDs (comma-separated, optional)");
  const owaspRaw = get("OWASP / MITRE ATLAS mapping (optional)");
  const notes = get("Notes for the maintainer");

  return {
    name,
    category,
    severity,
    description,
    positive_examples: splitList(positiveRaw),
    negative_examples: splitList(negativeRaw),
    source_url: sourceUrl,
    discovered_by: discoveredBy,
    cves: splitCsv(cvesRaw),
    owasp_mapping: splitCsv(owaspRaw),
    notes,
  };
}

function validateProbe(p: Probe): void {
  if (!p.name) fail("probe name is required");
  if (!CATEGORY_ALLOW.has(p.category))
    fail(
      `category "${p.category}" not in allowlist: ${[...CATEGORY_ALLOW].join(", ")}`,
    );
  if (!SEVERITY_ALLOW.has(p.severity))
    fail(
      `severity "${p.severity}" must be one of: ${[...SEVERITY_ALLOW].join(", ")}`,
    );
  if (!p.description || p.description.length < 20)
    fail(
      "description must be at least 20 characters — describe what the probe does",
    );
  if (p.positive_examples.length < 3)
    fail(
      `need at least 3 positive examples (got ${p.positive_examples.length}). One per line.`,
    );
  if (p.negative_examples.length < 3)
    fail(
      `need at least 3 negative examples (got ${p.negative_examples.length}). Lookalike-but-benign strings keep precision honest.`,
    );
  if (!p.discovered_by) fail("discovered_by is required for attribution");
  // Wall 3 — content sanitization. The probe body is untrusted GitHub-issue text
  // written into a YAML proposal; keep attribution and examples to safe shapes so
  // they cannot smuggle control content or bomb the pipeline.
  if (!/^[A-Za-z0-9._\-\s@()/:]+$/.test(p.discovered_by))
    fail("discovered_by must be a plain name/handle (letters, digits and . _ - @ ( ) / : only)");
  const allExamples = [...p.positive_examples, ...p.negative_examples];
  if (allExamples.length > 100) fail("too many examples (max 100 combined)");
  for (const ex of allExamples) {
    if (ex.length > 5000) fail(`example too long (${ex.length} chars, max 5000)`);
    if (/\x00/.test(ex)) fail("examples must not contain null bytes");
  }
}

function buildProposal(p: Probe, slug: string): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");

  const refExternal: string[] = [];
  if (p.source_url) refExternal.push(p.source_url);

  const proposal: Record<string, unknown> = {
    title: p.name,
    id: `ATR-DRAFT-PROBE-${slug.toUpperCase()}`,
    rule_version: 1,
    status: "draft",
    description: p.description.trim(),
    author: `ATR Community (red-team submission by ${p.discovered_by})`,
    date: todayPretty,
    schema_version: "0.1",
    detection_tier: "pattern",
    maturity: "experimental",
    severity: p.severity,
  };

  const references: Record<string, unknown> = {};
  if (p.cves && p.cves.length) references.cve = p.cves;
  if (p.owasp_mapping && p.owasp_mapping.length) {
    const owaspLlm = p.owasp_mapping.filter((m) => /^LLM\d/i.test(m));
    const atlas = p.owasp_mapping.filter((m) => /^AML\./i.test(m));
    const other = p.owasp_mapping.filter(
      (m) => !owaspLlm.includes(m) && !atlas.includes(m),
    );
    if (owaspLlm.length) references.owasp_llm = owaspLlm;
    if (atlas.length) references.mitre_atlas = atlas;
    if (other.length) references.external_mappings = other;
  }
  if (refExternal.length) references.external = refExternal;
  if (Object.keys(references).length) proposal.references = references;

  proposal.metadata_provenance = {
    discovered_by: p.discovered_by,
    source: "red-team-probe-submission",
    submitted_on: today,
  };

  proposal.tags = {
    category: p.category,
    scan_target: "runtime",
    confidence: "medium",
  };

  proposal.agent_source = {
    type: "llm_io",
    framework: ["any"],
    provider: ["any"],
  };

  proposal.detection = {
    condition: "any",
    false_positives: [],
    conditions: [],
  };

  proposal.response = {
    actions: ["alert"],
    notify: ["security_team"],
  };

  proposal.test_cases = {
    true_positives: p.positive_examples.map((s) => ({ input: s })),
    true_negatives: p.negative_examples.map((s) => ({ input: s })),
  };

  if (p.notes) {
    proposal._submitter_notes = p.notes;
  }

  proposal._red_team_probe_submission = {
    discovered_by: p.discovered_by,
    source_url: p.source_url ?? null,
    submitted_on: today,
    positive_example_count: p.positive_examples.length,
    negative_example_count: p.negative_examples.length,
  };

  const yamlBody = yaml.dump(proposal, {
    lineWidth: 100,
    noRefs: true,
    quotingType: '"',
  });

  const banner = `# ATR rule proposal -- generated by scripts/probe-to-atr.ts
# Source: red-team probe submission by ${p.discovered_by}
# Submitted on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this proposal can be promoted to rules/.
#
# Next steps for the reviewer:
#   1. Write a regex (or compound condition) that matches ALL true_positives
#      and matches NONE of the true_negatives.
#   2. Run: npx tsx scripts/check-rules-safety.ts <this file path>
#   3. If clean, move to rules/<category>/<full ATR ID>.yaml and assign the
#      next ATR-2026-NNNNN id.
`;

  return banner + "\n" + yamlBody;
}

function main(): void {
  let probe: Probe;
  if (PROBE_FILE) {
    const raw = readFileSync(PROBE_FILE, "utf-8");
    probe = yaml.load(raw) as Probe;
    if (!probe.positive_examples) probe.positive_examples = [];
    if (!probe.negative_examples) probe.negative_examples = [];
  } else if (ISSUE_BODY_FILE) {
    const raw = readFileSync(ISSUE_BODY_FILE, "utf-8");
    probe = parseIssueBody(raw);
  } else {
    fail("must pass either --probe <file.yaml> or --issue-body <body.txt>");
  }

  validateProbe(probe);

  const slug = slugify(probe.name);
  const outPath = resolve(OUT_DIR, `${slug}.proposal.yaml`);

  const exists = existsSync(outPath);
  if (exists && !FORCE) {
    fail(`proposal already exists: ${outPath} (pass --force to overwrite)`);
  }

  const yamlOut = buildProposal(probe, slug);

  console.log(`probe: ${probe.name}`);
  console.log(`category: ${probe.category}`);
  console.log(`severity: ${probe.severity}`);
  console.log(`discovered_by: ${probe.discovered_by}`);
  console.log(
    `positives: ${probe.positive_examples.length}, negatives: ${probe.negative_examples.length}`,
  );
  console.log(`slug: ${slug}`);
  console.log(`out: ${outPath}${WRITE ? " (writing)" : " (dry-run)"}`);

  if (WRITE) {
    if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });
    writeFileSync(outPath, yamlOut, "utf-8");
    console.log(`wrote ${yamlOut.length} bytes to ${outPath}`);
  } else {
    console.log("--- proposal preview ---");
    console.log(yamlOut);
  }

  // emit a machine-readable summary for the workflow to consume
  const summary = {
    slug,
    out_path: outPath.replace(REPO_ROOT + "/", ""),
    category: probe.category,
    severity: probe.severity,
    positive_count: probe.positive_examples.length,
    negative_count: probe.negative_examples.length,
    discovered_by: probe.discovered_by,
  };
  console.log(`::probe-summary::${JSON.stringify(summary)}`);
}

main();
