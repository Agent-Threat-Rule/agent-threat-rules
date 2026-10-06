/**
 * Run every trace-method rule's OWN declared test cases through the full
 * ATREngine -- not the trace-evaluator unit test -- to establish whether the
 * trace rules on disk actually evaluate end to end.
 *
 * Point RULES_DIR at a scratch directory to exercise a draft rule (see
 * docs/examples/*.trace.yaml).
 *
 * Usage: npx tsx scripts/detection-boundary/trace-selftest.ts
 *        RULES_DIR=docs/examples npx tsx scripts/detection-boundary/trace-selftest.ts
 */
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../../src/engine.js";
import { loadRulesFromDirectory } from "../../src/loader.js";
import type { AgentEvent, ATRTrace } from "../../src/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const RULES_DIR = process.env["RULES_DIR"]
  ? resolve(process.env["RULES_DIR"])
  : join(REPO_ROOT, "rules");

interface Case {
  readonly input?: string;
  readonly content?: string;
  readonly description?: string;
}

function traceEvent(traceJson: string): AgentEvent {
  return {
    type: "mcp_exchange",
    timestamp: new Date().toISOString(),
    content: traceJson,
    trace: JSON.parse(traceJson) as ATRTrace,
    fields: { user_input: traceJson, tool_input: traceJson, tool_response: traceJson },
  };
}

function payload(c: Case): string | null {
  const raw = c.input ?? c.content;
  if (typeof raw !== "string" || !raw.trim().startsWith("{")) return null;
  return raw;
}

async function main(): Promise<void> {
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();
  const rules = loadRulesFromDirectory(RULES_DIR) as unknown as Record<string, unknown>[];

  const traceRules = rules.filter((r) => {
    const d = (r["detection"] ?? {}) as Record<string, unknown>;
    return d["method"] === "trace" || d["trace"] !== undefined;
  });

  console.log(`rules loaded: ${rules.length}`);
  console.log(`trace-method rules: ${traceRules.length}`);

  let tpAll = 0;
  let tpOkAll = 0;
  let tnAll = 0;
  let tnOkAll = 0;

  for (const r of traceRules) {
    const id = String(r["id"]);
    const tc = (r["test_cases"] ?? {}) as Record<string, Case[] | undefined>;
    let tp = 0;
    let tpOk = 0;
    let tn = 0;
    let tnOk = 0;
    const notes: string[] = [];

    for (const c of tc["true_positives"] ?? []) {
      const raw = payload(c);
      if (raw === null) continue;
      tp++;
      const hit = engine.evaluate(traceEvent(raw)).some((m) => m.rule.id === id);
      if (hit) tpOk++;
      else notes.push(`TP MISS: ${c.description ?? ""}`);
    }
    for (const c of tc["true_negatives"] ?? []) {
      const raw = payload(c);
      if (raw === null) continue;
      tn++;
      const hit = engine.evaluate(traceEvent(raw)).some((m) => m.rule.id === id);
      if (!hit) tnOk++;
      else notes.push(`TN FIRED: ${c.description ?? ""}`);
    }

    tpAll += tp;
    tpOkAll += tpOk;
    tnAll += tn;
    tnOkAll += tnOk;
    console.log(
      `${id}  maturity=${String(r["maturity"])}  status=${String(r["status"])}  TP ${tpOk}/${tp}  TN ${tnOk}/${tn}`,
    );
    for (const n of notes) console.log(`      ${n}`);
  }

  console.log(`\nTOTAL  TP ${tpOkAll}/${tpAll}   TN ${tnOkAll}/${tnAll}`);
}

void main();
