#!/usr/bin/env bash
# =============================================================================
# ATR vs NVIDIA Garak Benchmark
# =============================================================================
#
# Tests ATR detection rules against NVIDIA Garak's in-the-wild jailbreak
# dataset (666 real-world jailbreak prompts).
#
# Prerequisites:
#   pip install garak   (or: python3 -m venv .venv && source .venv/bin/activate && pip install garak)
#   npm run build       (ATR must be built first)
#
# Usage:
#   bash scripts/eval-garak.sh
#
# Output:
#   data/garak-benchmark/garak-eval-report.json
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "ATR vs NVIDIA Garak Benchmark"
echo "=============================="
echo ""

# Step 1: Find Garak dataset
GARAK_DATA=""
for candidate in \
  ".venv/lib/python*/site-packages/garak/data/inthewild_jailbreak_llms.json" \
  "/tmp/garak-env/lib/python*/site-packages/garak/data/inthewild_jailbreak_llms.json" \
  "$(python3 -c 'import garak, os; print(os.path.join(os.path.dirname(garak.__file__), "data", "inthewild_jailbreak_llms.json"))' 2>/dev/null || echo '')"
do
  # shellcheck disable=SC2086
  for f in $candidate; do
    if [ -f "$f" ]; then
      GARAK_DATA="$f"
      break 2
    fi
  done
done

if [ -z "$GARAK_DATA" ]; then
  echo "Error: Garak dataset not found. Install garak first: pip install garak"
  exit 1
fi

echo "Dataset: $GARAK_DATA"

# Step 2: Convert to ATR event format
echo "Converting to ATR event format..."
EVENTS_FILE=$(mktemp)
node -e "
const prompts = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'));
// Emit each prompt as both llm_input (llm_io rules) and tool_response (mcp_exchange rules)
// so that all ATR rule types are exercised against the garak corpus.
const events = prompts.flatMap((p, i) => {
  const content = (typeof p === 'string' ? p : String(p)).slice(0, 5000);
  return [
    { type: 'llm_input',    timestamp: '2026-01-01T00:00:00Z', content, source: 'garak-inthewild', index: i },
    { type: 'tool_response', timestamp: '2026-01-01T00:00:00Z', content, source: 'garak-inthewild', index: i },
  ];
});
require('fs').writeFileSync(process.argv[2], JSON.stringify(events));
console.log('Prepared ' + prompts.length + ' prompts (' + events.length + ' events)');
" "$GARAK_DATA" "$EVENTS_FILE"

# Step 3: Run ATR evaluation
echo "Running ATR evaluation..."
mkdir -p data/garak-benchmark

node -e "
const { ATREngine } = require('./dist/engine.js');
async function run() {
  const engine = new ATREngine({ rulesDir: './rules' });
  await engine.loadRules();
  const events = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'));
  // Group events by index (each prompt emits 2 events: llm_input + tool_response)
  // A prompt is "detected" if ANY of its events trigger a rule.
  const promptHit = new Map();
  const byRule = {};
  const bySeverity = {};
  for (const event of events) {
    const matches = engine.evaluate(event);
    if (matches.length > 0) {
      promptHit.set(event.index, true);
      for (const m of matches) {
        byRule[m.rule.id] = byRule[m.rule.id] || { id: m.rule.id, title: m.rule.title, severity: m.rule.severity, count: 0 };
        byRule[m.rule.id].count++;
        bySeverity[m.rule.severity] = (bySeverity[m.rule.severity] || 0) + 1;
      }
    }
  }
  const totalPrompts = new Set(events.map(e => e.index)).size;
  const detected = promptHit.size;
  const missed = totalPrompts - detected;
  const report = {
    benchmark: 'NVIDIA Garak In-The-Wild Jailbreak Dataset',
    source: 'garak — data/inthewild_jailbreak_llms.json',
    date: new Date().toISOString().split('T')[0],
    atr_version: require('./package.json').version,
    rules_loaded: engine.getRuleCount(),
    dataset: { total_prompts: totalPrompts, type: '100% malicious (real-world jailbreaks)' },
    results: { detected, missed, recall: parseFloat((detected / totalPrompts * 100).toFixed(1)) },
    by_severity: bySeverity,
    top_rules: Object.values(byRule).sort((a,b) => b.count - a.count).slice(0, 15),
  };
  require('fs').writeFileSync('data/garak-benchmark/garak-eval-report.json', JSON.stringify(report, null, 2));
  console.log('');
  console.log('Results:');
  console.log('  Total prompts: ' + totalPrompts);
  console.log('  Detected:      ' + detected);
  console.log('  Missed:        ' + missed);
  console.log('  Recall:        ' + report.results.recall + '%');
  console.log('');
  console.log('Report: data/garak-benchmark/garak-eval-report.json');
}
run().catch(e => { console.error(e); process.exit(1); });
" "$EVENTS_FILE"

rm -f "$EVENTS_FILE"
echo ""
echo "Done."
