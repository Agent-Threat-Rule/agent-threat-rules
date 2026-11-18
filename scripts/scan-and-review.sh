#!/usr/bin/env bash
#
# scan-and-review.sh -- One-command full scan pipeline with quality review
#
# Runs: crawl -> audit (L1+L2 AST) -> triage -> quality report
#
# Usage:
#   # Re-scan existing 1,295 packages with L2 AST (recommended first run)
#   ./scripts/scan-and-review.sh --rescan
#
#   # Continue scanning new packages (next 2000)
#   ./scripts/scan-and-review.sh --count 2000
#
#   # Scan and push to Community Feed
#   ./scripts/scan-and-review.sh --count 500 --push-tc
#
#   # Preview
#   ./scripts/scan-and-review.sh --dry-run
#
# Output:
#   - audit-pipeline-*.json     Raw scan results
#   - triage-report-*.json      Triaged findings (ATR candidates separated)
#   - quality-review-*.md       ATR proposal quality analysis
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
MERGED_FILE="$REPO_ROOT/audit-pipeline-merged.json"
TRIAGE_FILE="$REPO_ROOT/triage-report-${TIMESTAMP}.json"
REVIEW_FILE="$REPO_ROOT/quality-review-${TIMESTAMP}.md"

# Defaults
MODE="continue"    # rescan | continue
COUNT=0            # 0 = auto (rescan=all, continue=500)
PUSH_TC=false
TC_URL="http://localhost:8234"
DRY_RUN=false
BATCH_SIZE=200

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rescan)     MODE="rescan"; shift ;;
    --count)      COUNT="$2"; shift 2 ;;
    --push-tc)    PUSH_TC=true; shift ;;
    --tc-url)     TC_URL="$2"; shift 2 ;;
    --batch-size) BATCH_SIZE="$2"; shift 2 ;;
    --dry-run)    DRY_RUN=true; shift ;;
    -h|--help)    head -25 "$0" | tail -23; exit 0 ;;
    *)            echo "Unknown: $1"; exit 1 ;;
  esac
done

log()  { echo "[$(date +%H:%M:%S)] $*"; }
warn() { echo "[$(date +%H:%M:%S)] WARNING: $*" >&2; }

cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Step 0: Determine scan target
# ---------------------------------------------------------------------------

log "============================================"
log "Full Scan Pipeline (L1 + L2 AST)"
log "============================================"

if [[ "$MODE" == "rescan" ]]; then
  if [[ "$COUNT" -eq 0 ]]; then
    # Count existing scanned packages
    if [[ -f "$MERGED_FILE" ]] && command -v jq &>/dev/null; then
      COUNT="$(jq '.results | length' "$MERGED_FILE" 2>/dev/null || echo 1295)"
    else
      COUNT=1295
    fi
  fi
  log "Mode: RESCAN existing $COUNT packages (with L2 AST upgrade)"
  log "This will reset the scan state and re-audit all packages."

  # Reset state
  if [[ "$DRY_RUN" == "false" ]]; then
    rm -f "$REPO_ROOT/scan-state.json"
    rm -f "$MERGED_FILE"
    log "State reset."
  fi
else
  if [[ "$COUNT" -eq 0 ]]; then
    COUNT=500
  fi
  log "Mode: CONTINUE scanning next $COUNT new packages"
fi

log "Batch size: $BATCH_SIZE"
log "Push to TC: $PUSH_TC"
log "Dry run: $DRY_RUN"
log ""

# ---------------------------------------------------------------------------
# Step 1: Run batched pipeline
# ---------------------------------------------------------------------------

TOTAL_SCANNED=0
BATCH_NUM=0
FAILED_BATCHES=0
REMAINING=$COUNT

while [[ "$REMAINING" -gt 0 ]]; do
  BATCH_NUM=$((BATCH_NUM + 1))
  THIS_BATCH=$BATCH_SIZE
  if [[ "$REMAINING" -lt "$THIS_BATCH" ]]; then
    THIS_BATCH=$REMAINING
  fi

  log "──────────────────────────────────"
  log "Batch $BATCH_NUM: scanning $THIS_BATCH packages ($TOTAL_SCANNED/$COUNT done)"
  log "──────────────────────────────────"

  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY-RUN] Would run: auto-scan-pipeline.sh --batch-size $THIS_BATCH"
    REMAINING=0
  else
    PIPELINE_ARGS="--batch-size $THIS_BATCH"
    if [[ "$PUSH_TC" == "true" ]]; then
      PIPELINE_ARGS="$PIPELINE_ARGS --push-tc --tc-url $TC_URL"
    fi

    # shellcheck disable=SC2086
    if bash scripts/auto-scan-pipeline.sh $PIPELINE_ARGS; then
      TOTAL_SCANNED=$((TOTAL_SCANNED + THIS_BATCH))
      log "Batch $BATCH_NUM complete. Progress: $TOTAL_SCANNED/$COUNT"
    else
      FAILED_BATCHES=$((FAILED_BATCHES + 1))
      warn "Batch $BATCH_NUM failed. Continuing to next batch."
    fi
    REMAINING=$((REMAINING - THIS_BATCH))
  fi
done

if [[ "$DRY_RUN" == "true" ]]; then
  log ""
  log "[DRY-RUN] Would scan $COUNT packages in ~$((COUNT / BATCH_SIZE + 1)) batches."
  log "[DRY-RUN] Estimated time: ~$((COUNT * 3 / 60)) minutes (3s per package average)."
  exit 0
fi

# ---------------------------------------------------------------------------
# Step 2: Run triage on full merged results
# ---------------------------------------------------------------------------

log ""
log "============================================"
log "Triage: Separating findings from ATR candidates"
log "============================================"

if [[ -f "$MERGED_FILE" ]]; then
  npx tsx scripts/triage-findings.ts --input "$MERGED_FILE" --output "$TRIAGE_FILE" 2>&1
else
  warn "No merged results file. Skipping triage."
fi

# ---------------------------------------------------------------------------
# Step 3: Quality review
# ---------------------------------------------------------------------------

log ""
log "============================================"
log "Quality Review: Generating analysis report"
log "============================================"

generate_review() {
  local merged="$1"
  local triage="$2"
  local output="$3"

  if ! command -v jq &>/dev/null; then
    warn "jq not installed. Skipping quality review."
    return
  fi

  local total_packages
  local total_tools
  local l1_threats
  local l2_findings
  local l2_critical
  local l2_high
  local triage_confirmed
  local triage_suspicious
  local triage_clean

  total_packages="$(jq '.total // (.results | length)' "$merged" 2>/dev/null || echo 0)"
  total_tools="$(jq '.totalTools // ([.results[].tools | length] | add)' "$merged" 2>/dev/null || echo 0)"

  # L1-only threats (genuineThreats without [AST-L2] prefix)
  l1_threats="$(jq '[.results[] | .genuineThreats[] | select(startswith("[AST-L2]") | not)] | length' "$merged" 2>/dev/null || echo 0)"

  # L2 AST findings
  l2_findings="$(jq '[.results[] | (.astAnalysis.findings // [])[] ] | length' "$merged" 2>/dev/null || echo 0)"
  l2_critical="$(jq '[.results[] | (.astAnalysis.findings // [])[] | select(.severity == "critical")] | length' "$merged" 2>/dev/null || echo 0)"
  l2_high="$(jq '[.results[] | (.astAnalysis.findings // [])[] | select(.severity == "high")] | length' "$merged" 2>/dev/null || echo 0)"

  # Triage stats
  if [[ -f "$triage" ]]; then
    triage_confirmed="$(jq '.summary.confirmed_malicious // 0' "$triage" 2>/dev/null || echo 0)"
    triage_suspicious="$(jq '.summary.highly_suspicious // 0' "$triage" 2>/dev/null || echo 0)"
    triage_clean="$(jq '.summary.clean // 0' "$triage" 2>/dev/null || echo 0)"
  else
    triage_confirmed=0
    triage_suspicious=0
    triage_clean=0
  fi

  # Risk level distribution
  local critical high medium low clean_count
  critical="$(jq '[.results[] | select(.riskLevel == "CRITICAL")] | length' "$merged" 2>/dev/null || echo 0)"
  high="$(jq '[.results[] | select(.riskLevel == "HIGH")] | length' "$merged" 2>/dev/null || echo 0)"
  medium="$(jq '[.results[] | select(.riskLevel == "MEDIUM")] | length' "$merged" 2>/dev/null || echo 0)"
  low="$(jq '[.results[] | select(.riskLevel == "LOW")] | length' "$merged" 2>/dev/null || echo 0)"
  clean_count="$(jq '[.results[] | select(.riskLevel == "CLEAN")] | length' "$merged" 2>/dev/null || echo 0)"

  # L2 unique categories
  local l2_categories
  l2_categories="$(jq -r '[.results[] | (.astAnalysis.findings // [])[] | .category] | group_by(.) | map({category: .[0], count: length}) | sort_by(-.count) | .[] | "| \(.category) | \(.count) |"' "$merged" 2>/dev/null || echo "| (none) | 0 |")"

  # Top threats (packages with highest L2 findings)
  local top_threats
  top_threats="$(jq -r '[.results[] | select((.astAnalysis.findings // []) | length > 0) | {package: .package, score: .riskScore, l2count: (.astAnalysis.findings | length), threats: (.genuineThreats[:3] | join("; "))}] | sort_by(-.l2count) | .[:15][] | "| \(.package) | \(.score) | \(.l2count) | \(.threats[:100]) |"' "$merged" 2>/dev/null || echo "| (none) | - | - | - |")"

  # ATR candidates from triage
  local atr_candidates=""
  if [[ -f "$triage" ]]; then
    atr_candidates="$(jq -r '.atrCandidates[:20][] | "| \(.package) | \(.proposedSeverity // "high") | \(.reasons[0][:80]) |"' "$triage" 2>/dev/null || echo "| (none) | - | - |")"
  fi

  # Cross-skill patterns
  local cross_patterns=""
  if [[ -f "$triage" ]]; then
    cross_patterns="$(jq -r '.patternFrequency[] | select(.count >= 2) | "| \(.pattern) | \(.count) | \(.packages[:5] | join(", ")) |"' "$triage" 2>/dev/null || echo "| (none) | - | - |")"
  fi

  cat > "$output" << REVIEW
# Scan Quality Review -- ${TIMESTAMP}

## Overview

| Metric | Value |
|--------|-------|
| Packages scanned | ${total_packages} |
| MCP tools extracted | ${total_tools} |
| L1 (regex) threats | ${l1_threats} |
| L2 (AST) findings | ${l2_findings} |
| L2 critical | ${l2_critical} |
| L2 high | ${l2_high} |

## Risk Distribution

| Level | Count | % |
|-------|-------|---|
| CRITICAL | ${critical} | $(echo "scale=1; $critical * 100 / $total_packages" | bc 2>/dev/null || echo "?")% |
| HIGH | ${high} | $(echo "scale=1; $high * 100 / $total_packages" | bc 2>/dev/null || echo "?")% |
| MEDIUM | ${medium} | $(echo "scale=1; $medium * 100 / $total_packages" | bc 2>/dev/null || echo "?")% |
| LOW | ${low} | $(echo "scale=1; $low * 100 / $total_packages" | bc 2>/dev/null || echo "?")% |
| CLEAN | ${clean_count} | $(echo "scale=1; $clean_count * 100 / $total_packages" | bc 2>/dev/null || echo "?")% |

## L2 AST Findings by Category

| Category | Count |
|----------|-------|
${l2_categories}

## L1 vs L2 Comparison

**L1 (regex) alone would find:** ${l1_threats} threats
**L2 (AST) additionally found:** ${l2_findings} code-level findings
**Improvement:** L2 adds ~$(echo "scale=0; $l2_findings * 100 / ($l1_threats + 1)" | bc 2>/dev/null || echo "?")% more findings with higher confidence

## Triage Summary

| Category | Count | Action |
|----------|-------|--------|
| Confirmed malicious | ${triage_confirmed} | -> ATR rule |
| Highly suspicious | ${triage_suspicious} | -> TC draft (needs 3+ reports) |
| Clean | ${triage_clean} | No action |

## ATR Candidates (confirmed malicious -> propose as rules)

| Package | Severity | Reason |
|---------|----------|--------|
${atr_candidates}

## Cross-Skill Patterns (same pattern in 2+ skills)

| Pattern | Count | Packages |
|---------|-------|----------|
${cross_patterns}

## Top Threat Packages (by L2 findings)

| Package | Score | L2 Findings | Threats |
|---------|-------|-------------|---------|
${top_threats}

---
Generated by scan-and-review.sh at ${TIMESTAMP}
REVIEW

  log "Quality review saved: $output"
}

if [[ -f "$MERGED_FILE" ]]; then
  generate_review "$MERGED_FILE" "$TRIAGE_FILE" "$REVIEW_FILE"

  # Print key numbers to terminal
  log ""
  log "============================================"
  log "SCAN COMPLETE"
  log "============================================"

  if command -v jq &>/dev/null; then
    local_total="$(jq '.total // (.results | length)' "$MERGED_FILE" 2>/dev/null || echo '?')"
    local_l2="$(jq '[.results[] | (.astAnalysis.findings // [])[] ] | length' "$MERGED_FILE" 2>/dev/null || echo '?')"
    local_confirmed="0"
    if [[ -f "$TRIAGE_FILE" ]]; then
      local_confirmed="$(jq '.summary.confirmed_malicious // 0' "$TRIAGE_FILE" 2>/dev/null || echo '0')"
    fi
    log "  Packages:        $local_total"
    log "  L2 AST findings: $local_l2"
    log "  ATR candidates:  $local_confirmed"
    if [[ "$FAILED_BATCHES" -gt 0 ]]; then
      log "  Failed batches:  $FAILED_BATCHES"
    fi
    log ""
    log "  Results:  $MERGED_FILE"
    log "  Triage:   $TRIAGE_FILE"
    log "  Review:   $REVIEW_FILE"
  fi
else
  warn "No results to review."
fi

log ""
log "Done."
