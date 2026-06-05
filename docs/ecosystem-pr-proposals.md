# Ecosystem PR Proposals — Differentiated by Platform

## Principle

Each platform gets a different integration based on what THEY need:
- Security platforms → rules feed (pull from TC)
- AI frameworks → middleware/guardrail (scan + optional TC pull)
- Developer tools → plugin (scan + auto-update)
- Awesome lists → documentation entry

Every integration includes a TC pull mechanism so they always get latest rules.
Nobody is required to push data back.

---

## Tier 1: Already Merged — Upgrade PRs

### Cisco AI Defense (PR #79 merged)
**Current:** 34 static ATR rules embedded in skill-scanner
**Upgrade PR:** Auto-update from TC API

```python
# cisco-ai-defense/skill-scanner/atr_updater.py
import requests, json, os

ATR_RULES_URL = "https://tc.panguard.ai/api/atr-rules"
LOCAL_CACHE = os.path.expanduser("~/.atr-cache/rules.json")

def fetch_latest_rules(since=None):
    """Pull latest ATR rules from Threat Cloud. Zero auth required."""
    params = {"since": since} if since else {}
    resp = requests.get(ATR_RULES_URL, params=params, timeout=10)
    return resp.json()["data"] if resp.ok else []

def get_rule_count():
    resp = requests.get("https://tc.panguard.ai/api/metrics", timeout=5)
    return resp.json()["data"]["totalAtrRules"] if resp.ok else 0
```

**Pitch:** "Your users are on static 34 rules. TC has 108 and growing. One file adds auto-update."
**Ask:** Logo usage ("Integrated with Cisco AI Defense")

---

### OWASP Agentic Top 10 (PR #14 merged)
**Current:** Detection mapping document
**Upgrade PR:** Add live stats badge + TC threat feed link

```markdown
## Live Threat Intelligence
ATR scans 53,000+ skills continuously. Current stats:
- [![ATR Rules](https://tc.panguard.ai/api/badge/stats)](https://tc.panguard.ai/api/metrics)
- [Skill Blacklist Feed](https://tc.panguard.ai/api/skill-blacklist) (JSON, public)
- [Domain Blocklist](https://tc.panguard.ai/api/feeds/domain-blocklist) (text/plain)
```

**Pitch:** "OWASP defines threats, ATR detects them. Now with live feeds."
**Ask:** "ATR is referenced by OWASP" statement for marketing

---

## Tier 2: New PRs — High ROI Platforms

### Portkey Gateway (11K stars)
**What they are:** AI gateway with guardrail plugin system
**What they need:** Free, fast, open-source guardrail (competitors are paid APIs)

**PR: Guardrail plugin with TC auto-update**
```typescript
// plugins/atr-guardrail/manifest.json
{
  "id": "atr-threat-detection",
  "name": "ATR Threat Detection",
  "description": "108 open-source detection rules for AI agent threats. Auto-updated from Threat Cloud.",
  "type": "guardrail",
  "config": {
    "severity_threshold": "high",
    "auto_update": true,
    "tc_url": "https://tc.panguard.ai"
  }
}
```

Key selling points vs their existing guardrails:
| | ATR | CrowdStrike AIDR | Zscaler AI Guard |
|--|-----|-------------------|------------------|
| Cost | Free | $$$ | $$$ |
| Latency | <1ms (regex) | API roundtrip | API roundtrip |
| Open source | MIT | No | No |
| Offline | Yes | No | No |
| Auto-update | TC pull (free) | Subscription | Subscription |
| Rules count | 108 | Unknown | Unknown |

**Pitch:** "Only free, zero-latency guardrail in your plugin ecosystem. Auto-updates from 53K-skill threat intelligence."
**Ask:** Plugin listing page logo + "Powered by ATR" mention

---

### Microsoft Agent Governance Toolkit (627 stars)
**What they are:** Policy engine for AI agents (p99 <0.1ms)
**What they need:** Detection rules upstream — their mcp-security.yaml has ~30 patterns

**PR Path A: Policy rules file**
```yaml
# examples/policies/atr-community-rules.yaml
# Auto-generated from ATR v1.1.0 (108 rules)
# Live updates: https://tc.panguard.ai/api/rules
metadata:
  source: "Agent Threat Rules (ATR)"
  version: "1.1.0"
  rules_count: 108
  update_url: "https://tc.panguard.ai/api/rules"
  license: "MIT"

policies:
  - name: "prompt-injection-detection"
    description: "ATR prompt injection rules (29 patterns)"
    source_rules: ["ATR-2026-00001", "ATR-2026-00002", ...]
    action: "block"
    severity: "critical"
```

**Pitch:** "Your toolkit is the policy engine. ATR is the detection rules upstream. 108 rules vs your 30. MIT. Auto-updated."
**Ask:** Integration docs mention + "Works with ATR" in their README

---

### NVIDIA Garak (7.3K stars)
**What they are:** Red team / LLM vulnerability scanner
**What they need:** Detection baseline to complement their probes

**PR: ATR detector module (Python)**
```python
# garak/detectors/atr.py
"""ATR-based threat detector — 108 regex rules, <1ms per check.
Rules auto-update from Threat Cloud API."""

class ATRDetector(Detector):
    """Fast regex-based detector using ATR community rules.
    
    Pulls latest rules from tc.panguard.ai/api/rules on init.
    Falls back to bundled rules if TC unreachable.
    """
    
    DEFAULT_TC_URL = "https://tc.panguard.ai/api/rules"
    
    def __init__(self):
        super().__init__()
        self.rules = self._fetch_rules() or self._load_bundled()
    
    def _fetch_rules(self):
        """Pull latest rules from TC. Zero auth required."""
        try:
            resp = requests.get(self.DEFAULT_TC_URL, timeout=10)
            return self._parse_rules(resp.json()["data"])
        except:
            return None
```

**Pitch:** "Garak probes for vulnerabilities. ATR detects them. Red + Blue in one tool. 108 rules, auto-updated, <1ms."
**Ask:** README mention in detectors section

---

### NVIDIA NeMo Guardrails (5.8K stars)
**What they are:** Conversational AI safety (topic control, content moderation)
**What they need:** Tool-calling security (they only do conversation)

**PR: ATR action for Colang**
```colang
define flow check_tool_safety
  """Check tool calls against ATR threat rules before execution."""
  $result = execute check_atr_rules(tool_name=$tool_name, tool_input=$tool_input)
  if $result.threat_detected
    bot say "Tool call blocked: {$result.rule_title}"
    stop
```

**Pitch:** "NeMo guards conversations. ATR guards tool calls. Different layers, one defense. Rules auto-pull from TC."
**Ask:** Actions gallery listing

---

### Meta PurpleLlama / CyberSecEval (4K stars)
**What they are:** AI safety benchmark suite
**What they need:** Tool-calling security test cases (they cover code safety, not agent tools)

**PR: Test case contribution (zero code)**
```markdown
# Tool-Calling Security Test Cases from ATR

Source: Agent Threat Rules v1.1.0 (108 rules, 53K skills scanned)
Live data: https://tc.panguard.ai/api/metrics

## Prompt Injection via Tool Description (29 test cases)
## Tool Poisoning via MCP Response (11 test cases)  
## Credential Exfiltration via Agent (14 test cases)
## Skill Supply Chain Attack (20 test cases)
```

**Pitch:** "CyberSecEval covers code safety. Here are 108 tool-calling security test cases with ground truth labels from 53K real-world scans."
**Ask:** Citation in their paper/benchmark

---

### FuzzingLabs MCP Security Hub (498 stars)
**What they are:** Offensive MCP tools collection (Nmap, SQLMap, Nuclei)
**What they need:** Defensive side (they're all offense, no defense)

**PR: Defensive MCP server**
```python
# code-security/atr-scanner/server.py
@mcp.tool()
async def scan_skill(content: str) -> dict:
    """Scan SKILL.md content against 108 ATR rules.
    Rules auto-updated from Threat Cloud."""
    rules = fetch_latest_rules()  # TC pull
    matches = evaluate(content, rules)
    return {"threats": len(matches), "details": matches}

@mcp.tool()  
async def check_blacklist(skill_name: str) -> dict:
    """Check if a skill is on the community blacklist."""
    resp = requests.get(f"https://tc.panguard.ai/api/skill-blacklist")
    ...
```

**Pitch:** "Your hub is all offense. ATR adds the blue team side. Scan before you fuzz."
**Ask:** README listing in tools section

---

### Trail of Bits MCP Context Protector (217 stars)
**What they are:** MCP security middleware (high quality bar)
**What they need:** Optional guardrail provider

**PR: Optional ATRGuardrailProvider**
- Non-blocking (warning mode by default)
- Zero required dependencies (bundle core patterns)
- TC pull for auto-updates (optional, graceful fallback)
- `--guardrail atr` CLI flag

**Pitch:** "Defense-in-depth. ATR adds 108 regex rules at <1ms. Optional, non-blocking, zero dependency if you vendor the patterns."
**Ask:** GuardrailProvider listing in docs

---

### Lakera PINT Benchmark (173 stars)
**What they are:** Prompt injection benchmark leaderboard
**What they need:** More submissions to validate benchmark

**PR: Leaderboard entry**
- Pre-requirement: email opensource@lakera.ai
- Numbers: 63.2% recall, 99.7% precision, F1 77.3% (850-sample PINT-format corpus, self-built — not Lakera's official PINT)
- Method: Regex-based, <1ms, 108 rules
- Positioning: "Fast first gate before LLM-based detectors"

**Pitch:** "Only regex-based entry. Shows the precision/recall tradeoff of pattern matching vs LLM."
**Ask:** Leaderboard entry + methodology mention

---

## TC Pull Integration Pattern (copy-paste for all PRs)

Every integration includes this auto-update snippet:

### TypeScript
```typescript
const TC_RULES_URL = "https://tc.panguard.ai/api/rules";

async function fetchLatestRules(since?: string) {
  const url = since ? `${TC_RULES_URL}?since=${since}` : TC_RULES_URL;
  const resp = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!resp.ok) return null; // fallback to bundled
  const { data } = await resp.json();
  return data;
}
```

### Python
```python
TC_RULES_URL = "https://tc.panguard.ai/api/rules"

def fetch_latest_rules(since=None):
    params = {"since": since} if since else {}
    resp = requests.get(TC_RULES_URL, params=params, timeout=10)
    return resp.json()["data"] if resp.ok else None
```

### Threat Feeds (any language)
```
GET https://tc.panguard.ai/api/rules           → All rules (JSON)
GET https://tc.panguard.ai/api/skill-blacklist  → Blacklisted skills (JSON)
GET https://tc.panguard.ai/api/feeds/ip-blocklist     → Malicious IPs (text/plain)
GET https://tc.panguard.ai/api/feeds/domain-blocklist  → Malicious domains (text/plain)
GET https://tc.panguard.ai/api/metrics          → Live threat stats (JSON)
```

Zero auth. Public endpoints. Rate limited to 100 req/min.

---

## Summary: What Each PR Includes

| Platform | Rules | TC Pull | Blacklist | Feeds | Logo Ask |
|----------|-------|---------|-----------|-------|----------|
| Cisco (upgrade) | ✅ auto-update | ✅ | ✅ | — | Integration badge |
| OWASP (upgrade) | — | — | ✅ | ✅ | Reference statement |
| Portkey | ✅ plugin | ✅ | ✅ | — | Plugin listing |
| Microsoft | ✅ policy YAML | ✅ | — | — | README mention |
| NVIDIA Garak | ✅ detector | ✅ | — | — | Detector listing |
| NVIDIA NeMo | ✅ action | ✅ | — | — | Action gallery |
| Meta | Test cases | — | — | ✅ | Paper citation |
| FuzzingLabs | ✅ MCP server | ✅ | ✅ | ✅ | README listing |
| Trail of Bits | ✅ guardrail | ✅ | — | — | Docs listing |
| Lakera | Leaderboard | — | — | — | Leaderboard entry |
