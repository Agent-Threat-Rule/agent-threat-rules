# Building on ATR

ATR is a detection layer, not a complete security product. It evaluates agent events against rules and returns match results. What you do with those results is up to you.

ATR 是偵測層，不是完整的安全產品。它評估 agent 事件、回傳匹配結果。怎麼處理結果由你決定。

```
YOUR PRODUCT
┌─────────────────────────────────────────────────────┐
│                                                     │
│  Agent Event ──→ ATR Engine ──→ Match Results        │
│                   (detect)        │                  │
│                                   ▼                  │
│                          Your Protection Layer       │
│                          - Block / Allow / Alert     │
│                          - Notify (Slack/Email/TG)   │
│                          - Dashboard                 │
│                          - Learning / Baseline       │
│                          - Compliance Reporting      │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## Quick Integration (TypeScript)

```typescript
import { ATREngine } from 'agent-threat-rules';

// 1. Load rules
const engine = new ATREngine({ rulesDir: './node_modules/agent-threat-rules/rules' });
await engine.loadRules();

// 2. Evaluate an event
const matches = engine.evaluate({
  type: 'llm_input',
  timestamp: new Date().toISOString(),
  content: userInput,
  fields: { user_input: userInput },
});

// 3. YOUR logic decides what to do with matches
for (const match of matches) {
  if (match.rule.severity === 'critical' && match.confidence > 0.8) {
    // Block, alert, log — whatever your product needs
    blockRequest(match);
    notifySecurityTeam(match);
  }
}
```

### Semantic LLM-as-Judge

Rule-level `detection.method: semantic` uses an injected judge function and the async engine path:

```typescript
import { ATREngine, createOpenAICompatibleJudge } from 'agent-threat-rules';

const engine = new ATREngine({
  rulesDir: './node_modules/agent-threat-rules/rules',
  semanticJudge: createOpenAICompatibleJudge({
    apiKey: process.env.LLM_API_KEY ?? '',
    baseUrl: process.env.LLM_BASE_URL,
    model: process.env.LLM_MODEL,
  }),
});

await engine.loadRules();
const matches = await engine.evaluateAsync(event);
```

See [`docs/semantic-judge.md`](docs/semantic-judge.md) for the judge contract, provider-agnostic prompt, local model setup, and deterministic test example.

## Quick Integration (Python)

```python
from pyatr import ATREngine, AgentEvent

engine = ATREngine(rules_dir="./rules")
engine.load_rules()

matches = engine.evaluate(AgentEvent(
    type="llm_input",
    content=user_input,
    fields={"user_input": user_input},
))

for match in matches:
    if match.rule.severity == "critical" and match.confidence > 0.8:
        block_request(match)
```

---

## What ATR Provides vs. What You Build

| ATR provides (detection) | You build (protection) |
|---|---|
| Rule format (YAML schema) | Response policy (what to do on match) |
| Rule library (113 rules) | Notification channels (Slack, email, etc.) |
| Evaluation engine (TS + Python) | Dashboard / monitoring UI |
| Match results with confidence scores | Baseline learning / false positive tuning |
| Session tracking (basic) | User/role-based policy |
| Coverage analysis (OWASP/MITRE gaps) | Compliance reporting |
| Rule scaffolding tools | Rule management / update pipeline |

---

## Integration Patterns

### Pattern 1: Claude Code Hook (simplest)

```bash
npx agent-threat-rules init
```

ATR evaluates every tool call. Returns `allow` or `deny` via stdio.
For basic protection without building a product.

### Pattern 2: Middleware (LangChain, CrewAI, etc.)

See [`examples/langchain-middleware/`](examples/langchain-middleware/) for a working example.

ATR sits between user input and the LLM. Blocks high-confidence threats, passes everything else through.

### Pattern 3: Sidecar (production agents)

```
Agent Process                    ATR Sidecar
┌──────────────┐                ┌──────────────┐
│ Receives     │   event JSON   │ ATR Engine   │
│ user input   │ ──────────→    │ evaluates    │
│              │                │ 113 rules    │
│ Calls tools  │   match JSON   │              │
│              │ ←──────────    │ returns      │
│ Your logic   │                │ matches      │
│ decides      │                └──────────────┘
└──────────────┘
```

ATR runs as a separate process (MCP server or HTTP). Your agent queries it per-event.

### Pattern 4: Embedded Library (full control)

Import ATR as a library. Build your own evaluation pipeline around it.
This pattern gives you full control over the evaluation pipeline.

```typescript
import { ATREngine, SessionTracker } from 'agent-threat-rules';

class MySecurityPipeline {
  private atr: ATREngine;
  private sessions: SessionTracker;

  async evaluate(event: AgentEvent): Promise<MyDecision> {
    // ATR detection
    const matches = this.atr.evaluate(event, this.sessions);

    // YOUR protection logic
    if (matches.length === 0) return { action: 'allow' };

    const worst = matches[0]; // sorted by severity
    if (worst.rule.severity === 'critical') {
      await this.alertOncall(worst);
      return { action: 'block', reason: worst.rule.title };
    }

    return { action: 'log', matches };
  }
}
```

---

## Products Built on ATR

| Product | What they add on top of ATR |
|---|---|
| *Your product here* | [Tell us](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues) |

---

## Integration Checklist

Before shipping your ATR integration:

- [ ] Load rules from `node_modules/agent-threat-rules/rules` (not hardcoded paths)
- [ ] Handle `engine.evaluate()` returning empty array (no threats)
- [ ] Handle `engine.evaluate()` returning multiple matches (pick highest severity)
- [ ] Set a confidence threshold (recommended: 0.7+ for auto-block, 0.5+ for alert)
- [ ] Log all matches (even below threshold) for false positive analysis
- [ ] Test with ATR's built-in test cases: `npx agent-threat-rules test`
- [ ] Subscribe to ATR releases for rule updates
- [ ] Report false positives back to ATR ([issue template](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues))

---

## FAQ

**Q: Can I add my own rules alongside ATR's?**
Yes. Point `ATREngine({ rulesDir })` at any directory. Load multiple directories:
```typescript
const engine = new ATREngine({ rulesDir: './atr-rules' });
await engine.loadRules();
await engine.loadRulesFromDirectory('./my-custom-rules'); // additive
```

**Q: Do I need to ship ATR rules with my product?**
ATR rules are MIT licensed. You can bundle them, or let users install `agent-threat-rules` separately.

**Q: How do I handle rule updates?**
Subscribe to npm releases. Pin to a minor version (`^0.4.0`) for compatible updates, or exact version for stability.

**Q: Can I use ATR with non-JavaScript agents?**
Yes. Use the Python engine (`pyatr`), or run `npx agent-threat-rules mcp` as a subprocess and communicate via MCP protocol.
