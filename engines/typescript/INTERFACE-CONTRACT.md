# ATR TypeScript Reference Implementation — Interface Contract

> **STATUS: DOCUMENTING EXISTING PRODUCTION SURFACE.** Unlike Python +
> Go interface contracts (which describe targets for future
> implementations), this contract describes the TypeScript engine that
> already ships as `agent-threat-rules` v2.1.3 on npm. This document
> exists so that all three languages have parallel documentation, and
> so that conformance claims have a normative TS reference to validate
> against once the conformance corpus ratifies.

**Status:** Normative for `agent-threat-rules` npm package.
**License:** MIT
**Impl path:** `../../src/`

---

## Package surface (public)

Exported from `../../src/index.ts`:

```typescript
// Core engine
export { ATREngine } from './engine.js';
export type {
  ATREngineConfig,
  ATRReporter,
  ATRDetectionReport,
  ATRCleanReport,
} from './engine.js';

// Rule loading
export {
  loadRuleFile,
  loadRulesFromDirectory,
  validateRule,
} from './loader.js';

// Threat-cloud reporting
export { createTCReporter } from './tc-reporter.js';
export type { TCReporterConfig } from './tc-reporter.js';

// Session correlation
export { SessionTracker } from './session-tracker.js';
export type { SessionStateSnapshot } from './session-tracker.js';

// Content hashing for TC anonymisation
export { computeContentHash } from './content-hash.js';

// Redaction
export {
  redactMatchedValue,
  redactMatchedValues,
} from './redact.js';
export type { RedactOptions } from './redact.js';

// Tier 0 invariants (skill manifest checks)
export { InvariantChecker } from './tier0-invariant.js';
export type {
  SkillManifest,
  InvariantViolation,
  InvariantViolationType,
} from './tier0-invariant.js';

// Tier 1 blacklist (known-bad skill lookup)
export { InMemoryBlacklist, buildBlacklistMatch } from './tier1-blacklist.js';
export type { BlacklistProvider, BlacklistEntry } from './tier1-blacklist.js';

// Capability extractor
export { extractCapabilities } from './capability-extractor.js';
export type { ExtractedCapabilities } from './capability-extractor.js';

// Layer 2.5 embedding similarity
export { EmbeddingModule } from './modules/embedding.js';
export type { EmbeddingModuleConfig } from './modules/embedding.js';
export { VectorStore, loadVectorEntries } from './embedding/vector-store.js';
export type { VectorEntry, SearchResult } from './embedding/vector-store.js';
export { TransformersJSModel, MockEmbeddingModel } from './embedding/model-loader.js';
export type { EmbeddingModel } from './embedding/model-loader.js';

// Modules
export { ModuleRegistry } from './modules/index.js';
export type { ATRModule, ModuleCondition, ModuleResult } from './modules/index.js';
export { SessionModule } from './modules/session.js';
export { SemanticModule } from './modules/semantic.js';
export type { SemanticModuleConfig } from './modules/semantic.js';

// Skill fingerprinting
export { SkillFingerprintStore } from './skill-fingerprint.js';

// Semantic layer config
export type { SemanticLayerConfig } from './layer-integration.js';

// Coverage reporting
export type { ScaffoldInput, ScaffoldResult, ScaffoldOptions } from './rule-scaffolder.js';
export type { CoverageGap, CoverageReport } from './coverage-analyzer.js';

// Output converters (Sigma, Splunk, etc.)
export type { ConvertedQuery, SIEMFormat, OutputFormat } from './converters/index.js';

// Shadow evaluation + flywheel
export type { PromotionCandidate } from './shadow-evaluator.js';
export type { FlywheelConfig } from './flywheel.js';

// Action executor (response actions)
export type { ActionExecutorConfig } from './action-executor.js';

// Hook handler (Claude Code hooks)
export type { HookHandlerConfig } from './hook-handler.js';
```

The MCP server entry is at `src/mcp-server.ts` and exposes ATR tools
to MCP-compatible clients.

---

## ATREngine class — core contract

```typescript
class ATREngine {
  /**
   * Construct an engine with optional config. If neither rulesDir nor
   * rules is provided, loadRules() will search for a bundled rules
   * directory (./rules / ../rules / node_modules/agent-threat-rules/rules).
   */
  constructor(config?: ATREngineConfig);

  /**
   * Load rules from configured directory and/or pre-loaded array.
   * Returns the number of rules loaded after profile resolution.
   *
   * Contract:
   * - Pre-compiles regex patterns at load time for hot-path latency
   * - Filters by severity / maturity per config (when supported)
   * - Skips rules whose RE2 grammar check fails (NOT loaded; logged)
   * - Throws on schema validation failure
   */
  async loadRules(): Promise<number>;

  /**
   * Evaluate a single AgentEvent against all loaded rules.
   * Returns matching ATRMatch results in rule-loaded order.
   *
   * Contract:
   * - Pre-check: Tier 0 invariants (hard boundaries, returns deny match)
   * - Tier 1: blacklist lookup (known-bad skill IDs)
   * - Tier 2: pattern matching (regex / behavioral conditions)
   * - Layer 2.5: optional embedding similarity (if module configured)
   * - Layer 3: optional semantic LLM-as-judge (if module configured)
   * - MUST emit matches in rule-loaded order
   * - MUST NOT mutate input AgentEvent
   * - MUST honor SKILL_CONTEXT_DENYLIST when event.scanContext === 'skill'
   * - MUST update session tracker if configured
   * - MUST POST to reporter if configured (fire-and-forget for performance)
   * - Synchronous (returns ATRMatch[], not Promise) for hot-path use
   */
  evaluate(event: AgentEvent): ATRMatch[];

  /**
   * Return all loaded rules (read-only).
   * Used by CLI / coverage analysis / external tooling.
   */
  getRules(): readonly ATRRule[];
}
```

---

## ATREngineConfig type — contract

```typescript
interface ATREngineConfig {
  /** Directory containing ATR rule YAML files */
  rulesDir?: string;

  /** Pre-loaded rules (for testing or embedding) */
  rules?: ATRRule[];

  /** Optional session tracker for behavioral detection across events */
  sessionTracker?: SessionTracker;

  /** Optional Tier 0: Invariant enforcement (hard boundaries, pre-check) */
  invariantChecker?: InvariantChecker;

  /** Optional Tier 1: Skill blacklist provider (known-bad lookup) */
  blacklistProvider?: BlacklistProvider;

  /** Optional Layer 2: Skill behavioral fingerprinting (no LLM required) */
  fingerprintStore?: SkillFingerprintStore;

  /** Optional Tier 2.5: Embedding similarity module (requires @xenova/transformers) */
  embeddingModule?: EmbeddingModule;

  /** Optional Layer 3: Semantic LLM-as-judge analysis (requires API key) */
  semanticModule?: SemanticLayerConfig;

  /** Optional: detection reporter for feeding results to ATR Threat Cloud */
  reporter?: ATRReporter;
}
```

---

## AgentEvent input type — contract

(Defined in `../../src/types.ts`)

```typescript
interface AgentEvent {
  /** Event type — drives which rule conditions apply */
  type: AgentEventType;
  /** RFC 3339 timestamp; engine fills if undefined */
  timestamp?: string;
  /** Raw input/output text */
  content?: string;
  /** Named fields per rule schema (tool_input, tool_output, etc.) */
  fields?: Record<string, string>;
  /** Arbitrary metadata */
  metadata?: Record<string, unknown>;
  /** Session correlation ID */
  sessionId?: string;
  /** When 'skill', engages SKILL.md scanning semantics */
  scanContext?: 'skill' | 'runtime' | 'agent_message' | string;
}

type AgentEventType =
  | 'llm_input'
  | 'llm_output'
  | 'tool_call'
  | 'tool_result'
  | 'mcp_exchange'
  | 'skill_load'
  | 'memory_write'
  | 'memory_read'
  | string; // forward-compat
```

---

## ATRMatch output type — contract

(Defined in `../../src/types.ts`)

```typescript
interface ATRMatch {
  ruleId: string;                    // e.g., "ATR-2026-00440"
  title: string;
  severity: ATRSeverity;             // critical | high | medium | low | informational
  category: string;
  subcategory?: string;
  confidence: number;                // 0.0 to 1.0
  matchedField: string;
  matchedValue: string;              // redacted unless config disables
  matchedPatterns: string[];
  ruleVersion?: number;
  ruleStatus?: 'active' | 'deprecated' | 'draft' | 'preview';
  responseAction?: string[];
  evidence?: {
    contentHash?: string;
    timestamp?: string;
  };
  // Future: when atr-event-v1.0.md ratifies, an `asATREvent()`
  // method will project ATRMatch into the spec event format.
}
```

---

## Invariants (parallel to Python + Go)

Conformant TS engine MUST guarantee:

1. **Determinism.** Same `(rules, event)` → same `ATRMatch[]`. No
   `Math.random()`, no `Date.now()`-keyed maps, no implementation-
   defined ordering.

2. **Order preservation.** Matches emit in rule-loaded order. Rules
   loaded later in the corpus emit later matches.

3. **Memory bound.** Single `evaluate()` call should not allocate
   more than 10MB heap for typical inputs (10KB content).

4. **Latency bound.** Single `evaluate()` call should complete within
   100ms p99 for inputs ≤10KB on 2024-era hardware.

5. **No mutation.** Engine MUST NOT mutate input AgentEvent or input
   rules between evaluate() calls.

6. **Redaction default-on.** Output `matchedValue` MUST be redacted
   via `redactMatchedValue()` unless explicitly disabled.

7. **Signature stability.** When TC reporter is signing, canonical
   JSON form (per `spec/conformance/SIGNING.md` § canonical form) is
   signed. Two engines with the same signing key produce identical
   signatures for identical events.

### TS-specific additional invariants

8. **Synchronous hot path.** `evaluate()` MUST return synchronously.
   Async work (TC POST, semantic LLM call) is fire-and-forget or
   queued, NOT awaited inline. Latency bound #4 depends on this.

9. **No process.exit.** Engine MUST NOT call `process.exit()` for any
   reason, including unrecoverable error. Throw or return error
   instead.

10. **No global state.** Engine instance state is fully encapsulated
    in the `ATREngine` instance. No singletons, no module-level mutable
    state, no globalThis pollution. Two `ATREngine` instances in the
    same process must not interfere.

11. **ESM-only.** Package is published ESM only (no CommonJS dual
    package). This is a deliberate architectural choice; CJS-needing
    consumers should use dynamic `import()`.

12. **Node 20+ required.** Uses `import.meta.dirname`, native
    `node:test`, native `fetch`, `structuredClone`. Older Node versions
    are not supported.

13. **ReDoS hazard documented per-rule.** v3.1.1 deferred rules
    (METR misalignment, SpAIware memory-poisoning) are not loaded by
    default; loading them requires explicit opt-in to acknowledge the
    catastrophic-backtracking risk. See `engines/typescript/README.md`
    § ReDoS posture.

---

## CLI

```
npx agent-threat-rules <command> [options]

Commands:
  evaluate <event.json>              Evaluate a single event
  scan-skill <skill.md>              Scan a SKILL.md file
  scan-mcp <mcp-config.json>         Scan an MCP server configuration
  benchmark [--corpus pint|skill]    Run benchmark corpus
  coverage [--profile <name>]        Generate coverage report
  convert --to <sigma|splunk|...>    Convert rules to SIEM format
  mcp-server                         Run as MCP server (stdio transport)
  version                            Show version info
```

---

## Hook handler (Claude Code integration)

```typescript
import { HookHandlerConfig } from 'agent-threat-rules';

// Used by .claude/hooks/* shell wrappers to integrate ATR scanning
// into Claude Code's user-prompt-submit / tool-use-pre / tool-use-post
// lifecycle.
```

Hook handler is engine-adjacent, not part of the core conformance surface.

---

## Reporter (Threat Cloud feed)

```typescript
import { createTCReporter, ATRReporter } from 'agent-threat-rules';

const reporter = createTCReporter({
  endpoint: 'https://tc.example.com/atr/v1/events',
  apiKey: process.env.ATR_TC_API_KEY,
  // Anonymisation: content hash only, never raw content
});

const engine = new ATREngine({ rules, reporter });
```

The reporter receives `ATRDetectionReport` (content-hashed, never raw
content). This anonymisation is structural — `redactMatchedValue()`
runs before the reporter sees the match.

---

## Configuration via environment variables

CLI tooling supports the standard ATR environment variables:

| Env var | Type | Default |
|---|---|---|
| `ATR_RULES_DIR` | string | (bundled) |
| `ATR_PROFILE_PATH` | string | (none, use full corpus) |
| `ATR_MIN_SEVERITY` | string | `informational` |
| `ATR_MIN_MATURITY` | string | `draft` |
| `ATR_FORENSIC_MODE` | bool | `false` |
| `ATR_TC_ENDPOINT` | string | (none, no TC reporting) |
| `ATR_TC_API_KEY` | string | (none) |
| `ATR_LOG_LEVEL` | string | `info` |
| `ATR_SEMANTIC_API_KEY` | string | (none, Layer 3 disabled) |
| `ATR_SEMANTIC_MODEL` | string | `claude-haiku-4.5` |

---

## Testing policy

- Every public function: ≥1 smoke test in `../../tests/`
- Every spec section in this contract: a unit test verifying compliance
- Benchmark corpora (PINT MCP + SKILL.md benchmark) are the
  precision/recall gates
- `npm test` MUST pass before any release
- `npm run lint` (ESLint + TypeScript strict mode) MUST pass

---

## References

- `engines/python/INTERFACE-CONTRACT.md` — Python sibling (parallel shape)
- `engines/go/INTERFACE-CONTRACT.md` — Go sibling (parallel shape)
- `../../src/engine.ts` — actual ATREngine impl
- `../../src/types.ts` — type definitions
- `../../src/index.ts` — public package exports
- `../../package.json` — npm metadata + scripts
- `spec/atr-schema.yaml` — rule format this engine consumes (current)
- `spec/atr-event-v1.0.md` — proposed event format (engine output will
  adapt to this on AEP-002 ratification)
