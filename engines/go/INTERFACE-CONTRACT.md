# ATR Go Reference Implementation — Interface Contract

**Status:** Normative for `atr-go` module. Any production-grade re-implementation MUST satisfy this interface to claim ATR conformance.

**License:** MIT

---

## Package surface (public)

```go
package atr

// Engine is the main ATR evaluation engine.
type Engine struct { /* opaque */ }

// NewEngine constructs an engine from explicit inputs.
func NewEngine(rules []Rule, profile *Profile, correlations []CorrelationRule, cfg *Config) (*Engine, error)

// NewEngineFromCorpus loads rules from a corpus directory.
func NewEngineFromCorpus(corpusPath string, cfg *Config) (*Engine, error)

// Evaluate runs the engine against a single AgentEvent and returns matching events.
// Contract: see § Invariants below.
func (e *Engine) Evaluate(ctx context.Context, event AgentEvent) ([]Event, error)

// ScanSkill scans a SKILL.md content string in skill context.
func (e *Engine) ScanSkill(ctx context.Context, content string) ([]Event, error)

// RunConformance runs the published conformance corpus and returns a structured result.
func (e *Engine) RunConformance(ctx context.Context, corpusPath string, level ConformanceLevel) (*ConformanceResult, error)

// EngineID returns the engine identifier in form <vendor>/<product>/<version>.
func (e *Engine) EngineID() string

// SpecVersion returns the ATR spec version this engine targets.
func (e *Engine) SpecVersion() string

// LoadedRuleCount returns the count of rules loaded after profile resolution.
func (e *Engine) LoadedRuleCount() int

// DetectLanguage runs the spec language-detection algorithm.
func DetectLanguage(text string) string

// Public type definitions follow.

type AgentEvent struct {
    Type         string            `json:"type"`
    Timestamp    string            `json:"timestamp,omitempty"`
    Content      string            `json:"content,omitempty"`
    Fields       map[string]string `json:"fields,omitempty"`
    Metadata     map[string]any    `json:"metadata,omitempty"`
    SessionID    string            `json:"sessionId,omitempty"`
    ScanContext  string            `json:"scanContext,omitempty"`
}

// Event is the output ATR event. Field names match
// spec/atr-event-v1.0.md when serialised to JSON via the custom
// MarshalJSON; in-Go they use idiomatic Go casing.
type Event struct {
    Timestamp                string             `json:"@timestamp"`
    EventID                  string             `json:"atr.event_id"`
    SpecVersion              string             `json:"atr.spec_version"`
    EngineID                 string             `json:"atr.engine_id"`
    RuleID                   string             `json:"atr.rule_id"`
    RuleVersion              int                `json:"atr.rule_version"`
    RuleStatus               string             `json:"atr.rule_status"`
    RuleMaturity             string             `json:"atr.rule_maturity,omitempty"`
    RuleReviewStatus         string             `json:"atr.rule_review_status,omitempty"`
    Severity                 string             `json:"atr.severity"`
    Category                 string             `json:"atr.category"`
    Subcategory              string             `json:"atr.subcategory,omitempty"`
    Confidence               float64            `json:"atr.confidence"`
    MatchedField             string             `json:"atr.matched_field"`
    MatchedValueRedacted     string             `json:"atr.matched_value_redacted"`
    ResponseAction           []string           `json:"atr.response_action"`
    ResponseTaken            []string           `json:"atr.response_taken"`
    ResponseThresholdMet     bool               `json:"atr.response_threshold_met"`
    AgentID                  string             `json:"agent.id"`
    AgentPlatform            string             `json:"agent.platform"`
    AgentPlatformVersion     string             `json:"agent.platform_version,omitempty"`
    AgentDelegationChain     []DelegationLink   `json:"agent.delegation_chain,omitempty"`
    AgentIdentityAssertion   string             `json:"agent.identity_assertion,omitempty"`
    SessionID                string             `json:"session.id"`
    ServiceName              string             `json:"service.name"`
    ServiceVersion           string             `json:"service.version,omitempty"`
    ToolName                 string             `json:"tool.name,omitempty"`
    ToolArgs                 map[string]any     `json:"tool.args,omitempty"`
    ToolPrivilegeClass       string             `json:"tool.privilege_class,omitempty"`
    ToolTargetJurisdiction   string             `json:"tool.target_jurisdiction,omitempty"`
    MemoryStoreID            string             `json:"memory.store_id,omitempty"`
    MemoryWriteKey           string             `json:"memory.write_key,omitempty"`
    MemoryPersistenceScope   string             `json:"memory.persistence_scope,omitempty"`
    EvidenceObservationID    string             `json:"evidence.observation_id,omitempty"`
    EvidenceSignature        string             `json:"evidence.signature,omitempty"`
    EvidenceSignatureKeyID   string             `json:"evidence.signature_key_id,omitempty"`
    EvidenceUpstreamChain    []string           `json:"evidence.upstream_chain,omitempty"`
    SovereignAttestation     *SovereignSig      `json:"atr.sovereign_attestation,omitempty"`
}

type DelegationLink struct {
    AgentID         string `json:"agent_id"`
    CapabilityGrant string `json:"capability_grant"`
    GrantedBy       string `json:"granted_by"`
}

type SovereignSig struct {
    Signer    string   `json:"signer"`
    Signature string   `json:"signature"`
    CAChain   []string `json:"ca_chain"`
}

type Config struct {
    ForensicMode    bool
    SigningKey      []byte // ed25519 private key (32 bytes seed)
    SigningKeyID    string
    MinSeverity     string
    MinMaturity     string
    ConformanceMode bool
}

type ConformanceLevel string

const (
    LevelL1Baseline    ConformanceLevel = "L1-baseline"
    LevelL2Profile     ConformanceLevel = "L2-profile"
    LevelL3Correlation ConformanceLevel = "L3-correlation"
)

type ConformanceResult struct {
    SchemaVersion string          `json:"schema_version"`
    CorpusVersion string          `json:"corpus_version"`
    SpecVersion   string          `json:"spec_version"`
    Level         ConformanceLevel `json:"level"`
    EngineID      string          `json:"engine_id"`
    RunTimestamp  string          `json:"engine_run_timestamp"`
    Fixtures      []FixtureResult `json:"fixtures"`
    Summary       *Summary        `json:"summary"`
}

type FixtureResult struct {
    FixtureID     string   `json:"fixture_id"`
    FixturePath   string   `json:"fixture_path"`
    ExpectedRules []string `json:"expected_rules"`
    RulesFired    []string `json:"engine_observed"`
    Pass          bool     `json:"pass"`
    MissReason    string   `json:"miss_reason,omitempty"`
}

type Summary struct {
    TotalFixtures              int     `json:"total_fixtures"`
    Passed                     int     `json:"passed"`
    Failed                     int     `json:"failed"`
    Precision                  float64 `json:"precision"`
    Recall                     float64 `json:"recall"`
    LanguageDetectionAccuracy  float64 `json:"language_detection_accuracy"`
    ConformanceClaim           string  `json:"conformance_claim"` // pass | fail | partial
}
```

---

## Invariants (same as Python impl per `engines/python/INTERFACE-CONTRACT.md`)

1. **Determinism.** Same `(rules, event)` → same `[]Event`.
2. **Order preservation.** Events emit in rule-loaded order.
3. **Memory bound.** ≤10MB heap per Evaluate() call.
4. **Latency bound.** ≤100ms p99 for inputs ≤10KB on 2024-era hardware.
5. **No mutation.** Input AgentEvent and Rule structs not mutated.
6. **Redaction default-on.** Unless `Config.ForensicMode=true`.
7. **Signature stability.** Same key + same canonical event → identical signature.

### Go-specific additional invariants

8. **Context cancellation.** `Evaluate(ctx, ...)` MUST honor `ctx.Done()` and return promptly with `ctx.Err()`. Long-running rule evaluation that ignores cancellation is a contract violation.

9. **Goroutine bound.** Engine MAY use goroutines internally for parallel rule evaluation. MUST NOT leak goroutines after Evaluate() returns.

10. **RE2 grammar enforcement.** Engine MUST use Go's `regexp/syntax` (RE2-backed). Rules that fail RE2 grammar checking are skipped at load time with logged warnings, NOT loaded into the rule set. This is a structural defense against Attacker class 4 (ReDoS) per `governance/STANDARD-THREAT-MODEL.md`.

11. **Strict JSON marshaling.** `Event.MarshalJSON()` MUST produce output that validates against `spec/schema/event.schema.json`. Failure is a programming error (panic-worthy in test, log-and-skip in production).

---

## Configuration via environment variables

CLI tooling SHOULD support the standard ATR environment variables:

| Env var | Type | Default |
|---|---|---|
| `ATR_CORPUS_PATH` | string | (required) |
| `ATR_PROFILE_PATH` | string | (none, use full corpus) |
| `ATR_MIN_SEVERITY` | string | `informational` |
| `ATR_MIN_MATURITY` | string | `draft` |
| `ATR_FORENSIC_MODE` | bool | `false` |
| `ATR_CONFORMANCE_MODE` | bool | `false` |
| `ATR_SIGNING_KEY_PATH` | string | (none, no signing) |
| `ATR_SIGNING_KEY_ID` | string | (none) |
| `ATR_LOG_LEVEL` | string | `info` |

---

## CLI command

```
atr-go <command> [options]

Commands:
  evaluate <event.json>              Evaluate a single event
  scan-skill <skill.md>              Scan a SKILL.md
  conformance --level <L1|L2|L3>     Run conformance corpus
  version                            Show version info
```

---

## Testing policy

Same as Python: every public function ≥1 smoke test; every spec section a unit test; conformance test is the integration gate.

Go-specific: `go test -race ./...` MUST pass (data-race detector clean).

---

## References

Same as Python `INTERFACE-CONTRACT.md`. See `engines/python/INTERFACE-CONTRACT.md` for the cross-language consistency principles.
