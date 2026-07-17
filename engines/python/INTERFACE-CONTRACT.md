# ATR Python Reference Implementation — Interface Contract

**Status:** Normative for `atr-python` package. Any production-grade
re-implementation must satisfy the same interface to claim ATR
conformance.

**License:** MIT

---

## Module API surface (public)

```python
# atr_engine/__init__.py

from atr_engine.engine import ATREngine
from atr_engine.event import AgentEvent, ATREvent
from atr_engine.rule import Rule, RuleStatus, RuleMaturity, RuleSeverity
from atr_engine.profile import Profile
from atr_engine.correlation import CorrelationRule
from atr_engine.language_detect import detect_language

__all__ = [
    "ATREngine",
    "AgentEvent",
    "ATREvent",
    "Rule",
    "RuleStatus",
    "RuleMaturity",
    "RuleSeverity",
    "Profile",
    "CorrelationRule",
    "detect_language",
]

__version__ = "0.0.1"      # Pre-release; reaches 1.0 on first L1 conformance pass
__spec_version__ = "1.0"   # ATR spec version this engine targets
__engine_id__ = "atr/python-reference/0.0.1"
```

---

## ATREngine class — core contract

```python
class ATREngine:
    def __init__(
        self,
        rules: list[Rule],
        profile: Profile | None = None,
        correlation_rules: list[CorrelationRule] | None = None,
        config: EngineConfig | None = None,
    ) -> None:
        """
        Initialize an ATR engine with a rule set, optional profile, and
        optional correlation rules.

        Args:
            rules: List of Rule objects loaded from YAML files. Engine
              MUST pre-compile detection conditions at construction time
              for hot-path latency.
            profile: Optional profile that filters / scopes the rule set.
              When None, all rules apply.
            correlation_rules: Optional list of CorrelationRule objects
              for L3 correlation conformance.
            config: Optional configuration (severity thresholds, redaction
              mode, conformance-mode flag).
        """

    @classmethod
    def from_corpus(
        cls,
        corpus_path: str | Path,
        profile_path: str | Path | None = None,
        config: EngineConfig | None = None,
    ) -> "ATREngine":
        """
        Convenience constructor: load all rules from a corpus directory
        (e.g., agent-threat-rules/rules/) plus optionally a profile.
        """

    def evaluate(self, event: AgentEvent) -> list[ATREvent]:
        """
        Evaluate a single AgentEvent against all loaded rules. Returns a
        list of ATREvent objects, one per rule that fired.

        Contract:
        - O(rules_loaded) per call. <100ms p99 for typical events.
        - MUST emit events in the order rules were loaded.
        - MUST set @timestamp = now (UTC, RFC 3339).
        - MUST emit redacted matched_value unless config.forensic_mode.
        - MUST sign events when config.signing_key is provided.
        - MUST update correlation state for any correlation rule that
          references the matched atomic rule.
        - MUST NOT mutate the input AgentEvent.
        """

    def scan_skill(self, content: str) -> list[ATREvent]:
        """
        Scan a SKILL.md content as a skill artifact. Sets scanContext='skill'
        per existing ATR engine semantics.

        Contract:
        - Decodes base64 blocks per existing engine behaviour.
        - All rules fire regardless of agent_source.type when
          scanContext='skill', per skill-context bypass.
        - Returns events with matched_field='skill_content'.
        """

    def run_conformance(
        self,
        corpus_path: str | Path,
        level: str = "L1-baseline",
    ) -> ConformanceResult:
        """
        Run the published conformance corpus against this engine and
        return a structured ConformanceResult conforming to
        spec/conformance/expected-results.schema.json.

        Contract:
        - MUST verify the signature on the corpus's expected-results.json
          before running. SignatureFailure aborts with no result.
        - MUST report per-fixture pass/fail.
        - MUST report overall precision, recall, language-detection
          accuracy.
        - MUST set conformance_claim ∈ {pass, fail, partial} per the
          thresholds in spec/conformance/<level>/manifest.json.
        """

    @property
    def engine_id(self) -> str:
        """Return engine_id in form <vendor>/<product>/<version>."""

    @property
    def spec_version(self) -> str:
        """Return ATR spec version this engine targets."""

    @property
    def loaded_rule_count(self) -> int:
        """Return count of rules loaded (post-profile-resolution)."""
```

---

## AgentEvent input type — contract

```python
@dataclass
class AgentEvent:
    type: str                              # e.g., "mcp_exchange", "llm_input", "llm_output", "tool_call"
    timestamp: str | None = None           # RFC 3339; engine fills if None
    content: str | None = None             # raw input text
    fields: dict[str, str] | None = None   # named fields per spec/atr-schema.yaml § Rules
    metadata: dict[str, Any] | None = None # arbitrary metadata
    sessionId: str | None = None
    scanContext: str | None = None         # "skill" for SKILL.md scanning per scan_skill()
```

Engines MUST accept the above shape. Engines MAY accept additional
fields without breaking conformance (forward-compat).

---

## ATREvent output type — contract

```python
@dataclass(kw_only=True)
class ATREvent:
    # Required fields per spec/atr-event-v1.0.md § Required fields
    timestamp: str                         # @timestamp
    event_id: str                          # atr.event_id (UUID v7)
    spec_version: str                      # atr.spec_version
    engine_id: str                         # atr.engine_id
    rule_id: str                           # atr.rule_id
    rule_version: int                      # atr.rule_version
    rule_status: str                       # atr.rule_status
    severity: str                          # atr.severity
    category: str                          # atr.category
    confidence: float                      # atr.confidence
    matched_field: str                     # atr.matched_field
    matched_value_redacted: str            # atr.matched_value_redacted
    response_action: list[str]             # atr.response_action
    response_taken: list[str]              # atr.response_taken
    response_threshold_met: bool           # atr.response_threshold_met
    agent_id: str                          # agent.id
    agent_platform: str                    # agent.platform
    session_id: str                        # session.id
    service_name: str                      # service.name

    # Optional fields per spec/atr-event-v1.0.md § Optional fields
    subcategory: str | None = None
    rule_maturity: str | None = None
    rule_review_status: str | None = None
    agent_platform_version: str | None = None
    service_version: str | None = None
    tool_name: str | None = None
    tool_args: dict | None = None
    tool_privilege_class: str | None = None
    tool_target_jurisdiction: str | None = None
    memory_store_id: str | None = None
    memory_write_key: str | None = None
    memory_persistence_scope: str | None = None
    evidence_observation_id: str | None = None
    evidence_signature: str | None = None
    evidence_signature_key_id: str | None = None
    evidence_upstream_chain: list[str] | None = None
    sovereign_attestation: dict | None = None

    def to_dict(self) -> dict:
        """
        Serialise to dict with field names in spec form
        (e.g., 'atr.rule_id' not 'rule_id'). MUST match
        spec/schema/event.schema.json.
        """
```

Field name mapping (Python attribute → spec field):
- `event.rule_id` → `"atr.rule_id"` in JSON
- `event.agent_id` → `"agent.id"` in JSON
- `event.service_name` → `"service.name"` in JSON
- ... (dots in JSON keys converted to underscores in Python; reverse on serialise)

---

## Invariants

Conformant engine MUST guarantee:

1. **Determinism.** Given the same `(rules, AgentEvent)` input, calling `evaluate()` twice MUST produce the same list of ATREvents (modulo timestamps and event_ids). No randomness, no implementation-defined ordering.

2. **Order preservation.** Events MUST emit in rule-loaded order. Rules loaded later in the corpus emit later events.

3. **Memory bound.** Single `evaluate()` call MUST NOT allocate more than 10MB heap. Engines MAY enforce smaller bounds.

4. **Latency bound.** Single `evaluate()` call MUST complete within 100ms p99 for inputs ≤10KB on a 2024-era laptop. Larger inputs scale linearly.

5. **No mutation.** Engine MUST NOT mutate input AgentEvent or input rules between evaluate() calls.

6. **Redaction default-on.** Output `matched_value_redacted` MUST be redacted unless `config.forensic_mode=True` is explicitly set per deployment.

7. **Signature stability.** When signing is enabled, the canonical JSON form (per `spec/conformance/SIGNING.md` § canonical form) is signed. Two engines configured with the same signing key produce identical signatures for identical events.

---

## Configuration

```python
@dataclass
class EngineConfig:
    forensic_mode: bool = False           # default: redact matched values
    signing_key: bytes | None = None      # ed25519 private key for evidence.signature
    signing_key_id: str | None = None     # evidence.signature_key_id
    min_severity: str = "informational"   # filter rules by severity at load time
    min_maturity: str = "draft"           # filter rules by maturity at load time
    conformance_mode: bool = False        # if True, disable redaction + enable strict spec validation
```

`conformance_mode=True` is required when running the conformance corpus
(it disables redaction so output matches the reference exactly).

---

## Conformance entry point

```python
def main():
    """CLI entry point: `atr-python conformance --level L1-baseline`."""
    ...
```

When invoked from CLI, runs the conformance corpus and prints results.
Suitable for CI integration.

---

## Test policy

- Every public method MUST have ≥1 smoke test in `tests/`.
- Every spec section referenced in this interface contract MUST have
  a unit test verifying compliance.
- Conformance test (against `spec/conformance/`) is the integration
  test; it gates the next release.

---

## References

- `spec/README.md` — spec index
- `spec/atr-schema.yaml` — rule format
- `spec/atr-event-v1.0.md` — event format
- `spec/atr-language-detection-v1.0.md` — language algorithm
- `spec/atr-profile-v1.0.md` — profile format
- `spec/atr-correlation-v1.0.md` — correlation format
- `spec/conformance/expected-results.schema.json` — conformance report
- `engines/typescript/src/engine.ts` (when restructure complete) — reference implementation that this contract was abstracted from
