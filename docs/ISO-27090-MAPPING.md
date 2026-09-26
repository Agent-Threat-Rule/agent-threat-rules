# ATR → ISO/IEC 27090 Mapping

Version: 0.1.0 (INTERNAL DRAFT — not published)
Status: Draft alignment mapping against ISO/IEC FDIS 27090 (FDIS ballot closes 2026-08-18)
Date: 2026-08-11
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Mapped corpus: Agent Threat Rules v3.5.11 — 783 rule files on `main`, of which 776 are
  effective and 7 are inert (counts read from disk on 2026-08-11; `git ls-tree` by
  category reconciles to 783, see §5.2)
Reference framework:
  - ISO/IEC FDIS 27090, "Cybersecurity — Artificial intelligence — Guidance for
    addressing security threats to artificial intelligence systems"
    (FDIS stage since 2026-02; ballot 2026-06-23 → 2026-08-18; publication expected H2 2026)

---

## 1. Purpose and limits

This document maps the Agent Threat Rules (ATR) detection corpus onto the threat
classes that ISO/IEC 27090 addresses, so that an organisation reading 27090 can see
which of its threats have an executable, machine-readable detection layer available
today and — more importantly — which do not.

**Three limits, stated up front.**

**1. The FDIS text is paywalled and has not been read.** This mapping is built from
ISO's public abstract and the scope descriptions published by national standards
bodies and the AI Standards Hub. It therefore maps to 27090's *threat classes*, not
to its clause numbering. No clause identifier (`x.y.z`) appears anywhere in this
document, because asserting one without reading the text would be fabrication. Once
the published standard is available, §4 should be re-cut against real clauses.

**2. This is an alignment mapping, not an endorsement.** ISO, IEC, and JTC 1/SC 27
have not adopted, reviewed, endorsed, or certified ATR. No participation or
submission channel is asserted. ATR is not a conformity-assessment instrument.

**3. ISO/IEC 27090 is informative guidance, not a requirements standard.** It
contains no "shall" requirements, no certification scheme, and — unlike ISO/IEC
42001 — nothing to be certified against. It also generates no presumption of
conformity with the EU AI Act or the Cyber Resilience Act. Nothing in this document
should be read as a compliance claim on anyone's behalf.

Every rule cited below was read from its YAML on disk at the commit this document
was written against. Rule IDs are public and permanent.

## 2. Where ATR sits relative to 27090

ISO/IEC 27090 describes threats to AI systems and the controls that address them, at
the level of guidance. ATR is a runtime detection-rule corpus: it produces evidence
that a described threat is being attempted against a live system, keyed to a stable
`ATR-YYYY-NNNNN` identifier.

The relationship is therefore **guidance → runtime evidence**, and it is one-way.
27090 tells an organisation what to worry about; ATR can tell it when one of those
things is happening, for the subset of threats that manifest as observable events in
an agent's input, tool-call, or MCP-exchange stream. Threats that manifest only as
statistical properties of a model, or only over long time horizons, are outside what
a per-event rule engine can see. Those are named honestly in §4.

## 3. The lane caveat — read this before using any coverage number below

ATR ships two lanes. The **hunt lane** (the default) loads the full ruleset. The
**enforce lane** loads only rules at `maturity: stable` (`engine.ts` gates on
`rule.maturity` via `laneAllows`), of which there are currently **106 out of 776
effective**. Maturity across the corpus breaks down as 600 `test`, 106 `stable`,
63 `experimental`, 14 `draft`.

Of the twelve rules cited in §4, exactly **two** — `ATR-2026-00080` and
`ATR-2026-00517` — are `maturity: stable`. Every other rule cited here is `test` or
`experimental`.

**Consequence: an enforce-lane deployment of ATR covers almost none of what this
document maps.** The coverage described in §4 is hunt-lane coverage. Any reader
planning to enforce rather than hunt should treat §4 as a roadmap, not an inventory.

## 4. Threat-class mapping

### 4.1 Prompt injection — strongest coverage

`prompt-injection` is ATR's largest category at **248 rule files**, roughly a third
of the corpus.

| Rule | Title | Maturity |
|---|---|---|
| `ATR-2026-00001` | Direct Prompt Injection via User Input | test |
| `ATR-2026-00002` | Indirect Prompt Injection via External Content | test |
| `ATR-2026-00004` | System Prompt Override Attempt | test |

Caveat carried over from ATR's own benchmark disclosures: on the self-built
850-sample PINT-*format* corpus, a single rule (`ATR-2026-00001`) accounts for the
large majority of detections. Breadth of the category should not be read as breadth
of independently-validated detection.

### 4.2 Evasion — covered, with the same caveat

| Rule | Title | Maturity |
|---|---|---|
| `ATR-2026-00003` | Jailbreak Attempt Detection | test |
| `ATR-2026-00080` | Encoding-Based Prompt Injection Evasion | **stable** |

`ATR-2026-00080` is one of only two stable rules in this whole mapping, and is
therefore one of the few items here that survives into an enforce-lane deployment.

ATR documents 64 known evasion techniques it does not catch. Evasion is an
adversarial moving target; this row should be read as "has coverage", never as
"solved".

### 4.3 Model extraction / model theft — partial, and better than expected

| Rule | Title | Maturity |
|---|---|---|
| `ATR-2026-00517` | Model Extraction / Distillation Attack via Systematic API Probing | **stable** |
| `ATR-2026-00072` | Model Behavior Extraction | test |
| `ATR-2026-00502` | Training Data Extraction via Divergent Repetition Attack | test |

This is the one class where ATR's behavioural angle lines up well with 27090's
framing: extraction through *legitimate* querying is exactly what `ATR-2026-00517`
targets, and it is stable.

### 4.4 Data poisoning — thin

The `data-poisoning` category holds **9 rule files** — the second-smallest category
in the corpus.

| Rule | Title | Maturity |
|---|---|---|
| `ATR-2026-00070` | Data Poisoning via RAG and Knowledge Base Contamination | test |
| `ATR-2026-01774` | RAG & Memory Poisoning — Embedded Directives, Trigger Tokens, False Authority & Coercion (Semantic) | experimental |
| `ATR-2026-02408` | Dataset / Model Loader Remote-Code Execution via Poisoned Dataset Artifact | test |
| `ATR-2026-00073` | Malicious Fine-tuning Data | test |

Note what these actually detect: **poisoning delivered through a runtime channel**
(RAG retrieval, agent memory, a loaded artifact). Training-time poisoning of a
corpus that ATR never observes is not detectable by a runtime rule engine, and this
mapping does not claim otherwise. Nine rules against one of 27090's five headline
threats is a real gap, not a rounding error.

### 4.5 Membership inference — **no coverage**

A case-insensitive search for "membership inference" across all 783 rule files on
`main` returns **zero matches**. ATR has no rule addressing this threat class.

This is stated plainly rather than softened into "low coverage" because the honest
answer is none. Membership inference is a statistical attack inferred from
distributions of model responses over many queries; a per-event pattern engine is
the wrong instrument for it, and no amount of rule-writing in the current
architecture would fix that. An organisation relying on 27090's membership-inference
guidance needs a different control, and ATR should not be presented as one.

### 4.6 Summary

| ISO/IEC 27090 threat class | ATR hunt-lane coverage | Enforce-lane | Honest verdict |
|---|---|---|---|
| Prompt injection | 248 rule files | 0 of 3 cited stable | Strongest, concentration caveat applies |
| Evasion | multiple families | 1 of 2 cited stable | Real coverage, permanently incomplete |
| Model extraction | 3 cited rules | 1 of 3 cited stable | Partial, best structural fit |
| Data poisoning | 9 rule files | 0 of 4 cited stable | Thin; runtime-channel only |
| Membership inference | **none** | none | **Not covered. Different instrument required.** |

Three of five classes have meaningful hunt-lane coverage. One is thin. One is absent.

## 5. Reconciliation notes

### 5.1 Numbers deliberately not cited here

The following ATR figures are currently flagged as not-for-external-use by
`benchmark-reconcile --outward` and are therefore absent from this document: the
benign-gate false-positive rates (the sample count was mislabelled and the corpus has
since changed; both lanes await re-measurement), and the wild-scan totals. No
substitute figures have been invented in their place.

The PINT-format corpus is referenced in §4.1 only as a caveat, and is explicitly
described as self-built. It is **not** a run of Lakera's official PINT benchmark,
whose corpus is private.

### 5.2 A defect found while writing this document

`data/stats.json` on `main` reports correct values for `total` (783), `effective`
(776), and `inert` (7), but its `byCategory` block sums to **675** and understates
every one of the ten categories. Counting rule files directly with `git ls-tree`
reconciles to 783.

Per-category figures in this document were taken from the file count, not from
`byCategory`. **Anyone citing per-category rule counts from `data/stats.json` today
is citing wrong numbers.** This should be fixed separately from this document.

A second, larger defect sits next to it. The root `stats.json` reports
`ruleCount.stable: 59`, and that field is consumed downstream as "the size of the
enforce lane". It is not. Its own inline comment says it is counted from the
`status:` field, whereas `engine.ts` gates the enforce lane on `maturity:`. Counted
correctly, the enforce lane holds **106** rules, not 59 — the two fields are
independent and disagree by 47 rules. `maturity: stable` and `status: stable`
intersect on only 34 rules.

Anything that reports enforce-lane capacity from `ruleCount.stable` is understating
it by roughly 44%. §3 of this document uses 106, derived by parsing `maturity` from
all 783 rule files.

### 5.3 Re-cut trigger

When ISO/IEC 27090 is published (expected H2 2026), §4 should be rebuilt against the
real clause structure and this file's status line updated. Until then, every
statement here is scoped to publicly documented threat classes.
