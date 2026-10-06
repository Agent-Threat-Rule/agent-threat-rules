# ATR — Agent Threat Rules: Design System

**Scope: this is the design system for the public website (agentthreatrule.org)
— visual language, colour, typography, layout, and the narrative copy for each
page section. It is not a software architecture document; for how the detection
engine and rule schema are built, see [`spec/atr-schema.yaml`](spec/atr-schema.yaml)
and the README.**

**Rule for every number on this page:** site statistics are pulled live from
`stats.ts` / [`data/stats.json`](data/stats.json) at build time. The figures
written into the copy examples below are illustrative placeholders showing
*shape and formatting only* — they are not a source of truth and must never be
hardcoded into the site. Rule counts move daily. Before any figure ships in
public copy, check it against `data/stats.json` and the README evaluation table.

## 1. VISUAL THEME & ATMOSPHERE

ATR's design philosophy centers on "cold authority." The site is a technical standard's public face, not a product marketing page, not a dashboard, not a docs site. It exists to make one statement: AI agents are under attack, and ATR is the detection standard the industry is converging on.

The emotional register is closer to a published research paper or an intelligence briefing that became interactive. Every element earns its place through information density, not decoration. The logo — a geometric "A" with horizontal speed lines evoking radar sweeps and scanning — sets the entire visual language: angular, precise, in motion.

**Core aesthetic principle:** "The data IS the design. If you need decoration, you don't have enough data."

**Key characteristics:**
- Light background (warm white) — open source means open, transparent, accessible. Dark themes signal "product" or "security dashboard." ATR is a standard, not a product.
- Full-viewport hero sections with the paradigm shift narrative as the centerpiece
- The logo's speed-line motif repeated subtly as a horizontal rule pattern throughout
- Monospace typography for all data — rule counts, precision scores, coverage ratios are design elements, not afterthoughts
- Zero gradients, zero glassmorphism, zero rounded cards. Angular geometry from the logo carried through every component.
- Photography replaced by data visualization and raw numbers — the "product shots" are coverage matrices, rule counts, and scan results
- Cinematic scroll rhythm (Tesla-style): one message per viewport, each scroll is a deliberate scene transition
- The narrative arc: "We used to protect people. Now we protect agents."

**Atmosphere:** A well-funded research lab's public briefing room. Precise, calm, authoritative. Not alarming, not flashy, not trying to sell you anything. The confidence of an organization that knows its data is good.

---

## 2. COLOR PALETTE & ROLES

### Primary Colors
- **Ink Black (#0B0B0F)**: Primary heading text, logo color, navigation labels. The exact black from the ATR logo — warm near-black with a barely perceptible blue undertone. Used for all authoritative text.
- **Paper White (#FAFAF8)**: Dominant background for all surfaces. Not pure white (#FFF) — a fraction warmer, like high-quality uncoated paper stock. Reduces eye strain, signals "document" not "screen."

### Accent
- **Signal Blue (#2563EB)**: The single chromatic accent. Used exclusively for: primary CTA buttons, interactive links, active states, and the "now" in the hero narrative. Not decorative — functional only. Chosen because blue signals "infrastructure" and "trust" without implying any specific vendor. This is Tailwind blue-600, universally readable.
- No secondary accent colors exist. ATR deliberately avoids color variety. One accent means every blue element is a call to action.

### Surface & Background
- **Paper White (#FAFAF8)**: Page background, all default surfaces
- **Ash (#F3F3F0)**: Alternate surface for section differentiation — barely perceptible shift from Paper White. Used on the numbers grid, standards row, and alternate sections.
- **Fog (#E8E8E5)**: Border color for cards, table rows, the horizontal speed-line motif. Visible but never dominant.

### Neutrals & Text
- **Ink Black (#0B0B0F)**: Headlines, navigation, hero statement — maximum authority
- **Graphite (#3B3B42)**: Body text, descriptions — readable without the weight of Ink Black
- **Stone (#6B6B76)**: Secondary text, labels, metadata — recedes but remains legible
- **Mist (#808089)**: Tertiary text, placeholders, disabled states (meets WCAG AA 4.5:1 on Paper White)
- **Fog (#E8E8E5)**: Borders, dividers, speed-line motif

### Semantic Colors
- **CRITICAL Red (#DC2626)**: CRITICAL severity badge only. Never decorative.
- **HIGH Orange (#EA580C)**: HIGH severity badge only.
- **MEDIUM Amber (#CA8A04)**: MEDIUM severity badge only.
- **LOW Blue (#2563EB)**: LOW severity uses accent blue (low severity = informational = interactive)
- **Coverage Green (#16A34A)**: "Shipped" labels, passing tests, full coverage indicators.

### Gradient System
No gradients. Period. Depth is achieved through whitespace, typography scale, and the horizontal speed-line motif. If the page looks flat, that's correct — standards documents don't need depth effects.

---

## 3. TYPOGRAPHY RULES

### Font Family
- **Display**: Inter Tight, -apple-system, sans-serif — used for hero statements and section headings. Tight proportions create density and authority at large sizes. Geometric feel matches the angular logo.
- **Body**: Inter, -apple-system, sans-serif — used for body text, descriptions, navigation. Optimized for readability at 16px.
- **Data**: JetBrains Mono, 'Courier New', monospace — used for ALL numbers, rule IDs, code, YAML, terminal output, stats. Data in monospace signals precision and technical credibility. This is ATR's most distinctive typographic choice: every number on the site is in JetBrains Mono.

### Typography Hierarchy Table

| Role | Font | Size | Weight | Line Height | Letter Spacing | Color | Notes |
|------|------|------|--------|-------------|----------------|-------|-------|
| Hero Statement | Inter Tight | clamp(36px, 6vw, 80px) | 900 | 1.05 | -3px | Ink Black / Stone | "Now we protect agents" in Ink Black, "We used to protect people" in Stone |
| Section Heading | Inter Tight | clamp(28px, 4vw, 48px) | 800 | 1.1 | -2px | Ink Black | One per viewport section |
| Section Label | JetBrains Mono | 12px | 500 | 1.0 | 3px | Stone | UPPERCASE, above section headings. "WHAT ATR DETECTS", "MERGED UPSTREAM" |
| Subheading | Inter Tight | 20px | 600 | 1.3 | -0.5px | Ink Black | Card titles, subsection headers |
| Body | Inter | 16px | 400 | 1.7 | 0 | Graphite | Paragraph text, descriptions |
| Body Small | Inter | 14px | 400 | 1.6 | 0 | Stone | Card descriptions, metadata |
| Data Large | JetBrains Mono | clamp(36px, 5vw, 64px) | 700 | 1.0 | -1px | Ink Black | Big stats: "100", "10/10", "<5ms" |
| Data Unit | JetBrains Mono | 0.4em of parent | 400 | 1.0 | 0 | Stone | Units after big stats: "rules", "%", "ms" |
| Data Inline | JetBrains Mono | 14px | 400 | 1.0 | 0 | Ink Black | Rule IDs, inline stats, code |
| Nav Item | Inter | 14px | 500 | 1.0 | 0.5px | Ink Black | Navigation labels |
| Button Label | Inter | 15px | 600 | 1.0 | 0.5px | White / Ink Black | CTA text |
| Badge | JetBrains Mono | 11px | 600 | 1.0 | 0.5px | Semantic color | Severity badges, status labels, UPPERCASE |

### Typography Principles
- **Monospace for every number.** This is the rule. When the live rule count renders as `<count> rules`, the numeral uses JetBrains Mono and the word "rules" uses Inter. This creates visual rhythm that says "we measured this precisely."
- **Weight contrast, not size contrast.** Hero is 900 weight. Body is 400. The difference in authority comes from weight, not from making things bigger.
- **Negative letter-spacing at display sizes.** -3px on hero, -2px on section headings. Creates density and gravitas. Normal spacing at body size for readability.
- **UPPERCASE monospace for section labels.** "WHAT ATR DETECTS", "THE NUMBERS", "MERGED UPSTREAM" — this is the intelligence briefing aesthetic. Sparse, formatted, classified-document-feeling.

---

## 4. COMPONENT STYLINGS

### Buttons

All buttons use sharp rectangles — 2px border-radius maximum. ATR's visual language is angular, matching the logo's geometric precision. No pills, no rounded corners.

**Primary CTA:**
- Default: bg Signal Blue (#2563EB), text #FFFFFF, fontSize 15px, fontWeight 600, padding 14px 32px, borderRadius 2px
- Hover: bg #1D4ED8 (blue-700, subtle darkening)
- Transition: background-color 0.2s ease
- Used for: "Integrate ATR", "Integration Guide"

**Secondary CTA:**
- Default: bg transparent, text Ink Black (#0B0B0F), border 1.5px solid Fog (#E8E8E5), padding 14px 32px, borderRadius 2px
- Hover: border-color Stone (#6B6B76)
- Transition: border-color 0.2s ease
- Used for: "Explore Rules", "View on GitHub"

**Text Link:**
- Default: text Signal Blue (#2563EB), no underline
- Hover: underline
- Used for: inline links, "View PR", "Full mapping"

### Speed-Line Motif

The ATR logo's horizontal speed lines become a recurring visual element:
- A set of 4-5 horizontal lines, varying in length (longest at center, shorter at edges)
- Used as: section dividers, decorative breaks between major scenes
- Color: Fog (#E8E8E5)
- Height: 1px per line, 4px gap between lines
- Max width: 120px, left-aligned or centered depending on context
- This replaces the generic `<hr>` element everywhere

### Cards & Containers

**Category Card (threat categories):**
- Background: Paper White (#FAFAF8)
- Border: 1px solid Fog (#E8E8E5)
- Border-radius: 0px (sharp corners — angular, like the logo)
- Padding: 28px
- Hover: border-color Stone (#6B6B76), no shadow, no scale
- Content: category name (Subheading), rule count in JetBrains Mono (Data Inline), one-line description (Body Small)

**Data Cell (numbers grid):**
- Background: Ash (#F3F3F0)
- Border: none (cells separated by 2px Paper White gap)
- Padding: 48px 36px
- Content: big number (Data Large) + unit (Data Unit) + description (Body Small)

**Standard Block (coverage scores):**
- Background: Paper White
- Border-right: 1px solid Fog (between blocks)
- Padding: 48px 36px, text centered
- Content: standard name (Section Label style), score (Data Large), detail (Body Small)

### Severity Badges
- Padding: 3px 10px
- Border-radius: 2px (sharp, consistent with buttons)
- Font: JetBrains Mono, 11px, weight 600, UPPERCASE
- CRITICAL: bg rgba(220,38,38,0.08), text #DC2626
- HIGH: bg rgba(234,88,12,0.08), text #EA580C
- MEDIUM: bg rgba(202,138,4,0.08), text #CA8A04
- LOW: bg rgba(37,99,235,0.08), text #2563EB

### Navigation
- Position: sticky top
- Background: Paper White with 1px bottom border in Fog
- Height: 64px
- Left: ATR logo (the geometric A mark only, no wordmark) + "ATR" in JetBrains Mono weight 700
- Center: page links (Rules, Coverage, Integrate, Contribute, Research) in Inter 14px weight 500
- Right: "Integrate" primary CTA button
- Nav uses `backdrop-blur-md` with `bg-paper/92` as a deliberate exception — the slight transparency improves scroll context. All other surfaces remain solid, authoritative.

### Code Blocks & YAML Preview
- Background: Ash (#F3F3F0)
- Border: 1px solid Fog (#E8E8E5)
- Border-radius: 0px
- Font: JetBrains Mono 14px, weight 400
- Padding: 24px
- Syntax highlighting: minimal — keywords in Signal Blue, strings in Graphite, comments in Stone
- The YAML preview in the rule explorer is the centerpiece interactive element

---

## 5. LAYOUT PRINCIPLES

### Spacing System
- **Base unit**: 8px
- **Scale**: 8, 16, 24, 32, 48, 64, 96, 120px
- **Section padding**: 120px vertical between major scenes (creates breathing room for one-message-per-viewport rhythm)
- **Card padding**: 28px
- **Grid gap**: 2px (tight, data-dense, like a spreadsheet)
- **Max content width**: 1120px (narrower than typical — creates generous margins that signal authority and focus)

### Grid & Container
- **Content**: 1120px max, centered
- **Hero**: Full-bleed background color, content within 900px max
- **Numbers grid**: 3-column, 2px gap, each cell is a data block
- **Category grid**: 3-column, 1px border between cells (table-like, not card-like)
- **Standards row**: 4-column, 1px border between blocks

### Viewport Scenes (Tesla-style scroll narrative)

Each major section occupies approximately one viewport height. The scroll rhythm:

| Scene | Content | Viewport | Background |
|-------|---------|----------|------------|
| 1. The Shift | Hero statement + stats + CTA | 100vh | Paper White |
| 2. The Threat | Big threat number + narrative | 100vh | Paper White |
| 3. The Numbers | 6-cell data grid | 100vh | Ash |
| 4. The Categories | threat categories (count from stats.ts) | auto (taller) | Paper White |
| 5. The Proof | "Cisco ships ATR" statement | 100vh | Paper White |
| 6. The Standards | 4-column coverage scores | 80vh | Ash |
| 7. The Future | Crystallization + AI-native contribution | 100vh | Paper White |
| 8. The CTA | "Integrate ATR" | 80vh | Paper White |

### Whitespace Philosophy

Whitespace is not empty space — it's the silence between statements that makes each one hit harder. One message per viewport. One stat per cell. One CTA per scene. If it feels sparse, it's working. ATR's data speaks for itself; the design's job is to not get in the way.

### Motion & Animation

ATR's motion language serves comprehension, not decoration. Every animation answers the question: "where did this come from, and why should I look at it now?"

**Scroll-reveal:** All content below the fold enters with a fade-up animation. Elements start 40px below their final position and at opacity 0, then ease into place over 0.8s with a cubic-bezier(0.16, 1, 0.3, 1) curve (fast start, gentle settle). Stagger: elements within the same scene arrive 100ms apart, creating a reading rhythm — title first, then subtitle, then data, then CTA.

**Number count-up:** All big monospace numbers (Data Large) animate from 0 to their final value over 1.5s on first viewport entry. Use an ease-out curve so the last 10% of the count slows dramatically — this creates a "landing" feeling. Numbers only animate once (IntersectionObserver with `once: true`).

**Hero entrance:** The hero is the only scene with a more dramatic entrance:
- Logo fades in first (0.6s delay from page load)
- "We used to protect people." fades in (0.3s after logo)
- "Now we protect agents." slides up + fades in (0.3s after previous, slightly faster — the "now" has more energy)
- Stats and CTAs fade up together (0.3s after statement)

**Speed-line motif animation:** When the speed-line divider enters viewport, lines draw from center outward (width 0 → full width) with 80ms stagger between lines. Subtle but makes the motif feel alive.

**Section transitions:** Use `scroll-snap-type: y proximity` (not mandatory) — this gently guides the user to land on each scene without locking them. Smooth scroll enabled.

**Hover states:** 0.2s ease transitions on all interactive elements. Cards: border-color shift only. Buttons: background-color shift only. Links: underline appears. No scale, no translate, no shadow — movement is reserved for scroll reveals.

**Page transition (between pages):** When navigating to /rules, /coverage, etc., the current page fades out (0.2s) and the new page fades in (0.3s). No slide, no wipe. Simple crossfade.

**What NOT to animate:**
- No parallax on scroll (feels 2018)
- No floating/bouncing elements (feels toy-like)
- No infinite animations (loading spinners excepted)
- No scroll-jacking (user controls their scroll speed)
- No particle effects, orbs, or ambient motion

**Performance:** All animations use `transform` and `opacity` only (GPU-composited). No layout-triggering properties (width, height, margin, padding) in animations. Use `will-change: transform, opacity` on animated elements.

### Border Radius Scale

| Value | Context |
|-------|---------|
| 0px | Cards, containers, code blocks — default is sharp |
| 2px | Buttons, badges — barely perceptible, precision feel |
| 0px | Everything else |

ATR uses sharp corners. The logo is angular. The data is precise. Rounded corners signal friendliness; sharp corners signal authority.

---

## 6. DEPTH & ELEVATION

### Elevation Levels

| Level | Treatment | Use |
|-------|-----------|-----|
| Level 0 (Flat) | No shadow, no border | Default state for all elements |
| Level 1 (Border) | 1px solid Fog | Cards, table cells, nav bottom edge |
| Level 2 (Section) | Background color shift (Paper White ↔ Ash) | Alternating sections |

### Shadow Philosophy

No shadows. ATR communicates hierarchy through:
1. **Typography scale** — bigger/bolder = more important
2. **Background alternation** — Paper White vs Ash distinguishes sections
3. **Border presence** — 1px Fog borders separate elements within a section
4. **Whitespace** — the primary depth cue is space itself

---

## 7. DO'S AND DON'TS

### Do
- Use JetBrains Mono for every single number on the site — rule counts, percentages, scores, ms values
- Keep one message per viewport — if you're showing two ideas on the same screen, split them
- Use the speed-line motif as section dividers — it connects every page to the logo
- Make prove points prominent — Cisco merge, OWASP 10/10, PINT benchmark are first-class content
- Show the crystallization mechanism and AI-native contribution as a major differentiator
- Keep all backgrounds light — Paper White (#FAFAF8) or Ash (#F3F3F0) only
- Use Ink Black (#0B0B0F) for headings — it's the logo's color and carries its authority
- Trust data to impress — "36,394 skills scanned" in 64px JetBrains Mono is more powerful than any animation
- Link to original sources (PR URLs, Zenodo DOI, CVE IDs) — transparency builds trust

### Don't
- Use dark backgrounds — dark themes signal "product" or "dashboard," not "open standard"
- Add shadows, glows, or glassmorphism — these are decorative and contradict the data-first philosophy
- Use rounded corners beyond 2px — angular geometry from the logo is the design language
- Add animations for the sake of movement — the only animation is a one-time count-up on data entry into viewport
- Use more than one chromatic color (Signal Blue) — monochrome + one accent is the rule
- Show any vendor's name, logo, or brand as ATR's own — ATR is an independent, vendor-neutral standard, and no company's branding belongs on it. Naming an organisation whose open-source repo merged a PR is a factual credit and is fine; presenting any vendor as ATR's owner, sponsor or parent is not.
- Use emojis, icons from icon libraries, or decorative illustrations — the logo mark is the only graphic element
- Make the site feel like a docs site (sidebar nav, breadcrumbs, version selector) — it's a cinematic narrative
- Add a blog, changelog, or news section — if it can go stale, it undermines the standard's authority
- Use AI-generated placeholder images or stock photos — this site has no images except the logo and data visualizations

---

## 8. RESPONSIVE BEHAVIOR

### Breakpoints

| Name | Width | Key Changes |
|------|-------|-------------|
| Mobile | <768px | Single-column layout, hero text scales down, numbers grid becomes 1-column, category grid becomes 1-column, nav collapses to hamburger, CTA buttons stack vertically |
| Tablet | 768-1024px | 2-column numbers grid, 2-column category grid, full nav visible |
| Desktop | 1024-1440px | 3-column grids, full nav, 1120px content max-width |
| Large Desktop | >1440px | Content remains 1120px centered, generous side margins increase |

### Touch Targets
- CTA buttons: minimum 48px height (above 44px WCAG requirement)
- Nav items: 48px tap area
- Category cards: entire card is tap target
- Rule explorer rows: 48px minimum row height

### Collapsing Strategy
- **Numbers grid**: 3-col → 2-col → 1-col
- **Category grid**: 3-col → 2-col → 1-col
- **Standards row**: 4-col → 2-col → 1-col stacked
- **Hero statement**: font-size scales via clamp(), line breaks shift
- **Navigation**: horizontal → hamburger drawer

---

## 9. AGENT PROMPT GUIDE

### Quick Color Reference
- Background: Paper White (#FAFAF8)
- Alternate surface: Ash (#F3F3F0)
- Heading text: Ink Black (#0B0B0F)
- Body text: Graphite (#3B3B42)
- Secondary text: Stone (#6B6B76)
- Tertiary text: Mist (#9B9BA5)
- Border: Fog (#E8E8E5)
- Accent / CTA: Signal Blue (#2563EB)
- CRITICAL: #DC2626
- HIGH: #EA580C
- MEDIUM: #CA8A04
- Coverage green: #16A34A

### The Narrative Structure

The homepage tells a story in 8 scenes:

**Scene 1 — The Shift (Hero):**
"We used to protect people." (in Stone, fading/dim)
"Now we protect agents." (in Ink Black, full weight)
Below: three monospace stats. Two CTA buttons.

**Scene 2 — The Threat:**
A single massive number (e.g., "30" in 200px JetBrains Mono, faint red).
Below: "MCP vulnerabilities in 60 days."
Below: narrative paragraph about the attack surface.

**Scene 3 — The Numbers:**
6-cell grid. Each cell: one big monospace number + one description line.
All six values are pulled live from stats.ts — never hardcoded. The cells are:
rule count, SKILL.md benchmark recall, skills scanned, OWASP Agentic coverage
(10/10), SAFE-MCP coverage (78/85), and one benchmark recall figure from the
README evaluation table. Do not put a false-positive or precision rate in this
grid: the lane FP rates are withdrawn and not citable, and a bare "precision"
number with no corpus attached is exactly the kind of claim this project has had
to retract.

**Scene 4 — The Categories:**
"What ATR detects."
Responsive grid (1/2/3 cols) of the threat categories. Each: name + count +
one-line description. There are ten category directories under `rules/`
(`ls rules/` is the live list): prompt-injection, tool-poisoning,
skill-compromise, context-exfiltration, agent-manipulation,
privilege-escalation, excessive-autonomy, model-abuse, data-poisoning,
model-security. If the site merges any of these for presentation, the merge
happens in the view layer and the underlying counts still come from stats.ts.

**Scene 5 — The Proof:**
"ATR rules ship inside Cisco's open-source skill scanner."
The story: we submitted a PR to the `cisco-ai-defense/skill-scanner` repository;
their maintainers reviewed and merged it. Link to PR #79.

**Copy boundary — do not overstate this.** The merge is into an open-source
scanner repository under Cisco's GitHub org. It is **not** a shipment inside the
Cisco AI Defense commercial product, and the site must never say "shipped in
Cisco AI Defense", "in Cisco AI Defense production", or imply a vendor
endorsement or partnership. Write what is verifiable: we sent a PR, they merged
it. Same discipline for every other org in the prove-points table.

**Scene 6 — The Standards:**
4-column row: OWASP Agentic 10/10 · SAFE-MCP 78/85 · AST10 7/10 · one
version-pinned benchmark figure pulled from stats.ts. Whatever benchmark cell is
shown must carry its ATR version and measurement date, as the README table does
— an unpinned benchmark number is not publishable.

**Scene 7 — The Future (AI-Native Contribution + Crystallization):**
"ATR rules don't have to be written by hand."
Explain: Threat Cloud crystallization — LLM analyzes new attacks, proposes rule YAML, community reviews.
Four contribution paths: report evasion, report FP, submit rule, AI-native via MCP server.
This is the key differentiator — no other detection standard has automated rule generation.

**Scene 8 — Integrate:**
"Integrate ATR."
`npm install -g agent-threat-rules`
Four paths: TypeScript, Python, Raw YAML, SIEM converters.
"The same path our ecosystem contributors walked."

### All Prove Points (must appear on site)

Every row's `Data` column is a **claim that must be re-verified before it ships**,
against `data/stats.json`, `ADOPTERS.md` (the source of truth for who actually
adopted ATR, with PR evidence), or the README evaluation table. Counts marked
"live" move on their own and must be bound to stats.ts, not typed into copy.

| Prove Point | Where | Data |
|-------------|-------|------|
| `cisco-ai-defense/skill-scanner` merge | Scene 5 (hero proof) + /integrate | PR #79 merged. Describe as an open-source repo merge, never as a Cisco product shipment. |
| Cisco rule-packs CLI | Scene 5 | PR #80 |
| OWASP Agentic Top 10 coverage | Scene 6 + /coverage | 10/10 categories — a *mapping* ATR maintains, not an OWASP endorsement or an official OWASP merge. Do not imply either. |
| SAFE-MCP coverage | Scene 6 + /coverage | 78/85 techniques (conservative lower bound) |
| OWASP AST10 coverage | Scene 6 + /coverage | 7/10, 3 are process-level |
| PINT-format corpus (self-built) | Scene 3 + /research | 850 samples. Pull recall/precision/F1 live from the README table with the ATR version and measurement date attached. Not a run of Lakera's official private PINT benchmark — say so. |
| Wild scan | Scene 2 + /research | 101,280 skills scanned, 1,434 flagged. These two are the only citable wild-scan figures; earlier scan totals and "confirmed malware" counts are frozen and must not be used. |
| npm downloads | Footer or Scene 3 | live — query npm, do not hardcode |
| Zenodo paper | /research | DOI 10.5281/zenodo.19178002 |
| CVE mappings | /rules | live — count from the rules' `references.cve` fields |
| Ecosystem PRs | /contribute or footer | live — `ADOPTERS.md` is the source of truth; a merged PR is not proof the integration is still present, so re-verify before publishing |
| Threat Cloud crystallization | Scene 7 + /contribute | LLM auto-generates rule proposals from new attacks |
| Five-tier architecture | /research | Tier 0-2 shipped, Tier 2.5-4 roadmap |

### Example Component Prompts

**Hero Section:**
"Create a full-viewport hero on Paper White (#FAFAF8). Center the ATR logo mark at top (the geometric A with speed lines, 80px height). Below: 'We used to protect people.' in Inter Tight 80px weight 900 color Stone (#6B6B76). Next line: 'Now we protect agents.' in Inter Tight 80px weight 900 color Ink Black (#0B0B0F). Below: three stats in JetBrains Mono — pull live values from stats.ts (rule count, category count, and one version-pinned coverage figure such as '10/10 OWASP Agentic') separated by centered dots. Do not hardcode these and do not use a bare precision or false-positive percentage here. Two buttons: primary Signal Blue 'Integrate ATR' and secondary bordered 'Explore Rules'. Both 2px border-radius."

**Numbers Grid:**
"Build a 3-column grid on Ash (#F3F3F0) background with 2px Paper White gaps between cells. Each cell: big number in JetBrains Mono 64px weight 700 Ink Black, unit text in JetBrains Mono 24px weight 400 Stone, description in Inter 14px weight 400 Stone below. Pull live values from stats.ts — the six cells are those listed in Scene 3 above: rule count, SKILL.md benchmark recall, skills scanned, OWASP Agentic 10/10, SAFE-MCP 78/85, and one version-pinned benchmark recall figure. No precision or false-positive percentage in this grid, per the Scene 3 boundary."

**Category Grid:**
"Create a 3-column grid with 1px Fog (#E8E8E5) borders between cells, on Paper White. Each cell: category name in Inter Tight 15px weight 600 Ink Black, rule count in JetBrains Mono 12px Signal Blue (#2563EB), one-line description in Inter 13px Stone. One cell per category directory under `rules/` (ten as of 2026-09-22 — bind the list to stats.ts rather than hardcoding a cell count). Hover: border-color transitions to Stone. Sharp corners everywhere."

**Proof Scene:**
"Full-viewport section, centered. Small monospace label 'MERGED UPSTREAM' in JetBrains Mono 12px Stone, 3px letter-spacing, uppercase. Main statement: 'ATR rules ship inside Cisco's open-source skill scanner.' in Inter Tight 48px weight 800 Ink Black, with 'open-source skill scanner' in Signal Blue. (Wording is deliberate: the merge is into the `cisco-ai-defense/skill-scanner` repo, not the Cisco AI Defense product — see the copy boundary in Scene 5.) Below: story paragraph in Inter 16px Graphite. Below: 'View the PR on GitHub' link in JetBrains Mono 13px Signal Blue with underline on hover."

**Crystallization Scene:**
"Full-viewport section. Label: 'THE FUTURE' in monospace uppercase Stone. Heading: 'ATR rules don't have to be written by hand.' in Inter Tight 48px weight 800 Ink Black. Left column: explanation of Threat Cloud crystallization — LLM analyzes new attack patterns, proposes YAML rules, community reviews and merges. Right column: four contribution paths stacked vertically, each with monospace numbering and description. Background Paper White."
