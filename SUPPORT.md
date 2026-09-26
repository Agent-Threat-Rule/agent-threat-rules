# Supporting Agent Threat Rules (ATR)

ATR is an MIT-licensed open detection rule standard for AI agent attacks. The rule corpus, detection engine, benchmark methodology, and integration tooling are maintained by a solo maintainer with community contributions. There is no commercial entity gating any part of the open standard.

If you depend on ATR in production or want the open standard to keep shipping, you can back the project through Open Collective.

---

## Open Collective

Open Collective is the project's primary funding channel. Funds are held by the fiscal host Open Source Collective, Inc. (501(c)(6), EIN 82-2037583), and contributions and payouts made through it appear in its public ledger.

Project page:
https://opencollective.com/agent-threat-rules

Five public tiers: Backer (from 5 USD), Friend 25 USD, Bronze 200 USD, Silver 1,000 USD, and Gold 5,000 USD per month. Funding milestones and custom sponsorship for organizations are described in [README.md §15](README.md#15-sponsorship).

---

## What your donation funds

50 USD funds reviewing one CISA KEV CVE entry and shipping a validated detection rule, complete with true-positive fixtures and a clean regression run against the 432-entry benign corpus. One extra rule the AI security ecosystem did not have before.

500 USD funds one week of full-time corpus expansion. The pipeline ingests CISA KEV and AVID feeds daily; human-in-the-loop validation is the rate-limiting step.

5,000 USD funds an independent security audit of the detection engine and rule parser, subcontracted to an external firm.

30,000 USD covers 6 months of full-time maintenance from a solo founder (Taiwan modest living rate).

50,000 USD covers the above plus the external audit plus onboarding a second maintainer to break the bus factor risk.

---

## Recognition

Every donor (regardless of amount) is listed in the CONTRIBUTORS file in the repository. Anonymity is the default option if you prefer not to be listed.

For donations above 1,000 USD, optional acknowledgment in the project README. For donations above 10,000 USD, optional acknowledgment in release notes and conference-talk slides.

---

## Commitment

The ATR rule corpus, detection engine, and benchmark methodology are MIT licensed in perpetuity. No vendor-private exclusives. No paywall. No commercial fork that holds back rules from the open repository. Every PR is reviewed in the open.

The maintainer commits to:
- Publishing every benchmark with its underlying corpus, so any third party can reproduce.
- Documenting limitations honestly. The README maintains a public list of known evasion techniques (currently 64).
- Disclosing all financial sponsors in the CONTRIBUTORS file.
- Treating ATR as a community standard, not a proprietary product.

---

## Other ways to help (no money required)

- Star the repository on GitHub: helps surface ATR to other defenders
- Open issues with attack examples ATR misses: directly improves the rule corpus
- File integration PRs for new agent frameworks, MCP servers, or threat intelligence platforms
- Cite ATR in your security write-ups, blog posts, conference talks
- Try the npm package or GitHub Action in your CI/CD and report what works or breaks

Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
Public ecosystem map: https://sovereign-ai-defense.vercel.app

Maintainer: Adam Lin (adam@agentthreatrule.org)
