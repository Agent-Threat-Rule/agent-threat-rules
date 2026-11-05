# Official NIST source verification

Retrieved on 2026-11-05 through the web connector:

- [NIST AI 100-1, AI RMF 1.0 (January 2023), official PDF](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf).
- [NIST AIRC, AI RMF Core, official HTML](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/). The HTML identifies itself as an excerpt of AI RMF 1.0 (2023) and says a revised version is in progress.

Both sources were successfully read and their relevant subcategory statements agree. `nist-core.json` preserves the exact Core statements used in the review, with table, printed-page and PDF-page references. PDF line wrapping and discretionary hyphenation were normalized. The PDF was also requested as screenshots for pages indexed 26, 27 and 36; the connector returned screenshot markers rather than durable local image files. The text retrieval, not an unattached screenshot, is the inspectable evidence.

## Interpretation boundaries

The phrase about sustaining the value of deployed AI systems is the statement of **MANAGE 2.2**, not MANAGE 1.3. MANAGE 1.3 instead addresses developed, planned and documented responses to risks deemed high priority by MAP. A rationale that quotes the former while naming the latter contains a directly verifiable definition error. Selecting MG.2.2 for a particular rule still requires checking whether that rule supports an applied mechanism for maintaining deployed-system value; lexical agreement alone does not prove implementation.

**GOVERN 2.1** concerns documented responsibilities and communication lines clear to people and teams throughout the organization. Agent instruction precedence, tool authorization, privilege boundaries, and technical agent roles do not by themselves demonstrate those organizational outcomes. GOV 3.2 and MAP 3.5 are useful comparisons for human-AI oversight, but they also require policies or defined, assessed and documented processes. They must not be substituted automatically merely because a rule mentions a human or authorization.

**MANAGE 2.4** includes two distinct elements: applied mechanisms to supersede, disengage or deactivate an AI system showing performance or outcomes inconsistent with intended use, and assigned, understood responsibilities. Detecting suspicious strings or recommending input filtering does not establish every element. **MANAGE 1.3** requires planned and documented responses to mapped high-priority risks. A detection rule may contribute evidence to either subcategory in a deployment, but should not be described as satisfying the entire organizational outcome without supporting artifacts. **MANAGE 2.3** is specifically about responding and recovering from a previously unknown risk; a rule's newness or a novel attack keyword is insufficient by itself.

These interpretations are review judgments grounded in the quoted text. They are not NIST endorsement, expert certification, or a legal compliance determination.
