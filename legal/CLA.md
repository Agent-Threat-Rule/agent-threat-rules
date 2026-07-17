# ATR Contributor License Agreement (DCO, not CLA)

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED.** The DCO requirement
> described here is the proposed standard for v2.0 governance. **It is
> not yet enforced.** Existing contributors do NOT need to backfill
> `Signed-off-by:` lines on past commits. The current v1.1 contribution
> model continues to apply until v2.0 TSC ratification. See
> `STANDARDIZATION-STATUS.md` at repo root for full status.

**Version:** 1.0
**Effective (proposed):** Bootstrapping under v1.1 Numbering Authority; formalised at v2.0 TSC ratification per `governance/CHARTER.md` § 11.
**License of this document:** MIT

---

## ATR uses DCO, not CLA

The Agent Threat Rules project follows the **Developer Certificate of Origin (DCO)** model used by the Linux kernel, OpenSSF, and most modern open-source detection-standard projects (SigmaHQ, YARA-X). We do NOT require a Contributor License Agreement.

Per `governance/CHARTER.md` § 7.2: "Contributor surveys at SigmaHQ, OWASP, and the Linux Foundation consistently identify CLA requirements as the largest single source of contributor friction; ATR's contributor base (red-team researchers + detection engineers + sovereign-CERT analysts) is precisely the demographic most CLA-averse."

---

## What you do as a contributor

Every commit you contribute MUST include a Developer Certificate of Origin sign-off:

```
Signed-off-by: Your Real Name <your-email@example.com>
```

This is one line. You add it with:

```bash
git commit -s -m "your commit message"
```

The `-s` flag adds the sign-off automatically from your `git config user.name` / `user.email`.

---

## What the sign-off means

By signing off, you certify the DCO v1.1 (https://developercertificate.org/):

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same open source license (unless I am permitted to submit under a different license), as indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project and the open source license(s) involved.

That's the entirety of the legal commitment. No CLA, no copyright assignment, no separate paperwork.

---

## What ATR's licenses mean for your contributions

Per `governance/CHARTER.md` § 7.1:

- **All contributions** (engine implementations, tooling, CI scripts, conformance test harness and fixtures, rule content in `rules/`, and specification documents): **MIT License**. You retain your copyright; the MIT licence governs use. ATR uses a single license across the whole project.

All contributions are MIT-licensed regardless of where in the repo they live.

---

## Patent non-assertion

Per `governance/CHARTER.md` § 7.4 and OASIS Non-Assertion Mode:

> By contributing under DCO, contributors covenant not to assert Essential Claims against conformant implementations of the ATR specification. This mirrors OASIS Non-Assertion Mode and is the permissive default. Contributors retain the right to assert against non-conformant implementations.

In plain English: you cannot use a patent you hold to attack someone who implements ATR correctly. You CAN assert against an implementation that misuses ATR (e.g., claims ATR-Certified status without passing the conformance corpus).

---

## What you do NOT do as a contributor

- You do NOT assign copyright to ATR or any organisation.
- You do NOT sign a separate paper or electronic CLA document.
- You do NOT need a corporate authority approval (unless your employer requires one for your own legal reasons — that is your contract with your employer, not ATR's requirement).
- You do NOT lose rights to your contribution; the MIT licence is a grant, not an assignment.

---

## If your employer is concerned

Some employers prefer a corporate-level contributor agreement (CCLA). ATR does not require one. If your employer needs one for their own audit purposes, the standard Linux Foundation CCLA template is acceptable and we will sign it; contact `tsc@agentthreatrule.org` (post-ratification) or `adam@agentthreatrule.org` (current).

The CCLA does not change the contribution licence (still MIT as above). It is an organisation-to-organisation written acknowledgement of the DCO terms.

---

## What if I forget to sign off?

CI will reject your PR with a comment pointing here. Fix with:

```bash
# Rebase and add sign-off to your last N commits
git rebase --signoff HEAD~N

# Or amend the most recent
git commit --amend -s --no-edit

git push -f
```

---

## References

- DCO v1.1: https://developercertificate.org/
- Linux kernel DCO: https://docs.kernel.org/process/submitting-patches.html#developer-s-certificate-of-origin-1-1
- `governance/CHARTER.md` § 7 (IPR)
- `governance/CHARTER.md` Appendix A (why DCO not CLA)
