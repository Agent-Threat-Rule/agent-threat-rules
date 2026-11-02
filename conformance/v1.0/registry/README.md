# ATR-Compatible Implementations — Registry v1.0

This file lists engines verified by the ATR Numbering Authority to pass
the Conformance Test Suite at the indicated Conformance Level for the
indicated Spec version. Listing in this registry authorizes the listed
organization to display the corresponding ATR-Certified mark per
[TRADEMARK.md §5](../../../TRADEMARK.md).

## Verified implementations

_None yet. The registry opens when SPEC.md reaches Final status. The
Draft period is being used to stabilize the fixture format._

## How to be listed

1. Run [`conformance/v1.0/runner/run-conformance.ts`](../runner/run-conformance.ts)
   against your engine and produce a clean report at the level you claim.
2. Open a GitHub issue tagged `certification-claim` with:
   - Engine name, version, repository URL
   - SHA-256 of the report file
   - Conformance Level claimed (L1, L2, or L3)
3. The ATR Numbering Authority reproduces the run on a clean environment.
4. On a successful reproduction, this file is updated with a row containing
   engine name, version, reviewed-on date, claimed level, and report SHA-256.

## Removal

Entries are removed if the engine ships a release that no longer passes
the suite or if the listed organization requests removal. Removal is
recorded in the git history; the registry never silently forgets a prior
listing.
