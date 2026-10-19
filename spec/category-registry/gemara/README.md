# Gemara catalogs for the ATR category registry

This directory holds the ATR category registry
([`../v1.0.yaml`](../v1.0.yaml)) expressed as [Gemara](https://github.com/gemaraproj/gemara)
catalogs, validated against the Gemara CUE schemas and published by
`.github/workflows/publish-gemara.yml` as a signed OCI bundle.

| File | Gemara type | What it holds |
|---|---|---|
| `atr-attack-vector-catalog.yaml` | `#VectorCatalog` | One vector per registry category. The vector id is the registry category id (which is also the `rules/` directory name) and the description is the registry's description. |
| `ai-agent-capability-catalog.yaml` | `#CapabilityCatalog` | Capabilities of AI agent systems that create the opportunity for the threats. |
| `atr-threat-catalog.yaml` | `#ThreatCatalog` | Threats at impact level, each mapped to the capabilities that enable it and the vectors that realize it. Every vector is reached by at least one threat. |
| `atr-detection-control-catalog.yaml` | `#ControlCatalog` | Detection controls an operator can apply with ATR, cut by when inspection happens. **Root artifact of the bundle.** |

## Why they live here

The vector catalog is a projection of the registry. When the projection and
the registry lived in different repositories, nothing stopped them drifting
apart. Here they sit side by side, and the catalogs are generated, not
hand-edited.

## Editing

The four catalogs are **generated**; do not edit them by hand. Edit one of the
two inputs and regenerate:

- [`../v1.0.yaml`](../v1.0.yaml), the registry: which categories exist, their
  ids and their descriptions.
- [`src/editorial.yaml`](src/editorial.yaml): everything the registry does not
  say (vector titles and grouping, and the capability, threat and control
  catalogs).

```sh
npx tsx scripts/generate-gemara-catalogs.ts           # regenerate
npx tsx scripts/generate-gemara-catalogs.ts --check   # what CI checks
```

The generator stops when the inputs disagree: a registry category with no
editorial entry, an editorial entry for a category the registry does not have,
a vector no threat reaches, or a reference to an id that does not exist.
`tests/gemara-catalogs.test.ts` fails when the committed catalogs differ from
the generator output.

## Validating

```sh
git clone --depth 1 --branch v1.6.0 https://github.com/gemaraproj/gemara.git /tmp/gemara
scripts/validate-gemara-catalogs.sh /tmp/gemara
```

Each catalog is checked with `cue vet -c -d '#<metadata.type>'` against the
Gemara release named by `bundle.gemara-version` in `src/editorial.yaml`.

## Versioning

`bundle.version` in `src/editorial.yaml` is stamped as `metadata.version` on
all four catalogs and is the OCI tag. Its MAJOR.MINOR is the registry version
(the generator enforces this); PATCH moves with any change that alters a
generated catalog. A published version is never overwritten. While the
registry's `status` is `draft`, every catalog carries `draft: true`.

## Publication

`.github/workflows/publish-gemara.yml` publishes the bundle to

```
ghcr.io/agent-threat-rule/agent-threat-rules/gemara:<bundle version>
```

using [`gemara-publish-action`](https://github.com/gemaraproj/gemara-publish-action).
Assembly starts at the control catalog and follows each catalog's `imports`
to the threat, capability and vector catalogs, so one bundle carries all four.

It runs by manual dispatch from a release tag. ATR release tags also start
it, but those runs are skipped until the repository variable
`GEMARA_PUBLISH_ON_TAGS` is `true`, so the first publish is always a manual
run. It never runs on a push to `main`. Rule changes move release tags, not the bundle: a release
whose catalogs are already published under their version pushes nothing, and
a release whose catalogs changed without a version bump fails before pushing.

The bundle is signed keyless with the workflow's GitHub OIDC identity; no key
is stored. To verify:

```sh
cosign verify ghcr.io/agent-threat-rule/agent-threat-rules/gemara:<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp \
    '^https://github\.com/Agent-Threat-Rule/agent-threat-rules/\.github/workflows/publish-gemara\.yml@refs/tags/v'
```

Once a version is published, to reference a catalog from another Gemara artifact, use the bundle as the
mapping-reference `url` and the catalog's `metadata.id` as the reference `id`:

```yaml
mapping-references:
  - id: ATR-AI-AGENT-VECTOR-CATALOG
    title: AI Agent Attack Vector Catalog (ATR)
    version: "1.0.0"
    url: oci://ghcr.io/agent-threat-rule/agent-threat-rules/gemara:1.0.0
```

License: MIT.
