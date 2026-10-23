# Versioned drawing and source design acceptance

Draft review package for the first contribution discussed in [#3890](https://github.com/tangency-labs/solidcraft/issues/3890#issuecomment-6363836282).

- [Acceptance contract](docs/acceptance.md): the four agreed cases and the evidence required from their future implementation.
- [Fixture guide](fixtures/README.md): two source designs, two historical states, path examples and the drawing-record bindings still awaiting the writer.
- [Scenario data](fixtures/scenarios.json): inputs and expected outcomes for a future harness; not a SolidCraft command script.
- `fixtures/C0/` and `fixtures/C1/`: native source-model JSON and illustrative drawing-record templates.
- [Binding requirements](fixtures/bindings.json): symbolic fixture identities and the values the Drawing implementation must supply.

The source designs use the existing legacy `solidcraft/1` input shape. The drawing files end in `.template.json`: their `${...}` values are deliberately unbound and they are **not importable drawings**. This package defines no drawing format version, ID representation, cache encoding, revision/tag policy or new application API.

The two snapshot directories are logical repository states, not actual Git commits. A future harness will create two commits in a disposable repository and use the application/storage APIs once available. Do not open these templates as if they were current production drawing files.

This contribution follows the acceptance-document/fixture approach used in [#4962](https://github.com/tangency-labs/solidcraft/pull/4962), without copying its geometry fixtures or extending its implementation scope. The target for a future draft PR is `drawings`, subject to the agreed child issue and review.
