# Versioned drawing and source design acceptance

Draft contract for [#3890](https://github.com/tangency-labs/solidcraft/issues/3890), based on CamWight's [K2 field proposal](https://github.com/tangency-labs/solidcraft/issues/3890#issuecomment-6363836282). The Drawing record and storage APIs are planned, not implemented by this contribution. Field spellings may change in review; bind the fixtures to the agreed writer rather than introducing a second schema.

## Scope and responsibility

Use one drawing and two source designs in one repository. Establish dependency discovery, historical resolution, relocation/relink behavior and deterministic authored records. The deliverable is an acceptance document and small fixtures. Drawing storage, source evaluation, view generation, UI, Git/jj integration and release policy remain with their respective owners.

CamWight owns the Drawing record/storage boundary. ID representation and the relationship between a printed revision and a protected repository tag remain for jyviko to clarify. `C0` and `C1` below are fixture commit labels, not released part revisions. No repository identity, commit hash or source fingerprint is added to `sources`.

## Fixture layout and distinguishable states

Each state has this layout after the future harness binds the drawing template:

```text
repository/
  drawings/pair.drawing.json
  models/plate.solidcraft
  models/block.solidcraft
```

The drawing has two sheets: one documents the plate's root component and the other the block's root component. Its source paths are `../models/plate.solidcraft` and `../models/block.solidcraft`.

| State | Drawing name | Plate dimensions, mm | Block dimensions, mm | Analytic volumes, mm³ |
| --- | --- | --- | --- | --- |
| C0 | Versioned pair initial | 40 × 30 × 5 | 10 × 10 × 20 | Plate 6000; block 2000 |
| C1 | Versioned pair changed | 60 × 30 × 5 | 12 × 10 × 20 | Plate 9000; block 2400 |

Both sources change at the same paths, so accidentally combining an old drawing with current source files is observable. Source feature identities and logical drawing/source/sheet identities are retained between states. Values are simple rectangular-solid calculations, not measurements from a CAD run.

## A1 List dependencies without evaluating sources

**Given** the drawing in plain-text form and, when K3 exists, its container form.

**When** the dependency reader lists `sources`.

**Then**:

- Return both source IDs and the exact relative paths, interpreted relative to the drawing's folder with `/` separators.
- Do not open, deserialize or evaluate either source design, or initialize geometry solely for this operation. Reading the drawing's authored record is allowed.
- Repeat with both source files absent: dependency listing still returns the declared references. Later source resolution may report them missing.
- Record source-open and evaluator invocation counts; both are zero. This must use the real reader, not a fixture script that extracts JSON itself.

## A2 Resolve a historical drawing and both sources together

**Given** C0 followed by C1 in a disposable repository, with the current branch at C1.

**When** a historical-open operation requests C0.

**Then** resolve the C0 drawing and both source blobs from C0 through their relative paths. The drawing name is `Versioned pair initial`; the plate is 40 × 30 × 5 and the block 10 × 10 × 20. Opening C1 yields its changed name and dimensions instead.

Record the requested commit, the resolved path/blob identities and the original source bytes. If geometry is evaluated, check the dimensions/volumes in the table too. File/blob identity is mandatory; a plausible rendered picture alone does not prove historical resolution.

Repeat with the working directory's plate replaced by unrelated bytes: opening C0 must still use the C0 source. If a required source is unavailable in the requested historical tree, report it missing; never substitute the current working copy or another revision. The operation must not overwrite or modify that working directory.

The repository/storage layer selects the revision. The drawing record continues to hold `{id, path}` only; this case does not introduce per-source versions or a new PDM API.

## A3 Save As, Relink and honest cached-view state

Run each subcase independently from C0; do not carry mutations between subcases.

| Action | Required outcome |
| --- | --- |
| Save As to `copies/review/pair.drawing.json`, keeping the same models | Source paths become `../../models/plate.solidcraft` and `../../models/block.solidcraft`; both still resolve to the intended models. The original drawing and source files remain unchanged. |
| Move `models/block.solidcraft` to `models/block-renamed.solidcraft`, then explicitly Relink that source | Only the selected source path changes. Sheet references remain associated with the block source; no view silently switches to the plate. IDs/references remain internally consistent using the agreed representation. |
| Remove the plate after a view was successfully generated from C0 | The affected view is `lost`, never `current`. Any retained old image is identified as historical/lost. Opening and listing the authored drawing still work. |
| Replace only the plate with its C1 bytes after generating C0 views | The affected view is `out of date`, never `current`. A successful explicit update, or the agreed automatic update, may establish a fresh result. This contract does not choose an update mode. |
| Reopen with derived cache absent | Do not claim that a cached view is current without evidence. Regeneration or the eventual no-cache state belongs to the view/session contract; do not invent an extra serialized status here. |
| Break an internal sheet-to-source reference while leaving its path present | Report a damaged drawing; do not silently allocate a replacement ID, repair the reference or retarget it to a look-alike source. This differs from a valid source reference whose external file is missing. |

Cache provenance belongs to `cache/` or the future session mechanism, never to authored `sources`. View records and cache encodings are later work: the fixture describes the observations required when those APIs exist, not a fabricated cache file or currently executable view test.

## A4 Deterministic authored text and round trips

Using the eventual writer, bind the template with the assigned `format` / `format_pending`, collision-free IDs and agreed encodings for units, paper, borders, documented components and exclusions.

For both plain JSON and the container:

1. Save, open and save again without an authored edit. The bytes must match, including the container form as required by K2; nondeterministic archive metadata is not an exemption.
2. Verify fixed key order and number formatting through the real writer. The indentation/order in this hand-authored template is not the canonical serialization specification.
3. Verify that authored `sources`, `sheets` and their ID references survive, and that drawing `properties` follow `document.metadata` preservation rules.
4. Generate or refresh a derived view cache without an authored edit. The plain text record remains byte-identical. A container may hold new `cache/` bytes, but those never appear in the authored text form.
5. Remove `cache/`: authored records and references remain intact. No saved model snapshot, rendered image, source fingerprint or last-seen source state is inserted into `sources`.

The fixture stays within K2's stated caps: two sheets, two sources, short UTF-8 names and relative paths. The implementation still owns validation of the full limits; this slice does not add a large limit-testing matrix.

## Evidence and pending bindings

Each future executable case records its implementation commit, API entry point, fixture hashes, observed outputs and pass/fail result. A1 needs reader/evaluator counters; A2 needs historical blob/path evidence; A3 needs source/view observations; A4 needs actual serializer bytes. Static JSON parsing and analytic arithmetic are preparation checks, not evidence that Drawing behavior passes.

Before executable tests, the owners must supply the writer's ID encoding, format/pending values, units/paper/border/documented-component/exclusion encodings, and later reader/view/session APIs. Use the same logical IDs across C0 and C1. Printed revision labels, protected tags, cross-repository links, choosing latest components, conflict merging and resuming historical work are outside this acceptance slice.

After human review, the proposed publication is a bounded child issue and a documentation/fixture draft PR targeting `drawings`, referencing #3890. It must not claim to close the parent storage issue or to implement the four behaviors.
