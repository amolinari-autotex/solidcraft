# Small versioned drawing fixture

`C0/` and `C1/` are complete logical input trees for one drawing with two source designs. They are not actual repository commits or formal released revisions. The future acceptance harness creates the commits in a disposable repository and binds the drawing through the real writer.

## Native sources

Each source is one original rectangular box at the origin in millimetres. Source JSON follows the existing `solidcraft/1` shape used by the repository's corpus: one `box` feature, `new_body`, feature ID 1 and `next_id` 2. IDs are local to each design. Keeping them unchanged between C0 and C1 preserves the source feature identity.

The inputs intentionally use an existing legacy format, not a newly guessed current format number. Opening may migrate them with the normal reader. A future runtime check must establish actual reader/evaluator compatibility before these are advertised as replay-verified native fixtures.

| Source | C0 | C1 | Shared properties |
| --- | --- | --- | --- |
| `models/plate.solidcraft` | 40 × 30 × 5 mm | 60 × 30 × 5 mm | Body `Plate`; feature `Stock`; no links or caches |
| `models/block.solidcraft` | 10 × 10 × 20 mm | 12 × 10 × 20 mm | Body `Block`; feature `Stock`; no links or caches |

The volume oracle is `length × width × height`; no geometry engine was used to obtain it. No additional imported parts, libraries, accounts or private PDM data are required.

## Drawing template

`drawings/pair.drawing-record.template.json` is illustrative JSON, **not a valid production drawing file**. `${...}` strings stand for writer-owned values whose exact types are still pending. The filename suffix deliberately avoids claiming that the application can open it.

- `format` shows the proposed `solidcraft-drawing/N` family; `N` is not an allocated version.
- `format_pending` must be supplied by the writer, not assigned by this fixture.
- Logical labels `source_a`, `source_b`, `sheet_a` and `sheet_b` must bind to the owner's collision-free IDs. These strings do not choose the final ID representation.
- Each sheet's `documents` value must bind to its specified source and that design's root component. `bindings.json` records these semantics without inventing the JSON shape of that field.
- Units, paper, border and exclusions are unbound for the same reason.
- `sources` contains no last-seen fingerprint, repository identity, commit hash or embedded source geometry.

Only the drawing name changes between the two templates. The two source paths and logical IDs remain the same.

## Independent mutations

The declarative `scenarios.json` describes actions for a future harness, not CLI commands. Start each A3 subcase from C0:

- **Save As:** relocate the drawing two levels below the repository root; resolve paths back to the same two source blobs.
- **Relink:** move the existing block to `models/block-renamed.solidcraft`, then explicitly relink it. There are still only two source designs.
- **Missing:** remove the plate after establishing a cached view.
- **Changed:** replace only the plate bytes with the C1 plate after establishing C0 cached views; keep the C0 block.
- **Broken internal reference:** bind a sheet to a nonexistent source ID while leaving both source files present. This is a damaged record, not an external missing-file case.

No fabricated container, view-cache binary, drawing command implementation or fake successful runtime report is included.
