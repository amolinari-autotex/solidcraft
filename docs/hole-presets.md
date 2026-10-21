# Personal Hole presets

Open **Hole**, expand **Personal presets**, and enter a name. **Save new** stores
the current hole parameters in this application's personal profile. The presets are
available in every project using that profile and survive restarting the application.

Select a saved name and press **Recall** to fill the open Hole form. Selecting a
name alone does not change its fields. Recall does not create or edit a feature;
the normal Hole **OK/Apply** operation validates and commits it. Cancel closes the
Hole form without changing the model. Saving, renaming or deleting a personal preset
is a preference change, independent of cancelling the Hole operation.

Presets include simple or drilled holes, counterbores, countersinks, tapping and
the extent mode. Dimensions, thread designations, expression text and explicit units
are retained without baking them into numeric results. Implicit length units are
written explicitly when saving, including mm; unitless expressions keep their text
inside an explicit unit expression. An expression using a named project parameter is evaluated
in the destination project by the normal Hole operation; the preset does not copy
that project's parameters.

Positions, faces, sketch identifiers, placement mode, target bodies, direction picks,
history and connection data are excluded. **To Object** retains only the extent
choice and requires a fresh destination selection after Recall. Current placement
picks remain in the open form.

Use **Rename** with the selected preset and a new name. **Delete** asks for a second
confirmation and removes only the personal preset. Neither operation edits existing
holes. Names are unique ignoring case. Saving an existing name reports a conflict
instead of replacing it silently.

The library is limited to 64 entries, names to 96 UTF-8 bytes and each parameter
expression to 512 UTF-8 bytes. Malformed saved rows are ignored without discarding
other valid preferences. Preference-page resets do not erase the library. There is
no design-file format change or dependency on a project, PDM service or connection.

The preference record reserves defaulted thread options for future independent
thread-depth and handedness changes. This version keeps those options on rename
and serialization, but rejects Recall when they contain values its Hole dialog
cannot represent. No support for those future features is implied.
