# Tapped-hole catalogue

The Hole dialog offers ISO metric coarse sizes, 15 additional fine diameter/pitch
pairs, and a finite set of 14 UNC and 14 UNF sizes. This is a verified subset,
not complete coverage of these standards. Unified sizes range from #4 through
#12 and 1/4 through 1 inch. Include the family in a designation, for example
`1/4-20 UNC` or `#10-32 UNF`.

Internal units are millimetres. Inch nominal diameters convert using exactly
25.4 mm/in; pitch is 25.4 divided by threads per inch. Numbered screw sizes are
nominal screw diameters, not numbered drill diameters.

For UNC/UNF, the proposed pilot diameter comes from Guhring's **CUT TAPS,
approximately 75% theoretical thread** column. Fractional, letter and numbered
drills are converted to millimetres without rounding away the recommendation.
These are starting recommendations for cutting taps, not form taps. Material,
depth, tolerances, drilling accuracy and the tap manufacturer's process guidance
still determine the appropriate drill; the command's explicit `diameter` can
override the recommendation.

Metric holes retain the existing major-minus-pitch estimate, rounded to 0.001 mm.
This preserves existing command behavior, including M8's 6.75 mm default. It is
not presented as a tabulated 75% cut-tap recommendation. Existing files retain
their saved diameter expressions. Custom metric dimensions remain editable, and
Custom stays selected even when its current dimensions match a catalogue entry.

Tapped holes create the physical pilot bore and cosmetic thread metadata. The
separate Thread command and its automatic sizing remain ISO metric only; this
catalogue does not enable modelled UNC/UNF threads. BSPP/G, BSPT/R, NPT, thread
classes, handedness and sealing behavior are outside this tranche. In particular,
no tapered thread is represented as a cylindrical metric thread.

## Primary sources

- [Guhring, Tap Drill Sizes](https://guhring.com/media/catalogs/lgbkp3ieki4.pdf),
  PDF page 2: UNC/UNF pitch and practical CUT TAPS approximately75% drills;
  page 1: decimal equivalents for named drills. The separate FORM TAPS columns
  are not used. Also verifies 14 of the additional metric fine pairs.
- [PEM, Thread Code Comparison Chart](https://www.pemnet.com/resources/download-center/thread-code-comparison-chart/):
  nominal diameters of #4, #6, #8, #10 and #12 screws.
- [Yamawa, European catalogue, printed page159](https://www.yamawa.eu/wp-content/uploads/Catalogo_sfogliabile_YEU21/files/basic-html/page161.html):
  M12x1.25 diameter/pitch pair. Its product-specific pilot recommendation is not
  used for the retained metric estimate.
- [OSG, Tap Drill Sizes and Pitch Diameter Limits, Vol3 (2024)](https://osgtool.com/800274ca-v3/):
  independent cross-check of UNC/UNF pitches. OSG's calculated percentages and
  Guhring's practical named drills are not interchangeable columns.

## Trial

On a small plate, open Hole, choose Tapped, then switch Profile between ISO metric,
UNC and UNF. Try M8, M8x1, 1/4-20 UNC and #10-32 UNF. Check the displayed drill,
create the hole, save, reopen and check the designation and bore. In ISO metric,
choose Custom, edit the nominal diameter and pitch, and verify that Custom stays
selected and an invalid draft cannot apply an earlier valid value.
