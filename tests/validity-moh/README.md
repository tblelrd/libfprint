# Fixed-point enrollment regression vectors

`fixed.keyfile` contains synthetic input images, expected keypoint/metadata
digests, complete envelope digests and enrollment selection/failure scenarios.
The C tests also parse the resulting container and sections independently.
No sensor captures or personal templates are included.

Expectations were frozen before the C-only cleanup from independent Python
models based on python-validity PR #261 (`fork_commit`, `oracle_commit` and
the frozen oracle SHA-256 are recorded in the fixture). The fixed extractor
uses the driver-compatible caps, edge rule, tie ordering and weight indexing;
the tested serializer is `trailer_fixed`. These expectations must not be
regenerated from the implementation under test.

`tables-synthetic/` contains made-up, authenticated tables, not vendor data.
These and all synthetic-image cases run without hardware or vendor files.
Optional `real` cases contain digests only and run when
`FP_VALIDITY_MOH_TABLES_DIR=/path/to/moh` supplies locally extracted tables.
No raw descriptors, pixels derived from fingers or vendor tables belong here.

The comparison extractors, host pose matcher, Python models and detailed stage
dumps remain in the E480 research workspace and are outside this contribution.

The independent generators used for the frozen fixture are preserved at
[E480 research reference revision 20858875](https://gitlab.freedesktop.org/vublayancanavar/libfprint/-/tree/208588751dda4c1c39b70bfd274e969bc5e7d800/tests/validity-moh).
`gen-golden.py` supplies synthetic input images/scenario scripts;
`gen-golden-fixed.py` computes the fixed-point/serializer expectations from
the pinned fork and oracle. This fixture retains the fixed driver-mode,
multi-section and enrollment scenarios from that reference, omitting stage
arrays, alternate modes and raw outputs made with driver tables. For a change
to the algorithm, compare with that independent reference before changing
expected hashes.
