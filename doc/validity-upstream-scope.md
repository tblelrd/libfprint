# VCSFW driver contribution and 06cb:00a2 extension

This branch targets official libfprint master. It includes the native VCSFW
prerequisite submitted in [MR !626](https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/626)
and the E480 extension. Its relationship to !626 is explicit; this does not
assert that the earlier MR is abandoned or superseded by maintainer agreement.

## Authorship and review boundaries

The original 38 prerequisite commits through `1cf22b8` are preserved unchanged:
37 by Gary T. Giesen and the initial driver commit by Leonardo Francisco.
One following commit adds the reduced E480 support. A final integration commit
applies the internal `fpi_` naming rule to the prerequisite driver as well and
adds this scope note. There is no new public application API.

The E480 template algorithm incorporates work from Dmitry Muzyka's
python-validity PR #261. Its MIT notice is retained in
`libfprint/drivers/validity/COPYING.python-validity`; native source files
retain their LGPL notices. The independent fixed-point regression vectors
record their reference commits and derivation.

The driver operates natively in C. It does not load or call a vendor DLL.
Runtime signed blobs and algorithm tables are external dependencies, not
included in this branch. Their extraction/distribution and support for other
sensor models remain subjects for upstream review. The two prerequisite
Python programs are USB replay and manual hardware-test tools, not the
fingerprint enrollment implementation. MOH research models/generators and
experimental template variants are excluded.

## Hardware and validation limits

The E480 observations are documented in `validity-00a2-hardware.md` and refer
to the previously installed revision, not a hardware run of this branch.
The enabled 00a2 state reuses existing ownership/pairing; it does not provision
or erase the sensor. The prerequisite driver's paths for other device models
are inherited from !626, not hardware-validated by the E480 work.

All preparation/verification runs here use offline scripted devices. Neither
the manual hardware test nor a real-device enrollment is part of the MR
preparation workflow. CI/replay availability and the unexplained earlier
post-wake failure remain disclosed in the hardware report.
