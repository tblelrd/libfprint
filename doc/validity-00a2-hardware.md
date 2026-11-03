# ThinkPad E480 / Synaptics 06cb:00a2 hardware results

Tested on 2026-10-14 with the native validity driver based on libfprint MR !626, development/integration revision 90b65ef, fprintd 1.94.5-2, and Omarchy on Arch Linux. This is a single-reader functional report; it does not measure false acceptance, false rejection, or long-term reliability rates.

## Sensor and supported state

- USB 06cb:00a2; ROM 6.7, product 0x30, build 164.
- Firmware extension 1.3 already loaded; FM-3380-001b / sensor type 0x0199.
- Owned sensor with the security update applied. The driver reuses the existing Windows pairing.
- No provisioning, factory reset, partition erase, pairing replacement, firmware upload, or calibration-flash rewrite was needed.

## Observed behavior

- Probe/open, accepted init, authenticated encrypted session and three RAM calibration iterations passed.
- Two open/close cycles on the same FpDevice passed: open resets the reader, re-sends init, creates a fresh TLS session and recalibrates.
- Host enrollment used six placements and the trailer_fixed builder. One template was stored successfully after checking database space. Final record readback and FpPrint serialization succeeded.
- A fresh process/open verified the saved reference successfully. Subsequent scans matched the enrolled finger and rejected other fingers in the user's basic checks. The scan logs are not labeled sufficiently to estimate error rates.
- Cancelling a finger wait completed capture/LED cleanup; the next scan matched on the same open device without a reset in between.
- Native closed-session suspend/resume passed, followed by a fresh-open match after wake.
- Production packages with validity_dev=false worked through the standard native fprintd daemon. An existing serialized reference was imported; migration did not enroll again.
- A traced daemon suspend/resume cycle and a subsequent normal-logging cycle passed. The latter requested one retry-scan and then matched after wake.
- Omarchy sudo, polkit, fingerprint lock unlock and password fallback were reported working by the user. The lock fingerprint and password paths were explicitly confirmed before the final all-tests-complete confirmation.
- The temporary raw-user USB access rule/ACL was removed; native fprintd still matched afterward.

## Limitations and failures kept in the report

An early test helper incorrectly assumed systemctl suspend waited for wake; the resulting USB open crossed physical sleep and failed. The helper was corrected to subscribe to logind PrepareForSleep before requesting suspend and wait for the completed cycle.

One later, correctly synchronized native-fprintd cycle stalled after wake with no sensor light and eventually returned an empty-image protocol error. It did not reproduce in the subsequent traced and normal-daemon cycles. Its cause remains unexplained; no driver change is claimed to have fixed it.

Deletion, clear-storage, database compaction, unsupported firmware states and other 00a2 sensor/ROM combinations are not validated. Active-operation physical sleep was tested only through scripted devices, not on hardware. The enabled state is deliberately narrower than the entire model family.

## Offline validation and data

The installed revision's production build passed 11 applicable test suites. The reduced contribution keeps the tested fixed-point template implementation and focused coverage: eight selected suites pass, including 49 template cases and scripted open/capture/enrollment/cancellation/suspend sequences; one replay suite skips for unavailable dependencies. Driver-table cases use locally supplied data and compare stored digests. The cleanup has been validated offline and has not been installed or tested again on the physical reader. Generic socket-dependent context/device suites cannot run in this sandbox. Three driver suites also pass under address/undefined-behavior sanitizers; leak checking is disabled because LeakSanitizer cannot run under the sandbox tracer.

Runtime signed blobs and MOH tables are external, obtained from the local vendor driver data; they are not embedded in this source contribution. Synthetic fixture tables are labeled as such. The report includes no fingerprint images/templates, Windows pairing keys, DMI serial, database backup or identifying device serial. Original data and logs remain private.

The MIT notice for Python-derived portions is retained in libfprint/drivers/validity/COPYING.python-validity. Credit for the existing native VCSFW driver goes to MR !626 contributors; the Python MOH baseline is Dmitry Muzyka's PR #261 work.
