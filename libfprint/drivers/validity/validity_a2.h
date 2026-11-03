/*
 * 06cb:00a2 ("Metallica" VCSFW) device policy and safety gates
 *
 * Copyright (C) 2026 libfprint contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <glib.h>
#include "fp-device.h"
#include "validity_capture.h"
#include "validity_data.h"

/* ================================================================
 * Per-device-type policy
 *
 * What the driver may do to a sensor of a given device type. Every type
 * that existed before 06cb:00a2 gets the permissive policy, which is the
 * driver's behaviour unchanged. 06cb:00a2 gets the restricted policy: the
 * driver only works with a sensor that the vendor driver already owns,
 * paired and updated, and never changes its flash layout, pairing,
 * firmware or calibration partition (see validity_a2.c).
 * ================================================================ */
typedef struct
{
  /* Check the 01, 43 02 and 06<init> replies of every open against the
  * single chip state the type is supported in (validity_a2_*_gate). */
  gboolean safety_gates;

  /* Pairing a sensor with no partitions: reset_blob, partition_flash
   * (4f), 50, erase (3f), write (41), reboot (05). */
  gboolean allow_provisioning;

  /* Firmware-extension upload when 43 02 reports none (incl. its 05). */
  gboolean allow_fwext_upload;

  /* init_clean_slate when no firmware extension is loaded. */
  gboolean allow_clean_slate;

  /* On-chip enrollment (69/68/6b, 47 stores, db_write_enable). */
  gboolean allow_enroll;

  /* Host template enrollment (00a2), without 69/68/6b. */
  gboolean allow_host_enroll;

  /* clear_storage: db_write_enable + erase of the template partition. */
  gboolean allow_clear_storage;

  /* delete: 48 (del_record) of the print's finger record and of its user
   * record once empty -- persistent template DB writes. */
  gboolean allow_delete;

  /* Erase the template partition after deleting the last print. */
  gboolean allow_reclaim_erase;

  /* g_usb_device_reset() at probe. */
  gboolean allow_usb_reset;

  /* Tier-0 in-driver reconnect after an error mid-operation (USB reset,
   * then the whole open sequence again). */
  gboolean allow_reconnect;

  /* USB-reset the device at every open (before the first command) and send
   * the init blob again after it. 06cb:00a2 keeps its TLS session in RAM
   * after a close and answers the next plain command with 0x0315; a USB
   * reset clears that (hardware, 2026-10-14). */
  gboolean reset_at_open;

  /* Send the init blob once per device instance (one USB enumeration),
   * not on every open; see fpi_validity_init_action(). */
  gboolean init_once_per_instance;

  /* Verify and identify run the image-streaming flow of
   * fpi_validity_a2_capture.c: exact EP 0x83 event codes, the image read with
   * several 51 requests, no 04 after a complete readout (04 only to stop a
   * capture that was not read), the 5e handle passed to 60/62, a strict 60
   * parser with the tag-2 rule, a bounded match wait, and cleanup
   * (04/62/39) on cancel. */
  gboolean stream_capture_flow;

  /* Image header flags: FALSE = the vendor driver's rule (use an image
   * whose flags lack bit 31), TRUE = reject any non-zero flags. Only used
   * by stream_capture_flow. */
  gboolean strict_image_flags;

  /* FpDevice::capture (one 112x112 image) for diagnostics. Only in a
   * developer build (meson -Dvalidity_dev=true); never in a package. */
  gboolean allow_image_capture;
} ValidityDevicePolicy;

/* Policy for a ValidityDeviceType value. Never NULL: an unknown type gets
 * the restricted policy (fail closed). */
const ValidityDevicePolicy *fpi_validity_device_policy (guint dev_type);

/* The FpDevice features dev_probe clears for @policy, so that neither the
 * libfprint core nor fprintd calls an action the driver refuses: image
 * capture unless this is a developer build (@dev_build) and the policy
 * allows it, storage delete without allow_delete, storage clear without
 * allow_clear_storage. Listing stays. */
FpDeviceFeature fpi_validity_policy_features_to_clear (const ValidityDevicePolicy *policy,
                                                       gboolean                    dev_build);

/* Whether @policy allows any operation that sends db_write_enable
 * (provisioning, fwext upload, enrollment, clear_storage, delete reclaim) */
gboolean fpi_validity_policy_uses_db_write_enable (const ValidityDevicePolicy *policy);

/* Free the data-package blobs that @policy never sends (reset.bin without
 * provisioning, init_clean_slate.bin without clean_slate,
 * db_write_enable.bin without any operation that uses it), so that no
 * later code path can find them. Returns how many were dropped. */
guint fpi_validity_policy_drop_unused_data (const ValidityDevicePolicy *policy,
                                            ValidityDataStore          *store);

/* What happened to the init blob (06<init>) on this device instance. Kept
 * for the lifetime of the FpDevice, across open/close. */
typedef enum {
  VALIDITY_INIT_NOT_SENT = 0,
  VALIDITY_INIT_SENT,        /* sent, no verdict yet (or the reply was lost) */
  VALIDITY_INIT_ACCEPTED,    /* status 0x0000 */
  VALIDITY_INIT_REJECTED,    /* any other status */
} ValidityInitState;

typedef enum {
  VALIDITY_INIT_ACTION_SEND = 0,
  VALIDITY_INIT_ACTION_SKIP,     /* already accepted on this instance */
  VALIDITY_INIT_ACTION_REFUSE,   /* sent before without being accepted */
} ValidityInitAction;

/* Whether an open sends the init blob. Without init_once_per_instance it
 * is sent on every open (the driver's behaviour for other types). With
 * it, it is sent once per device instance; after a rejection or a lost
 * reply the instance refuses to open, so the blob is never re-sent until
 * the device is enumerated again (fprintd restart, re-plug, reboot). */
ValidityInitAction fpi_validity_init_action (const ValidityDevicePolicy *policy,
                                             ValidityInitState           state);

/* ================================================================
 * 06cb:00a2 safety gates
 *
 * Each gate takes a raw reply (wire bytes, 2-byte status included) and
 * returns TRUE if the driver may continue, or FALSE with an
 * FP_DEVICE_ERROR that says why it refuses. They never trigger any
 * device traffic; the caller fails the open.
 * ================================================================ */

/* Length of the GET_VERSION (01) reply of the 00a2 ROM, status included */
#define VALIDITY_A2_ROM_INFO_REPLY_LEN 38

/* Result of fpi_validity_a2_check_rom_info(). Byte indexes r[n] count from the
 * first status byte of the 01 reply. */
typedef enum {
  VALIDITY_A2_ROM_OK = 0,
  VALIDITY_A2_ROM_BAD_LENGTH,     /* reply is not 38 bytes */
  VALIDITY_A2_ROM_BAD_STATUS,     /* r[0..1] != 00 00 */
  VALIDITY_A2_ROM_WRONG_PRODUCT,  /* r[13] != 0x30 */
  VALIDITY_A2_ROM_WRONG_VERSION,  /* r[10].r[11] != 6.7 */
  VALIDITY_A2_ROM_NOT_TARGET_1,   /* r[12] != 1 */
  VALIDITY_A2_ROM_NOT_OWNED,      /* r[37] & 0xf != 7 (owned and paired) */
  VALIDITY_A2_ROM_NOT_PATCHED,    /* r[34..35] != 03 d1 (security update) */
  VALIDITY_A2_ROM_PATCH_PENDING,  /* r[17] != 0: a RAM patch the vendor
                                   * driver unloads (1a) before anything */
  VALIDITY_A2_ROM_NOT_SECURE,     /* r[25] lacks 0x02 (secure mode) or 0x20
                                   * (production key / _a2 partition table) */
} ValidityA2RomCheck;

ValidityA2RomCheck fpi_validity_a2_check_rom_info (const guint8 *reply,
                                                   gsize         reply_len);

/* 01 (GET_VERSION): owned, patched 00a2 ROM 6.7, product 0x30, r[12] = 1,
 * no RAM patch reported (r[17] = 0), secure mode and production key set in
 * r[25] -- the state of the one sensor this driver was validated with */
gboolean fpi_validity_a2_rom_info_gate (const guint8 *reply,
                                        gsize         reply_len,
                                        GError      **error);

/* 43 02 (GET_FW_INFO): status 0 and a parseable, loaded fwext */
gboolean fpi_validity_a2_fwext_gate (const guint8 *reply,
                                     gsize         reply_len,
                                     GError      **error);

/* 06<init>: status 0x0000, nothing else (never retried, never another blob) */
gboolean fpi_validity_a2_init_gate (const guint8 *reply,
                                    gsize         reply_len,
                                    GError      **error);

/* The only init blob the driver sends to 06cb:00a2: 06 + the vendor
 * driver's init descriptor (synaWudfBioUsb 5.2.326.26, descriptor index
 * 31; python-validity PR #261 init_hardcoded), the blob the E480 sensor
 * accepted with status 0x0000. The data package's HMAC key is public, so
 * the HMAC only catches accidents; this pin makes sure that no other 06
 * blob (another generation, the security update, the reset blob) can be
 * sent from a package that happens to be installed. */
#define VALIDITY_A2_INIT_BLOB_LEN 581
#define VALIDITY_A2_INIT_BLOB_SHA256 \
  "0f3128a1c93b49f0a5162bbad26b22ae02f539ab0668678ea090449922e39674"

/* TRUE if @data is @expected_len bytes, starts with 06 and its SHA-256
 * is @expected_sha256 (lowercase hex); else FALSE with
 * FP_DEVICE_ERROR_DATA_INVALID. */
gboolean fpi_validity_a2_init_blob_check (const guint8 *data,
                                          gsize         len,
                                          gsize         expected_len,
                                          const gchar  *expected_sha256,
                                          GError      **error);

/* fpi_validity_a2_init_blob_check() against the pinned 00a2 init blob */
gboolean fpi_validity_a2_init_blob_ok (const guint8 *data,
                                       gsize         len,
                                       GError      **error);

/* ================================================================
 * 06cb:00a2 sensor gate (after 75, 6f and the capture setup)
 *
 * The capture and calibration code was written for the 57K0 sensor type
 * 0x199 that this sensor reports (75: major 0x0190, version 0x6a). Refuse
 * anything else before the first capture program is sent, and refuse to
 * finish an open without a calibration (the sensor will not capture
 * without one; it is kept in RAM only, never written to flash).
 * ================================================================ */

#define VALIDITY_A2_SENSOR_TYPE 0x0199

typedef enum {
  VALIDITY_A2_SENSOR_OK = 0,
  VALIDITY_A2_SENSOR_UNKNOWN,          /* 75 did not resolve to a type */
  VALIDITY_A2_SENSOR_WRONG_TYPE,       /* not 0x199, or aliased */
  VALIDITY_A2_SENSOR_NO_CAPTURE_PROG,  /* capture setup failed */
  VALIDITY_A2_SENSOR_WRONG_GEOMETRY,   /* not 0x78 B/line, 224 lines, key 0x38 */
  VALIDITY_A2_SENSOR_NO_FACTORY_CAL,   /* no factory value for the key line */
  VALIDITY_A2_SENSOR_NOT_CALIBRATED,   /* no calibration data after open */
} ValidityA2SensorCheck;

/* @sensor_type: the type 75 resolved to (0 if none); @real_sensor_type:
 * after the driver's silicon aliasing; @need_calibration: also require the
 * calibration data (end of open) */
ValidityA2SensorCheck fpi_validity_a2_check_sensor (guint16                     sensor_type,
                                                    guint16                     real_sensor_type,
                                                    const ValidityCaptureState *capture,
                                                    gboolean                    need_calibration);

gboolean fpi_validity_a2_sensor_gate (guint16                     sensor_type,
                                      guint16                     real_sensor_type,
                                      const ValidityCaptureState *capture,
                                      gboolean                    need_calibration,
                                      GError                    **error);
