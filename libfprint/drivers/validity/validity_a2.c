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

#define FP_COMPONENT "validity"

#include "drivers_api.h"
#include "validity.h"
#include "validity_a2.h"
#include "validity_fwext.h"
#include "vcsfw_protocol.h"

/* ================================================================
 * Why 00a2 is restricted
 *
 * 06cb:00a2 sensors (ThinkPad E480/L390 and others) ship blank and are
 * provisioned by the Windows driver: it partitions the flash with a
 * signed partition table chosen from the 01 reply, uploads the fwext
 * 6_07f_lenovo_sm_qm, pairs the sensor to the machine's DMI identity and
 * sends a one-time "security update" (the 2020 fix for CVE-2019-18618).
 * Its fwext has no on-chip enroll module (68 answers 0x0401), so
 * enrollment uses the host template builder in fpi_validity_a2_enroll.c.
 *
 * What the driver supports is the state such a sensor is left in: owned
 * and paired (r[37] low nibble 7), security update applied (r[34..35] =
 * 03 d1), fwext loaded (43 02 status 0). From there it reuses the
 * existing pairing (TLS keys in partition 1, PSK from DMI) and only sends
 * the volatile init RAM patch before TLS. It never:
 *   - provisions or re-pairs (reset_blob, 4f, 50, flash erase/write, 05),
 *   - uploads firmware or sends clean_slate or the security update,
 *   - factory-resets (10) -- no code path does that for any device,
 *   - writes partition 6 (calibration stays in RAM, as for all devices),
 *   - erases the template partition on its own (delete reclaim) or via
 *     clear_storage, or deletes template records (48),
 *   - retries a rejected init, with the same or another blob.
 * The gates below refuse every other chip state before the first command
 * that could act on it. Evidence: GET_VERSION/GET_FW_INFO/GET_FLASH_INFO
 * replies of a real E480 sensor (tests/test-validity.c) and static
 * analysis of the vendor driver's DeviceInit (which reads r[12], r[13],
 * r[25], r[34..35] and r[37] the same way).
 * ================================================================ */

static const ValidityDevicePolicy policy_permissive = {
  .safety_gates         = FALSE,
  .allow_provisioning   = TRUE,
  .allow_fwext_upload   = TRUE,
  .allow_clean_slate    = TRUE,
  .allow_enroll         = TRUE,
  .allow_clear_storage  = TRUE,
  .allow_delete         = TRUE,
  .allow_reclaim_erase  = TRUE,
  .allow_usb_reset      = TRUE,
  .allow_reconnect      = TRUE,
  .reset_at_open        = FALSE,
  .init_once_per_instance = FALSE,
  .stream_capture_flow  = FALSE,
  .strict_image_flags   = FALSE,
  .allow_image_capture  = FALSE,
};

/* Init, USB reset and reconnect (00a2):
 * - The init blob is a volatile RAM patch. The vendor driver sends it once
 *   per device object: again after a re-enumeration (driver or PnP
 *   restart), never on a resume that keeps the device, and never with a
 *   USB reset (WinUSB only resets pipes). Re-sending it on a sensor that
 *   already has it was observed to return 0x0000 here (a new process sent
 *   it on top of a previous one), so a new instance re-sends it.
 * - USB reset at probe and at every open: after a host process (or an
 *   open on the same instance) established TLS and closed, the sensor keeps
 *   that session in RAM and answers the next plain 01 with 0x0315. A USB
 *   reset clears it (two runs on hardware, 2026-10-14), as the other
 *   models' probe reset and python-validity's reset on close do. Because a
 *   reset may also drop the RAM patch, an open that reset the device sends
 *   the init again; a rejected or unanswered init still refuses.
 * - No in-driver reconnect: it USB-resets the sensor and re-runs the open
 *   after a TLS or transport error. The vendor driver reacts to a TLS
 *   failure on an owned sensor by factory-resetting it; this driver just
 *   reports the error.
 * Capture and match (fpi_validity_a2_capture.c): the sensor streams the
 * 112x112 image over several 51 replies and errors on a 04 after a
 * complete readout, so verify/identify use the streaming flow. Image
 * flags follow the vendor driver's rule. The diagnostic image capture
 * exists only in developer builds. */
static const ValidityDevicePolicy policy_restricted = {
  .safety_gates         = TRUE,
  .allow_provisioning   = FALSE,
  .allow_fwext_upload   = FALSE,
  .allow_clean_slate    = FALSE,
  .allow_enroll         = FALSE,
  .allow_host_enroll    = TRUE,
  .allow_clear_storage  = FALSE,
  .allow_delete         = FALSE,
  .allow_reclaim_erase  = FALSE,
  .allow_usb_reset      = TRUE,
  .allow_reconnect      = FALSE,
  .reset_at_open        = TRUE,
  .init_once_per_instance = TRUE,
  .stream_capture_flow  = TRUE,
  .strict_image_flags   = FALSE,
  .allow_image_capture  = TRUE,
};

const ValidityDevicePolicy *
fpi_validity_device_policy (guint dev_type)
{
  switch ((ValidityDeviceType) dev_type)
    {
    case VALIDITY_DEV_90:
    case VALIDITY_DEV_97:
    case VALIDITY_DEV_9A:
    case VALIDITY_DEV_9D:
    case VALIDITY_DEV_AB:
    case VALIDITY_DEV_CB:
    case VALIDITY_DEV_B7:
    case VALIDITY_DEV_D2:
      return &policy_permissive;

    case VALIDITY_DEV_A2:
      return &policy_restricted;

    default:
      {
        /* Keep unknown devices read-only, including host enrollment. */
        static const ValidityDevicePolicy unknown = {
          .safety_gates = TRUE,
          .allow_usb_reset = TRUE,
          .reset_at_open = TRUE,
          .init_once_per_instance = TRUE,
          .stream_capture_flow = TRUE,
        };
        return &unknown;
      }
    }
}

FpDeviceFeature
fpi_validity_policy_features_to_clear (const ValidityDevicePolicy *policy,
                                       gboolean                    dev_build)
{
  FpDeviceFeature clear = FP_DEVICE_FEATURE_NONE;

  if (!dev_build || !policy->allow_image_capture)
    clear |= FP_DEVICE_FEATURE_CAPTURE;
  if (!policy->allow_delete)
    clear |= FP_DEVICE_FEATURE_STORAGE_DELETE;
  if (!policy->allow_clear_storage)
    clear |= FP_DEVICE_FEATURE_STORAGE_CLEAR;

  return clear;
}

gboolean
fpi_validity_policy_uses_db_write_enable (const ValidityDevicePolicy *policy)
{
  /* validity_pair.c (provisioning), validity_fwext.c (upload),
   * validity_enroll.c, validity_verify.c (clear_storage and the delete
   * reclaim share clear_run_state) */
  return policy->allow_provisioning || policy->allow_fwext_upload ||
         policy->allow_enroll || policy->allow_host_enroll || policy->allow_clear_storage ||
         policy->allow_reclaim_erase;
}

guint
fpi_validity_policy_drop_unused_data (const ValidityDevicePolicy *policy,
                                      ValidityDataStore          *store)
{
  const struct
  {
    ValidityDataTag tag;
    const gchar    *file;
    gboolean        used;
  } blobs[] = {
    { VALIDITY_DATA_RESET, "reset.bin", policy->allow_provisioning },
    { VALIDITY_DATA_INIT_CLEAN_SLATE, "init_clean_slate.bin",
      policy->allow_clean_slate },
    { VALIDITY_DATA_DB_WRITE_ENABLE, "db_write_enable.bin",
      fpi_validity_policy_uses_db_write_enable (policy) },
  };
  guint dropped = 0;

  for (gsize i = 0; i < G_N_ELEMENTS (blobs); i++)
    {
      if (blobs[i].used || store->entries[blobs[i].tag] == NULL)
        continue;

      fp_info ("Ignoring %s from the data package: this sensor model never "
               "gets it", blobs[i].file);
      g_clear_pointer (&store->entries[blobs[i].tag], g_bytes_unref);
      dropped++;
    }

  return dropped;
}

ValidityInitAction
fpi_validity_init_action (const ValidityDevicePolicy *policy,
                          ValidityInitState           state)
{
  if (policy == NULL || !policy->init_once_per_instance)
    return VALIDITY_INIT_ACTION_SEND;

  switch (state)
    {
    case VALIDITY_INIT_NOT_SENT:
      return VALIDITY_INIT_ACTION_SEND;

    case VALIDITY_INIT_ACCEPTED:
      return VALIDITY_INIT_ACTION_SKIP;

    case VALIDITY_INIT_SENT:
    case VALIDITY_INIT_REJECTED:
    default:
      return VALIDITY_INIT_ACTION_REFUSE;
    }
}

/* ================================================================
 * 01 (GET_VERSION) gate
 * ================================================================ */

#define A2_ROM_PRODUCT 0x30
#define A2_ROM_MAJOR 6
#define A2_ROM_MINOR 7
#define A2_ROM_TARGET 1
#define A2_ROM_STATE_OWNED 7
#define A2_ROM_SECURITY_0 0x03
#define A2_ROM_SECURITY_1 0xd1
/* r[25]: 0x02 = secure mode, 0x20 = production key (the vendor driver
 * picks the _a2 signed partition table by it); the E480 reports 0x23 */
#define A2_ROM_FLAGS_REQUIRED 0x22

ValidityA2RomCheck
fpi_validity_a2_check_rom_info (const guint8 *reply,
                                gsize         reply_len)
{
  if (reply == NULL || reply_len != VALIDITY_A2_ROM_INFO_REPLY_LEN)
    return VALIDITY_A2_ROM_BAD_LENGTH;

  if (reply[0] != 0x00 || reply[1] != 0x00)
    return VALIDITY_A2_ROM_BAD_STATUS;

  if (reply[13] != A2_ROM_PRODUCT)
    return VALIDITY_A2_ROM_WRONG_PRODUCT;

  if (reply[10] != A2_ROM_MAJOR || reply[11] != A2_ROM_MINOR)
    return VALIDITY_A2_ROM_WRONG_VERSION;

  /* The vendor driver aborts DeviceInit unless this byte is 1 */
  if (reply[12] != A2_ROM_TARGET)
    return VALIDITY_A2_ROM_NOT_TARGET_1;

  /* Provisioning state: 2 = blank, 5 = partially provisioned, 6/7 = owned,
   * 0xf = broken. Only the state this sensor was observed in is accepted. */
  if ((reply[37] & 0x0f) != A2_ROM_STATE_OWNED)
    return VALIDITY_A2_ROM_NOT_OWNED;

  /* 03 d1 = the vendor security update is applied; anything else makes the
   * vendor driver (re)send it, which this driver never does */
  if (reply[34] != A2_ROM_SECURITY_0 || reply[35] != A2_ROM_SECURITY_1)
    return VALIDITY_A2_ROM_NOT_PATCHED;

  /* Id of a loaded RAM patch. The vendor driver unloads it with 1a before
   * anything else; it read 00 before and after our init (the init patch
   * does not show here), so any other value is a state never seen */
  if (reply[17] != 0x00)
    return VALIDITY_A2_ROM_PATCH_PENDING;

  /* Without these bits the vendor driver takes other paths (non-secure
   * mode, other partition table); only the observed ones are accepted */
  if ((reply[25] & A2_ROM_FLAGS_REQUIRED) != A2_ROM_FLAGS_REQUIRED)
    return VALIDITY_A2_ROM_NOT_SECURE;

  return VALIDITY_A2_ROM_OK;
}

gboolean
fpi_validity_a2_rom_info_gate (const guint8 *reply,
                               gsize         reply_len,
                               GError      **error)
{
  ValidityA2RomCheck check = fpi_validity_a2_check_rom_info (reply, reply_len);
  g_autofree gchar *reason = NULL;

  switch (check)
    {
    case VALIDITY_A2_ROM_OK:
      fp_info ("06cb:00a2 gate: ROM %u.%u, product 0x%02x, owned (state %u), "
               "security update applied (03 d1), r[17] 0x%02x, r[25] 0x%02x",
               reply[10], reply[11], reply[13], reply[37] & 0x0f, reply[17],
               reply[25]);
      return TRUE;

    case VALIDITY_A2_ROM_BAD_LENGTH:
      reason = g_strdup_printf ("its GET_VERSION reply has %" G_GSIZE_FORMAT
                                " bytes, not %d",
                                reply ? reply_len : 0,
                                VALIDITY_A2_ROM_INFO_REPLY_LEN);
      break;

    case VALIDITY_A2_ROM_BAD_STATUS:
      reason = g_strdup_printf ("GET_VERSION returned status 0x%02x%02x",
                                reply[1], reply[0]);
      break;

    case VALIDITY_A2_ROM_WRONG_PRODUCT:
      reason = g_strdup_printf ("it reports product 0x%02x, not 0x%02x",
                                reply[13], A2_ROM_PRODUCT);
      break;

    case VALIDITY_A2_ROM_WRONG_VERSION:
      reason = g_strdup_printf ("it runs ROM %u.%u, not %d.%d",
                                reply[10], reply[11],
                                A2_ROM_MAJOR, A2_ROM_MINOR);
      break;

    case VALIDITY_A2_ROM_NOT_TARGET_1:
      reason = g_strdup_printf ("GET_VERSION byte 12 is 0x%02x, not 0x%02x",
                                reply[12], A2_ROM_TARGET);
      break;

    case VALIDITY_A2_ROM_NOT_OWNED:
      reason = g_strdup_printf ("its provisioning state is %u, not %d (owned "
                                "and paired); this driver never provisions, "
                                "pairs or factory-resets a 00a2 sensor",
                                reply[37] & 0x0f, A2_ROM_STATE_OWNED);
      break;

    case VALIDITY_A2_ROM_NOT_PATCHED:
      reason = g_strdup_printf ("its security state is %02x %02x, not "
                                "03 d1; this driver never sends the vendor "
                                "security update",
                                reply[34], reply[35]);
      break;

    case VALIDITY_A2_ROM_PATCH_PENDING:
      reason = g_strdup_printf ("GET_VERSION byte 17 is 0x%02x, not 0x00 (a "
                                "loaded RAM patch the vendor driver unloads "
                                "with 1a, which this driver never sends)",
                                reply[17]);
      break;

    case VALIDITY_A2_ROM_NOT_SECURE:
      reason = g_strdup_printf ("GET_VERSION byte 25 is 0x%02x, without the "
                                "secure-mode (0x02) and production-key (0x20) "
                                "bits", reply[25]);
      break;

    default:
      reason = g_strdup_printf ("unknown gate result %d", (gint) check);
      break;
    }

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
               "Refusing to use this 06cb:00a2 sensor: %s. Only a sensor "
               "already set up by the vendor driver is supported", reason);
  return FALSE;
}

/* ================================================================
 * 43 02 (GET_FW_INFO) gate
 * ================================================================ */

gboolean
fpi_validity_a2_fwext_gate (const guint8 *reply,
                            gsize         reply_len,
                            GError      **error)
{
  ValidityFwInfo info;
  guint16 status = 0;

  if (!fpi_vcsfw_parse_status (reply, reply_len, &status))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
                   "Refusing to use this 06cb:00a2 sensor: its GET_FW_INFO "
                   "reply is too short (%" G_GSIZE_FORMAT " bytes)",
                   reply ? reply_len : 0);
      return FALSE;
    }

  if (status != VCSFW_STATUS_OK)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
                   "Refusing to use this 06cb:00a2 sensor: it has no "
                   "firmware extension loaded (GET_FW_INFO status 0x%04x). "
                   "This driver never uploads firmware to a 00a2 sensor "
                   "(it would need %s)", status,
                   fpi_validity_fwext_get_firmware_name (0x06cb, 0x00a2, NULL));
      return FALSE;
    }

  if (!fpi_validity_fwext_parse_fw_info (reply + 2, reply_len - 2, status, &info) ||
      !info.loaded)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
                   "Refusing to use this 06cb:00a2 sensor: its GET_FW_INFO "
                   "reply (%" G_GSIZE_FORMAT " bytes) cannot be parsed",
                   reply_len);
      return FALSE;
    }

  fp_info ("06cb:00a2 gate: firmware extension %u.%u loaded "
           "(build time 0x%08x, %u modules)",
           info.major, info.minor, info.buildtime, info.module_count);
  return TRUE;
}

/* ================================================================
 * 06<init> gate
 * ================================================================ */

gboolean
fpi_validity_a2_init_gate (const guint8 *reply,
                           gsize         reply_len,
                           GError      **error)
{
  guint16 status = 0;

  if (!fpi_vcsfw_parse_status (reply, reply_len, &status))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "The 06cb:00a2 sensor's reply to the init blob is too "
                   "short (%" G_GSIZE_FORMAT " bytes); not continuing",
                   reply ? reply_len : 0);
      return FALSE;
    }

  /* The vendor driver also accepts 0x0412 and 0x0491 here and retries on
   * 0x0401; only 0x0000 was observed on this sensor, so anything else
   * stops the open. No other blob is tried. */
  if (status != VCSFW_STATUS_OK)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "The 06cb:00a2 sensor rejected the init blob (status "
                   "0x%04x); not retrying it or any other blob", status);
      return FALSE;
    }

  return TRUE;
}

/* ================================================================
 * The init blob itself
 * ================================================================ */

/* 06: load a RAM patch (the init blob is one) */
#define A2_CMD_LOAD_PATCH 0x06

gboolean
fpi_validity_a2_init_blob_check (const guint8 *data,
                                 gsize         len,
                                 gsize         expected_len,
                                 const gchar  *expected_sha256,
                                 GError      **error)
{
  g_autofree gchar *digest = NULL;

  if (data == NULL || len == 0 || len != expected_len ||
      data[0] != A2_CMD_LOAD_PATCH)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "The init blob in the data package (%" G_GSIZE_FORMAT
                   " bytes, first byte 0x%02x) is not the reviewed "
                   "06cb:00a2 init blob (%" G_GSIZE_FORMAT " bytes, 0x%02x); "
                   "not sending it", data ? len : 0,
                   data && len ? data[0] : 0, expected_len,
                   A2_CMD_LOAD_PATCH);
      return FALSE;
    }

  digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256, data, len);
  if (g_strcmp0 (digest, expected_sha256) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "The init blob in the data package (sha256 %s) is not the "
                   "reviewed 06cb:00a2 init blob (sha256 %s); not sending it",
                   digest, expected_sha256);
      return FALSE;
    }

  return TRUE;
}

gboolean
fpi_validity_a2_init_blob_ok (const guint8 *data,
                              gsize         len,
                              GError      **error)
{
  return fpi_validity_a2_init_blob_check (data, len, VALIDITY_A2_INIT_BLOB_LEN,
                                          VALIDITY_A2_INIT_BLOB_SHA256, error);
}

/* ================================================================
 * Sensor gate (75 / capture setup / calibration)
 * ================================================================ */

/* 57K0 type 0x199 (python-validity SensorTypeInfo): 0x78 bytes per line,
 * 2x repeat, 112 calibration lines -> 224 lines per frame, key
 * calibration line 0x38; 3 calibration frames, 3 iterations */
#define A2_BYTES_PER_LINE 0x78
#define A2_LINES_PER_FRAME 224
#define A2_KEY_CALIBRATION_LINE 0x38
#define A2_CALIBRATION_FRAMES 3
#define A2_CALIBRATION_ITERATIONS 3

ValidityA2SensorCheck
fpi_validity_a2_check_sensor (guint16                     sensor_type,
                              guint16                     real_sensor_type,
                              const ValidityCaptureState *capture,
                              gboolean                    need_calibration)
{
  if (sensor_type == 0)
    return VALIDITY_A2_SENSOR_UNKNOWN;

  if (sensor_type != VALIDITY_A2_SENSOR_TYPE ||
      real_sensor_type != VALIDITY_A2_SENSOR_TYPE)
    return VALIDITY_A2_SENSOR_WRONG_TYPE;

  if (capture == NULL || capture->capture_prog == NULL ||
      capture->capture_prog_len == 0 || !capture->is_type1_device)
    return VALIDITY_A2_SENSOR_NO_CAPTURE_PROG;

  if (capture->bytes_per_line != A2_BYTES_PER_LINE ||
      capture->lines_per_frame != A2_LINES_PER_FRAME ||
      capture->key_calibration_line != A2_KEY_CALIBRATION_LINE ||
      capture->calibration_frames != A2_CALIBRATION_FRAMES ||
      capture->calibration_iterations != A2_CALIBRATION_ITERATIONS)
    return VALIDITY_A2_SENSOR_WRONG_GEOMETRY;

  if (capture->factory_calibration_values == NULL ||
      capture->factory_calibration_values_len <= A2_KEY_CALIBRATION_LINE)
    return VALIDITY_A2_SENSOR_NO_FACTORY_CAL;

  if (need_calibration &&
      (capture->calib_data == NULL || capture->calib_data_len == 0))
    return VALIDITY_A2_SENSOR_NOT_CALIBRATED;

  return VALIDITY_A2_SENSOR_OK;
}

gboolean
fpi_validity_a2_sensor_gate (guint16                     sensor_type,
                             guint16                     real_sensor_type,
                             const ValidityCaptureState *capture,
                             gboolean                    need_calibration,
                             GError                    **error)
{
  const gchar *reason;

  switch (fpi_validity_a2_check_sensor (sensor_type, real_sensor_type, capture,
                                        need_calibration))
    {
    case VALIDITY_A2_SENSOR_OK:
      return TRUE;

    case VALIDITY_A2_SENSOR_UNKNOWN:
      reason = "its sensor type could not be identified";
      break;

    case VALIDITY_A2_SENSOR_WRONG_TYPE:
      reason = "it is not sensor type 0x199";
      break;

    case VALIDITY_A2_SENSOR_NO_CAPTURE_PROG:
      reason = "no capture program is known for it";
      break;

    case VALIDITY_A2_SENSOR_WRONG_GEOMETRY:
      reason = "its capture geometry differs from sensor type 0x199";
      break;

    case VALIDITY_A2_SENSOR_NO_FACTORY_CAL:
      reason = "its factory calibration values are missing";
      break;

    case VALIDITY_A2_SENSOR_NOT_CALIBRATED:
      reason = "the sensor calibration did not run";
      break;

    default:
      reason = "unknown sensor check result";
      break;
    }

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
               "Refusing to capture with this 06cb:00a2 sensor: %s "
               "(type 0x%04x)", reason, sensor_type);
  return FALSE;
}
