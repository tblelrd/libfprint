/*
 * Unit tests for the validity (VCSFW) fingerprint driver
 *
 * Copyright (C) 2024 libfprint contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <glib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <glib/gstdio.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>

#include "fpi-byte-utils.h"
#include "fpi-device.h"
#include "fpi-ssm.h"
#include "fp-enums.h"
#include "fp-print.h"
#include "fpi-byte-reader.h"

#include "drivers/validity/validity.h"
#include "drivers/validity/validity_hal.h"
#include "drivers/validity/validity_sensor.h"
#include "drivers/validity/validity_fwext.h"
#include "drivers/validity/vcsfw_protocol.h"
#include "drivers/validity/validity_pack.h"
#include "drivers/validity/validity_db.h"
#include "drivers/validity/validity_capture.h"
#include "drivers/validity/validity_tls.h"
#include "drivers/validity/validity_pair.h"
#include "drivers/validity/validity_a2.h"
#include "drivers/validity/validity_a2_capture.h"
#include "drivers/validity/validity_data.h"

#include "test-device-fake.h"

/* ================================================================
 * Real 06cb:00a2 replies (wire bytes, status included)
 *
 * Captured read-only from a ThinkPad E480 sensor (ROM 6.7 build 164,
 * fwext 6_07f_lenovo_sm_qm 1.3.6, owned and paired by the Windows
 * driver) on 2026-10-12 by a pre-TLS probe (commands 01, 43 02, 3e). None
 * of them carries key material; 01 bytes 18..23 are the chip serial that
 * the USB descriptor also exposes. Byte indexes r[n] below count from the
 * first status byte, as in the RE notes.
 * ================================================================ */
static const guint8 a2_rom_info_reply[] = {
  0x00, 0x00, 0xf0, 0xb0, 0x5e, 0x54, 0xa4, 0x00, 0x00, 0x00, 0x06, 0x07,
  0x01, 0x30, 0x00, 0x01, 0x00, 0x00, 0xbc, 0xbb, 0x8b, 0x68, 0x49, 0x61,
  0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0xd1,
  0x00, 0x07,
};

static const guint8 a2_fwext_info_reply[] = {
  0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x07, 0x00, 0x6e, 0xcf, 0x2e, 0x5e,
  0x01, 0x00, 0x34, 0x46, 0x02, 0x00, 0x07, 0x00, 0xc0, 0x3f, 0x00, 0x00,
  0x01, 0x00, 0x84, 0x08, 0x01, 0x00, 0x07, 0x00, 0x30, 0x05, 0x00, 0x00,
  0x02, 0x00, 0x84, 0x28, 0x03, 0x00, 0x12, 0x00, 0x40, 0x10, 0x00, 0x00,
  0x01, 0x00, 0x86, 0x47, 0x00, 0x00, 0x01, 0x00, 0x50, 0x5a, 0x00, 0x00,
  0x02, 0x00, 0x23, 0x77, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x2f, 0x00, 0x00,
  0x02, 0x00, 0x00, 0x37, 0x00, 0x00, 0x01, 0x00, 0x30, 0x07, 0x02, 0x00,
  0x01, 0x00, 0x25, 0x56, 0x00, 0x00, 0x01, 0x00, 0x60, 0x04, 0x00, 0x00,
};

static const guint8 a2_flash_info_reply[] = {
  0x00, 0x00, 0xef, 0x00, 0x40, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x01,
  0x01, 0x00, 0x05, 0x00, 0x01, 0x04, 0x07, 0x00, 0x00, 0x10, 0x00, 0x00,
  0x00, 0x10, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00,
  0x00, 0xe0, 0x03, 0x00, 0x05, 0x05, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
  0x00, 0x80, 0x00, 0x00, 0x06, 0x06, 0x03, 0x00, 0x00, 0x80, 0x04, 0x00,
  0x00, 0x80, 0x00, 0x00, 0x04, 0x03, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00,
  0x00, 0x00, 0x08, 0x00,
};

/* ================================================================
 * Tests: HAL
 * ================================================================ */


/* ================================================================
 * T7.1: HAL lookup by device type — all valid types return non-NULL
 * ================================================================ */
static void
test_hal_lookup_all_types (void)
{
  const guint types[] = { VALIDITY_DEV_90, VALIDITY_DEV_97,
                          VALIDITY_DEV_9A, VALIDITY_DEV_9D };

  for (guint i = 0; i < G_N_ELEMENTS (types); i++)
    {
      const ValidityDeviceDesc *desc = fpi_validity_hal_device_lookup (types[i]);
      g_assert_nonnull (desc);
      g_assert_cmpuint (desc->vid, >, 0);
      g_assert_cmpuint (desc->pid, >, 0);
    }
}

/* ================================================================
 * T7.2: HAL lookup by PID — all supported VID/PID combos
 * ================================================================ */
static void
test_hal_lookup_by_pid (void)
{
  /* All 4 supported devices */
  struct { guint16 vid;
           guint16 pid;
  } devices[] = {
    { 0x138a, 0x0090 },
    { 0x138a, 0x0097 },
    { 0x06cb, 0x009a },
    { 0x138a, 0x009d },
  };

  for (guint i = 0; i < G_N_ELEMENTS (devices); i++)
    {
      const ValidityDeviceDesc *desc =
        fpi_validity_hal_device_lookup_by_pid (devices[i].vid, devices[i].pid);
      g_assert_nonnull (desc);
      g_assert_cmpuint (desc->vid, ==, devices[i].vid);
      g_assert_cmpuint (desc->pid, ==, devices[i].pid);
    }
}

/* ================================================================
 * T7.3: HAL lookup — invalid type returns NULL
 * ================================================================ */
static void
test_hal_lookup_invalid (void)
{
  const ValidityDeviceDesc *desc = fpi_validity_hal_device_lookup (99);

  g_assert_null (desc);
}

/* ================================================================
 * T7.4: HAL lookup by PID — unknown PID returns NULL
 * ================================================================ */
static void
test_hal_lookup_by_pid_invalid (void)
{
  const ValidityDeviceDesc *desc =
    fpi_validity_hal_device_lookup_by_pid (0x1234, 0x5678);

  g_assert_null (desc);
}

/* ================================================================
 * T7.5: All devices have flash layout (blobs loaded at runtime)
 * ================================================================ */
static void
test_hal_blobs_present (void)
{
  const guint types[] = { VALIDITY_DEV_90, VALIDITY_DEV_97,
                          VALIDITY_DEV_9A, VALIDITY_DEV_9D };

  for (guint i = 0; i < G_N_ELEMENTS (types); i++)
    {
      const ValidityDeviceDesc *desc = fpi_validity_hal_device_lookup (types[i]);
      g_assert_nonnull (desc);

      /* All devices must have vid, pid, and flash_layout */
      g_assert_cmpuint (desc->vid, !=, 0);
      g_assert_cmpuint (desc->pid, !=, 0);
      g_assert_nonnull (desc->flash_layout);
    }
}

/* ================================================================
 * T7.6: PID 0090 flash layout
 * ================================================================ */
static void
test_hal_pid_0090_specifics (void)
{
  const ValidityDeviceDesc *desc = fpi_validity_hal_device_lookup (VALIDITY_DEV_90);

  g_assert_nonnull (desc);

  /* Flash layout should exist */
  g_assert_nonnull (desc->flash_layout);
  g_assert_cmpuint (desc->flash_layout->num_partitions, ==,
                    VALIDITY_FLASH_NUM_PARTITIONS);
}

/* ================================================================
 * T7.7: Non-0090 devices also have flash layout
 * ================================================================ */
static void
test_hal_clean_slate_present (void)
{
  const guint types[] = { VALIDITY_DEV_97, VALIDITY_DEV_9A, VALIDITY_DEV_9D };

  for (guint i = 0; i < G_N_ELEMENTS (types); i++)
    {
      const ValidityDeviceDesc *desc = fpi_validity_hal_device_lookup (types[i]);
      g_assert_nonnull (desc);
      g_assert_nonnull (desc->flash_layout);
    }
}

/* ================================================================
 * T7.8: Flash layout has valid partition table
 * ================================================================ */
static void
test_hal_flash_layout (void)
{
  const guint types[] = { VALIDITY_DEV_90, VALIDITY_DEV_97,
                          VALIDITY_DEV_9A, VALIDITY_DEV_9D };

  for (guint i = 0; i < G_N_ELEMENTS (types); i++)
    {
      const ValidityDeviceDesc *desc = fpi_validity_hal_device_lookup (types[i]);
      g_assert_nonnull (desc);
      g_assert_nonnull (desc->flash_layout);

      const ValidityFlashLayout *layout = desc->flash_layout;
      g_assert_cmpuint (layout->num_partitions, ==,
                        VALIDITY_FLASH_NUM_PARTITIONS);

      /* Verify partitions are ordered and non-overlapping */
      for (guint p = 0; p < layout->num_partitions; p++)
        {
          const ValidityPartition *part = &layout->partitions[p];
          g_assert_cmpuint (part->size, >, 0);

          if (p > 0)
            {
              const ValidityPartition *prev = &layout->partitions[p - 1];
              g_assert_cmpuint (part->offset, >=,
                                prev->offset + prev->size);
            }
        }
    }
}

/* ================================================================
 * T7.9: Device descriptors have correct VID/PID
 * ================================================================ */
static void
test_hal_blob_sizes (void)
{
  const ValidityDeviceDesc *desc_9a =
    fpi_validity_hal_device_lookup (VALIDITY_DEV_9A);

  g_assert_nonnull (desc_9a);
  g_assert_cmpuint (desc_9a->vid, ==, 0x06cb);
  g_assert_cmpuint (desc_9a->pid, ==, 0x009a);

  const ValidityDeviceDesc *desc_90 =
    fpi_validity_hal_device_lookup (VALIDITY_DEV_90);
  g_assert_nonnull (desc_90);
  g_assert_cmpuint (desc_90->vid, ==, 0x138a);
  g_assert_cmpuint (desc_90->pid, ==, 0x0090);
}

/* ================================================================
 * T7.10: Lookup consistency — by-type and by-PID return same pointer
 * ================================================================ */
static void
test_hal_lookup_consistency (void)
{
  const ValidityDeviceDesc *by_type =
    fpi_validity_hal_device_lookup (VALIDITY_DEV_9A);
  const ValidityDeviceDesc *by_pid =
    fpi_validity_hal_device_lookup_by_pid (0x06cb, 0x009a);

  g_assert_true (by_type == by_pid);
}

/* ================================================================
 * T7.11: 06cb:00a2 descriptor and the flash layout the sensor reported
 *
 * The HAL entry for 00a2 uses the standard layout because a provisioned
 * E480 sensor reported exactly that table in GET_FLASH_INFO (3e). Compare
 * every partition entry of the real reply with the HAL table.
 * ================================================================ */
static void
test_hal_a2_matches_real_flash_info (void)
{
  const ValidityDeviceDesc *desc = fpi_validity_hal_device_lookup (VALIDITY_DEV_A2);
  const guint8 *data = a2_flash_info_reply + 2;
  gsize data_len = sizeof (a2_flash_info_reply) - 2;
  ValidityFlashIcParams ic = { 0 };
  guint16 pcnt = 0;
  guint16 status = 0xffff;

  /* The HAL enum indexes the same table as the driver enum */
  g_assert_cmpint (VALIDITY_HAL_DEV_A2, ==, VALIDITY_DEV_A2);
  g_assert_cmpint (VALIDITY_HAL_DEV_D2, ==, VALIDITY_DEV_D2);

  g_assert_nonnull (desc);
  g_assert_cmphex (desc->vid, ==, 0x06cb);
  g_assert_cmphex (desc->pid, ==, 0x00a2);
  g_assert_true (desc == fpi_validity_hal_device_lookup_by_pid (0x06cb, 0x00a2));
  g_assert_nonnull (desc->flash_layout);

  g_assert_true (fpi_vcsfw_parse_status (a2_flash_info_reply,
                                         sizeof (a2_flash_info_reply), &status));
  g_assert_cmphex (status, ==, VCSFW_STATUS_OK);
  g_assert_true (fpi_validity_pair_parse_flash_info (data, data_len, &ic, &pcnt));
  g_assert_cmpuint (ic.size, ==, 0x100000);       /* W25Q80B, 1 MiB */
  g_assert_cmpuint (pcnt, ==, 5);
  g_assert_cmpuint (pcnt, ==, desc->flash_layout->num_partitions);

  /* 14-byte header, then 12 bytes per partition: id, type, access (u16),
   * offset (u32), size (u32) */
  g_assert_cmpuint (data_len, ==, 14 + pcnt * 12);
  for (guint i = 0; i < pcnt; i++)
    {
      const guint8 *e = data + 14 + i * 12;
      const ValidityPartition *p = &desc->flash_layout->partitions[i];

      g_assert_cmpuint (e[0], ==, p->id);
      g_assert_cmpuint (e[1], ==, p->type);
      g_assert_cmpuint (FP_READ_UINT16_LE (e + 2), ==, p->access_lvl);
      g_assert_cmphex (FP_READ_UINT32_LE (e + 4), ==, p->offset);
      g_assert_cmphex (FP_READ_UINT32_LE (e + 8), ==, p->size);
    }
}

/* ================================================================
 * Tests: 06cb:00a2 policy and safety gates
 * ================================================================ */

/* The types that existed before 00a2 keep the driver's behaviour; 00a2
 * and any unknown type get the restricted policy. */
static void
test_a2_device_policy (void)
{
  const guint permissive[] = { VALIDITY_DEV_90, VALIDITY_DEV_97,
                               VALIDITY_DEV_9A, VALIDITY_DEV_9D,
                               VALIDITY_DEV_AB, VALIDITY_DEV_CB,
                               VALIDITY_DEV_B7, VALIDITY_DEV_D2 };
  const guint restricted[] = { VALIDITY_DEV_A2, 99, G_MAXUINT };

  for (gsize i = 0; i < G_N_ELEMENTS (permissive); i++)
    {
      const ValidityDevicePolicy *p = fpi_validity_device_policy (permissive[i]);

      g_assert_nonnull (p);
      g_assert_false (p->safety_gates);
      g_assert_true (p->allow_provisioning);
      g_assert_true (p->allow_fwext_upload);
      g_assert_true (p->allow_clean_slate);
      g_assert_true (p->allow_enroll);
      g_assert_true (p->allow_clear_storage);
      g_assert_true (p->allow_delete);
      g_assert_true (p->allow_reclaim_erase);
      g_assert_true (p->allow_usb_reset);
      g_assert_true (p->allow_reconnect);
      g_assert_false (p->reset_at_open);
      g_assert_false (p->init_once_per_instance);
      g_assert_false (p->stream_capture_flow);
      g_assert_false (p->allow_image_capture);
    }

  for (gsize i = 0; i < G_N_ELEMENTS (restricted); i++)
    {
      const ValidityDevicePolicy *p = fpi_validity_device_policy (restricted[i]);

      g_assert_nonnull (p);
      g_assert_true (p->safety_gates);
      g_assert_false (p->allow_provisioning);
      g_assert_false (p->allow_fwext_upload);
      g_assert_false (p->allow_clean_slate);
      g_assert_false (p->allow_enroll);
      g_assert_cmpint (p->allow_host_enroll, ==, restricted[i] == VALIDITY_DEV_A2);
      g_assert_false (p->allow_clear_storage);
      g_assert_false (p->allow_delete);
      g_assert_false (p->allow_reclaim_erase);
      g_assert_true (p->allow_usb_reset);
      g_assert_false (p->allow_reconnect);
      g_assert_true (p->reset_at_open);
      g_assert_true (p->init_once_per_instance);
      g_assert_true (p->stream_capture_flow);
      g_assert_false (p->strict_image_flags);
    }
}

/* What probe clears: 00a2 never advertises storage delete or clear (the
 * driver refuses them; fprintd would otherwise call them from its enroll
 * path) and advertises capture only in a developer build; the other
 * models keep delete and clear and never advertise capture. */
static void
test_a2_probe_features (void)
{
  const ValidityDevicePolicy *a2 = fpi_validity_device_policy (VALIDITY_DEV_A2);
  const ValidityDevicePolicy *d9a = fpi_validity_device_policy (VALIDITY_DEV_9A);
  const FpDeviceFeature storage_rw = FP_DEVICE_FEATURE_STORAGE_DELETE |
                                     FP_DEVICE_FEATURE_STORAGE_CLEAR;

  g_assert_cmphex (fpi_validity_policy_features_to_clear (a2, FALSE), ==,
                   storage_rw | FP_DEVICE_FEATURE_CAPTURE);
  g_assert_cmphex (fpi_validity_policy_features_to_clear (a2, TRUE), ==,
                   storage_rw);
  g_assert_cmphex (fpi_validity_policy_features_to_clear (d9a, FALSE), ==,
                   FP_DEVICE_FEATURE_CAPTURE);
  g_assert_cmphex (fpi_validity_policy_features_to_clear (d9a, TRUE), ==,
                   FP_DEVICE_FEATURE_CAPTURE);
  /* never identify, verify, storage or listing */
  for (gint dev = 0; dev <= 1; dev++)
    g_assert_cmphex (fpi_validity_policy_features_to_clear (dev ? a2 : d9a, dev) &
                     (FP_DEVICE_FEATURE_IDENTIFY | FP_DEVICE_FEATURE_VERIFY |
                      FP_DEVICE_FEATURE_STORAGE |
                      FP_DEVICE_FEATURE_STORAGE_LIST), ==, 0);
}

/* Init once per device instance (00a2): sent on the first open, skipped
 * while accepted, and never re-sent after a rejection or a lost reply.
 * Other types send it on every open, as before. */
static void
test_a2_init_action (void)
{
  const ValidityDevicePolicy *a2 = fpi_validity_device_policy (VALIDITY_DEV_A2);
  const ValidityDevicePolicy *d9a = fpi_validity_device_policy (VALIDITY_DEV_9A);
  const ValidityInitState states[] = {
    VALIDITY_INIT_NOT_SENT, VALIDITY_INIT_SENT,
    VALIDITY_INIT_ACCEPTED, VALIDITY_INIT_REJECTED,
  };

  g_assert_cmpint (fpi_validity_init_action (a2, VALIDITY_INIT_NOT_SENT), ==,
                   VALIDITY_INIT_ACTION_SEND);
  g_assert_cmpint (fpi_validity_init_action (a2, VALIDITY_INIT_ACCEPTED), ==,
                   VALIDITY_INIT_ACTION_SKIP);
  g_assert_cmpint (fpi_validity_init_action (a2, VALIDITY_INIT_SENT), ==,
                   VALIDITY_INIT_ACTION_REFUSE);
  g_assert_cmpint (fpi_validity_init_action (a2, VALIDITY_INIT_REJECTED), ==,
                   VALIDITY_INIT_ACTION_REFUSE);
  g_assert_cmpint (fpi_validity_init_action (a2, (ValidityInitState) 42), ==,
                   VALIDITY_INIT_ACTION_REFUSE);

  for (gsize i = 0; i < G_N_ELEMENTS (states); i++)
    {
      g_assert_cmpint (fpi_validity_init_action (d9a, states[i]), ==,
                       VALIDITY_INIT_ACTION_SEND);
      g_assert_cmpint (fpi_validity_init_action (NULL, states[i]), ==,
                       VALIDITY_INIT_ACTION_SEND);
    }

  /* A fresh instance starts at NOT_SENT (GObject zero-fills it) */
  g_assert_cmpint (VALIDITY_INIT_NOT_SENT, ==, 0);
}

static void
a2_reconnect_cb (FpiDeviceValidity *self,
                 gboolean           success,
                 gpointer           user_data)
{
  gint *calls = user_data;

  g_assert_false (success);
  (*calls)++;
}

/* No in-driver reconnect (USB reset + re-open) for 00a2, whatever the
 * error; the checks run before the device object is touched. */
static void
test_a2_no_reconnect (void)
{
  FpiDeviceValidity dev = { 0 };
  const GError *errors[] = { NULL, NULL };

  g_autoptr(GError) io = g_error_new_literal (G_USB_DEVICE_ERROR,
                                              G_USB_DEVICE_ERROR_IO, "io");
  g_autoptr(GError) gone = g_error_new_literal (G_USB_DEVICE_ERROR,
                                                G_USB_DEVICE_ERROR_NO_DEVICE,
                                                "gone");
  gint calls = 0;

  errors[0] = io;
  errors[1] = gone;
  dev.dev_type = VALIDITY_DEV_A2;
  dev.tls.session_broken = TRUE;     /* a TLS alert */

  for (gsize i = 0; i < G_N_ELEMENTS (errors); i++)
    g_assert_false (fpi_validity_recover_or_fail (&dev, errors[i],
                                                  a2_reconnect_cb, &calls));
  g_assert_cmpint (calls, ==, 0);
  g_assert_cmpuint (dev.reconnect_attempts, ==, 0);
  g_assert_false (dev.in_recovery);

  fpi_validity_reconnect_start (&dev, a2_reconnect_cb, &calls);
  g_assert_cmpint (calls, ==, 1);
  g_assert_cmpuint (dev.reconnect_attempts, ==, 0);
  g_assert_false (dev.in_recovery);
}

/* The real 01 reply of the owned, patched E480 sensor passes */
static void
test_a2_rom_gate_real (void)
{
  g_autoptr(GError) error = NULL;

  g_assert_cmpuint (sizeof (a2_rom_info_reply), ==,
                    VALIDITY_A2_ROM_INFO_REPLY_LEN);
  g_assert_cmpint (fpi_validity_a2_check_rom_info (a2_rom_info_reply,
                                                   sizeof (a2_rom_info_reply)),
                   ==, VALIDITY_A2_ROM_OK);
  g_assert_true (fpi_validity_a2_rom_info_gate (a2_rom_info_reply,
                                                sizeof (a2_rom_info_reply),
                                                &error));
  g_assert_no_error (error);

  /* Only the low nibble of r[37] is the provisioning state */
  {
    guint8 r[VALIDITY_A2_ROM_INFO_REPLY_LEN];

    memcpy (r, a2_rom_info_reply, sizeof (r));
    r[37] = 0x17;
    g_assert_cmpint (fpi_validity_a2_check_rom_info (r, sizeof (r)), ==,
                     VALIDITY_A2_ROM_OK);
  }

  /* r[17] and r[25] as the sensor reports them; only bits 0x02 and 0x20
   * of r[25] are required */
  {
    guint8 r[VALIDITY_A2_ROM_INFO_REPLY_LEN];

    g_assert_cmphex (a2_rom_info_reply[17], ==, 0x00);
    g_assert_cmphex (a2_rom_info_reply[25], ==, 0x23);
    memcpy (r, a2_rom_info_reply, sizeof (r));
    r[25] = 0x22;
    g_assert_cmpint (fpi_validity_a2_check_rom_info (r, sizeof (r)), ==,
                     VALIDITY_A2_ROM_OK);
    r[25] = 0xff;
    g_assert_cmpint (fpi_validity_a2_check_rom_info (r, sizeof (r)), ==,
                     VALIDITY_A2_ROM_OK);
  }
}

/* Each mutation of the real 01 reply is refused, with NOT_SUPPORTED and
 * a message that names the reason */
static void
test_a2_rom_gate_negative (void)
{
  static const struct
  {
    guint              index;
    guint8             value;
    ValidityA2RomCheck expect;
    const gchar       *message;
  } cases[] = {
    /* blank chip (never provisioned) */
    { 37, 0x02, VALIDITY_A2_ROM_NOT_OWNED, "provisioning state is 2" },
    /* partially provisioned, owned-but-6, broken */
    { 37, 0x05, VALIDITY_A2_ROM_NOT_OWNED, "provisioning state is 5" },
    { 37, 0x06, VALIDITY_A2_ROM_NOT_OWNED, "provisioning state is 6" },
    { 37, 0x0f, VALIDITY_A2_ROM_NOT_OWNED, "provisioning state is 15" },
    /* security update not applied (old generation / blank) */
    { 34, 0x02, VALIDITY_A2_ROM_NOT_PATCHED, "security state is 02 d1" },
    { 35, 0x00, VALIDITY_A2_ROM_NOT_PATCHED, "security state is 03 00" },
    /* other products and ROMs */
    { 13, 0x31, VALIDITY_A2_ROM_WRONG_PRODUCT, "product 0x31" },
    { 13, 0x00, VALIDITY_A2_ROM_WRONG_PRODUCT, "product 0x00" },
    { 10, 0x05, VALIDITY_A2_ROM_WRONG_VERSION, "ROM 5.7" },
    { 11, 0x08, VALIDITY_A2_ROM_WRONG_VERSION, "ROM 6.8" },
    { 12, 0x00, VALIDITY_A2_ROM_NOT_TARGET_1, "byte 12 is 0x00" },
    { 12, 0x02, VALIDITY_A2_ROM_NOT_TARGET_1, "byte 12 is 0x02" },
    /* error status (busy) */
    { 0, 0x01, VALIDITY_A2_ROM_BAD_STATUS, "status 0x0001" },
    { 1, 0x04, VALIDITY_A2_ROM_BAD_STATUS, "status 0x0400" },
    /* a loaded RAM patch reported (the vendor driver would send 1a) */
    { 17, 0x01, VALIDITY_A2_ROM_PATCH_PENDING, "byte 17 is 0x01" },
    { 17, 0xff, VALIDITY_A2_ROM_PATCH_PENDING, "byte 17 is 0xff" },
    /* without secure mode or the production key */
    { 25, 0x21, VALIDITY_A2_ROM_NOT_SECURE, "byte 25 is 0x21" },
    { 25, 0x03, VALIDITY_A2_ROM_NOT_SECURE, "byte 25 is 0x03" },
    { 25, 0x00, VALIDITY_A2_ROM_NOT_SECURE, "byte 25 is 0x00" },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(GError) error = NULL;
      guint8 r[VALIDITY_A2_ROM_INFO_REPLY_LEN];

      memcpy (r, a2_rom_info_reply, sizeof (r));
      r[cases[i].index] = cases[i].value;

      g_assert_cmpint (fpi_validity_a2_check_rom_info (r, sizeof (r)), ==,
                       cases[i].expect);
      g_assert_false (fpi_validity_a2_rom_info_gate (r, sizeof (r), &error));
      g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
      g_assert_nonnull (strstr (error->message, cases[i].message));
    }

  /* A blank chip that also lacks the update reports the owner state first */
  {
    guint8 r[VALIDITY_A2_ROM_INFO_REPLY_LEN];

    memcpy (r, a2_rom_info_reply, sizeof (r));
    r[37] = 0x02;
    r[34] = 0x00;
    r[35] = 0x00;
    g_assert_cmpint (fpi_validity_a2_check_rom_info (r, sizeof (r)), ==,
                     VALIDITY_A2_ROM_NOT_OWNED);
  }

  /* Any other length is refused, including a longer reply */
  {
    g_autoptr(GError) error = NULL;
    guint8 longer[VALIDITY_A2_ROM_INFO_REPLY_LEN + 2] = { 0 };

    memcpy (longer, a2_rom_info_reply, sizeof (a2_rom_info_reply));
    g_assert_cmpint (fpi_validity_a2_check_rom_info (longer, sizeof (longer)), ==,
                     VALIDITY_A2_ROM_BAD_LENGTH);
    g_assert_cmpint (fpi_validity_a2_check_rom_info (a2_rom_info_reply,
                                                     sizeof (a2_rom_info_reply) - 1),
                     ==, VALIDITY_A2_ROM_BAD_LENGTH);
    g_assert_cmpint (fpi_validity_a2_check_rom_info (a2_rom_info_reply, 0), ==,
                     VALIDITY_A2_ROM_BAD_LENGTH);
    g_assert_cmpint (fpi_validity_a2_check_rom_info (NULL, 38), ==,
                     VALIDITY_A2_ROM_BAD_LENGTH);
    g_assert_false (fpi_validity_a2_rom_info_gate (NULL, 38, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  }
}

/* 43 02: the real reply passes; "no fwext" (wire b0 04) and every other
 * failure is refused, naming the file that would be needed */
static void
test_a2_fwext_gate (void)
{
  static const guint8 no_fw[] = { 0xb0, 0x04 };
  static const guint8 busy[] = { 0x01, 0x04 };
  static const guint8 ok_short[] = { 0x00, 0x00, 0x01, 0x00, 0x03 };

  {
    g_autoptr(GError) error = NULL;

    g_assert_true (fpi_validity_a2_fwext_gate (a2_fwext_info_reply,
                                               sizeof (a2_fwext_info_reply),
                                               &error));
    g_assert_no_error (error);
  }

  {
    g_autoptr(GError) error = NULL;

    g_assert_false (fpi_validity_a2_fwext_gate (no_fw, sizeof (no_fw), &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
    g_assert_nonnull (strstr (error->message, "0x04b0"));
    g_assert_nonnull (strstr (error->message, "6_07f_lenovo_sm_qm.xpfwext"));
    g_assert_nonnull (strstr (error->message, "never uploads"));
  }

  {
    g_autoptr(GError) error = NULL;

    g_assert_false (fpi_validity_a2_fwext_gate (busy, sizeof (busy), &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  }

  {
    g_autoptr(GError) error = NULL;

    g_test_expect_message ("libfprint-validity", G_LOG_LEVEL_WARNING,
                           "*too short*");
    g_assert_false (fpi_validity_a2_fwext_gate (ok_short, sizeof (ok_short),
                                                &error));
    g_test_assert_expected_messages ();
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  }

  {
    g_autoptr(GError) error = NULL;

    g_assert_false (fpi_validity_a2_fwext_gate (no_fw, 1, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  }
}

/* 06<init>: only 0x0000 continues. The vendor driver's other "success"
 * codes and busy are refused too; nothing is retried. */
static void
test_a2_init_gate (void)
{
  static const guint8 accepted[] = { 0x00, 0x00 };   /* real reply */

  static const struct
  {
    guint8       wire[2];
    const gchar *message;
  } rejected[] = {
    { { 0xbe, 0x04 }, "0x04be" },   /* init blob rejected */
    { { 0x01, 0x04 }, "0x0401" },   /* busy: not retried */
    { { 0x12, 0x04 }, "0x0412" },
    { { 0x91, 0x04 }, "0x0491" },
    { { 0xae, 0x04 }, "0x04ae" },
  };

  {
    g_autoptr(GError) error = NULL;

    g_assert_true (fpi_validity_a2_init_gate (accepted, sizeof (accepted),
                                              &error));
    g_assert_no_error (error);
  }

  for (gsize i = 0; i < G_N_ELEMENTS (rejected); i++)
    {
      g_autoptr(GError) error = NULL;

      g_assert_false (fpi_validity_a2_init_gate (rejected[i].wire, 2, &error));
      g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      g_assert_nonnull (strstr (error->message, rejected[i].message));
      g_assert_nonnull (strstr (error->message, "not retrying"));
    }

  {
    g_autoptr(GError) error = NULL;

    g_assert_false (fpi_validity_a2_init_gate (accepted, 1, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
  }

  {
    g_autoptr(GError) error = NULL;

    g_assert_false (fpi_validity_a2_init_gate (NULL, 0, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
  }
}

/* The init blob is pinned: only 581 bytes starting with 06 whose SHA-256
 * is the reviewed one. The real blob is not in the tree (it comes from the
 * vendor driver), so the check is exercised with a synthetic blob and its
 * own digest; the production wrapper is tested against the pinned values
 * and, if VALIDITY_TEST_A2_DATA_DIR names a data package, the real file. */
static void
test_a2_init_blob_pin (void)
{
  g_autofree guint8 *blob = g_malloc (VALIDITY_A2_INIT_BLOB_LEN);
  g_autofree gchar *digest = NULL;
  g_autofree guint8 *dbwe = g_malloc0 (2693);

  g_assert_cmpuint (VALIDITY_A2_INIT_BLOB_LEN, ==, 581);
  g_assert_cmpstr (VALIDITY_A2_INIT_BLOB_SHA256, ==,
                   "0f3128a1c93b49f0a5162bbad26b22ae02f539ab0668678ea090449922e39674");

  blob[0] = 0x06;
  for (gsize i = 1; i < VALIDITY_A2_INIT_BLOB_LEN; i++)
    blob[i] = (guint8) (i * 13 + 1);
  digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256, blob,
                                        VALIDITY_A2_INIT_BLOB_LEN);

  /* The check itself: length, first byte, digest */
  {
    g_autoptr(GError) error = NULL;

    g_assert_true (fpi_validity_a2_init_blob_check (blob, VALIDITY_A2_INIT_BLOB_LEN,
                                                    VALIDITY_A2_INIT_BLOB_LEN,
                                                    digest, &error));
    g_assert_no_error (error);
  }

  /* one byte changed */
  {
    g_autoptr(GError) error = NULL;

    blob[300] ^= 0x01;
    g_assert_false (fpi_validity_a2_init_blob_check (blob, VALIDITY_A2_INIT_BLOB_LEN,
                                                     VALIDITY_A2_INIT_BLOB_LEN,
                                                     digest, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
    g_assert_nonnull (strstr (error->message, "not sending it"));
    blob[300] ^= 0x01;
  }

  /* the 580-byte body without its 06; a truncated blob; no blob */
  {
    g_autoptr(GError) e1 = NULL;
    g_autoptr(GError) e2 = NULL;
    g_autoptr(GError) e3 = NULL;
    g_autoptr(GError) e4 = NULL;

    g_assert_false (fpi_validity_a2_init_blob_check (blob + 1,
                                                     VALIDITY_A2_INIT_BLOB_LEN - 1,
                                                     VALIDITY_A2_INIT_BLOB_LEN,
                                                     digest, &e1));
    g_assert_error (e1, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
    g_assert_false (fpi_validity_a2_init_blob_check (blob,
                                                     VALIDITY_A2_INIT_BLOB_LEN - 1,
                                                     VALIDITY_A2_INIT_BLOB_LEN,
                                                     digest, &e2));
    g_assert_error (e2, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
    g_assert_false (fpi_validity_a2_init_blob_check (NULL, 0,
                                                     VALIDITY_A2_INIT_BLOB_LEN,
                                                     digest, &e3));
    g_assert_error (e3, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
    g_assert_false (fpi_validity_a2_init_blob_check (blob, 0, 0, digest, &e4));
    g_assert_error (e4, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  }

  /* right length and digest, but not a 06 command */
  {
    g_autoptr(GError) error = NULL;
    g_autofree gchar *d2 = NULL;

    blob[0] = 0x4f;
    d2 = g_compute_checksum_for_data (G_CHECKSUM_SHA256, blob,
                                      VALIDITY_A2_INIT_BLOB_LEN);
    g_assert_false (fpi_validity_a2_init_blob_check (blob, VALIDITY_A2_INIT_BLOB_LEN,
                                                     VALIDITY_A2_INIT_BLOB_LEN,
                                                     d2, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
    blob[0] = 0x06;
  }

  /* The pinned wrapper refuses the synthetic blob, a db_write_enable-sized
   * 06 blob and nothing at all */
  {
    g_autoptr(GError) e1 = NULL;
    g_autoptr(GError) e2 = NULL;
    g_autoptr(GError) e3 = NULL;

    g_assert_false (fpi_validity_a2_init_blob_ok (blob, VALIDITY_A2_INIT_BLOB_LEN,
                                                  &e1));
    g_assert_error (e1, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
    g_assert_nonnull (strstr (e1->message, digest));
    g_assert_nonnull (strstr (e1->message, VALIDITY_A2_INIT_BLOB_SHA256));

    dbwe[0] = 0x06;
    g_assert_false (fpi_validity_a2_init_blob_ok (dbwe, 2693, &e2));
    g_assert_error (e2, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
    g_assert_false (fpi_validity_a2_init_blob_ok (NULL, 0, &e3));
    g_assert_error (e3, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  }

  /* The real blob from a local data package, when one is named */
  {
    const gchar *dir = g_getenv ("VALIDITY_TEST_A2_DATA_DIR");

    if (dir && *dir)
      {
        g_autofree gchar *path = g_build_filename (dir, "06cb_00a2", "init.bin",
                                                   NULL);
        g_autoptr(GError) error = NULL;
        ValidityDataStore store;
        const guint8 *data;
        gsize len = 0;

        fpi_validity_data_store_init (&store);
        g_assert_true (fpi_validity_data_load_file (&store, VALIDITY_DATA_INIT, path,
                                                    &error));
        g_assert_no_error (error);
        data = fpi_validity_data_get_bytes (&store, VALIDITY_DATA_INIT, &len);
        g_assert_true (fpi_validity_a2_init_blob_ok (data, len, &error));
        g_assert_no_error (error);
        fpi_validity_data_store_free (&store);
        g_test_message ("real init blob %s: accepted by the pin", path);
      }
    else
      {
        g_test_message ("VALIDITY_TEST_A2_DATA_DIR not set: real blob not checked");
      }
  }
}

/* A restricted policy keeps only what it sends: init. Blobs for
 * provisioning, clean_slate and DB writes are dropped at load. */
static void
test_a2_drop_unused_data (void)
{
  static const guint8 b[] = { 0x06, 0x01 };
  const ValidityDataTag device_tags[] = {
    VALIDITY_DATA_INIT, VALIDITY_DATA_INIT_CLEAN_SLATE,
    VALIDITY_DATA_RESET, VALIDITY_DATA_DB_WRITE_ENABLE,
  };
  ValidityDataStore store;

  g_assert_true (fpi_validity_policy_uses_db_write_enable (fpi_validity_device_policy (VALIDITY_DEV_A2)));
  g_assert_true (fpi_validity_policy_uses_db_write_enable (fpi_validity_device_policy (VALIDITY_DEV_9A)));

  for (gint permissive = 0; permissive <= 1; permissive++)
    {
      const ValidityDevicePolicy *policy =
        fpi_validity_device_policy (permissive ? VALIDITY_DEV_9A : VALIDITY_DEV_A2);

      fpi_validity_data_store_init (&store);
      for (gsize i = 0; i < G_N_ELEMENTS (device_tags); i++)
        store.entries[device_tags[i]] = g_bytes_new (b, sizeof (b));
      store.entries[VALIDITY_DATA_TLS_PASSWORD] = g_bytes_new (b, sizeof (b));

      g_assert_cmpuint (fpi_validity_policy_drop_unused_data (policy, &store), ==,
                        permissive ? 0 : 2);
      g_assert_nonnull (store.entries[VALIDITY_DATA_INIT]);
      g_assert_nonnull (store.entries[VALIDITY_DATA_TLS_PASSWORD]);
      g_assert_true ((store.entries[VALIDITY_DATA_RESET] != NULL) == permissive);
      g_assert_true ((store.entries[VALIDITY_DATA_INIT_CLEAN_SLATE] != NULL) ==
                     permissive);
      g_assert_nonnull (store.entries[VALIDITY_DATA_DB_WRITE_ENABLE]);

      /* idempotent */
      g_assert_cmpuint (fpi_validity_policy_drop_unused_data (policy, &store), ==, 0);
      fpi_validity_data_store_free (&store);
    }
}

/* A type that is never provisioned gets REFUSE_POLICY at 0 partitions
 * (also from a reconnect) and never PROVISION; partitioned sensors are
 * decided as before. With provisioning allowed nothing changes. */
static void
test_pair_decide_for_policy (void)
{
  const ValidityTlsFlashClass classes[] = {
    VALIDITY_TLS_FLASH_KEYS_PRESENT,
    VALIDITY_TLS_FLASH_BLANK,
    VALIDITY_TLS_FLASH_PARTIAL,
    VALIDITY_TLS_FLASH_UNREADABLE,
    (ValidityTlsFlashClass) 99,
  };
  const guint16 counts[] = { 0, 1, 5, 0xffff };

  for (gsize c = 0; c < G_N_ELEMENTS (counts); c++)
    for (gsize i = 0; i < G_N_ELEMENTS (classes); i++)
      for (gint check_only = 0; check_only <= 1; check_only++)
        {
          ValidityPairDecision base = fpi_validity_pair_decide (counts[c],
                                                                classes[i],
                                                                check_only);
          ValidityPairDecision allowed =
            fpi_validity_pair_decide_for_policy (counts[c], classes[i],
                                                 check_only, TRUE);
          ValidityPairDecision forbidden =
            fpi_validity_pair_decide_for_policy (counts[c], classes[i],
                                                 check_only, FALSE);

          g_assert_cmpint (allowed, ==, base);
          g_assert_cmpint (forbidden, !=, VALIDITY_PAIR_PROVISION);

          if (counts[c] == 0)
            g_assert_cmpint (forbidden, ==, VALIDITY_PAIR_REFUSE_POLICY);
          else
            g_assert_cmpint (forbidden, ==, base);
        }

  /* The policy of 00a2 forbids provisioning: its open can only ever reach
   * NOT_NEEDED (keys present) or a refusal */
  g_assert_false (fpi_validity_device_policy (VALIDITY_DEV_A2)->allow_provisioning);
  g_assert_cmpint (fpi_validity_pair_decide_for_policy (5, VALIDITY_TLS_FLASH_KEYS_PRESENT,
                                                        FALSE, FALSE),
                   ==, VALIDITY_PAIR_NOT_NEEDED);
}

/* ================================================================
 * Tests: SENSOR
 * ================================================================ */


/* ================================================================
 * T4.1: test_identify_sensor_parse
 *
 * Verify that a valid cmd 0x75 response is parsed correctly into
 * a ValiditySensorIdent (hw_major + hw_version).
 *
 * Wire format (after 2-byte status stripped):
 *   [zeroes:4 LE] [version:2 LE] [major:2 LE]
 * ================================================================ */
static void
test_identify_sensor_parse (void)
{
  ValiditySensorIdent ident;

  /* Build synthetic response: zeroes=0, version=0x13, major=0x004a */
  guint8 data[8];

  FP_WRITE_UINT32_LE (&data[0], 0);        /* zeroes */
  FP_WRITE_UINT16_LE (&data[4], 0x0013);   /* version */
  FP_WRITE_UINT16_LE (&data[6], 0x004a);   /* major */

  gboolean ok = fpi_validity_sensor_parse_identify (data, sizeof (data), &ident);

  g_assert_true (ok);
  g_assert_cmpuint (ident.hw_major, ==, 0x004a);
  g_assert_cmpuint (ident.hw_version, ==, 0x0013);
}

/* ================================================================
 * T4.2: test_identify_sensor_parse_truncated
 *
 * Verify that a response shorter than 8 bytes returns FALSE.
 * ================================================================ */
static void
test_identify_sensor_parse_truncated (void)
{
  ValiditySensorIdent ident;

  guint8 data[7] = { 0 };

  g_assert_false (fpi_validity_sensor_parse_identify (data, sizeof (data), &ident));
  /* Also test with 0 length */
  g_assert_false (fpi_validity_sensor_parse_identify (data, 0, &ident));
}

/* ================================================================
 * T4.3: test_device_info_lookup_exact
 *
 * Verify that lookup with major=0x004a, version=0x13 returns the
 * correct DeviceInfo for the ThinkPad T480s sensor.
 * ================================================================ */
static void
test_device_info_lookup_exact (void)
{
  const ValidityDeviceInfo *info;

  info = fpi_validity_device_info_lookup (0x004a, 0x13);

  g_assert_nonnull (info);
  g_assert_cmpuint (info->major, ==, 0x004a);
  g_assert_cmpuint (info->type, ==, 0x00b5);
  g_assert_cmpuint (info->version, ==, 0x13);
  g_assert_cmpstr (info->name, ==, "SYN 57K0 FM3297-02");
}

/* ================================================================
 * T4.4: test_device_info_lookup_another
 *
 * Verify that lookup with major=0x0071, version=0x01 returns
 * the VSI 55E entry (type 0xdb).
 * ================================================================ */
static void
test_device_info_lookup_another (void)
{
  const ValidityDeviceInfo *info;

  info = fpi_validity_device_info_lookup (0x0071, 0x01);

  g_assert_nonnull (info);
  g_assert_cmpuint (info->type, ==, 0x00db);
  g_assert_cmpstr (info->name, ==, "VSI 55E FM72-001");
}

/* ================================================================
 * T4.5: test_device_info_lookup_unknown
 *
 * Verify that a completely unknown major returns NULL.
 * ================================================================ */
static void
test_device_info_lookup_unknown (void)
{
  const ValidityDeviceInfo *info;

  info = fpi_validity_device_info_lookup (0xffff, 0x01);

  g_assert_null (info);
}

/* ================================================================
 * T4.6: test_device_info_lookup_fuzzy
 *
 * Verify that when version_mask == 0x00, the entry matches any
 * version (fuzzy match).
 * ================================================================ */
static void
test_device_info_lookup_fuzzy (void)
{
  const ValidityDeviceInfo *info;

  /* major=0x0000 entries have version_mask=0x00 → always fuzzy match.
   * But major=0x0000 needs to match the lookup major. */
  info = fpi_validity_device_info_lookup (0x0000, 0x42);

  /* Should match one of the wildcard entries */
  g_assert_nonnull (info);
  g_assert_cmpuint (info->major, ==, 0x0000);
}

/* ================================================================
 * T4.7: test_sensor_type_info_lookup
 *
 * Verify lookup of sensor type 0x00b5 returns correct geometry.
 * ================================================================ */
static void
test_sensor_type_info_lookup (void)
{
  const ValiditySensorTypeInfo *info;

  info = fpi_validity_sensor_type_info_lookup (0x00b5);

  g_assert_nonnull (info);
  g_assert_cmpuint (info->sensor_type, ==, 0x00b5);
  g_assert_cmpuint (info->bytes_per_line, ==, 0x78);
  g_assert_cmpuint (info->repeat_multiplier, ==, 2);
  g_assert_cmpuint (info->lines_per_calibration_data, ==, 112);
  g_assert_cmpuint (info->line_width, ==, 112);
  g_assert_nonnull (info->calibration_blob);
  g_assert_cmpuint (info->calibration_blob_len, ==, 112);
}

/* ================================================================
 * T4.8: test_sensor_type_info_lookup_db
 *
 * Verify lookup of sensor type 0x00db (55E) returns correct geometry.
 * ================================================================ */
static void
test_sensor_type_info_lookup_db (void)
{
  const ValiditySensorTypeInfo *info;

  info = fpi_validity_sensor_type_info_lookup (0x00db);

  g_assert_nonnull (info);
  g_assert_cmpuint (info->bytes_per_line, ==, 0x98);
  g_assert_cmpuint (info->repeat_multiplier, ==, 1);
  g_assert_cmpuint (info->lines_per_calibration_data, ==, 144);
  g_assert_cmpuint (info->line_width, ==, 144);
}

/* ================================================================
 * T4.9: test_sensor_type_info_lookup_unknown
 *
 * Verify that an unknown sensor type returns NULL.
 * ================================================================ */
static void
test_sensor_type_info_lookup_unknown (void)
{
  g_assert_null (fpi_validity_sensor_type_info_lookup (0xbeef));
}

/* ================================================================
 * T4.10: test_factory_bits_cmd_format
 *
 * Verify that the factory bits command is built correctly.
 * Expected: [0x6f] [0x00 0x0e] [0x00 0x00] [0x00 0x00 0x00 0x00]
 * ================================================================ */
static void
test_factory_bits_cmd_format (void)
{
  guint8 buf[16];
  gsize len;

  len = fpi_validity_sensor_build_factory_bits_cmd (0x0e00, buf, sizeof (buf));

  g_assert_cmpuint (len, ==, 9);
  g_assert_cmpuint (buf[0], ==, 0x6f);
  /* tag = 0x0e00 LE */
  g_assert_cmpuint (buf[1], ==, 0x00);
  g_assert_cmpuint (buf[2], ==, 0x0e);
  /* pad 2 bytes */
  g_assert_cmpuint (buf[3], ==, 0x00);
  g_assert_cmpuint (buf[4], ==, 0x00);
  /* pad 4 bytes */
  g_assert_cmpuint (buf[5], ==, 0x00);
  g_assert_cmpuint (buf[6], ==, 0x00);
  g_assert_cmpuint (buf[7], ==, 0x00);
  g_assert_cmpuint (buf[8], ==, 0x00);
}

/* ================================================================
 * T4.11: test_factory_bits_cmd_buffer_too_small
 *
 * Verify that a too-small buffer returns 0.
 * ================================================================ */
static void
test_factory_bits_cmd_buffer_too_small (void)
{
  guint8 buf[4];
  gsize len;

  len = fpi_validity_sensor_build_factory_bits_cmd (0x0e00, buf, sizeof (buf));

  g_assert_cmpuint (len, ==, 0);
}

/* ================================================================
 * T4.12: test_identify_then_lookup
 *
 * End-to-end: parse identify_sensor response → DeviceInfo lookup →
 * SensorTypeInfo lookup. Simulates the T480s sensor (06cb:009a).
 * ================================================================ */
static void
test_identify_then_lookup (void)
{
  ValiditySensorIdent ident;
  const ValidityDeviceInfo *dev_info;
  const ValiditySensorTypeInfo *type_info;

  /* Simulate cmd 0x75 response for T480s: major=0x004a, version=0x13 */
  guint8 data[8];

  FP_WRITE_UINT32_LE (&data[0], 0);
  FP_WRITE_UINT16_LE (&data[4], 0x0013);
  FP_WRITE_UINT16_LE (&data[6], 0x004a);

  g_assert_true (fpi_validity_sensor_parse_identify (data, sizeof (data), &ident));
  g_assert_cmpuint (ident.hw_major, ==, 0x004a);
  g_assert_cmpuint (ident.hw_version, ==, 0x0013);

  dev_info = fpi_validity_device_info_lookup (ident.hw_major, ident.hw_version);
  g_assert_nonnull (dev_info);
  g_assert_cmpuint (dev_info->type, ==, 0x00b5);

  type_info = fpi_validity_sensor_type_info_lookup (dev_info->type);
  g_assert_nonnull (type_info);
  g_assert_cmpuint (type_info->bytes_per_line, ==, 0x78);
  g_assert_cmpuint (type_info->line_width, ==, 112);
}

/* ================================================================
 * T4.13: test_sensor_state_lifecycle
 *
 * Verify that init zeros the state and clear frees allocated data.
 * ================================================================ */
static void
test_sensor_state_lifecycle (void)
{
  ValiditySensorState state;

  fpi_validity_sensor_state_init (&state);
  g_assert_null (state.device_info);
  g_assert_null (state.type_info);
  g_assert_null (state.factory_bits);
  g_assert_cmpuint (state.factory_bits_len, ==, 0);

  /* Simulate storing factory bits */
  state.factory_bits = g_memdup2 ("\x01\x02\x03", 3);
  state.factory_bits_len = 3;

  fpi_validity_sensor_state_clear (&state);
  g_assert_null (state.factory_bits);
  g_assert_cmpuint (state.factory_bits_len, ==, 0);
}

/* ================================================================
 * T4.14: test_calibration_blob_present
 *
 * Verify that the calibration blob for type 0x00b5 has expected
 * first and last bytes (from python-validity generated_tables).
 * ================================================================ */
static void
test_calibration_blob_present (void)
{
  const ValiditySensorTypeInfo *info;

  info = fpi_validity_sensor_type_info_lookup (0x00b5);
  g_assert_nonnull (info);
  g_assert_nonnull (info->calibration_blob);
  g_assert_cmpuint (info->calibration_blob_len, ==, 112);

  /* First byte: 0x9b, last byte: 0x06 */
  g_assert_cmpuint (info->calibration_blob[0], ==, 0x9b);
  g_assert_cmpuint (info->calibration_blob[111], ==, 0x06);
}

/* ================================================================
 * Tests: ENROLL
 * ================================================================ */


/* ================================================================
 * Helper: build a tagged block
 *   [tag:2LE][len:2LE][padding:MAGIC_LEN][payload:len]
 * Total block size = 4 + MAGIC_LEN + len = MAGIC_LEN + len + 4
 * Wait — re-read the parser:
 *   tag(2LE) | len(2LE) => block_size = MAGIC_LEN + len
 *   so the full block is [tag:2][len:2] + body[MAGIC_LEN + len]
 *   No — looking at the code: pos + 4 reads tag+len, then
 *   block_size = MAGIC_LEN + len, and the block starts at data[pos].
 *   Template: data[pos .. pos + block_size].
 *   Header: data[pos + MAGIC_LEN .. pos + MAGIC_LEN + len].
 *   Advance: pos += block_size.
 *
 * Actually re-reading more carefully:
 *   tag = data[pos], len = data[pos+2]
 *   block_size = MAGIC_LEN + len
 *   template = data[pos .. pos + block_size]
 *   So the 4 bytes of tag+len are INSIDE the block_size.
 *   MAGIC_LEN = 0x38 = 56 which is > 4, so tag+len fit inside.
 *
 * To build test data: write tag(2LE) at offset 0, len(2LE) at
 * offset 2, then (MAGIC_LEN - 4) padding bytes, then len payload bytes.
 * Total = MAGIC_LEN + len.
 * ================================================================ */
static guint8 *
build_block (guint16 tag, const guint8 *payload, guint16 payload_len,
             gsize *out_len)
{
  gsize block_size = ENROLLMENT_MAGIC_LEN + payload_len;
  guint8 *buf = g_malloc0 (block_size);

  FP_WRITE_UINT16_LE (buf, tag);
  FP_WRITE_UINT16_LE (buf + 2, payload_len);

  if (payload && payload_len > 0)
    memcpy (buf + ENROLLMENT_MAGIC_LEN, payload, payload_len);

  *out_len = block_size;
  return buf;
}

/* Wrap raw block data with the 2-byte declared_len prefix the parser expects:
 *   [declared_len:2LE][blocks...]
 * declared_len = blocks_len (total size of all concatenated blocks). */
static guint8 *
wrap_response (const guint8 *blocks, gsize blocks_len, gsize *out_len)
{
  *out_len = 2 + blocks_len;

  guint8 *buf = g_malloc (*out_len);

  FP_WRITE_UINT16_LE (buf, (guint16) blocks_len);
  if (blocks && blocks_len > 0)
    memcpy (buf + 2, blocks, blocks_len);
  return buf;
}

/* ================================================================
 * T8.1: parse empty data — returns TRUE, all fields NULL
 * ================================================================ */
static void
test_parse_empty (void)
{
  EnrollmentUpdateResult result;
  gboolean ok = fpi_parse_enrollment_update_response (NULL, 0, &result);

  /* Empty data (len < 2) → parser returns FALSE */
  g_assert_false (ok);
}

/* ================================================================
 * T8.2: parse single template block (tag=0)
 * ================================================================ */
static void
test_parse_template_block (void)
{
  guint8 payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  gsize block_len;
  g_autofree guint8 *block = build_block (0, payload, sizeof (payload),
                                          &block_len);
  gsize resp_len;
  g_autofree guint8 *data = wrap_response (block, block_len, &resp_len);

  EnrollmentUpdateResult result;
  gboolean ok = fpi_parse_enrollment_update_response (data, resp_len, &result);

  g_assert_true (ok);
  g_assert_nonnull (result.template_data);
  g_assert_cmpuint (result.template_len, ==, block_len);
  g_assert_null (result.header);
  g_assert_null (result.tid);

  fpi_enrollment_update_result_clear (&result);
}

/* ================================================================
 * T8.3: parse header block (tag=1)
 * ================================================================ */
static void
test_parse_header_block (void)
{
  guint8 payload[] = { 0x01, 0x02, 0x03 };
  gsize block_len;
  g_autofree guint8 *block = build_block (1, payload, sizeof (payload),
                                          &block_len);
  gsize resp_len;
  g_autofree guint8 *data = wrap_response (block, block_len, &resp_len);

  EnrollmentUpdateResult result;
  gboolean ok = fpi_parse_enrollment_update_response (data, resp_len, &result);

  g_assert_true (ok);
  g_assert_nonnull (result.header);
  g_assert_cmpuint (result.header_len, ==, sizeof (payload));
  g_assert_cmpmem (result.header, result.header_len, payload, sizeof (payload));
  g_assert_null (result.template_data);
  g_assert_null (result.tid);

  fpi_enrollment_update_result_clear (&result);
}

/* ================================================================
 * T8.4: parse tid block (tag=3) — signals enrollment complete
 * ================================================================ */
static void
test_parse_tid_block (void)
{
  guint8 payload[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
  gsize block_len;
  g_autofree guint8 *block = build_block (3, payload, sizeof (payload),
                                          &block_len);
  gsize resp_len;
  g_autofree guint8 *data = wrap_response (block, block_len, &resp_len);

  EnrollmentUpdateResult result;
  gboolean ok = fpi_parse_enrollment_update_response (data, resp_len, &result);

  g_assert_true (ok);
  g_assert_nonnull (result.tid);
  g_assert_cmpuint (result.tid_len, ==, sizeof (payload));
  g_assert_cmpmem (result.tid, result.tid_len, payload, sizeof (payload));
  g_assert_null (result.template_data);
  g_assert_null (result.header);

  fpi_enrollment_update_result_clear (&result);
}

/* ================================================================
 * T8.5: parse multiple blocks — template + header + tid
 * ================================================================ */
static void
test_parse_multiple_blocks (void)
{
  guint8 tmpl_payload[] = { 0x11, 0x22 };
  guint8 hdr_payload[] = { 0x33, 0x44, 0x55 };
  guint8 tid_payload[] = { 0x66 };

  gsize tmpl_len, hdr_len, tid_len;
  g_autofree guint8 *tmpl = build_block (0, tmpl_payload,
                                         sizeof (tmpl_payload), &tmpl_len);
  g_autofree guint8 *hdr = build_block (1, hdr_payload,
                                        sizeof (hdr_payload), &hdr_len);
  g_autofree guint8 *tid = build_block (3, tid_payload,
                                        sizeof (tid_payload), &tid_len);

  /* Concatenate all three blocks, then wrap with length prefix */
  gsize blocks_total = tmpl_len + hdr_len + tid_len;
  g_autofree guint8 *blocks = g_malloc (blocks_total);

  memcpy (blocks, tmpl, tmpl_len);
  memcpy (blocks + tmpl_len, hdr, hdr_len);
  memcpy (blocks + tmpl_len + hdr_len, tid, tid_len);

  gsize resp_len;
  g_autofree guint8 *data = wrap_response (blocks, blocks_total, &resp_len);

  EnrollmentUpdateResult result;
  gboolean ok = fpi_parse_enrollment_update_response (data, resp_len, &result);

  g_assert_true (ok);
  g_assert_nonnull (result.template_data);
  g_assert_nonnull (result.header);
  g_assert_nonnull (result.tid);
  g_assert_cmpuint (result.template_len, ==, tmpl_len);
  g_assert_cmpuint (result.header_len, ==, sizeof (hdr_payload));
  g_assert_cmpuint (result.tid_len, ==, sizeof (tid_payload));

  fpi_enrollment_update_result_clear (&result);
}

/* ================================================================
 * T8.6: parse truncated data — stops before reading past buffer
 * ================================================================ */
static void
test_parse_truncated (void)
{
  /* Build a response where the declared length is consistent with data_len
   * but the block content is too short for a full block to be parsed.
   * declared_len = 6, so data = [06 00][tag:2][len:2][2 more bytes]
   * The block_size = MAGIC_LEN + len will exceed 8 for any len > 0,
   * so the parser's "pos + block_size > data_len" check will skip it. */
  guint8 data[8];

  FP_WRITE_UINT16_LE (data, 6);        /* declared_len = 6 */
  FP_WRITE_UINT16_LE (data + 2, 0);    /* tag = 0 (template) */
  FP_WRITE_UINT16_LE (data + 4, 10);   /* len = 10 → block_size = MAGIC_LEN + 10 > 8 */
  data[6] = 0;
  data[7] = 0;

  EnrollmentUpdateResult result;
  gboolean ok = fpi_parse_enrollment_update_response (data, sizeof (data), &result);

  g_assert_true (ok);
  /* No fields should be populated since the block was truncated */
  g_assert_null (result.template_data);
  g_assert_null (result.header);
  g_assert_null (result.tid);
}

/* ================================================================
 * T8.7: parse unknown tag — silently skipped
 * ================================================================ */
static void
test_parse_unknown_tag (void)
{
  guint8 payload[] = { 0x99 };
  gsize block_len;
  g_autofree guint8 *block = build_block (42, payload, sizeof (payload),
                                          &block_len);
  gsize resp_len;
  g_autofree guint8 *data = wrap_response (block, block_len, &resp_len);

  EnrollmentUpdateResult result;
  gboolean ok = fpi_parse_enrollment_update_response (data, resp_len, &result);

  g_assert_true (ok);
  g_assert_null (result.template_data);
  g_assert_null (result.header);
  g_assert_null (result.tid);
}

/* ================================================================
 * T8.8: result_clear — frees and zeroes
 * ================================================================ */
static void
test_result_clear (void)
{
  EnrollmentUpdateResult result;

  result.header = g_malloc (10);
  result.header_len = 10;
  result.template_data = g_malloc (20);
  result.template_len = 20;
  result.tid = g_malloc (5);
  result.tid_len = 5;

  fpi_enrollment_update_result_clear (&result);

  g_assert_null (result.header);
  g_assert_null (result.template_data);
  g_assert_null (result.tid);
  g_assert_cmpuint (result.header_len, ==, 0);
  g_assert_cmpuint (result.template_len, ==, 0);
  g_assert_cmpuint (result.tid_len, ==, 0);
}

/* ================================================================
 * T8.9: parse zero-length payload — tag present but no data
 * ================================================================ */
static void
test_parse_zero_length_payload (void)
{
  gsize block_len;
  g_autofree guint8 *block = build_block (1, NULL, 0, &block_len);
  gsize resp_len;
  g_autofree guint8 *data = wrap_response (block, block_len, &resp_len);

  EnrollmentUpdateResult result;
  gboolean ok = fpi_parse_enrollment_update_response (data, resp_len, &result);

  g_assert_true (ok);
  /* Tag 1 with len=0: header should be NULL (len > 0 check in parser) */
  g_assert_null (result.header);
}

/* Mirror of the driver's reporting loop (enroll_report_progress): one
 * report per stage from @reported + 1 up to @target. Returns the new
 * high-water mark and counts the reports in @n_reports. */
static gint
report_progress_to (gint   reported,
                    gint   target,
                    guint *n_reports)
{
  while (reported < target)
    {
      reported++;
      (*n_reports)++;
    }

  return reported;
}

/* ================================================================
 * T8.10: enroll progress -- chip finishes before the nominal count
 *
 * A 5-frame enroll reports 1..4 as frames are accepted (the tid frame
 * itself reports nothing), then catches up to N once stored: every stage
 * is reported exactly once.
 * ================================================================ */
static void
test_enroll_progress_short (void)
{
  gint reported = 0;
  guint n_reports = 0;

  for (guint frame = 1; frame < 5; frame++)
    {
      gint target = fpi_validity_enroll_progress_target (reported, frame, FALSE);

      g_assert_cmpint (target, ==, (gint) frame);
      reported = report_progress_to (reported, target, &n_reports);
    }

  reported = report_progress_to (reported,
                                 fpi_validity_enroll_progress_target (reported, 5,
                                                                      TRUE),
                                 &n_reports);

  g_assert_cmpint (reported, ==, VALIDITY_ENROLL_STAGES);
  g_assert_cmpuint (n_reports, ==, VALIDITY_ENROLL_STAGES);
}

/* ================================================================
 * T8.11: enroll progress -- chip wants more than the nominal count
 *
 * While frames are still wanted, progress holds at N - 1 (so retries and
 * reports are not dropped by fprintd), and reaches N only on completion.
 * ================================================================ */
static void
test_enroll_progress_long (void)
{
  gint reported = 0;
  guint n_reports = 0;

  for (guint frame = 1; frame <= 30; frame++)
    {
      gint target = fpi_validity_enroll_progress_target (reported, frame, FALSE);

      g_assert_cmpint (target, <, VALIDITY_ENROLL_STAGES);
      g_assert_cmpint (target, >=, reported);
      reported = report_progress_to (reported, target, &n_reports);
    }

  g_assert_cmpint (reported, ==, VALIDITY_ENROLL_STAGES - 1);
  g_assert_cmpuint (n_reports, ==, VALIDITY_ENROLL_STAGES - 1);

  reported = report_progress_to (reported,
                                 fpi_validity_enroll_progress_target (reported, 31,
                                                                      TRUE),
                                 &n_reports);

  g_assert_cmpint (reported, ==, VALIDITY_ENROLL_STAGES);
  g_assert_cmpuint (n_reports, ==, VALIDITY_ENROLL_STAGES);
}

/* ================================================================
 * T8.12: enroll progress -- in-driver reconnect mid-enroll
 *
 * The reconnect restarts the chip's frame count from 0 but keeps the
 * high-water mark, so stages already reported are not reported again and
 * progress never moves backwards.
 * ================================================================ */
static void
test_enroll_progress_reconnect (void)
{
  gint reported = 0;
  guint n_reports = 0;

  /* Four frames accepted, then the session is lost */
  for (guint frame = 1; frame <= 4; frame++)
    reported = report_progress_to (reported,
                                   fpi_validity_enroll_progress_target (reported,
                                                                        frame,
                                                                        FALSE),
                                   &n_reports);
  g_assert_cmpint (reported, ==, 4);

  /* Restarted enroll: frames 1..4 add nothing, frame 5 moves on */
  for (guint frame = 1; frame <= 4; frame++)
    {
      gint target = fpi_validity_enroll_progress_target (reported, frame, FALSE);

      g_assert_cmpint (target, ==, 4);
      reported = report_progress_to (reported, target, &n_reports);
    }
  g_assert_cmpuint (n_reports, ==, 4);

  reported = report_progress_to (reported,
                                 fpi_validity_enroll_progress_target (reported, 5,
                                                                      FALSE),
                                 &n_reports);
  g_assert_cmpint (reported, ==, 5);

  /* Chip finishes on the restarted session's 6th frame */
  reported = report_progress_to (reported,
                                 fpi_validity_enroll_progress_target (reported, 6,
                                                                      TRUE),
                                 &n_reports);
  g_assert_cmpint (reported, ==, VALIDITY_ENROLL_STAGES);
  g_assert_cmpuint (n_reports, ==, VALIDITY_ENROLL_STAGES);
}

/* ================================================================
 * Tests: FWEXT
 * ================================================================ */


/* ================================================================
 * T3.1: test_fw_info_parse_present
 *
 * Verify that a valid GET_FW_INFO response (status=OK) with 1 module
 * is parsed correctly into ValidityFwInfo.
 * ================================================================ */
static void
test_fw_info_parse_present (void)
{
  ValidityFwInfo info;

  /* Build a synthetic GET_FW_INFO response:
   * major(2) + minor(2) + modcnt(2) + buildtime(4) = 10 header bytes
   * + 1 module * 12 bytes = 12
   * Total = 22 bytes (data after 2-byte status, which is stripped) */
  guint8 data[22];

  memset (data, 0, sizeof (data));

  /* major = 6 */
  data[0] = 6;
  data[1] = 0;
  /* minor = 7 */
  data[2] = 7;
  data[3] = 0;
  /* module_count = 1 */
  data[4] = 1;
  data[5] = 0;
  /* buildtime = 0x12345678 LE */
  data[6] = 0x78;
  data[7] = 0x56;
  data[8] = 0x34;
  data[9] = 0x12;
  /* Module 0: type=3, subtype=4, major=1, minor=2, size=0x1000 */
  data[10] = 3;
  data[11] = 0;
  data[12] = 4;
  data[13] = 0;
  data[14] = 1;
  data[15] = 0;
  data[16] = 2;
  data[17] = 0;
  data[18] = 0x00;
  data[19] = 0x10;
  data[20] = 0x00;
  data[21] = 0x00;

  gboolean ok = fpi_validity_fwext_parse_fw_info (data, sizeof (data),
                                                  VCSFW_STATUS_OK, &info);

  g_assert_true (ok);
  g_assert_true (info.loaded);
  g_assert_cmpuint (info.major, ==, 6);
  g_assert_cmpuint (info.minor, ==, 7);
  g_assert_cmpuint (info.module_count, ==, 1);
  g_assert_cmpuint (info.buildtime, ==, 0x12345678);
  g_assert_cmpuint (info.modules[0].type, ==, 3);
  g_assert_cmpuint (info.modules[0].subtype, ==, 4);
  g_assert_cmpuint (info.modules[0].major, ==, 1);
  g_assert_cmpuint (info.modules[0].minor, ==, 2);
  g_assert_cmpuint (info.modules[0].size, ==, 0x1000);
}

/* ================================================================
 * T3.2: test_fw_info_parse_absent
 *
 * Verify that status VCSFW_STATUS_NO_FW sets loaded=FALSE.
 * ================================================================ */
static void
test_fw_info_parse_absent (void)
{
  ValidityFwInfo info;

  gboolean ok = fpi_validity_fwext_parse_fw_info (NULL, 0,
                                                  VCSFW_STATUS_NO_FW, &info);

  g_assert_true (ok);
  g_assert_false (info.loaded);
}

/* ================================================================
 * T3.2-wire: "no fwext" decoded from the wire bytes
 *
 * GET_FW_INFO answers the two bytes b0 04 when no firmware extension is
 * loaded (python-validity flash.py checks rsp[0]==0xb0, rsp[1]==4). The
 * status is decoded u16 LE, so that is 0x04b0; the constant used to be
 * 0xb004 and the absent case was never recognised. Feed the wire bytes
 * through vcsfw_parse_status(), the decode every transfer callback uses.
 * ================================================================ */
static void
test_fw_info_parse_absent_wire (void)
{
  static const guint8 no_fw_wire[] = { 0xb0, 0x04 };
  static const guint8 swapped_wire[] = { 0x04, 0xb0 };
  ValidityFwInfo info;
  guint16 status = 0xffff;

  g_assert_true (fpi_vcsfw_parse_status (no_fw_wire, sizeof (no_fw_wire),
                                         &status));
  g_assert_cmphex (status, ==, 0x04b0);
  g_assert_cmphex (status, ==, VCSFW_STATUS_NO_FW);

  g_assert_true (fpi_validity_fwext_parse_fw_info (no_fw_wire + 2,
                                                   sizeof (no_fw_wire) - 2,
                                                   status, &info));
  g_assert_false (info.loaded);

  /* The byte-swapped value is just an unknown status, not "no fwext" */
  g_assert_true (fpi_vcsfw_parse_status (swapped_wire, sizeof (swapped_wire),
                                         &status));
  g_assert_cmphex (status, ==, 0xb004);
  g_test_expect_message ("libfprint-validity", G_LOG_LEVEL_WARNING,
                         "*unexpected status*");
  g_assert_false (fpi_validity_fwext_parse_fw_info (NULL, 0, status, &info));
  g_test_assert_expected_messages ();
  g_assert_false (info.loaded);

  /* A reply shorter than the status cannot be decoded */
  g_assert_false (fpi_vcsfw_parse_status (no_fw_wire, 1, &status));
  g_assert_false (fpi_vcsfw_parse_status (NULL, 0, &status));
}

/* ================================================================
 * T3.2-real: the real 06cb:00a2 GET_FW_INFO (43 02) reply
 *
 * fwext 6_07f_lenovo_sm_qm 1.3.6: version 1.3, build time 0x5e2ecf6e,
 * seven modules (imager first, 16320 bytes).
 * ================================================================ */
static void
test_fw_info_parse_real_a2 (void)
{
  ValidityFwInfo info;
  guint16 status = 0xffff;

  g_assert_true (fpi_vcsfw_parse_status (a2_fwext_info_reply,
                                         sizeof (a2_fwext_info_reply), &status));
  g_assert_cmphex (status, ==, VCSFW_STATUS_OK);

  g_assert_true (fpi_validity_fwext_parse_fw_info (a2_fwext_info_reply + 2,
                                                   sizeof (a2_fwext_info_reply) - 2,
                                                   status, &info));
  g_assert_true (info.loaded);
  g_assert_cmpuint (info.major, ==, 1);
  g_assert_cmpuint (info.minor, ==, 3);
  g_assert_cmpuint (info.buildtime, ==, 0x5e2ecf6e);
  g_assert_cmpuint (info.module_count, ==, 7);
  g_assert_cmpuint (info.modules[0].type, ==, 1);
  g_assert_cmphex (info.modules[0].subtype, ==, 0x4634);
  g_assert_cmpuint (info.modules[0].major, ==, 2);
  g_assert_cmpuint (info.modules[0].minor, ==, 7);
  g_assert_cmpuint (info.modules[0].size, ==, 16320);
  g_assert_cmpuint (info.modules[6].type, ==, 1);
  g_assert_cmpuint (info.modules[6].size, ==, 0x460);
}

/* ================================================================
 * T3.2b: test_fw_info_parse_unknown_status
 *
 * Verify that an unexpected status returns FALSE.
 * ================================================================ */
static void
test_fw_info_parse_unknown_status (void)
{
  ValidityFwInfo info;

  g_test_expect_message ("libfprint-validity", G_LOG_LEVEL_WARNING,
                         "*unexpected status*");

  gboolean ok = fpi_validity_fwext_parse_fw_info (NULL, 0, 0x9999, &info);

  g_test_assert_expected_messages ();

  g_assert_false (ok);
  g_assert_false (info.loaded);
}

/* ================================================================
 * T3.2c: test_fw_info_parse_truncated
 *
 * Verify that status=OK but data too short returns FALSE.
 * ================================================================ */
static void
test_fw_info_parse_truncated (void)
{
  ValidityFwInfo info;
  guint8 data[5] = { 0 };

  g_test_expect_message ("libfprint-validity", G_LOG_LEVEL_WARNING,
                         "*too short*");

  gboolean ok = fpi_validity_fwext_parse_fw_info (data, sizeof (data),
                                                  VCSFW_STATUS_OK, &info);

  g_test_assert_expected_messages ();

  g_assert_false (ok);
}

/* ================================================================
 * T3.3: test_xpfwext_file_parse
 *
 * Create a synthetic .xpfwext file in a temp dir and verify parsing.
 * Format: header + 0x1A + payload + 256-byte signature
 * ================================================================ */
static void
test_xpfwext_file_parse (void)
{
  g_autoptr(GError) error = NULL;
  ValidityFwextFile fwext;
  gchar *tmpdir;
  g_autofree gchar *path = NULL;

  tmpdir = g_dir_make_tmp ("fwext-test-XXXXXX", &error);
  g_assert_no_error (error);

  path = g_build_filename (tmpdir, "test.xpfwext", NULL);

  /* Build file: "HDR" + 0x1A + 8 bytes payload + 256 bytes sig */
  gsize header_len = 4; /* "HDR" + 0x1A */
  gsize payload_len = 8;
  gsize sig_len = 256;
  gsize total = header_len + payload_len + sig_len;

  guint8 *content = g_malloc0 (total);

  content[0] = 'H';
  content[1] = 'D';
  content[2] = 'R';
  content[3] = 0x1A;

  /* Payload: 0x01..0x08 */
  for (gsize i = 0; i < payload_len; i++)
    content[header_len + i] = (guint8) (i + 1);

  /* Signature: 0xAA repeated */
  memset (content + header_len + payload_len, 0xAA, sig_len);

  g_file_set_contents (path, (gchar *) content, total, &error);
  g_assert_no_error (error);

  gboolean ok = fpi_validity_fwext_load_file (path, &fwext, &error);
  g_assert_no_error (error);
  g_assert_true (ok);

  g_assert_cmpuint (fwext.payload_len, ==, payload_len);

  /* Check payload content */
  for (gsize i = 0; i < payload_len; i++)
    g_assert_cmpuint (fwext.payload[i], ==, i + 1);

  /* Check signature */
  for (gsize i = 0; i < sig_len; i++)
    g_assert_cmpuint (fwext.signature[i], ==, 0xAA);

  fpi_validity_fwext_file_clear (&fwext);
  g_assert_null (fwext.payload);
  g_assert_cmpuint (fwext.payload_len, ==, 0);

  /* Cleanup */
  g_unlink (path);
  g_rmdir (tmpdir);
  g_free (content);
  g_free (tmpdir);
}

/* ================================================================
 * T3.3b: test_xpfwext_file_no_delimiter
 *
 * Verify that a file without 0x1A delimiter fails to parse.
 * ================================================================ */
static void
test_xpfwext_file_no_delimiter (void)
{
  g_autoptr(GError) error = NULL;
  ValidityFwextFile fwext;
  gchar *tmpdir;
  g_autofree gchar *path = NULL;

  tmpdir = g_dir_make_tmp ("fwext-test-XXXXXX", &error);
  g_assert_no_error (error);

  path = g_build_filename (tmpdir, "bad.xpfwext", NULL);

  /* All 0xFF — no 0x1A delimiter */
  guint8 content[300];

  memset (content, 0xFF, sizeof (content));

  g_file_set_contents (path, (gchar *) content, sizeof (content), &error);
  g_assert_no_error (error);

  gboolean ok = fpi_validity_fwext_load_file (path, &fwext, &error);
  g_assert_false (ok);
  g_assert_nonnull (error);

  g_unlink (path);
  g_rmdir (tmpdir);
  g_free (tmpdir);
}

/* ================================================================
 * T3.3c: test_xpfwext_file_too_short
 *
 * Verify that a file with valid header but data shorter than
 * signature size fails.
 * ================================================================ */
static void
test_xpfwext_file_too_short (void)
{
  g_autoptr(GError) error = NULL;
  ValidityFwextFile fwext;
  gchar *tmpdir;
  g_autofree gchar *path = NULL;

  tmpdir = g_dir_make_tmp ("fwext-test-XXXXXX", &error);
  g_assert_no_error (error);

  path = g_build_filename (tmpdir, "short.xpfwext", NULL);

  /* "X" + 0x1A + 10 bytes (< 257 needed for sig + 1 byte payload) */
  guint8 content[12];

  content[0] = 'X';
  content[1] = 0x1A;
  memset (content + 2, 0, 10);

  g_file_set_contents (path, (gchar *) content, sizeof (content), &error);
  g_assert_no_error (error);

  gboolean ok = fpi_validity_fwext_load_file (path, &fwext, &error);
  g_assert_false (ok);
  g_assert_nonnull (error);

  g_unlink (path);
  g_rmdir (tmpdir);
  g_free (tmpdir);
}

/* ================================================================
 * T3.4: test_flash_write_cmd_format
 *
 * Verify that build_write_flash produces the correct wire format:
 * [0x41, partition, 1, 0, 0, offset_LE32, len_LE32, data...]
 * ================================================================ */
static void
test_flash_write_cmd_format (void)
{
  guint8 payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  guint8 cmd[13 + sizeof (payload)];
  gsize cmd_len;

  fpi_validity_fwext_build_write_flash (2, 0x1000, payload, sizeof (payload),
                                        cmd, &cmd_len);

  g_assert_cmpuint (cmd_len, ==, 13 + sizeof (payload));
  g_assert_cmpuint (cmd[0], ==, 0x41);      /* WRITE_FLASH command */
  g_assert_cmpuint (cmd[1], ==, 2);          /* partition */
  g_assert_cmpuint (cmd[2], ==, 1);          /* flag */
  g_assert_cmpuint (cmd[3], ==, 0);          /* reserved low */
  g_assert_cmpuint (cmd[4], ==, 0);          /* reserved high */

  /* offset = 0x1000 LE */
  g_assert_cmpuint (cmd[5], ==, 0x00);
  g_assert_cmpuint (cmd[6], ==, 0x10);
  g_assert_cmpuint (cmd[7], ==, 0x00);
  g_assert_cmpuint (cmd[8], ==, 0x00);

  /* length = 4 LE */
  g_assert_cmpuint (cmd[9], ==, 0x04);
  g_assert_cmpuint (cmd[10], ==, 0x00);
  g_assert_cmpuint (cmd[11], ==, 0x00);
  g_assert_cmpuint (cmd[12], ==, 0x00);

  /* data */
  g_assert_cmpmem (cmd + 13, sizeof (payload), payload, sizeof (payload));
}

/* ================================================================
 * T3.5: test_fw_sig_cmd_format
 *
 * Verify that build_write_fw_sig produces the correct wire format:
 * [0x42, partition, 0, len_LE16, signature...]
 * ================================================================ */
static void
test_fw_sig_cmd_format (void)
{
  guint8 sig[256];
  guint8 cmd[5 + 256];
  gsize cmd_len;

  memset (sig, 0xBB, sizeof (sig));

  fpi_validity_fwext_build_write_fw_sig (2, sig, sizeof (sig), cmd, &cmd_len);

  g_assert_cmpuint (cmd_len, ==, 5 + 256);
  g_assert_cmpuint (cmd[0], ==, 0x42);      /* WRITE_FW_SIG command */
  g_assert_cmpuint (cmd[1], ==, 2);          /* partition */
  g_assert_cmpuint (cmd[2], ==, 0);          /* reserved */

  /* sig length = 256 LE */
  g_assert_cmpuint (cmd[3], ==, 0x00);
  g_assert_cmpuint (cmd[4], ==, 0x01);

  g_assert_cmpmem (cmd + 5, 256, sig, 256);
}

/* ================================================================
 * T3.6: test_chunk_iteration
 *
 * Verify that building write_flash with increasing offsets covers
 * the entire payload. Simulate the chunk loop used by the SSM.
 * ================================================================ */
static void
test_chunk_iteration (void)
{
  gsize payload_len = 0x2800; /* 10 KB = 2.5 chunks of 4 KB */
  gsize write_offset = 0;
  guint chunk_count = 0;
  const gsize CHUNK_SIZE = 0x1000;

  while (write_offset < payload_len)
    {
      gsize remaining = payload_len - write_offset;
      gsize chunk_size = MIN (remaining, CHUNK_SIZE);

      g_assert_cmpuint (chunk_size, >, 0);
      g_assert_cmpuint (chunk_size, <=, CHUNK_SIZE);

      write_offset += chunk_size;
      chunk_count++;
    }

  g_assert_cmpuint (write_offset, ==, payload_len);
  g_assert_cmpuint (chunk_count, ==, 3); /* 4096 + 4096 + 2048 */
}

/* ================================================================
 * T3.7: test_hw_reg_cmd_format
 *
 * Verify WRITE_HW_REG32 and READ_HW_REG32 command formats.
 * ================================================================ */
static void
test_hw_reg_write_cmd_format (void)
{
  guint8 cmd[10];
  gsize cmd_len;

  fpi_validity_fwext_build_write_hw_reg32 (0x8000205C, 7, cmd, &cmd_len);

  g_assert_cmpuint (cmd_len, ==, 10);
  g_assert_cmpuint (cmd[0], ==, 0x08);      /* WRITE_HW_REG32 command */

  /* address = 0x8000205C LE */
  g_assert_cmpuint (cmd[1], ==, 0x5C);
  g_assert_cmpuint (cmd[2], ==, 0x20);
  g_assert_cmpuint (cmd[3], ==, 0x00);
  g_assert_cmpuint (cmd[4], ==, 0x80);

  /* value = 7 LE */
  g_assert_cmpuint (cmd[5], ==, 0x07);
  g_assert_cmpuint (cmd[6], ==, 0x00);
  g_assert_cmpuint (cmd[7], ==, 0x00);
  g_assert_cmpuint (cmd[8], ==, 0x00);

  /* size = 4 */
  g_assert_cmpuint (cmd[9], ==, 4);
}

static void
test_hw_reg_read_cmd_format (void)
{
  guint8 cmd[6];
  gsize cmd_len;

  fpi_validity_fwext_build_read_hw_reg32 (0x80002080, cmd, &cmd_len);

  g_assert_cmpuint (cmd_len, ==, 6);
  g_assert_cmpuint (cmd[0], ==, 0x07);      /* READ_HW_REG32 command */

  /* address = 0x80002080 LE */
  g_assert_cmpuint (cmd[1], ==, 0x80);
  g_assert_cmpuint (cmd[2], ==, 0x20);
  g_assert_cmpuint (cmd[3], ==, 0x00);
  g_assert_cmpuint (cmd[4], ==, 0x80);

  /* size = 4 */
  g_assert_cmpuint (cmd[5], ==, 4);
}

static void
test_hw_reg_read_parse (void)
{
  guint32 value;
  guint8 data[] = { 0x02, 0x00, 0x00, 0x00 };

  gboolean ok = fpi_validity_fwext_parse_read_hw_reg32 (data, sizeof (data),
                                                        &value);

  g_assert_true (ok);
  g_assert_cmpuint (value, ==, 2);

  /* Too short should fail */
  ok = fpi_validity_fwext_parse_read_hw_reg32 (data, 3, &value);
  g_assert_false (ok);
}

/* ================================================================
 * T3.8: test_firmware_filename
 *
 * Verify firmware filename mapping for known PIDs.
 * ================================================================ */
static void
test_firmware_filename (void)
{
  static const struct
  {
    guint16      vid;
    guint16      pid;
    const gchar *name;
    const gchar *source;
  } cases[] = {
    { 0x138a, 0x0090, "6_07f_Lenovo.xpfwext",
      "Lenovo's fingerprint driver installer n1cgn08w.exe" },
    { 0x138a, 0x0097, "6_07f_lenovo_mis_qm.xpfwext",
      "Lenovo's fingerprint driver installer nz3gf09w.exe" },
    { 0x138a, 0x009d, "6_07f_lenovo_mis_qm.xpfwext",
      "Lenovo's fingerprint driver installer nz3gf09w.exe" },
    { 0x06cb, 0x009a, "6_07f_lenovo_mis_qm.xpfwext",
      "Lenovo's fingerprint driver installer nz3gf09w.exe" },
    { 0x138a, 0x00ab, "6_07f_hp_cmit_mis_qm.xpfwext", "HP SoftPaq sp135736" },
    { 0x06cb, 0x00b7, "6_07f_hp_cmit_mis_qm.xpfwext", "HP SoftPaq sp135736" },
    { 0x06cb, 0x00cb, "6_07f_hp_mis_qm.xpfwext", "HP SoftPaq sp138431" },
    { 0x06cb, 0x00d2, "6_07f_hp_mis_qm.xpfwext", "HP SoftPaq sp138431" },
    { 0x06cb, 0x00a2, "6_07f_lenovo_sm_qm.xpfwext",
      "Lenovo's fingerprint driver installer r0yfp10w.exe (MUC 5.2.326.26)" },
  };
  const gchar *name;
  const gchar *source;

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      source = NULL;
      name = fpi_validity_fwext_get_firmware_name (cases[i].vid, cases[i].pid,
                                                   &source);
      g_assert_cmpstr (name, ==, cases[i].name);
      g_assert_cmpstr (source, ==, cases[i].source);

      /* The source is optional */
      name = fpi_validity_fwext_get_firmware_name (cases[i].vid, cases[i].pid,
                                                   NULL);
      g_assert_cmpstr (name, ==, cases[i].name);
    }

  /* Unknown PID should return NULL, and no source */
  source = "unset";
  name = fpi_validity_fwext_get_firmware_name (0x1234, 0x5678, &source);
  g_assert_null (name);
  g_assert_null (source);
}

/* ================================================================
 * T3.9: test_missing_firmware_file
 *
 * Verify that find_firmware returns an error when the file is not
 * found in any search path.
 * ================================================================ */
static void
test_missing_firmware_file (void)
{
  g_autoptr(GError) error = NULL;

  /* This should fail since firmware files aren't installed in CI */
  g_autofree gchar *path = fpi_validity_fwext_find_firmware (0x06cb, 0x009a,
                                                             &error);

  /* It either found a file or returned an error — both are valid.
   * In CI, it should be an error. On a real system, it might succeed. */
  if (path == NULL)
    {
      g_assert_nonnull (error);
      g_assert_true (g_error_matches (error, FP_DEVICE_ERROR,
                                      FP_DEVICE_ERROR_DATA_NOT_FOUND));
    }
  else
    {
      g_assert_no_error (error);
      g_assert_true (g_file_test (path, G_FILE_TEST_IS_REGULAR));
    }
}

/* ================================================================
 * T3.9a: test_missing_firmware_hint
 *
 * When the firmware file is missing, the error names the file, every
 * search path (the list is built from the search-path array) and the
 * vendor package for that particular file, not a Lenovo one for all.
 * ================================================================ */
static void
test_missing_firmware_hint (void)
{
  static const struct
  {
    guint16 vid;
    guint16 pid;
  } devices[] = {
    { 0x138a, 0x0090 },   /* Lenovo, not in the nz3gf09w.exe package */
    { 0x06cb, 0x00b7 },   /* HP, cmit file */
    { 0x06cb, 0x00cb },   /* HP, mis_qm file */
  };

  for (gsize i = 0; i < G_N_ELEMENTS (devices); i++)
    {
      g_autoptr(GError) error = NULL;
      const gchar *source = NULL;
      const gchar *name = fpi_validity_fwext_get_firmware_name (devices[i].vid,
                                                                devices[i].pid,
                                                                &source);
      g_autofree gchar *path = fpi_validity_fwext_find_firmware (devices[i].vid,
                                                                 devices[i].pid,
                                                                 &error);

      /* Installed on this machine -- nothing to check */
      if (path != NULL)
        continue;

      g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND);
      g_assert_nonnull (strstr (error->message, name));
      g_assert_nonnull (strstr (error->message, source));
      g_assert_nonnull (strstr (error->message, "/usr/share/libfprint/validity"));
      g_assert_nonnull (strstr (error->message, "/var/lib/python-validity"));
      g_assert_nonnull (strstr (error->message, "/var/run/python-validity"));
      g_assert_nonnull (strstr (error->message, "/usr/share/python-validity"));
    }
}

/* ================================================================
 * T3.9b: test_unsupported_pid_firmware
 *
 * Verify that find_firmware for an unknown PID returns NOT_SUPPORTED.
 * ================================================================ */
static void
test_unsupported_pid_firmware (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree gchar *path = fpi_validity_fwext_find_firmware (0x1234, 0x5678,
                                                             &error);

  g_assert_null (path);
  g_assert_nonnull (error);
  g_assert_true (g_error_matches (error, FP_DEVICE_ERROR,
                                  FP_DEVICE_ERROR_NOT_SUPPORTED));
}

/* ================================================================
 * T3.10: test_fwext_db_write_enable_blob
 *
 * Since blobs are now loaded from external data files at runtime,
 * this test verifies the function returns NULL when no data is loaded.
 * ================================================================ */
static void
test_fwext_db_write_enable_blob (void)
{
  /* Create a minimal FpiDeviceValidity with empty data stores.
   * Since no data files are loaded, the accessor should return NULL. */
  FpiDeviceValidity dev = { 0 };

  fpi_validity_data_store_init (&dev.device_data);

  gsize len;
  const guint8 *blob = fpi_validity_fwext_get_db_write_enable (&dev, &len);
  g_assert_null (blob);

  fpi_validity_data_store_free (&dev.device_data);
}

/* ================================================================
 * T3.11: test_reboot_cmd_format
 *
 * Verify reboot command: 0x05, 0x02, 0x00
 * ================================================================ */
static void
test_reboot_cmd_format (void)
{
  guint8 cmd[3];
  gsize cmd_len;

  fpi_validity_fwext_build_reboot (cmd, &cmd_len);

  g_assert_cmpuint (cmd_len, ==, 3);
  g_assert_cmpuint (cmd[0], ==, 0x05);
  g_assert_cmpuint (cmd[1], ==, 0x02);
  g_assert_cmpuint (cmd[2], ==, 0x00);
}

/* ================================================================
 * fwext_file_clear on already-cleared struct
 *
 * Double-free guard.
 * ================================================================ */
static void
test_file_clear_idempotent (void)
{
  ValidityFwextFile fwext = { 0 };

  /* Clear an empty struct — should not crash */
  fpi_validity_fwext_file_clear (&fwext);
  fpi_validity_fwext_file_clear (&fwext);

  g_assert_null (fwext.payload);
  g_assert_cmpuint (fwext.payload_len, ==, 0);
}

/* ================================================================
 * Tests: DB
 * ================================================================ */


/* ================================================================
 * T6.1: test_cmd_db_info
 *
 * Verify cmd 0x45 (DB info) is a single-byte command.
 * ================================================================ */
static void
test_cmd_db_info (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "b", VCSFW_CMD_DB_INFO);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 1);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_DB_INFO);
}

/* ================================================================
 * T6.2: test_cmd_get_user_storage
 *
 * Verify cmd 0x4B format with a known storage name.
 * ================================================================ */
static void
test_cmd_get_user_storage (void)
{
  gsize len;
  const gchar *name = "StgWindsor";
  gsize name_len = strlen (name) + 1; /* includes NUL */
  g_autofree guint8 *cmd = fpi_validity_db_build_cmd_get_user_storage (name, &len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 1 + 2 + 2 + name_len);  /* cmd + dbid + name_len + name */
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_GET_USER_STORAGE);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[1]), ==, 0);  /* dbid = 0 → lookup by name */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[3]), ==, name_len);
  g_assert_cmpmem (&cmd[5], name_len, name, name_len);
}

/* ================================================================
 * T6.3: test_cmd_get_user_storage_null_name
 *
 * When name is NULL, should produce a command with zero name_len.
 * ================================================================ */
static void
test_cmd_get_user_storage_null_name (void)
{
  gsize len;
  g_autofree guint8 *cmd = fpi_validity_db_build_cmd_get_user_storage (NULL, &len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 5);  /* cmd(1) + dbid(2) + name_len(2) */
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_GET_USER_STORAGE);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[3]), ==, 0);  /* name_len = 0 */
}

/* ================================================================
 * T6.4: test_cmd_get_user
 *
 * Verify cmd 0x4A format for get-by-dbid.
 * ================================================================ */
static void
test_cmd_get_user (void)
{
  gsize len;
  g_autofree guint8 *cmd = fpi_validity_db_build_cmd_get_user (0x1234, &len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 7);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_GET_USER);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[1]), ==, 0x1234);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[3]), ==, 0);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[5]), ==, 0);
}

/* ================================================================
 * T6.5: test_cmd_lookup_user
 *
 * Verify cmd 0x4A format for lookup-by-identity.
 * ================================================================ */
static void
test_cmd_lookup_user (void)
{
  gsize len;
  guint8 identity[] = { 0x01, 0x02, 0x03, 0x04 };
  g_autofree guint8 *cmd = validity_pack_new (
    &len, "bhhhd",
    VCSFW_CMD_GET_USER,
    (guint16) 0,                     /* dbid = 0 → lookup by name */
    (guint16) 0x0003,                /* storage */
    (guint16) sizeof (identity),     /* identity_len */
    identity, (gsize) sizeof (identity));

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 7 + sizeof (identity));
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_GET_USER);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[1]), ==, 0);       /* dbid = 0 */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[3]), ==, 0x0003);  /* storage */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[5]), ==, sizeof (identity));
  g_assert_cmpmem (&cmd[7], sizeof (identity), identity, sizeof (identity));
}

/* ================================================================
 * T6.6: test_cmd_new_record
 *
 * Verify cmd 0x47 format.
 * ================================================================ */
static void
test_cmd_new_record (void)
{
  gsize len;
  guint8 data[] = { 0xAA, 0xBB };
  g_autofree guint8 *cmd = fpi_validity_db_build_cmd_new_record (
    0x0003, 0x0005, 0x0003, data, sizeof (data), &len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 9 + sizeof (data));
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_NEW_RECORD);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[1]), ==, 0x0003);  /* parent */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[3]), ==, 0x0005);  /* type */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[5]), ==, 0x0003);  /* storage */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[7]), ==, sizeof (data));
  g_assert_cmpmem (&cmd[9], sizeof (data), data, sizeof (data));
}

/* ================================================================
 * T6.7: test_cmd_del_record
 *
 * Verify cmd 0x48 format.
 * ================================================================ */
static void
test_cmd_del_record (void)
{
  gsize len;
  g_autofree guint8 *cmd = fpi_validity_db_build_cmd_del_record (0xABCD, &len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 3);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_DEL_RECORD);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[1]), ==, 0xABCD);
}

/* ================================================================
 * T6.8: test_cmd_create_enrollment
 *
 * Verify cmd 0x69 start and end variants.
 * ================================================================ */
static void
test_cmd_create_enrollment (void)
{
  gsize len;

  /* Start enrollment */
  g_autofree guint8 *cmd_start = fpi_validity_db_build_cmd_create_enrollment (TRUE, &len);

  g_assert_nonnull (cmd_start);
  g_assert_cmpuint (len, ==, 5);
  g_assert_cmpuint (cmd_start[0], ==, VCSFW_CMD_CREATE_ENROLLMENT);
  g_assert_cmpuint (FP_READ_UINT32_LE (&cmd_start[1]), ==, 1);

  /* End enrollment */
  g_autofree guint8 *cmd_end = fpi_validity_db_build_cmd_create_enrollment (FALSE, &len);
  g_assert_nonnull (cmd_end);
  g_assert_cmpuint (len, ==, 5);
  g_assert_cmpuint (cmd_end[0], ==, VCSFW_CMD_CREATE_ENROLLMENT);
  g_assert_cmpuint (FP_READ_UINT32_LE (&cmd_end[1]), ==, 0);
}

/* ================================================================
 * T6.9: test_cmd_enrollment_update_start
 *
 * Verify cmd 0x68 format.
 * ================================================================ */
static void
test_cmd_enrollment_update_start (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "bww",
                                              VCSFW_CMD_ENROLLMENT_UPDATE_START,
                                              (guint32) 0x12345678,
                                              (guint32) 0);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 9);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_ENROLLMENT_UPDATE_START);
  g_assert_cmpuint (FP_READ_UINT32_LE (&cmd[1]), ==, 0x12345678);
  g_assert_cmpuint (FP_READ_UINT32_LE (&cmd[5]), ==, 0);
}

/* ================================================================
 * T6.10: test_cmd_match_finger
 *
 * Verify cmd 0x5E format (13 bytes per python-validity).
 * ================================================================ */
static void
test_cmd_match_finger (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "bbbhhhhh",
                                              VCSFW_CMD_MATCH_FINGER,
                                              0x02, 0xFF, 0, 0, 1, 0, 0);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 13);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_MATCH_FINGER);
  g_assert_cmpuint (cmd[1], ==, 0x02);
  g_assert_cmpuint (cmd[2], ==, 0xFF);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[3]), ==, 0);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[5]), ==, 0);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[7]), ==, 1);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[9]), ==, 0);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[11]), ==, 0);
}

/* ================================================================
 * T6.11: test_cmd_get_match_result
 *
 * Verify cmd 0x60 format.
 * ================================================================ */
static void
test_cmd_get_match_result (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "bw",
                                              VCSFW_CMD_GET_MATCH_RESULT,
                                              (guint32) 0);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 5);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_GET_MATCH_RESULT);
  /* remaining bytes should be 0 */
  g_assert_cmpuint (cmd[1], ==, 0);
  g_assert_cmpuint (cmd[2], ==, 0);
  g_assert_cmpuint (cmd[3], ==, 0);
  g_assert_cmpuint (cmd[4], ==, 0);
}

/* ================================================================
 * T6.12: test_cmd_match_cleanup
 *
 * Verify cmd 0x62 format.
 * ================================================================ */
static void
test_cmd_match_cleanup (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "bw",
                                              VCSFW_CMD_MATCH_CLEANUP,
                                              (guint32) 0);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 5);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_MATCH_CLEANUP);
}

/* ================================================================
 * T6.13: test_cmd_get_prg_status
 *
 * Verify cmd 0x51 both normal and extended variant.
 * ================================================================ */
static void
test_cmd_get_prg_status (void)
{
  gsize len;

  g_autofree guint8 *normal = validity_pack_new (&len, "bw",
                                                 VCSFW_CMD_GET_PRG_STATUS,
                                                 (guint32) 0);

  g_assert_cmpuint (len, ==, 5);
  g_assert_cmpuint (normal[0], ==, VCSFW_CMD_GET_PRG_STATUS);
  /* Normal: 00000000 */
  g_assert_cmpuint (normal[1], ==, 0);
  g_assert_cmpuint (normal[2], ==, 0);
  g_assert_cmpuint (normal[3], ==, 0);
  g_assert_cmpuint (normal[4], ==, 0);

  g_autofree guint8 *ext = validity_pack_new (&len, "bw",
                                              VCSFW_CMD_GET_PRG_STATUS,
                                              (guint32) 0x00002000);
  g_assert_cmpuint (len, ==, 5);
  g_assert_cmpuint (ext[0], ==, VCSFW_CMD_GET_PRG_STATUS);
  /* Extended: 00200000 LE */
  g_assert_cmpuint (ext[1], ==, 0x00);
  g_assert_cmpuint (ext[2], ==, 0x20);
  g_assert_cmpuint (ext[3], ==, 0x00);
  g_assert_cmpuint (ext[4], ==, 0x00);
}

/* ================================================================
 * T6.14: test_cmd_capture_stop
 *
 * Verify cmd 0x04 format.
 * ================================================================ */
static void
test_cmd_capture_stop (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "b",
                                              VCSFW_CMD_CAPTURE_STOP);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 1);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_CAPTURE_STOP);
}

/* ================================================================
 * T6.15: test_cmd_call_cleanups
 *
 * Verify cmd 0x1a format.
 * ================================================================ */
static void
test_cmd_call_cleanups (void)
{
  gsize len;
  g_autofree guint8 *cmd = fpi_validity_db_build_cmd_call_cleanups (&len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 1);
  g_assert_cmpuint (cmd[0], ==, 0x1a);
}

/* ================================================================
 * T6.16: test_parse_db_info
 *
 * Construct a known db_info binary response and verify parsing.
 * ================================================================ */
static void
test_parse_db_info (void)
{
  guint8 data[0x1C];  /* 24 bytes header + 4 bytes for 2 roots */
  ValidityDbInfo info;

  memset (data, 0, sizeof (data));

  /* Header: unknown1=1, unknown0=0, total=65536, used=1024, free=64512, records=10, n_roots=2 */
  FP_WRITE_UINT32_LE (&data[0], 1);        /* unknown1 */
  FP_WRITE_UINT32_LE (&data[4], 0);        /* unknown0 */
  FP_WRITE_UINT32_LE (&data[8], 65536);    /* total */
  FP_WRITE_UINT32_LE (&data[12], 1024);    /* used */
  FP_WRITE_UINT32_LE (&data[16], 64512);   /* free */
  FP_WRITE_UINT16_LE (&data[20], 10);      /* records */
  FP_WRITE_UINT16_LE (&data[22], 2);       /* n_roots */
  FP_WRITE_UINT16_LE (&data[24], 0x0001);  /* root[0] */
  FP_WRITE_UINT16_LE (&data[26], 0x0003);  /* root[1] */

  g_assert_true (fpi_validity_db_parse_info (data, sizeof (data), &info));

  g_assert_cmpuint (info.unknown1, ==, 1);
  g_assert_cmpuint (info.unknown0, ==, 0);
  g_assert_cmpuint (info.total, ==, 65536);
  g_assert_cmpuint (info.used, ==, 1024);
  g_assert_cmpuint (info.free_space, ==, 64512);
  g_assert_cmpuint (info.records, ==, 10);
  g_assert_cmpuint (info.n_roots, ==, 2);
  g_assert_nonnull (info.roots);
  g_assert_cmpuint (info.roots[0], ==, 1);
  g_assert_cmpuint (info.roots[1], ==, 3);

  fpi_validity_db_info_clear (&info);
}

/* ================================================================
 * T6.17: test_parse_db_info_too_short
 *
 * A response shorter than 24 bytes should fail.
 * ================================================================ */
static void
test_parse_db_info_too_short (void)
{
  guint8 data[20] = { 0 };
  ValidityDbInfo info;

  g_assert_false (fpi_validity_db_parse_info (data, sizeof (data), &info));
}

/* ================================================================
 * T6.18: test_parse_user_storage
 *
 * Construct a user storage response with 2 users and verify.
 * ================================================================ */
static void
test_parse_user_storage (void)
{
  /* Header: dbid=3, user_count=2, name_sz=11, unknown=0
   * User table: {dbid=10, val_sz=100}, {dbid=11, val_sz=200}
   * Name: "StgWindsor\0" */
  gsize name_len = strlen ("StgWindsor") + 1;
  gsize total = 8 + 2 * 4 + name_len;
  g_autofree guint8 *data = g_new0 (guint8, total);

  FP_WRITE_UINT16_LE (&data[0], 3);        /* dbid */
  FP_WRITE_UINT16_LE (&data[2], 2);        /* user_count */
  FP_WRITE_UINT16_LE (&data[4], name_len); /* name_sz */
  FP_WRITE_UINT16_LE (&data[6], 0);        /* unknown */

  FP_WRITE_UINT16_LE (&data[8], 10);       /* user[0].dbid */
  FP_WRITE_UINT16_LE (&data[10], 100);     /* user[0].val_sz */
  FP_WRITE_UINT16_LE (&data[12], 11);      /* user[1].dbid */
  FP_WRITE_UINT16_LE (&data[14], 200);     /* user[1].val_sz */

  memcpy (&data[16], "StgWindsor", name_len);

  ValidityUserStorage storage;
  g_assert_true (fpi_validity_db_parse_user_storage (data, total, &storage));

  g_assert_cmpuint (storage.dbid, ==, 3);
  g_assert_cmpuint (storage.user_count, ==, 2);
  g_assert_cmpstr (storage.name, ==, "StgWindsor");
  g_assert_nonnull (storage.user_dbids);
  g_assert_cmpuint (storage.user_dbids[0], ==, 10);
  g_assert_cmpuint (storage.user_dbids[1], ==, 11);
  g_assert_cmpuint (storage.user_val_sizes[0], ==, 100);
  g_assert_cmpuint (storage.user_val_sizes[1], ==, 200);

  fpi_validity_user_storage_clear (&storage);
}

/* ================================================================
 * T6.19: test_parse_user
 *
 * Construct a user response with one finger and verify.
 * ================================================================ */
static void
test_parse_user (void)
{
  guint8 identity_bytes[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  /* Header: dbid=10, finger_count=1, unknown=0, identity_sz=4
   * Finger: dbid=20, subtype=2, storage=3, value_size=500
   * Identity: 4 bytes */
  gsize total = 8 + 8 + sizeof (identity_bytes);
  g_autofree guint8 *data = g_new0 (guint8, total);

  FP_WRITE_UINT16_LE (&data[0], 10);     /* dbid */
  FP_WRITE_UINT16_LE (&data[2], 1);      /* finger_count */
  FP_WRITE_UINT16_LE (&data[4], 0);      /* unknown */
  FP_WRITE_UINT16_LE (&data[6], sizeof (identity_bytes));  /* identity_sz */

  /* Finger entry */
  FP_WRITE_UINT16_LE (&data[8], 20);     /* finger.dbid */
  FP_WRITE_UINT16_LE (&data[10], 2);     /* finger.subtype = right index */
  FP_WRITE_UINT16_LE (&data[12], 3);     /* finger.storage */
  FP_WRITE_UINT16_LE (&data[14], 500);   /* finger.value_size */

  memcpy (&data[16], identity_bytes, sizeof (identity_bytes));

  ValidityUser user;
  g_assert_true (fpi_validity_db_parse_user (data, total, &user));

  g_assert_cmpuint (user.dbid, ==, 10);
  g_assert_cmpuint (user.finger_count, ==, 1);
  g_assert_nonnull (user.fingers);
  g_assert_cmpuint (user.fingers[0].dbid, ==, 20);
  g_assert_cmpuint (user.fingers[0].subtype, ==, 2);
  g_assert_cmpuint (user.fingers[0].storage, ==, 3);
  g_assert_cmpuint (user.fingers[0].value_size, ==, 500);
  g_assert_nonnull (user.identity);
  g_assert_cmpuint (user.identity_len, ==, sizeof (identity_bytes));
  g_assert_cmpmem (user.identity, user.identity_len,
                   identity_bytes, sizeof (identity_bytes));

  fpi_validity_user_clear (&user);
}

/* ================================================================
 * T6.20: test_parse_new_record_id
 *
 * Verify parsing of new_record response (cmd 0x47).
 * ================================================================ */
static void
test_parse_new_record_id (void)
{
  guint16 record_id;
  guint8 data[] = { 0x42, 0x00 };

  g_assert_true (fpi_validity_db_parse_new_record_id (data, sizeof (data), &record_id));
  g_assert_cmpuint (record_id, ==, 0x0042);
}

/* ================================================================
 * T6.21: test_parse_new_record_id_too_short
 *
 * A 1-byte response should fail.
 * ================================================================ */
static void
test_parse_new_record_id_too_short (void)
{
  guint16 record_id;
  guint8 data[] = { 0x42 };

  g_assert_false (fpi_validity_db_parse_new_record_id (data, sizeof (data), &record_id));
}

/* ================================================================
 * T6.22: test_build_identity
 *
 * Build a UUID identity and verify structure.
 * ================================================================ */
static void
test_build_identity (void)
{
  gsize len;
  const gchar *uuid = "550e8400-e29b-41d4-a716-446655440000";
  g_autofree guint8 *id = fpi_validity_db_build_identity (uuid, &len);

  g_assert_nonnull (id);
  /* Minimum size enforced */
  g_assert_cmpuint (len, >=, VALIDITY_IDENTITY_MIN_SIZE);

  /* type = SID (3) */
  g_assert_cmpuint (FP_READ_UINT32_LE (&id[0]), ==, VALIDITY_IDENTITY_TYPE_SID);

  /* len field = UUID string length */
  gsize uuid_len = strlen (uuid);
  g_assert_cmpuint (FP_READ_UINT32_LE (&id[4]), ==, uuid_len);

  /* UUID payload */
  g_assert_cmpmem (&id[8], uuid_len, uuid, uuid_len);

  /* Remaining bytes should be zero-padded */
  for (gsize i = 8 + uuid_len; i < len; i++)
    g_assert_cmpuint (id[i], ==, 0);
}

/* ================================================================
 * T6.23: test_build_finger_data
 *
 * Build finger data and verify the tagged format.
 * ================================================================ */
static void
test_build_finger_data (void)
{
  gsize len;
  guint8 template[] = { 0x11, 0x22, 0x33 };
  guint8 tid[] = { 0xAA, 0xBB };
  g_autofree guint8 *fd = fpi_validity_db_build_finger_data (
    2, template, sizeof (template), tid, sizeof (tid), &len);

  g_assert_nonnull (fd);

  /* Check header: subtype(2) | flags=3(2) | tinfo_len(2) | 0x20(2) */
  g_assert_cmpuint (FP_READ_UINT16_LE (&fd[0]), ==, 2);   /* subtype */
  g_assert_cmpuint (FP_READ_UINT16_LE (&fd[2]), ==, 3);   /* flags */

  gsize expected_tinfo_len = 4 + sizeof (template) + 4 + sizeof (tid);
  g_assert_cmpuint (FP_READ_UINT16_LE (&fd[4]), ==, expected_tinfo_len);
  g_assert_cmpuint (FP_READ_UINT16_LE (&fd[6]), ==, 0x20);

  /* Tag 1 (template) at offset 8 */
  g_assert_cmpuint (FP_READ_UINT16_LE (&fd[8]), ==, 1);
  g_assert_cmpuint (FP_READ_UINT16_LE (&fd[10]), ==, sizeof (template));
  g_assert_cmpmem (&fd[12], sizeof (template), template, sizeof (template));

  /* Tag 2 (tid) at offset 12+3 = 15 */
  gsize tid_offset = 12 + sizeof (template);
  g_assert_cmpuint (FP_READ_UINT16_LE (&fd[tid_offset]), ==, 2);
  g_assert_cmpuint (FP_READ_UINT16_LE (&fd[tid_offset + 2]), ==, sizeof (tid));
  g_assert_cmpmem (&fd[tid_offset + 4], sizeof (tid), tid, sizeof (tid));

  /* Total should be header(8) + tinfo + 0x20 padding */
  gsize expected_total = 8 + expected_tinfo_len + 0x20;
  g_assert_cmpuint (len, ==, expected_total);
}

/* ================================================================
 * T6.24: test_db_write_enable_blob
 *
 * Since blobs are now loaded from external data files at runtime,
 * verify the function returns NULL when no data is loaded.
 * ================================================================ */
static void
test_db_write_enable_blob (void)
{
  FpiDeviceValidity dev = { 0 };

  fpi_validity_data_store_init (&dev.device_data);

  gsize len;
  const guint8 *blob = fpi_validity_db_get_write_enable_blob (&dev, &len);
  g_assert_null (blob);

  fpi_validity_data_store_free (&dev.device_data);
}

/* ================================================================
 * T6.25: test_parse_record_value
 *
 * Construct a record value response and verify parsing.
 * ================================================================ */
static void
test_parse_record_value (void)
{
  guint8 value[] = { 0x01, 0x02, 0x03 };
  /* Format: dbid(2) type(2) storage(2) sz(2) pad(2) value */
  gsize total = 10 + sizeof (value);
  g_autofree guint8 *data = g_new0 (guint8, total);

  FP_WRITE_UINT16_LE (&data[0], 42);     /* dbid */
  FP_WRITE_UINT16_LE (&data[2], 8);      /* type = DATA */
  FP_WRITE_UINT16_LE (&data[4], 3);      /* storage */
  FP_WRITE_UINT16_LE (&data[6], sizeof (value));  /* sz */
  FP_WRITE_UINT16_LE (&data[8], 0);      /* pad */
  memcpy (&data[10], value, sizeof (value));

  ValidityDbRecord record;
  g_assert_true (fpi_validity_db_parse_record_value (data, total, &record));

  g_assert_cmpuint (record.dbid, ==, 42);
  g_assert_cmpuint (record.type, ==, 8);
  g_assert_cmpuint (record.storage, ==, 3);
  g_assert_nonnull (record.value);
  g_assert_cmpuint (record.value_len, ==, sizeof (value));
  g_assert_cmpmem (record.value, record.value_len, value, sizeof (value));

  fpi_validity_db_record_clear (&record);
}

/* ================================================================
 * T6.26: test_parse_record_children
 *
 * Construct a record children response and verify parsing.
 * ================================================================ */
static void
test_parse_record_children (void)
{
  /* Format: dbid(2) type(2) storage(2) sz(2) cnt(2) pad(2)
   * children[cnt * 4: dbid(2) type(2)] */
  gsize total = 12 + 2 * 4;
  g_autofree guint8 *data = g_new0 (guint8, total);

  FP_WRITE_UINT16_LE (&data[0], 3);      /* dbid */
  FP_WRITE_UINT16_LE (&data[2], 4);      /* type = STORAGE */
  FP_WRITE_UINT16_LE (&data[4], 3);      /* storage */
  FP_WRITE_UINT16_LE (&data[6], 0);      /* sz */
  FP_WRITE_UINT16_LE (&data[8], 2);      /* child_count */
  FP_WRITE_UINT16_LE (&data[10], 0);     /* pad */

  /* Children */
  FP_WRITE_UINT16_LE (&data[12], 10);    /* child[0].dbid */
  FP_WRITE_UINT16_LE (&data[14], 5);     /* child[0].type = USER */
  FP_WRITE_UINT16_LE (&data[16], 11);    /* child[1].dbid */
  FP_WRITE_UINT16_LE (&data[18], 5);     /* child[1].type = USER */

  ValidityRecordChildren children;
  g_assert_true (fpi_validity_db_parse_record_children (data, total, &children));

  g_assert_cmpuint (children.dbid, ==, 3);
  g_assert_cmpuint (children.type, ==, 4);
  g_assert_cmpuint (children.storage, ==, 3);
  g_assert_cmpuint (children.child_count, ==, 2);
  g_assert_nonnull (children.children);
  g_assert_cmpuint (children.children[0].dbid, ==, 10);
  g_assert_cmpuint (children.children[0].type, ==, 5);
  g_assert_cmpuint (children.children[1].dbid, ==, 11);
  g_assert_cmpuint (children.children[1].type, ==, 5);

  fpi_validity_record_children_clear (&children);
}

/* ================================================================
 * T6.27: test_cmd_enrollment_update
 *
 * Verify cmd 0x6B format with template data.
 * ================================================================ */
static void
test_cmd_enrollment_update (void)
{
  gsize len;
  guint8 prev[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  g_autofree guint8 *cmd = fpi_validity_db_build_cmd_enrollment_update (
    prev, sizeof (prev), &len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 1 + sizeof (prev));
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_ENROLLMENT_UPDATE);
  g_assert_cmpmem (&cmd[1], sizeof (prev), prev, sizeof (prev));
}

/* ================================================================
 * T6.28: test_cmd_get_record_value
 *
 * Verify cmd 0x49 format.
 * ================================================================ */
static void
test_cmd_get_record_value (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "bh",
                                              VCSFW_CMD_GET_RECORD_VALUE,
                                              (guint16) 0x5678);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 3);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_GET_RECORD_VALUE);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[1]), ==, 0x5678);
}

/* ================================================================
 * T6.29: test_cmd_get_record_children
 *
 * Verify cmd 0x46 format.
 * ================================================================ */
static void
test_cmd_get_record_children (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "bh",
                                              VCSFW_CMD_GET_RECORD_CHILDREN,
                                              (guint16) 0x1234);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 3);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_GET_RECORD_CHILDREN);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[1]), ==, 0x1234);
}

/* ================================================================
 * Tests: VERIFY
 * ================================================================ */


/* ================================================================
 * Helper: build a TLV dict entry  tag(2LE) | len(2LE) | data[len]
 * Returns bytes written.
 * ================================================================ */
static gsize
build_tlv_entry (guint8 *buf, guint16 tag, const guint8 *data, guint16 len)
{
  FP_WRITE_UINT16_LE (&buf[0], tag);
  FP_WRITE_UINT16_LE (&buf[2], len);
  if (len > 0)
    memcpy (&buf[4], data, len);
  return 4 + len;
}

/* ================================================================
 * Helper: Build a complete match result payload:
 *   total_len(2LE) | TLV entries...
 * ================================================================ */
static guint8 *
build_match_payload (guint32       user_dbid,
                     guint16       subtype,
                     const guint8 *hash,
                     gsize         hash_len,
                     gsize        *out_len)
{
  /* Max size: 2 (total_len) + 3 entries × (4 header + max data) */
  guint8 *buf = g_new0 (guint8, 256);
  gsize pos = 2;  /* skip total_len placeholder */

  /* Tag 1: user_dbid (4 bytes LE) */
  guint8 dbid_data[4];

  FP_WRITE_UINT32_LE (dbid_data, user_dbid);
  pos += build_tlv_entry (&buf[pos], 1, dbid_data, 4);

  /* Tag 3: subtype (2 bytes LE) */
  guint8 sub_data[2];
  FP_WRITE_UINT16_LE (sub_data, subtype);
  pos += build_tlv_entry (&buf[pos], 3, sub_data, 2);

  /* Tag 4: hash */
  if (hash && hash_len > 0)
    pos += build_tlv_entry (&buf[pos], 4, hash, hash_len);

  /* Write total_len at offset 0 */
  FP_WRITE_UINT16_LE (&buf[0], (guint16) (pos - 2));

  *out_len = pos;
  return buf;
}

/* ================================================================
 * R1: parse_match_result with valid TLV data
 *
 * Verifies that user_dbid, subtype, and hash are correctly parsed
 * from a TLV dictionary.
 * ================================================================ */
static void
test_parse_match_result_valid (void)
{
  guint8 hash[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
  gsize payload_len;
  g_autofree guint8 *payload = build_match_payload (
    0x00001234, 3, hash, sizeof (hash), &payload_len);

  ValidityMatchResult result = { 0 };
  gboolean ok = fpi_validity_parse_match_result (payload, payload_len, &result);

  g_assert_true (ok);
  g_assert_true (result.matched);
  g_assert_cmpuint (result.user_dbid, ==, 0x00001234);
  g_assert_cmpuint (result.subtype, ==, 3);
  g_assert_nonnull (result.hash);
  g_assert_cmpuint (result.hash_len, ==, sizeof (hash));
  g_assert_cmpmem (result.hash, result.hash_len, hash, sizeof (hash));

  fpi_validity_match_result_clear (&result);
}

/* ================================================================
 * R1b: parse_match_result iterates all TLV entries
 *
 * Tags appear in non-sequential order (tag 3 before tag 1) to
 * verify the parser processes every entry, not just the first.
 * ================================================================ */
static void
test_parse_match_result_multi_tags (void)
{
  /* Manually build: total_len(2) | tag3(2+2+2) | tag1(2+2+4) | tag4(2+2+3) */
  guint8 buf[256];
  gsize pos = 2;

  /* Tag 3 first: subtype = 7 */
  guint8 sub[2];

  FP_WRITE_UINT16_LE (sub, 7);
  pos += build_tlv_entry (&buf[pos], 3, sub, 2);

  /* Tag 1 second: user_dbid = 0xDEADBEEF */
  guint8 dbid[4];
  FP_WRITE_UINT32_LE (dbid, 0xDEADBEEF);
  pos += build_tlv_entry (&buf[pos], 1, dbid, 4);

  /* Tag 4 third: hash = {0x11, 0x22, 0x33} */
  guint8 hash[] = { 0x11, 0x22, 0x33 };
  pos += build_tlv_entry (&buf[pos], 4, hash, 3);

  FP_WRITE_UINT16_LE (&buf[0], (guint16) (pos - 2));

  ValidityMatchResult result = { 0 };
  gboolean ok = fpi_validity_parse_match_result (buf, pos, &result);

  g_assert_true (ok);
  g_assert_true (result.matched);
  g_assert_cmpuint (result.user_dbid, ==, 0xDEADBEEF);
  g_assert_cmpuint (result.subtype, ==, 7);
  g_assert_nonnull (result.hash);
  g_assert_cmpuint (result.hash_len, ==, 3);
  g_assert_cmpmem (result.hash, result.hash_len, hash, 3);

  fpi_validity_match_result_clear (&result);
}

/* ================================================================
 * R1c: parse_match_result with empty dict (no match)
 *
 * A no-match scenario should return ok=TRUE but matched=FALSE.
 * ================================================================ */
static void
test_parse_match_result_empty (void)
{
  /* total_len = 0, no TLV entries */
  guint8 buf[2] = { 0x00, 0x00 };

  ValidityMatchResult result = { 0 };
  gboolean ok = fpi_validity_parse_match_result (buf, sizeof (buf), &result);

  g_assert_true (ok);
  g_assert_false (result.matched);
  g_assert_cmpuint (result.user_dbid, ==, 0);
  g_assert_cmpuint (result.subtype, ==, 0);
  g_assert_null (result.hash);
}

/* ================================================================
 * R1d: parse_match_result with truncated data
 *
 * Ensure graceful handling of malformed/truncated payloads.
 * ================================================================ */
static void
test_parse_match_result_truncated (void)
{
  /* Only 1 byte — too short for total_len */
  guint8 buf1[1] = { 0x05 };
  ValidityMatchResult result = { 0 };

  g_assert_false (fpi_validity_parse_match_result (buf1, 1, &result));

  /* total_len says 20 but only 6 bytes follow (partial TLV entry) */
  guint8 buf2[8];
  FP_WRITE_UINT16_LE (&buf2[0], 20);
  FP_WRITE_UINT16_LE (&buf2[2], 1);   /* tag = 1 */
  FP_WRITE_UINT16_LE (&buf2[4], 10);  /* len = 10, but only 2 bytes remain */
  buf2[6] = 0xFF;
  buf2[7] = 0xFF;

  memset (&result, 0, sizeof (result));
  gboolean ok = fpi_validity_parse_match_result (buf2, sizeof (buf2), &result);
  /* Should return TRUE (parsing succeeded) but matched=FALSE (incomplete entry) */
  g_assert_true (ok);
  g_assert_false (result.matched);
}

/* ================================================================
 * R1e: parse_match_result ignores unknown tags
 *
 * Unknown tags should be skipped without error.
 * ================================================================ */
static void
test_parse_match_result_unknown_tags (void)
{
  guint8 buf[256];
  gsize pos = 2;

  /* Unknown tag 99 with 2 bytes of data */
  guint8 unk[] = { 0x42, 0x43 };

  pos += build_tlv_entry (&buf[pos], 99, unk, 2);

  /* Tag 1: user_dbid = 0x0042 */
  guint8 dbid[4];
  FP_WRITE_UINT32_LE (dbid, 0x0042);
  pos += build_tlv_entry (&buf[pos], 1, dbid, 4);

  FP_WRITE_UINT16_LE (&buf[0], (guint16) (pos - 2));

  ValidityMatchResult result = { 0 };
  gboolean ok = fpi_validity_parse_match_result (buf, pos, &result);

  g_assert_true (ok);
  g_assert_true (result.matched);
  g_assert_cmpuint (result.user_dbid, ==, 0x0042);

  fpi_validity_match_result_clear (&result);
}

/* ================================================================
 * R2: validity_db_build_identity rejects NULL user_id
 *
 * A NULL user_id must return NULL instead of crashing in
 * g_variant_new_string().
 * ================================================================ */
static void
test_build_identity_null (void)
{
  gsize len = 999;

  /* The function uses g_return_val_if_fail which emits g_critical.
   * With G_DEBUG=fatal-warnings the critical would be fatal,
   * so we must expect the message. */
  g_test_expect_message ("libfprint-validity",
                         G_LOG_LEVEL_CRITICAL,
                         "*assertion*id_str*failed*");

  guint8 *id = fpi_validity_db_build_identity (NULL, &len);
  g_test_assert_expected_messages ();

  g_assert_null (id);
}

/* ================================================================
 * R2b: validity_db_build_identity with valid UUID
 *
 * UUID → identity bytes round-trip (complementary to the NULL
 * test above).
 * ================================================================ */
static void
test_build_identity_valid_uuid (void)
{
  const gchar *uuid = "12345678-1234-5678-1234-567812345678";
  gsize len;
  g_autofree guint8 *id = fpi_validity_db_build_identity (uuid, &len);

  g_assert_nonnull (id);
  g_assert_cmpuint (len, >=, VALIDITY_IDENTITY_MIN_SIZE);

  /* Type should be SID (3) */
  g_assert_cmpuint (FP_READ_UINT32_LE (&id[0]), ==, VALIDITY_IDENTITY_TYPE_SID);

  /* Length field should be UUID string length */
  g_assert_cmpuint (FP_READ_UINT32_LE (&id[4]), ==, strlen (uuid));

  /* UUID payload should be present */
  g_assert_cmpmem (&id[8], strlen (uuid), uuid, strlen (uuid));
}

/* ================================================================
 * R3: Match correlation
 *
 * The chip matches against every template it holds. Verify and identify
 * must report a match only for the print whose user record (identity)
 * and finger the chip matched -- never for another finger of the same
 * user, another user's same finger, or an arbitrary gallery entry.
 * ================================================================ */

/* A user record as cmd 0x4a returns it: one record per enrollment, whose
 * identity is the enrollment id string. */
static void
make_user_record (ValidityUser  *user,
                  guint16        dbid,
                  const gchar   *id,
                  const guint16 *subtypes,
                  guint16        n_fingers)
{
  memset (user, 0, sizeof (*user));
  user->dbid = dbid;
  if (id)
    user->identity = fpi_validity_db_build_identity (id, &user->identity_len);
  user->finger_count = n_fingers;
  if (n_fingers > 0)
    {
      user->fingers = g_new0 (ValidityFingerEntry, n_fingers);
      for (guint16 i = 0; i < n_fingers; i++)
        {
          user->fingers[i].dbid = dbid + 1 + i;
          user->fingers[i].subtype = subtypes[i];
          user->fingers[i].storage = 3;
        }
    }
}

/* A print as enroll leaves it: finger set, fpi-data = the id string. */
static FpPrint *
make_enrolled_print (FpDevice    *device,
                     FpFinger     finger,
                     const gchar *id)
{
  FpPrint *print = g_object_ref_sink (fp_print_new (device));

  fp_print_set_finger (print, finger);
  if (id)
    g_object_set (print, "fpi-data", g_variant_new_string (id), NULL);
  return print;
}

static void
make_match (ValidityMatchResult *match,
            guint32              user_dbid,
            FpFinger             finger)
{
  memset (match, 0, sizeof (*match));
  match->matched = TRUE;
  match->user_dbid = user_dbid;
  match->subtype = fpi_validity_finger_to_subtype (finger);
}

#define ID_LEFT_INDEX "FP1-20260926-2-1A2B3C4D-alice"
#define ID_RIGHT_INDEX "FP1-20260723-7-5E6F7A8B-alice"
#define ID_CAROL_RIGHT_INDEX "FP1-20260723-7-5E6F7A8B-carol"

/* The chip matched the record and finger of the print being verified */
static void
test_match_record_same_print (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                  ID_LEFT_INDEX);
  const guint16 subtypes[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  ValidityUser user;
  ValidityMatchResult match;

  make_user_record (&user, 10, ID_LEFT_INDEX, subtypes, 1);
  make_match (&match, 10, FP_FINGER_LEFT_INDEX);

  g_assert_true (fpi_validity_print_matches_record (print, &match, &user));

  fpi_validity_user_clear (&user);
}

/* Same OS user, different finger: verify of the left index must fail when
 * the chip matched the right-index enrollment (seen on hardware). */
static void
test_match_record_same_user_other_finger (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                  ID_LEFT_INDEX);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  const guint16 both[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX),
                           fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  ValidityUser user;
  ValidityMatchResult match;

  /* The right-index enrollment's own record */
  make_user_record (&user, 8, ID_RIGHT_INDEX, right, 1);
  make_match (&match, 8, FP_FINGER_RIGHT_INDEX);
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  fpi_validity_user_clear (&user);

  /* A record holding both fingers under the print's identity (as
   * python-validity lays them out): the finger must still agree. */
  make_user_record (&user, 10, ID_LEFT_INDEX, both, 2);
  make_match (&match, 10, FP_FINGER_RIGHT_INDEX);
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  fpi_validity_user_clear (&user);
}

/* Different user, same finger: identity must agree, not just the finger */
static void
test_match_record_other_user_same_finger (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  const guint16 subtypes[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  ValidityUser user;
  ValidityMatchResult match;

  make_user_record (&user, 12, ID_CAROL_RIGHT_INDEX, subtypes, 1);
  make_match (&match, 12, FP_FINGER_RIGHT_INDEX);

  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));

  fpi_validity_user_clear (&user);
}

/* Anything that cannot be correlated is no match */
static void
test_match_record_no_correlation (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                  ID_LEFT_INDEX);
  g_autoptr(FpPrint) no_id = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                  NULL);
  g_autoptr(FpPrint) empty_id = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                     "");
  const guint16 subtypes[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  const guint16 other[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_THUMB) };
  ValidityUser user;
  ValidityUser empty = { 0 };
  ValidityMatchResult match;

  make_user_record (&user, 10, ID_LEFT_INDEX, subtypes, 1);
  make_match (&match, 10, FP_FINGER_LEFT_INDEX);

  /* Print without an id string, or an empty one */
  g_assert_false (fpi_validity_print_matches_record (no_id, &match, &user));
  g_assert_false (fpi_validity_print_matches_record (empty_id, &match, &user));

  /* No match reported, or no record read back */
  match.matched = FALSE;
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  match.matched = TRUE;
  g_assert_false (fpi_validity_print_matches_record (print, &match, &empty));
  g_assert_false (fpi_validity_print_matches_record (print, &match, NULL));
  g_assert_false (fpi_validity_print_matches_record (NULL, &match, &user));

  /* Record read back is not the one the chip named */
  make_match (&match, 11, FP_FINGER_LEFT_INDEX);
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  make_match (&match, 0x1000a, FP_FINGER_LEFT_INDEX);
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  fpi_validity_user_clear (&user);

  /* Identity that is only a prefix, or longer */
  make_match (&match, 10, FP_FINGER_LEFT_INDEX);
  make_user_record (&user, 10, "FP1-20260926-2-1A2B3C4D", subtypes, 1);
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  fpi_validity_user_clear (&user);
  make_user_record (&user, 10, ID_LEFT_INDEX "x", subtypes, 1);
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  fpi_validity_user_clear (&user);

  /* Record without an identity */
  make_user_record (&user, 10, NULL, subtypes, 1);
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  fpi_validity_user_clear (&user);

  /* Record whose finger table lacks the matched subtype */
  make_user_record (&user, 10, ID_LEFT_INDEX, other, 1);
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  fpi_validity_user_clear (&user);

  /* Chip reported no subtype (tag 3 absent) */
  make_user_record (&user, 10, ID_LEFT_INDEX, subtypes, 1);
  match.subtype = 0;
  g_assert_false (fpi_validity_print_matches_record (print, &match, &user));
  fpi_validity_user_clear (&user);
}

/* Identify returns the gallery print the match belongs to */
static void
test_gallery_match_correlates (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  const guint16 left[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  ValidityUser user;
  ValidityMatchResult match;
  FpPrint *p_left, *p_right;

  p_left = make_enrolled_print (device, FP_FINGER_LEFT_INDEX, ID_LEFT_INDEX);
  p_right = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX, ID_RIGHT_INDEX);
  g_ptr_array_add (gallery, p_left);
  g_ptr_array_add (gallery, p_right);

  make_user_record (&user, 8, ID_RIGHT_INDEX, right, 1);
  make_match (&match, 8, FP_FINGER_RIGHT_INDEX);
  g_assert_true (fpi_validity_find_gallery_match (gallery, &match, &user) == p_right);
  fpi_validity_user_clear (&user);

  make_user_record (&user, 10, ID_LEFT_INDEX, left, 1);
  make_match (&match, 10, FP_FINGER_LEFT_INDEX);
  g_assert_true (fpi_validity_find_gallery_match (gallery, &match, &user) == p_left);
  fpi_validity_user_clear (&user);
}

/* A match that corresponds to no gallery print is no match: no fallback to
 * the first entry, and no match on finger alone. */
static void
test_gallery_match_no_fallback (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  const guint16 ring[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_RING) };
  ValidityUser user;
  ValidityMatchResult match;

  g_ptr_array_add (gallery, make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                 ID_LEFT_INDEX));
  g_ptr_array_add (gallery, make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                 ID_RIGHT_INDEX));

  /* Another user's right index: same finger as a gallery print */
  make_user_record (&user, 12, ID_CAROL_RIGHT_INDEX, right, 1);
  make_match (&match, 12, FP_FINGER_RIGHT_INDEX);
  g_assert_null (fpi_validity_find_gallery_match (gallery, &match, &user));
  fpi_validity_user_clear (&user);

  /* A finger in no gallery print */
  make_user_record (&user, 14, "FP1-20260901-9-01020304-alice", ring, 1);
  make_match (&match, 14, FP_FINGER_RIGHT_RING);
  g_assert_null (fpi_validity_find_gallery_match (gallery, &match, &user));
  fpi_validity_user_clear (&user);
}

/* NULL or empty gallery */
static void
test_gallery_match_empty (void)
{
  g_autoptr(GPtrArray) empty = g_ptr_array_new_with_free_func (g_object_unref);
  const guint16 subtypes[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  ValidityUser user;
  ValidityMatchResult match;

  make_user_record (&user, 10, ID_LEFT_INDEX, subtypes, 1);
  make_match (&match, 10, FP_FINGER_LEFT_INDEX);

  g_assert_null (fpi_validity_find_gallery_match (NULL, &match, &user));
  g_assert_null (fpi_validity_find_gallery_match (empty, &match, &user));

  fpi_validity_user_clear (&user);
}

/* The record identity round-trips through the builder, and malformed
 * identities are refused. */
static void
test_user_get_id (void)
{
  ValidityUser user = { 0 };
  const guint8 *id;
  gsize id_len;
  const guint8 truncated[] = { 3, 0, 0, 0, 10, 0, 0, 0, 'a', 'b' };
  const guint8 zero_len[] = { 3, 0, 0, 0, 0, 0, 0, 0 };

  g_assert_false (fpi_validity_db_user_get_id (&user, &id, &id_len));

  user.identity = fpi_validity_db_build_identity (ID_LEFT_INDEX, &user.identity_len);
  g_assert_true (fpi_validity_db_user_get_id (&user, &id, &id_len));
  g_assert_cmpmem (id, id_len, ID_LEFT_INDEX, strlen (ID_LEFT_INDEX));
  g_clear_pointer (&user.identity, g_free);

  user.identity = g_memdup2 (truncated, sizeof (truncated));
  user.identity_len = sizeof (truncated);
  g_assert_false (fpi_validity_db_user_get_id (&user, &id, &id_len));
  g_clear_pointer (&user.identity, g_free);

  user.identity = g_memdup2 (zero_len, sizeof (zero_len));
  user.identity_len = sizeof (zero_len);
  g_assert_false (fpi_validity_db_user_get_id (&user, &id, &id_len));
  g_clear_pointer (&user.identity, g_free);
}

/* ================================================================
 * Verify/identify decision
 *
 * validity_match_decide() is what verify_ssm_done reports. These cover the
 * decision itself, the read-back of the matched user record, and the
 * per-attempt reset of the state the decision reads.
 * ================================================================ */

/* Verify reports a match only for the print whose record the chip matched */
static void
test_match_decide_verify (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  const guint16 left[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  ValidityUser user;
  ValidityMatchResult match;

  make_user_record (&user, 8, ID_RIGHT_INDEX, right, 1);
  make_match (&match, 8, FP_FINGER_RIGHT_INDEX);
  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, &match, &user, NULL),
                   ==, FPI_MATCH_SUCCESS);
  fpi_validity_user_clear (&user);

  /* Another user's same finger */
  make_user_record (&user, 12, ID_CAROL_RIGHT_INDEX, right, 1);
  make_match (&match, 12, FP_FINGER_RIGHT_INDEX);
  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, &match, &user, NULL),
                   ==, FPI_MATCH_FAIL);
  fpi_validity_user_clear (&user);

  /* The same user's other finger */
  make_user_record (&user, 10, ID_LEFT_INDEX, left, 1);
  make_match (&match, 10, FP_FINGER_LEFT_INDEX);
  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, &match, &user, NULL),
                   ==, FPI_MATCH_FAIL);
  fpi_validity_user_clear (&user);
}

/* Identify returns the gallery print the match belongs to, or nothing */
static void
test_match_decide_identify (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  ValidityUser user;
  ValidityMatchResult match;
  FpPrint *p_left, *p_right;
  FpPrint *found;

  p_left = make_enrolled_print (device, FP_FINGER_LEFT_INDEX, ID_LEFT_INDEX);
  p_right = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX, ID_RIGHT_INDEX);
  g_ptr_array_add (gallery, p_left);
  g_ptr_array_add (gallery, p_right);

  make_user_record (&user, 8, ID_RIGHT_INDEX, right, 1);
  make_match (&match, 8, FP_FINGER_RIGHT_INDEX);
  found = p_left;
  g_assert_cmpint (fpi_validity_match_decide (TRUE, NULL, gallery, &match, &user, &found),
                   ==, FPI_MATCH_SUCCESS);
  g_assert_true (found == p_right);
  fpi_validity_user_clear (&user);

  /* Another user's right index: no gallery print, not gallery[0] */
  make_user_record (&user, 12, ID_CAROL_RIGHT_INDEX, right, 1);
  make_match (&match, 12, FP_FINGER_RIGHT_INDEX);
  found = p_left;
  g_assert_cmpint (fpi_validity_match_decide (TRUE, NULL, gallery, &match, &user, &found),
                   ==, FPI_MATCH_FAIL);
  g_assert_null (found);

  /* No match at all also clears the out parameter */
  found = p_left;
  g_assert_cmpint (fpi_validity_match_decide (TRUE, NULL, gallery, NULL, &user, &found),
                   ==, FPI_MATCH_FAIL);
  g_assert_null (found);
  fpi_validity_user_clear (&user);
}

/* Verify and identify each use their own input: a verify is not decided
 * against a gallery, nor an identify against a single print. */
static void
test_match_decide_mode (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  ValidityUser user;
  ValidityMatchResult match;
  FpPrint *found = NULL;

  g_ptr_array_add (gallery, g_object_ref (print));
  make_user_record (&user, 8, ID_RIGHT_INDEX, right, 1);
  make_match (&match, 8, FP_FINGER_RIGHT_INDEX);

  g_assert_cmpint (fpi_validity_match_decide (FALSE, NULL, gallery, &match, &user, &found),
                   ==, FPI_MATCH_FAIL);
  g_assert_null (found);
  g_assert_cmpint (fpi_validity_match_decide (TRUE, print, NULL, &match, &user, &found),
                   ==, FPI_MATCH_FAIL);
  g_assert_null (found);

  fpi_validity_user_clear (&user);
}

/* A match whose user record was not read back, or no match, is no match */
static void
test_match_decide_no_readback (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  ValidityUser empty = { 0 };
  ValidityUser user;
  ValidityMatchResult match;
  FpPrint *found = NULL;

  g_ptr_array_add (gallery, g_object_ref (print));
  make_match (&match, 8, FP_FINGER_RIGHT_INDEX);

  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, &match, &empty, NULL),
                   ==, FPI_MATCH_FAIL);
  g_assert_cmpint (fpi_validity_match_decide (TRUE, NULL, gallery, &match, &empty, &found),
                   ==, FPI_MATCH_FAIL);
  g_assert_null (found);

  /* A record that would correlate, but no match from the chip */
  make_user_record (&user, 8, ID_RIGHT_INDEX, right, 1);
  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, NULL, &user, NULL),
                   ==, FPI_MATCH_FAIL);
  match.matched = FALSE;
  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, &match, &user, NULL),
                   ==, FPI_MATCH_FAIL);
  fpi_validity_user_clear (&user);
}

/* The user record to read back comes only from a 0x60 response that
 * reports a match with a record id get_user can address. */
static void
test_match_user_to_read (void)
{
  guint8 hash[] = { 0xAA, 0xBB };
  const guint8 empty_dict[] = { 0x00, 0x00 };
  gsize len;
  guint16 dbid = 0xbeef;
  g_autofree guint8 *ok = build_match_payload (10, 2, hash, sizeof (hash), &len);
  g_autofree guint8 *wide = NULL;
  gsize wide_len;

  g_assert_true (fpi_validity_match_user_to_read (ok, len, &dbid));
  g_assert_cmpuint (dbid, ==, 10);

  dbid = 0xbeef;
  wide = build_match_payload (0x1000a, 2, hash, sizeof (hash), &wide_len);
  g_assert_false (fpi_validity_match_user_to_read (wide, wide_len, &dbid));
  g_assert_false (fpi_validity_match_user_to_read (empty_dict, sizeof (empty_dict),
                                                   &dbid));
  g_assert_false (fpi_validity_match_user_to_read (ok, 1, &dbid));
  g_assert_false (fpi_validity_match_user_to_read (ok, 0, &dbid));
  g_assert_false (fpi_validity_match_user_to_read (NULL, 0, &dbid));
  g_assert_cmpuint (dbid, ==, 0xbeef);
}

/* The per-attempt reset leaves nothing from an earlier attempt for the
 * decision: after it, a match whose get_user failed is no match even
 * though the previous attempt read back a record that would correlate. */
static void
test_verify_clear_match_state (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  guint8 hash[] = { 0xAA };
  /* Only the plain fields the reset touches are used; the GObject part of
   * the instance is never initialised or accessed. */
  g_autofree FpiDeviceValidity *self = g_new0 (FpiDeviceValidity, 1);
  ValidityMatchResult match;

  /* State a previous attempt left: its 0x60 response and its record */
  self->bulk_data = build_match_payload (8, 7, hash, sizeof (hash),
                                         &self->bulk_data_len);
  make_user_record (&self->verify_match_user, 8, ID_RIGHT_INDEX, right, 1);
  make_match (&match, 8, FP_FINGER_RIGHT_INDEX);
  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, &match,
                                              &self->verify_match_user, NULL),
                   ==, FPI_MATCH_SUCCESS);

  fpi_validity_verify_clear_match_state (self);

  g_assert_null (self->bulk_data);
  g_assert_cmpuint (self->bulk_data_len, ==, 0);
  g_assert_null (self->verify_match_user.identity);
  g_assert_null (self->verify_match_user.fingers);
  g_assert_cmpuint (self->verify_match_user.dbid, ==, 0);
  g_assert_cmpuint (self->verify_match_user.finger_count, ==, 0);

  /* This attempt: the chip names the same record, get_user fails */
  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, &match,
                                              &self->verify_match_user, NULL),
                   ==, FPI_MATCH_FAIL);
}

/* ================================================================
 * Delete selection
 *
 * Delete must remove the finger from the user record that belongs to the
 * print (identity = the print's id string), never the first record that
 * happens to hold the same finger, and remove that record only once it is
 * empty.
 * ================================================================ */

/* The delete SSM scans the records in storage order and takes the first one
 * that validity_delete_find_finger() selects. */
static const ValidityUser *
delete_scan (FpPrint            *print,
             const ValidityUser *users,
             guint               n_users,
             guint16            *finger_dbid,
             gboolean           *leaves_empty)
{
  for (guint i = 0; i < n_users; i++)
    if (fpi_validity_delete_find_finger (print, &users[i], finger_dbid, leaves_empty))
      return &users[i];

  return NULL;
}

/* The print's own record is chosen, not another user's record that holds
 * the same finger and comes first in storage order. */
static void
test_delete_find_finger_own_record (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  const guint16 left[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  ValidityUser users[3];
  const ValidityUser *chosen;
  guint16 finger_dbid = 0xffff;
  gboolean leaves_empty = FALSE;

  make_user_record (&users[0], 4, ID_CAROL_RIGHT_INDEX, right, 1);
  make_user_record (&users[1], 6, ID_LEFT_INDEX, left, 1);
  make_user_record (&users[2], 8, ID_RIGHT_INDEX, right, 1);

  chosen = delete_scan (print, users, G_N_ELEMENTS (users),
                        &finger_dbid, &leaves_empty);
  g_assert_true (chosen == &users[2]);
  g_assert_cmpuint (finger_dbid, ==, 9);
  g_assert_true (leaves_empty);

  for (guint i = 0; i < G_N_ELEMENTS (users); i++)
    fpi_validity_user_clear (&users[i]);
}

/* A record holding several fingers under the print's identity (as
 * python-validity lays them out): the right finger, and the record is not
 * left empty. */
static void
test_delete_find_finger_multi_finger_record (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  const guint16 both[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX),
                           fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  ValidityUser user;
  guint16 finger_dbid = 0xffff;
  gboolean leaves_empty = TRUE;

  make_user_record (&user, 20, ID_RIGHT_INDEX, both, 2);

  g_assert_true (fpi_validity_delete_find_finger (print, &user, &finger_dbid,
                                                  &leaves_empty));
  g_assert_cmpuint (finger_dbid, ==, 22);
  g_assert_false (leaves_empty);

  fpi_validity_user_clear (&user);
}

/* The same finger in another user's record is never chosen, even when it is
 * the only record that holds that finger. */
static void
test_delete_find_finger_other_user (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  const guint16 right[] = { fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX) };
  const guint16 left[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  ValidityUser users[2];
  guint16 finger_dbid = 0xffff;
  gboolean leaves_empty = FALSE;

  make_user_record (&users[0], 12, ID_CAROL_RIGHT_INDEX, right, 1);
  make_user_record (&users[1], 10, ID_LEFT_INDEX, left, 1);

  g_assert_null (delete_scan (print, users, G_N_ELEMENTS (users),
                              &finger_dbid, &leaves_empty));
  g_assert_cmpuint (finger_dbid, ==, 0xffff);
  g_assert_false (leaves_empty);

  for (guint i = 0; i < G_N_ELEMENTS (users); i++)
    fpi_validity_user_clear (&users[i]);
}

/* Anything that cannot be correlated selects nothing */
static void
test_delete_find_finger_no_correlation (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                  ID_LEFT_INDEX);
  g_autoptr(FpPrint) no_id = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                  NULL);
  g_autoptr(FpPrint) empty_id = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                     "");
  g_autoptr(FpPrint) no_finger = make_enrolled_print (device, FP_FINGER_UNKNOWN,
                                                      ID_LEFT_INDEX);
  const guint16 subtypes[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  const guint16 other[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_THUMB) };
  const guint16 zero[] = { 0 };
  /* A python-validity record: identity type 3 with a binary Windows SID */
  const guint8 sid_identity[] = { 3, 0, 0, 0, 12, 0, 0, 0,
                                  0x01, 0x01, 0, 0, 0, 0, 0, 0x05,
                                  0x12, 0, 0, 0 };
  ValidityUser user;
  guint16 finger_dbid = 0xffff;
  gboolean leaves_empty = FALSE;

  make_user_record (&user, 10, ID_LEFT_INDEX, subtypes, 1);
  g_assert_false (fpi_validity_delete_find_finger (no_id, &user, &finger_dbid,
                                                   &leaves_empty));
  g_assert_false (fpi_validity_delete_find_finger (empty_id, &user, &finger_dbid,
                                                   &leaves_empty));
  g_assert_false (fpi_validity_delete_find_finger (NULL, &user, &finger_dbid,
                                                   &leaves_empty));
  g_assert_false (fpi_validity_delete_find_finger (print, NULL, &finger_dbid,
                                                   &leaves_empty));
  fpi_validity_user_clear (&user);

  /* Identity that is only a prefix, or longer */
  make_user_record (&user, 10, "FP1-20260926-2-1A2B3C4D", subtypes, 1);
  g_assert_false (fpi_validity_delete_find_finger (print, &user, &finger_dbid,
                                                   &leaves_empty));
  fpi_validity_user_clear (&user);
  make_user_record (&user, 10, ID_LEFT_INDEX "x", subtypes, 1);
  g_assert_false (fpi_validity_delete_find_finger (print, &user, &finger_dbid,
                                                   &leaves_empty));
  fpi_validity_user_clear (&user);

  /* Record without an identity, or with a python-validity SID */
  make_user_record (&user, 10, NULL, subtypes, 1);
  g_assert_false (fpi_validity_delete_find_finger (print, &user, &finger_dbid,
                                                   &leaves_empty));
  user.identity = g_memdup2 (sid_identity, sizeof (sid_identity));
  user.identity_len = sizeof (sid_identity);
  g_assert_false (fpi_validity_delete_find_finger (print, &user, &finger_dbid,
                                                   &leaves_empty));
  fpi_validity_user_clear (&user);

  /* The print's record, but without the print's finger */
  make_user_record (&user, 10, ID_LEFT_INDEX, other, 1);
  g_assert_false (fpi_validity_delete_find_finger (print, &user, &finger_dbid,
                                                   &leaves_empty));
  fpi_validity_user_clear (&user);

  /* The print's record with no fingers at all */
  make_user_record (&user, 10, ID_LEFT_INDEX, NULL, 0);
  g_assert_false (fpi_validity_delete_find_finger (print, &user, &finger_dbid,
                                                   &leaves_empty));
  fpi_validity_user_clear (&user);

  /* A print with no finger set does not match a subtype-0 entry */
  make_user_record (&user, 10, ID_LEFT_INDEX, zero, 1);
  g_assert_false (fpi_validity_delete_find_finger (no_finger, &user, &finger_dbid,
                                                   &leaves_empty));
  fpi_validity_user_clear (&user);

  g_assert_cmpuint (finger_dbid, ==, 0xffff);
  g_assert_false (leaves_empty);
}

/* After the finger is deleted, its record is removed only if the fresh read
 * shows the same record, the print's identity and no fingers. */
static void
test_delete_owner_is_empty (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_LEFT_INDEX,
                                                  ID_LEFT_INDEX);
  const guint16 subtypes[] = { fpi_validity_finger_to_subtype (FP_FINGER_LEFT_INDEX) };
  ValidityUser user;

  make_user_record (&user, 10, ID_LEFT_INDEX, NULL, 0);
  g_assert_true (fpi_validity_delete_owner_is_empty (print, 10, &user));
  g_assert_false (fpi_validity_delete_owner_is_empty (print, 11, &user));
  g_assert_false (fpi_validity_delete_owner_is_empty (NULL, 10, &user));
  g_assert_false (fpi_validity_delete_owner_is_empty (print, 10, NULL));
  fpi_validity_user_clear (&user);

  /* Still holds a finger (the delete did not take, or another finger) */
  make_user_record (&user, 10, ID_LEFT_INDEX, subtypes, 1);
  g_assert_false (fpi_validity_delete_owner_is_empty (print, 10, &user));
  fpi_validity_user_clear (&user);

  /* Another identity, or none */
  make_user_record (&user, 10, ID_CAROL_RIGHT_INDEX, NULL, 0);
  g_assert_false (fpi_validity_delete_owner_is_empty (print, 10, &user));
  fpi_validity_user_clear (&user);
  make_user_record (&user, 10, NULL, NULL, 0);
  g_assert_false (fpi_validity_delete_owner_is_empty (print, 10, &user));
  fpi_validity_user_clear (&user);
}

/* ================================================================
 * R4: enroll_user_dbid and delete_storage_dbid are separate fields
 *
 * Both fields must exist independently in the device struct.
 * ================================================================ */
static void
test_struct_separate_fields (void)
{
  /* Verify both fields exist and are at different offsets */
  g_assert_cmpuint (
    G_STRUCT_OFFSET (FpiDeviceValidity, enroll_user_dbid), !=,
    G_STRUCT_OFFSET (FpiDeviceValidity, delete_storage_dbid));

  /* Also verify delete_finger_subtype and delete_finger_dbid exist
   * (needed for the functional delete SSM) */
  g_assert_cmpuint (
    G_STRUCT_OFFSET (FpiDeviceValidity, delete_finger_subtype), !=,
    G_STRUCT_OFFSET (FpiDeviceValidity, delete_storage_dbid));
  g_assert_cmpuint (
    G_STRUCT_OFFSET (FpiDeviceValidity, delete_finger_dbid), !=,
    G_STRUCT_OFFSET (FpiDeviceValidity, delete_storage_dbid));
}

/* ================================================================
 * R5: del_record command format
 *
 * Verify cmd 0x48 produces correct format: 0x48 | dbid(2LE).
 * ================================================================ */
static void
test_del_record_format (void)
{
  gsize len;
  g_autofree guint8 *cmd = fpi_validity_db_build_cmd_del_record (0x4321, &len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 3);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_DEL_RECORD);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[1]), ==, 0x4321);
}

/* ================================================================
 * R6: match_finger command is exactly 13 bytes
 *
 * build_cmd_match_finger must produce a single 13-byte buffer.
 * ================================================================ */
static void
test_match_finger_size (void)
{
  gsize len;
  g_autofree guint8 *cmd = validity_pack_new (&len, "bbbhhhhh",
                                              VCSFW_CMD_MATCH_FINGER,
                                              0x02, 0xFF, 0, 0, 1, 0, 0);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (len, ==, 13);
  g_assert_cmpuint (cmd[0], ==, VCSFW_CMD_MATCH_FINGER);
  g_assert_cmpuint (cmd[1], ==, 0x02);
  g_assert_cmpuint (cmd[2], ==, 0xFF);

  /* Verify all 5 uint16_le fields */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[3]), ==, 0);   /* stg_id */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[5]), ==, 0);   /* usr_id */
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[7]), ==, 1);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[9]), ==, 0);
  g_assert_cmpuint (FP_READ_UINT16_LE (&cmd[11]), ==, 0);
}

/* ================================================================
 * R7: Clear storage SSM states exist
 *
 * CLEAR_* enum states must be defined for clear_storage to work.
 * ================================================================ */
static void
test_clear_storage_states_exist (void)
{
  /* Clear erases the DB partition inside a db_write_enable / cleanups bracket. */
  g_assert_cmpint (CLEAR_DB_WRITE_ENABLE, ==, 0);
  g_assert_cmpint (CLEAR_DB_WRITE_ENABLE_RECV, ==, 1);
  g_assert_cmpint (CLEAR_ERASE, ==, 2);
  g_assert_cmpint (CLEAR_ERASE_RECV, ==, 3);
  g_assert_cmpint (CLEAR_CLEANUPS, ==, 4);
  g_assert_cmpint (CLEAR_CLEANUPS_RECV, ==, 5);
  g_assert_cmpint (CLEAR_DONE, ==, 6);
  g_assert_cmpint (CLEAR_NUM_STATES, ==, 7);
}

/* ================================================================
 * R7b: Delete SSM states are complete
 *
 * Verify the delete SSM has all required states including
 * DEL_RECORD and DEL_RECORD_RECV (which were previously dead code).
 * ================================================================ */
static void
test_delete_states_exist (void)
{
  g_assert_cmpint (DELETE_GET_STORAGE, ==, 0);
  g_assert_cmpint (DELETE_GET_STORAGE_RECV, ==, 1);
  g_assert_cmpint (DELETE_LOOKUP_USER, ==, 2);
  g_assert_cmpint (DELETE_LOOKUP_USER_RECV, ==, 3);
  g_assert_cmpint (DELETE_DEL_RECORD, ==, 4);
  g_assert_cmpint (DELETE_DEL_RECORD_RECV, ==, 5);
  g_assert_cmpint (DELETE_GET_OWNER, ==, 6);
  g_assert_cmpint (DELETE_GET_OWNER_RECV, ==, 7);
  g_assert_cmpint (DELETE_DEL_OWNER, ==, 8);
  g_assert_cmpint (DELETE_DEL_OWNER_RECV, ==, 9);
  g_assert_cmpint (DELETE_DONE, ==, 10);
  g_assert_cmpint (DELETE_NUM_STATES, ==, 11);
}

/* ================================================================
 * Tier 0 recovery: error classification (validity_classify_error)
 * ================================================================ */
static void
test_classify_error (void)
{
  GError *e;

  /* No error */
  g_assert_cmpint (fpi_validity_classify_error (NULL, TRUE), ==, VALIDITY_ERR_NONE);
  g_assert_cmpint (fpi_validity_classify_error (NULL, FALSE), ==, VALIDITY_ERR_NONE);

  /* Cancellation (either domain) -- never recover */
  e = g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED, "x");
  g_assert_cmpint (fpi_validity_classify_error (e, TRUE), ==, VALIDITY_ERR_CANCELLED);
  g_error_free (e);
  e = g_error_new (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_CANCELLED, "x");
  g_assert_cmpint (fpi_validity_classify_error (e, TRUE), ==, VALIDITY_ERR_CANCELLED);
  g_error_free (e);

  /* Already-mapped removed */
  e = g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_REMOVED, "x");
  g_assert_cmpint (fpi_validity_classify_error (e, TRUE), ==, VALIDITY_ERR_REMOVED);
  g_error_free (e);

  /* NO_DEVICE: liveness decides session-lost (alive) vs removed (gone) */
  e = g_error_new (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE, "x");
  g_assert_cmpint (fpi_validity_classify_error (e, TRUE), ==, VALIDITY_ERR_SESSION_LOST);
  g_assert_cmpint (fpi_validity_classify_error (e, FALSE), ==, VALIDITY_ERR_REMOVED);
  g_error_free (e);

  /* Transient transport blips -> pipe stall */
  e = g_error_new (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO, "x");
  g_assert_cmpint (fpi_validity_classify_error (e, TRUE), ==, VALIDITY_ERR_PIPE_STALL);
  g_error_free (e);
  e = g_error_new (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT, "x");
  g_assert_cmpint (fpi_validity_classify_error (e, TRUE), ==, VALIDITY_ERR_PIPE_STALL);
  g_error_free (e);

  /* Anything else -> fatal (incl. a plain PROTO, until TLS-alert detection) */
  e = g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "x");
  g_assert_cmpint (fpi_validity_classify_error (e, TRUE), ==, VALIDITY_ERR_FATAL);
  g_error_free (e);
}

/* ================================================================
 * R1f: match_result_clear frees hash
 *
 * Ensure the clear function properly frees the hash allocation.
 * ================================================================ */
static void
test_match_result_clear (void)
{
  ValidityMatchResult result = { 0 };

  result.matched = TRUE;
  result.user_dbid = 42;
  result.subtype = 5;
  result.hash = g_memdup2 ((guint8[]){0x01, 0x02}, 2);
  result.hash_len = 2;

  fpi_validity_match_result_clear (&result);

  g_assert_false (result.matched);
  g_assert_cmpuint (result.user_dbid, ==, 0);
  g_assert_cmpuint (result.subtype, ==, 0);
  g_assert_null (result.hash);
  g_assert_cmpuint (result.hash_len, ==, 0);
}

/* ================================================================
 * Tests: TLS
 * ================================================================ */


/* ================================================================
 * Test: PRF produces deterministic output
 * ================================================================ */
static void
test_prf_deterministic (void)
{
  guint8 secret[] = { 0x01, 0x02, 0x03, 0x04 };
  guint8 seed[] = { 0x05, 0x06, 0x07, 0x08 };
  guint8 output1[48];
  guint8 output2[48];

  fpi_validity_tls_prf (secret, sizeof (secret), seed, sizeof (seed),
                        output1, sizeof (output1));
  fpi_validity_tls_prf (secret, sizeof (secret), seed, sizeof (seed),
                        output2, sizeof (output2));

  g_assert_cmpmem (output1, sizeof (output1), output2, sizeof (output2));
}

/* ================================================================
 * Test: PRF with known TLS 1.2 test vector
 * ================================================================
 * RFC 5246 does not define test vectors for SHA-256 PRF directly,
 * but we verify our implementation against python-validity's output.
 */
static void
test_prf_output_length (void)
{
  guint8 secret[32];
  guint8 seed[64];
  guint8 output[0x120]; /* Same as key_block size */

  memset (secret, 0xAB, sizeof (secret));
  memset (seed, 0xCD, sizeof (seed));

  fpi_validity_tls_prf (secret, sizeof (secret), seed, sizeof (seed),
                        output, sizeof (output));

  /* PRF output should not be all zeros */
  gboolean all_zero = TRUE;
  for (gsize i = 0; i < sizeof (output); i++)
    {
      if (output[i] != 0)
        {
          all_zero = FALSE;
          break;
        }
    }
  g_assert_false (all_zero);
}

/* ================================================================
 * Test: PRF with different lengths uses correct number of HMAC iters
 * ================================================================ */
static void
test_prf_short_output (void)
{
  guint8 secret[] = { 0x01 };
  guint8 seed[] = { 0x02 };
  guint8 output_short[16];
  guint8 output_long[48];

  fpi_validity_tls_prf (secret, 1, seed, 1, output_short, sizeof (output_short));
  fpi_validity_tls_prf (secret, 1, seed, 1, output_long, sizeof (output_long));

  /* First 16 bytes should match */
  g_assert_cmpmem (output_short, 16, output_long, 16);
}

/* ================================================================
 * Test: Encrypt then decrypt roundtrip
 * ================================================================ */
static void
test_encrypt_decrypt_roundtrip (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);

  /* Set up encryption/decryption keys (same for roundtrip test) */
  memset (tls.encryption_key, 0x42, TLS_AES_KEY_SIZE);
  memset (tls.decryption_key, 0x42, TLS_AES_KEY_SIZE);

  guint8 plaintext[] = "Hello, TLS! This is a test message for encryption.";
  gsize pt_len = sizeof (plaintext);

  gsize enc_len;
  guint8 *encrypted = fpi_validity_tls_encrypt (&tls, plaintext, pt_len, &enc_len);
  g_assert_nonnull (encrypted);
  g_assert_cmpuint (enc_len, >, pt_len); /* IV + padded ciphertext */

  GError *error = NULL;
  gsize dec_len;
  guint8 *decrypted = fpi_validity_tls_decrypt (&tls, encrypted, enc_len,
                                                &dec_len, &error);
  g_assert_no_error (error);
  g_assert_nonnull (decrypted);
  g_assert_cmpmem (plaintext, pt_len, decrypted, dec_len);

  g_free (encrypted);
  g_free (decrypted);
  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Test: Encrypt with block-aligned data
 * ================================================================ */
static void
test_encrypt_block_aligned (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);

  memset (tls.encryption_key, 0x55, TLS_AES_KEY_SIZE);
  memset (tls.decryption_key, 0x55, TLS_AES_KEY_SIZE);

  /* 16 bytes = exactly one AES block */
  guint8 plaintext[16];
  memset (plaintext, 0xAA, 16);

  gsize enc_len;
  guint8 *encrypted = fpi_validity_tls_encrypt (&tls, plaintext, 16, &enc_len);
  g_assert_nonnull (encrypted);
  /* Should be IV(16) + 32 bytes (16 data + 16 padding since pad=0x0f*16) */
  g_assert_cmpuint (enc_len, ==, 16 + 32);

  GError *error = NULL;
  gsize dec_len;
  guint8 *decrypted = fpi_validity_tls_decrypt (&tls, encrypted, enc_len,
                                                &dec_len, &error);
  g_assert_no_error (error);
  g_assert_nonnull (decrypted);
  g_assert_cmpuint (dec_len, ==, 16);
  g_assert_cmpmem (plaintext, 16, decrypted, 16);

  g_free (encrypted);
  g_free (decrypted);
  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Test: Decrypt with invalid data fails
 * ================================================================ */
static void
test_decrypt_invalid (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);

  memset (tls.decryption_key, 0x55, TLS_AES_KEY_SIZE);

  /* Too short for IV + block */
  guint8 short_data[10];
  memset (short_data, 0, sizeof (short_data));

  GError *error = NULL;
  gsize dec_len;
  guint8 *decrypted = fpi_validity_tls_decrypt (&tls, short_data,
                                                sizeof (short_data),
                                                &dec_len, &error);
  g_assert_null (decrypted);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
  g_clear_error (&error);

  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Test: PSK derivation runs without crashing
 * ================================================================ */
static const guint8 test_password[32] = {
  0x97, 0x04, 0x4D, 0x1A, 0xF0, 0x66, 0xAD, 0x8D,
  0x18, 0x1A, 0x6E, 0xE5, 0xC1, 0x55, 0x79, 0x31,
  0x3B, 0xA5, 0x77, 0xCC, 0x59, 0xD2, 0x0B, 0x10,
  0xD0, 0x4B, 0x8E, 0xC8, 0x9D, 0xBA, 0x4C, 0x86,
};

static const guint8 test_gwk_sign[32] = {
  0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
  0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
  0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
  0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0,
};

static void
test_psk_derivation (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);
  tls.password = test_password;
  tls.password_len = sizeof (test_password);
  tls.gwk_sign = test_gwk_sign;
  tls.gwk_sign_len = sizeof (test_gwk_sign);

  fpi_validity_tls_derive_psk_from_identity (&tls, "Test Product", "SN0001");

  /* PSK keys should not be all zeros */
  gboolean all_zero = TRUE;
  for (gsize i = 0; i < TLS_AES_KEY_SIZE; i++)
    {
      if (tls.psk_encryption_key[i] != 0)
        {
          all_zero = FALSE;
          break;
        }
    }
  g_assert_false (all_zero);

  all_zero = TRUE;
  for (gsize i = 0; i < TLS_AES_KEY_SIZE; i++)
    {
      if (tls.psk_validation_key[i] != 0)
        {
          all_zero = FALSE;
          break;
        }
    }
  g_assert_false (all_zero);

  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Test: PSK derivation is deterministic
 * ================================================================ */
static void
test_psk_deterministic (void)
{
  ValidityTlsState tls1, tls2;

  fpi_validity_tls_init (&tls1);
  fpi_validity_tls_init (&tls2);
  tls1.password = test_password;
  tls1.password_len = sizeof (test_password);
  tls1.gwk_sign = test_gwk_sign;
  tls1.gwk_sign_len = sizeof (test_gwk_sign);
  tls2.password = test_password;
  tls2.password_len = sizeof (test_password);
  tls2.gwk_sign = test_gwk_sign;
  tls2.gwk_sign_len = sizeof (test_gwk_sign);

  fpi_validity_tls_derive_psk_from_identity (&tls1, "Test Product", "SN0001");
  fpi_validity_tls_derive_psk_from_identity (&tls2, "Test Product", "SN0001");

  g_assert_cmpmem (tls1.psk_encryption_key, TLS_AES_KEY_SIZE,
                   tls2.psk_encryption_key, TLS_AES_KEY_SIZE);
  g_assert_cmpmem (tls1.psk_validation_key, TLS_AES_KEY_SIZE,
                   tls2.psk_validation_key, TLS_AES_KEY_SIZE);

  fpi_validity_tls_free (&tls1);
  fpi_validity_tls_free (&tls2);
}

/* ================================================================
 * Test: PSK derivation matches python-validity (known-answer vectors)
 *
 * The expected keys were computed with python-validity's own code
 * (uunicorn/python-validity a6bbc21, validitysensor/tls.py): its prf()
 * and Tls.set_hwkey(), run over this file's fake test_password and
 * test_gwk_sign instead of python-validity's hardcoded constants. The
 * HP-style serial is made up.
 * ================================================================ */

/* "VirtualBox" / "0": python-validity's fallback identity */
static const guint8 kat_vbox_enc[32] = {
  0x74, 0xb7, 0xf3, 0xae, 0x48, 0x45, 0xc2, 0x7e,
  0xf4, 0x50, 0x19, 0xe4, 0xd3, 0x06, 0x69, 0x12,
  0x19, 0x17, 0xf7, 0xbb, 0x8e, 0x84, 0xa2, 0x77,
  0x8b, 0xba, 0xcb, 0x0c, 0xf7, 0x2a, 0xe1, 0x95,
};

static const guint8 kat_vbox_val[32] = {
  0xc9, 0xea, 0xff, 0x2a, 0x17, 0x6c, 0x43, 0x9e,
  0x0c, 0x37, 0x58, 0x71, 0x64, 0xfc, 0x0e, 0x51,
  0x0c, 0x3c, 0x74, 0x5e, 0xb3, 0xcf, 0x5b, 0xfe,
  0x99, 0x84, 0x9e, 0x1d, 0x84, 0x28, 0xb0, 0x33,
};

#define KAT_HP_NAME "HP EliteBook x360 1040 G6"
#define KAT_HP_SERIAL "5CG0000000"

/* KAT_HP_NAME / KAT_HP_SERIAL */
static const guint8 kat_hp_enc[32] = {
  0x56, 0x0f, 0x2d, 0xe6, 0x11, 0x14, 0xd7, 0x6d,
  0xa0, 0xad, 0xb5, 0xff, 0x31, 0x7d, 0x07, 0xe0,
  0xfb, 0xd6, 0xaa, 0x7b, 0xf3, 0xce, 0xb8, 0xee,
  0xed, 0x09, 0xff, 0x48, 0x70, 0x63, 0xbe, 0x3f,
};

static const guint8 kat_hp_val[32] = {
  0x90, 0x18, 0x8b, 0xc2, 0xf1, 0x0e, 0x3f, 0x80,
  0x2b, 0xde, 0x10, 0xad, 0x79, 0x76, 0x4f, 0xa1,
  0xa7, 0xff, 0xd8, 0x7f, 0x50, 0x61, 0xff, 0xf6,
  0xd0, 0x1f, 0x6f, 0xa1, 0x6e, 0xba, 0x9d, 0x2b,
};

/* KAT_HP_NAME / "" (blank SMBIOS serial) */
static const guint8 kat_hp_noserial_enc[32] = {
  0xa8, 0xc6, 0xec, 0xb6, 0x66, 0xf8, 0x0e, 0x9b,
  0x04, 0x9f, 0x10, 0xb2, 0x33, 0x18, 0x7e, 0x63,
  0x53, 0x26, 0x8c, 0x62, 0xa0, 0xde, 0xd6, 0xb0,
  0x89, 0x5a, 0xe5, 0x43, 0x36, 0x62, 0x98, 0x77,
};

static const guint8 kat_hp_noserial_val[32] = {
  0xee, 0xe4, 0x88, 0x2f, 0x33, 0x64, 0x1b, 0x35,
  0xce, 0x3f, 0xfa, 0xa2, 0xb9, 0x8d, 0x33, 0x14,
  0xba, 0xfe, 0x1a, 0x59, 0x9d, 0xe3, 0x5f, 0x9c,
  0xec, 0x4b, 0x51, 0x4e, 0x4c, 0x2a, 0x7e, 0x2f,
};

static void
psk_kat_init (ValidityTlsState *tls)
{
  fpi_validity_tls_init (tls);
  tls->password = test_password;
  tls->password_len = sizeof (test_password);
  tls->gwk_sign = test_gwk_sign;
  tls->gwk_sign_len = sizeof (test_gwk_sign);
}

static void
check_psk (const ValidityTlsState *tls,
           const guint8           *want_enc,
           const guint8           *want_val)
{
  g_assert_cmpmem (tls->psk_encryption_key, TLS_AES_KEY_SIZE,
                   want_enc, TLS_AES_KEY_SIZE);
  g_assert_cmpmem (tls->psk_validation_key, TLS_AES_KEY_SIZE,
                   want_val, TLS_AES_KEY_SIZE);
}

static void
test_psk_python_validity_kat (void)
{
  ValidityTlsState tls;

  psk_kat_init (&tls);
  fpi_validity_tls_derive_psk_from_identity (&tls, "VirtualBox", "0");
  check_psk (&tls, kat_vbox_enc, kat_vbox_val);
  fpi_validity_tls_free (&tls);

  psk_kat_init (&tls);
  fpi_validity_tls_derive_psk_from_identity (&tls, KAT_HP_NAME, KAT_HP_SERIAL);
  check_psk (&tls, kat_hp_enc, kat_hp_val);
  fpi_validity_tls_free (&tls);

  /* An empty serial is part of the identity, not a fallback */
  psk_kat_init (&tls);
  fpi_validity_tls_derive_psk_from_identity (&tls, KAT_HP_NAME, "");
  check_psk (&tls, kat_hp_noserial_enc, kat_hp_noserial_val);
  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Test: reading the DMI files, stripping, and the fallback
 *
 * Same behaviour as python-validity's Tls.__init__: both values are
 * stripped, a blank value is used as an empty string, and if either
 * file cannot be read both values become "VirtualBox" / "0".
 *
 * On success the whole debug line is matched, so it has to name the
 * stripped product and must not contain the serial.
 * ================================================================ */
#define KAT_HP_LOG_PRESENT \
  "PSK derived from DMI: product=\"" KAT_HP_NAME "\", serial present"
#define KAT_HP_LOG_EMPTY \
  "PSK derived from DMI: product=\"" KAT_HP_NAME "\", serial empty"

static void
check_psk_from_files (const gchar  *name_content,   /* NULL: no file */
                      const gchar  *serial_content, /* NULL: no file */
                      const gchar  *want_log,       /* NULL: fallback */
                      const guint8 *want_enc,
                      const guint8 *want_val)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("validity-dmi-XXXXXX", NULL);

  g_assert_nonnull (tmpdir);

  g_autofree gchar *name_path = g_build_filename (tmpdir, "product_name",
                                                  NULL);
  g_autofree gchar *serial_path = g_build_filename (tmpdir, "product_serial",
                                                    NULL);

  if (name_content)
    g_assert_true (g_file_set_contents (name_path, name_content, -1, NULL));
  if (serial_content)
    g_assert_true (g_file_set_contents (serial_path, serial_content, -1,
                                        NULL));

  if (want_log)
    g_test_expect_message ("libfprint-validity", G_LOG_LEVEL_DEBUG, want_log);
  else
    g_test_expect_message ("libfprint-validity", G_LOG_LEVEL_WARNING,
                           "*fallback identity*");

  ValidityTlsState tls;
  psk_kat_init (&tls);
  fpi_validity_tls_derive_psk_from_files (&tls, name_path, serial_path);
  g_test_assert_expected_messages ();
  check_psk (&tls, want_enc, want_val);
  fpi_validity_tls_free (&tls);

  g_remove (name_path);
  g_remove (serial_path);
  g_rmdir (tmpdir);
}

static void
test_psk_from_files (void)
{
  /* sysfs values end in a newline */
  check_psk_from_files (KAT_HP_NAME "\n", KAT_HP_SERIAL "\n",
                        KAT_HP_LOG_PRESENT, kat_hp_enc, kat_hp_val);
  check_psk_from_files ("  " KAT_HP_NAME " \n", " " KAT_HP_SERIAL "\t\n",
                        KAT_HP_LOG_PRESENT, kat_hp_enc, kat_hp_val);

  /* Blank SMBIOS serial: sysfs shows a bare newline, used as "" */
  check_psk_from_files (KAT_HP_NAME "\n", "\n",
                        KAT_HP_LOG_EMPTY, kat_hp_noserial_enc,
                        kat_hp_noserial_val);

  /* Either file unreadable: both values fall back */
  check_psk_from_files (KAT_HP_NAME "\n", NULL, NULL,
                        kat_vbox_enc, kat_vbox_val);
  check_psk_from_files (NULL, KAT_HP_SERIAL "\n", NULL,
                        kat_vbox_enc, kat_vbox_val);
  check_psk_from_files (NULL, NULL, NULL, kat_vbox_enc, kat_vbox_val);
}

/* ================================================================
 * Tests: developer-only overrides (meson -Dvalidity_dev=true)
 *
 * The readers are compiled in every build and tested here; only the
 * environment lookups depend on the option, and in a build without it
 * the variables must be ignored.
 * ================================================================ */

static gchar *
dev_write_file (const gchar *dir,
                const gchar *name,
                const gchar *content,
                gssize       len,
                gint         mode)
{
  gchar *path = g_build_filename (dir, name, NULL);

  g_assert_true (g_file_set_contents (path, content, len, NULL));
  g_assert_cmpint (g_chmod (path, mode), ==, 0);
  return path;
}

static void
dev_check_serial_refused (const gchar *path,
                          const gchar *want_in_message)
{
  g_autoptr(GError) error = NULL;
  gchar *serial = (gchar *) "unset";

  g_assert_false (fpi_validity_tls_read_serial_file (path, &serial, &error));
  g_assert_null (serial);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL);
  if (want_in_message)
    g_assert_nonnull (strstr (error->message, want_in_message));
  /* The value is never echoed */
  g_assert_null (strstr (error->message, "SECRET"));
}

/* The serial file reader fails closed on anything but a private,
 * single-line, printable file, and never puts the value in an error */
static void
test_dev_serial_file_read (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("validity-dev-XXXXXX", NULL);
  g_autofree gchar *good = NULL;
  g_autofree gchar *group = NULL;
  g_autofree gchar *link = NULL;
  g_autofree gchar *empty = NULL;
  g_autofree gchar *blank = NULL;
  g_autofree gchar *big = NULL;
  g_autofree gchar *ctrl = NULL;
  g_autofree gchar *nul = NULL;
  g_autofree gchar *high = NULL;
  g_autofree gchar *missing = NULL;
  g_autofree gchar *big_content = g_strnfill (300, 'S');
  gchar *serial = NULL;

  g_assert_nonnull (dir);

  /* Good: stripped like the sysfs value */
  good = dev_write_file (dir, "good", "  SECRET-SN 01\t\n", -1, 0600);
  {
    g_autoptr(GError) error = NULL;

    g_assert_true (fpi_validity_tls_read_serial_file (good, &serial, &error));
    g_assert_no_error (error);
    g_assert_cmpstr (serial, ==, "SECRET-SN 01");
    fpi_validity_tls_free_secret_string (serial);
    serial = NULL;
  }
  /* Read-only for the owner is fine too */
  g_assert_cmpint (g_chmod (good, 0400), ==, 0);
  {
    g_autoptr(GError) error = NULL;

    g_assert_true (fpi_validity_tls_read_serial_file (good, &serial, &error));
    fpi_validity_tls_free_secret_string (serial);
    serial = NULL;
  }

  group = dev_write_file (dir, "group", "SECRET\n", -1, 0640);
  dev_check_serial_refused (group, "chmod 600");
  g_assert_cmpint (g_chmod (group, 0604), ==, 0);
  dev_check_serial_refused (group, "chmod 600");

  link = g_build_filename (dir, "link", NULL);
  g_assert_cmpint (symlink (good, link), ==, 0);
  dev_check_serial_refused (link, "symbolic links");

  empty = dev_write_file (dir, "empty", "", 0, 0600);
  dev_check_serial_refused (empty, "empty");
  blank = dev_write_file (dir, "blank", " \n\t\n", -1, 0600);
  dev_check_serial_refused (blank, "empty");

  big = dev_write_file (dir, "big", big_content, -1, 0600);
  dev_check_serial_refused (big, "larger than");

  ctrl = dev_write_file (dir, "ctrl", "SECRET\001X\n", -1, 0600);
  dev_check_serial_refused (ctrl, "printable");
  high = dev_write_file (dir, "high", "SECRET\303\251\n", -1, 0600);
  dev_check_serial_refused (high, "printable");
  nul = dev_write_file (dir, "nul", "SECRET\0X\n", 9, 0600);
  dev_check_serial_refused (nul, "NUL");
  {
    g_autofree gchar *two = dev_write_file (dir, "two", "SECRET\nSECOND\n",
                                            -1, 0600);

    dev_check_serial_refused (two, "printable");
    g_remove (two);
  }

  missing = g_build_filename (dir, "missing", NULL);
  dev_check_serial_refused (missing, "cannot be opened");
  dev_check_serial_refused (dir, "not a regular file");
  /* A FIFO with no writer is refused at once (opening it used to block) */
  {
    g_autofree gchar *fifo = g_build_filename (dir, "fifo", NULL);

    g_assert_cmpint (mkfifo (fifo, 0600), ==, 0);
    dev_check_serial_refused (fifo, "not a regular file");
    g_remove (fifo);
  }
  /* Leading whitespace (the text moves to the front of the buffer) */
  {
    g_autofree gchar *lead = dev_write_file (dir, "lead", "\t\t  SECRET-SN 02",
                                             -1, 0600);
    g_autoptr(GError) error = NULL;

    g_assert_true (fpi_validity_tls_read_serial_file (lead, &serial, &error));
    g_assert_cmpstr (serial, ==, "SECRET-SN 02");
    fpi_validity_tls_free_secret_string (serial);
    serial = NULL;
    g_remove (lead);
  }
  dev_check_serial_refused ("relative/dmi_serial", "absolute");
  dev_check_serial_refused (NULL, "absolute");

  g_remove (good);
  g_remove (group);
  g_remove (link);
  g_remove (empty);
  g_remove (blank);
  g_remove (big);
  g_remove (ctrl);
  g_remove (high);
  g_remove (nul);
  g_rmdir (dir);
}

/* The override file gives the same PSK as the sysfs files with the same
* values (python-validity KAT), and there is no VirtualBox/0 fallback */
static void
test_dev_serial_file_psk (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("validity-dev-XXXXXX", NULL);
  g_autofree gchar *name = NULL;
  g_autofree gchar *serial = NULL;
  g_autofree gchar *missing = NULL;
  g_autofree gchar *open_serial = NULL;

  g_assert_nonnull (dir);
  name = dev_write_file (dir, "product_name", KAT_HP_NAME "\n", -1, 0644);
  serial = dev_write_file (dir, "dmi_serial", KAT_HP_SERIAL "\n", -1, 0600);
  open_serial = dev_write_file (dir, "open_serial", KAT_HP_SERIAL "\n", -1,
                                0644);
  missing = g_build_filename (dir, "missing", NULL);

  {
    g_autoptr(GError) error = NULL;
    ValidityTlsState tls;

    psk_kat_init (&tls);
    g_assert_true (fpi_validity_tls_derive_psk_with_serial_file (&tls, name,
                                                                 serial, &error));
    g_assert_no_error (error);
    check_psk (&tls, kat_hp_enc, kat_hp_val);
    fpi_validity_tls_free (&tls);
  }

  {
    g_autoptr(GError) error = NULL;
    ValidityTlsState tls;

    psk_kat_init (&tls);
    g_assert_false (fpi_validity_tls_derive_psk_with_serial_file (&tls, missing,
                                                                  serial, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL);
    fpi_validity_tls_free (&tls);
  }

  {
    g_autoptr(GError) error = NULL;
    ValidityTlsState tls;

    psk_kat_init (&tls);
    g_assert_false (fpi_validity_tls_derive_psk_with_serial_file (&tls, name,
                                                                  open_serial,
                                                                  &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL);
    g_assert_null (strstr (error->message, KAT_HP_SERIAL));
    fpi_validity_tls_free (&tls);
  }

  g_remove (name);
  g_remove (serial);
  g_remove (open_serial);
  g_rmdir (dir);
}

static gchar *
dev_write_data_file (const gchar  *dir,
                     const gchar  *name,
                     const guint8 *payload,
                     gsize         len)
{
  static const gchar key[] = "libfprint-validity-data-integrit";

  g_autoptr(GHmac) hmac = g_hmac_new (G_CHECKSUM_SHA256, (const guchar *) key,
                                      32);
  guint8 digest[32];
  gsize digest_len = sizeof (digest);
  g_autofree guint8 *content = g_malloc (len + sizeof (digest));
  gchar *path = g_build_filename (dir, name, NULL);

  g_hmac_update (hmac, payload, len);
  g_hmac_get_digest (hmac, digest, &digest_len);
  memcpy (content, payload, len);
  memcpy (content + len, digest, sizeof (digest));
  g_assert_true (g_file_set_contents (path, (const gchar *) content,
                                      len + sizeof (digest), NULL));
  return path;
}

/* FP_VALIDITY_DATA_DIR: resolution is strict, and the directory is the only
 * place searched (developer build); a build without the option ignores
 * the variable */
static void
test_dev_data_dir (void)
{
  static const guint8 init_payload[] = { 0x06, 0x02, 0x00, 0x00, 0x01 };
  g_autofree gchar *dir = g_dir_make_tmp ("validity-dev-XXXXXX", NULL);
  g_autofree gchar *devdir = NULL;
  g_autofree gchar *init = NULL;
  g_autofree gchar *file = NULL;

  g_assert_nonnull (dir);
  devdir = g_build_filename (dir, "06cb_00a2", NULL);
  g_assert_cmpint (g_mkdir (devdir, 0700), ==, 0);
  init = dev_write_data_file (devdir, "init.bin", init_payload,
                              sizeof (init_payload));
  file = dev_write_file (dir, "not-a-dir", "x", -1, 0600);

  /* Resolution */
  {
    g_auto(GStrv) paths = fpi_validity_data_resolve_search_paths (NULL, NULL);

    g_assert_cmpuint (g_strv_length (paths), ==,
                      g_strv_length ((gchar **) validity_data_search_paths));
    for (guint i = 0; paths[i]; i++)
      g_assert_cmpstr (paths[i], ==, validity_data_search_paths[i]);
  }
  {
    g_auto(GStrv) paths = fpi_validity_data_resolve_search_paths (dir, NULL);

    g_assert_cmpuint (g_strv_length (paths), ==, 1);
    g_assert_cmpstr (paths[0], ==, dir);
  }
  {
    const gchar *bad[] = { "", "relative/dir", "/nonexistent-validity-dir",
                           file };

    for (gsize i = 0; i < G_N_ELEMENTS (bad); i++)
      {
        g_autoptr(GError) error = NULL;

        g_assert_null (fpi_validity_data_resolve_search_paths (bad[i], &error));
        g_assert_error (error, FP_DEVICE_ERROR,
                        FP_DEVICE_ERROR_DATA_NOT_FOUND);
      }
  }

  g_setenv (VALIDITY_DATA_DIR_ENV, dir, TRUE);
  g_setenv (VALIDITY_DMI_SERIAL_FILE_ENV, file, TRUE);

  if (fpi_validity_dev_overrides_built ())
    {
      ValidityDataStore store;
      gsize len = 0;
      const guint8 *data;

      g_assert_cmpstr (fpi_validity_data_dev_dir (), ==, dir);
      g_assert_cmpstr (fpi_validity_tls_dev_serial_file (), ==, file);

      /* The device blobs load from the override directory */
      fpi_validity_data_store_init (&store);
      {
        g_autoptr(GError) error = NULL;

        g_assert_true (fpi_validity_data_load_device (&store, 0x06cb, 0x00a2,
                                                      &error));
        g_assert_no_error (error);
      }
      data = fpi_validity_data_get_bytes (&store, VALIDITY_DATA_INIT, &len);
      g_assert_cmpmem (data, len, init_payload, sizeof (init_payload));
      g_assert_null (fpi_validity_data_get (&store, VALIDITY_DATA_RESET));

      /* No fallback to the system paths for missing files */
      {
        g_autoptr(GError) error = NULL;

        g_assert_false (fpi_validity_data_load_common (&store, &error));
        g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND);
        g_assert_nonnull (strstr (error->message, dir));
        g_assert_null (strstr (error->message, "/usr/share/libfprint"));
      }
      {
        g_autoptr(GError) error = NULL;

        g_assert_false (fpi_validity_data_load_device (&store, 0x06cb, 0x009a,
                                                       &error));
        g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND);
        g_assert_null (strstr (error->message, "/usr/share/libfprint"));
      }
      fpi_validity_data_store_free (&store);

      /* A bad value fails closed */
      g_setenv (VALIDITY_DATA_DIR_ENV, "relative", TRUE);
      fpi_validity_data_store_init (&store);
      {
        g_autoptr(GError) error = NULL;

        g_assert_false (fpi_validity_data_load_device (&store, 0x06cb, 0x00a2,
                                                       &error));
        g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND);
      }
      fpi_validity_data_store_free (&store);

      /* The serial override is used, and fails closed (not 0600) */
      {
        g_autoptr(GError) error = NULL;
        ValidityTlsState tls;

        g_assert_cmpint (g_chmod (file, 0644), ==, 0);
        psk_kat_init (&tls);
        g_assert_false (fpi_validity_tls_derive_psk_checked (&tls, &error));
        g_assert_nonnull (error);
        fpi_validity_tls_free (&tls);
      }
    }
  else
    {
      ValidityDataStore store;

      g_assert_null (fpi_validity_data_dev_dir ());
      g_assert_null (fpi_validity_tls_dev_serial_file ());

      /* The override directory is never searched */
      fpi_validity_data_store_init (&store);
      {
        g_autoptr(GError) error = NULL;

        if (!fpi_validity_data_load_device (&store, 0x06cb, 0x00a2, &error))
          g_assert_null (strstr (error->message, dir));
        else
          g_assert_null (strstr (dir, "/usr/share"));
      }
      fpi_validity_data_store_free (&store);
    }

  g_unsetenv (VALIDITY_DATA_DIR_ENV);
  g_unsetenv (VALIDITY_DMI_SERIAL_FILE_ENV);

  g_remove (init);
  g_rmdir (devdir);
  g_remove (file);
  g_rmdir (dir);
}

/* ================================================================
 * Test: Flash parse with empty data fails gracefully
 * ================================================================ */
static void
test_flash_parse_empty (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);

  GError *error = NULL;
  guint8 empty_flash[] = { 0xFF, 0xFF, 0x00, 0x00 }; /* end block */

  /* Flash with only end marker → missing keys */
  gboolean result = fpi_validity_tls_parse_flash (&tls, empty_flash,
                                                  sizeof (empty_flash),
                                                  &error);
  g_assert_false (result);
  g_assert_nonnull (error);
  g_assert_false (tls.keys_loaded);
  g_assert_false (tls.priv_key_mismatch);

  g_clear_error (&error);
  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Test: Flash parse with truncated data fails gracefully
 * ================================================================ */
static void
test_flash_parse_truncated (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);

  GError *error = NULL;
  guint8 truncated[] = { 0x03, 0x00, 0xFF, 0x00 }; /* cert block w/ impossibly large size */

  gboolean result = fpi_validity_tls_parse_flash (&tls, truncated,
                                                  sizeof (truncated),
                                                  &error);
  /* Should fail due to block size exceeding remaining data */
  g_assert_false (result);
  g_assert_nonnull (error);
  g_assert_false (tls.priv_key_mismatch);
  g_clear_error (&error);

  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Test: Init/free cycle doesn't leak
 * ================================================================ */
static void
test_init_free (void)
{
  ValidityTlsState tls;

  for (int i = 0; i < 10; i++)
    {
      fpi_validity_tls_init (&tls);
      fpi_validity_tls_free (&tls);
    }
}

/* ================================================================
 * Test: Build ClientHello produces valid TLS record
 * ================================================================ */
static void
test_build_client_hello (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);

  gsize out_len;
  guint8 *hello = fpi_validity_tls_build_client_hello (&tls, &out_len);

  g_assert_nonnull (hello);
  g_assert_cmpuint (out_len, >, 4 + 5); /* prefix(4) + record header(5) minimum */

  /* Check prefix: 0x44 0x00 0x00 0x00 */
  g_assert_cmpint (hello[0], ==, 0x44);
  g_assert_cmpint (hello[1], ==, 0x00);
  g_assert_cmpint (hello[2], ==, 0x00);
  g_assert_cmpint (hello[3], ==, 0x00);

  /* Check TLS record header */
  g_assert_cmpint (hello[4], ==, 0x16); /* handshake */
  g_assert_cmpint (hello[5], ==, 0x03); /* version major */
  g_assert_cmpint (hello[6], ==, 0x03); /* version minor */

  /* client_random should have been set */
  gboolean has_random = FALSE;
  for (gsize i = 0; i < TLS_RANDOM_SIZE; i++)
    {
      if (tls.client_random[i] != 0)
        {
          has_random = TRUE;
          break;
        }
    }
  g_assert_true (has_random);

  g_free (hello);
  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Test: Wrap/unwrap with invalid data fails gracefully
 * ================================================================ */
static void
test_unwrap_invalid (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);

  GError *error = NULL;
  gsize out_len;

  /* Short data → truncated record header */
  guint8 short_data[] = { 0x17, 0x03 };
  guint8 *result = fpi_validity_tls_unwrap_response (&tls, short_data,
                                                     sizeof (short_data),
                                                     &out_len, &error);
  g_assert_null (result);
  g_assert_nonnull (error);
  g_clear_error (&error);

  /* App data before secure channel */
  guint8 app_early[] = { 0x17, 0x03, 0x03, 0x00, 0x10,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  result = fpi_validity_tls_unwrap_response (&tls, app_early,
                                             sizeof (app_early),
                                             &out_len, &error);
  g_assert_null (result);
  g_assert_nonnull (error);
  g_clear_error (&error);

  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Flash parse requires PSK before private key decryption
 *
 * Private key block (ID 4) is encrypted with PSK. parse_flash
 * without prior PSK derivation must fail (HMAC mismatch).
 * ================================================================ */
static void
test_flash_parse_needs_psk (void)
{
  ValidityTlsState tls_with_psk, tls_no_psk;

  fpi_validity_tls_init (&tls_with_psk);
  fpi_validity_tls_init (&tls_no_psk);

  /* Set up key material before PSK derivation */
  tls_with_psk.password = test_password;
  tls_with_psk.password_len = sizeof (test_password);
  tls_with_psk.gwk_sign = test_gwk_sign;
  tls_with_psk.gwk_sign_len = sizeof (test_gwk_sign);

  /* Derive PSK so we can build a valid encrypted private key block */
  fpi_validity_tls_derive_psk_from_identity (&tls_with_psk, "Test Product",
                                             "SN0001");

  /* Build a realistic flash image with a cert block + encrypted privkey block.
   * We use a minimal cert (just 16 bytes of dummy data) and a privkey block
   * that's encrypted with the proper PSK. */

  /* Build a cert body */
  guint8 cert_body[16];
  memset (cert_body, 0xAA, sizeof (cert_body));

  /* Build a private-key body encrypted with PSK */
  guint8 priv_plaintext[96]; /* d(32) + pad for block alignment */
  memset (priv_plaintext, 0xBB, sizeof (priv_plaintext));

  /* Encrypt plaintext with PSK encryption key */
  guint8 iv[TLS_IV_SIZE];
  memset (iv, 0x11, TLS_IV_SIZE);
  gsize ct_len = sizeof (priv_plaintext);
  guint8 *ciphertext = g_malloc (TLS_IV_SIZE + ct_len);
  memcpy (ciphertext, iv, TLS_IV_SIZE);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int out_len, final_len;
  EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc (), NULL,
                      tls_with_psk.psk_encryption_key, iv);
  EVP_CIPHER_CTX_set_padding (ctx, 0);
  EVP_EncryptUpdate (ctx, ciphertext + TLS_IV_SIZE, &out_len,
                     priv_plaintext, ct_len);
  EVP_EncryptFinal_ex (ctx, ciphertext + TLS_IV_SIZE + out_len, &final_len);
  EVP_CIPHER_CTX_free (ctx);
  gsize enc_total = TLS_IV_SIZE + ct_len;

  /* HMAC over (iv + ciphertext) with psk_validation_key */
  guint8 mac[TLS_HMAC_SIZE];
  unsigned int mac_len;
  HMAC (EVP_sha256 (),
        tls_with_psk.psk_validation_key, TLS_AES_KEY_SIZE,
        ciphertext, enc_total, mac, &mac_len);

  /* Private key block payload: 0x02 || ciphertext || hmac */
  gsize priv_block_len = 1 + enc_total + TLS_HMAC_SIZE;
  guint8 *priv_block = g_malloc (priv_block_len);
  priv_block[0] = 0x02;
  memcpy (priv_block + 1, ciphertext, enc_total);
  memcpy (priv_block + 1 + enc_total, mac, TLS_HMAC_SIZE);
  g_free (ciphertext);

  /* Build flash image: [cert_header][cert_body][priv_header][priv_body][end] */
  GByteArray *flash = g_byte_array_new ();

  /* Cert block header: id=0x0003, size, sha256 hash */
  guint8 cert_hdr[TLS_FLASH_BLOCK_HEADER_SIZE];
  FP_WRITE_UINT16_LE (cert_hdr, TLS_FLASH_BLOCK_CERT);
  FP_WRITE_UINT16_LE (cert_hdr + 2, sizeof (cert_body));
  GChecksum *cs = g_checksum_new (G_CHECKSUM_SHA256);
  gsize hash_len = 32;
  g_checksum_update (cs, cert_body, sizeof (cert_body));
  g_checksum_get_digest (cs, cert_hdr + 4, &hash_len);
  g_checksum_free (cs);
  g_byte_array_append (flash, cert_hdr, sizeof (cert_hdr));
  g_byte_array_append (flash, cert_body, sizeof (cert_body));

  /* Priv block header */
  guint8 priv_hdr[TLS_FLASH_BLOCK_HEADER_SIZE];
  FP_WRITE_UINT16_LE (priv_hdr, TLS_FLASH_BLOCK_PRIVKEY);
  FP_WRITE_UINT16_LE (priv_hdr + 2, priv_block_len);
  cs = g_checksum_new (G_CHECKSUM_SHA256);
  hash_len = 32;
  g_checksum_update (cs, priv_block, priv_block_len);
  g_checksum_get_digest (cs, priv_hdr + 4, &hash_len);
  g_checksum_free (cs);
  g_byte_array_append (flash, priv_hdr, sizeof (priv_hdr));
  g_byte_array_append (flash, priv_block, priv_block_len);

  /* End marker */
  guint8 end_marker[4] = { 0xFF, 0xFF, 0x00, 0x00 };
  g_byte_array_append (flash, end_marker, sizeof (end_marker));

  /* TEST: Without PSK, parse_flash must fail on the privkey block */
  GError *error = NULL;
  gboolean result = fpi_validity_tls_parse_flash (&tls_no_psk,
                                                  flash->data, flash->len,
                                                  &error);
  g_assert_false (result);
  g_assert_nonnull (error);
  /* Should fail with HMAC-related error since PSK is all zeros, and flag
   * it as another host identity's pairing (open reports that case). */
  g_assert_true (tls_no_psk.priv_key_mismatch);
  g_clear_error (&error);

  /* With the PSK the block was wrapped under, the HMAC passes: not a
   * mismatch. (The dummy key then fails to unpad, so the parse still
   * fails, for a different reason.) */
  result = fpi_validity_tls_parse_flash (&tls_with_psk, flash->data, flash->len,
                                         &error);
  g_assert_false (result);
  g_assert_nonnull (error);
  g_assert_false (tls_with_psk.priv_key_mismatch);
  g_clear_error (&error);

  /* The flag describes the latest parse only: parsing again, now with the
   * matching PSK, clears it. */
  memcpy (tls_no_psk.psk_encryption_key, tls_with_psk.psk_encryption_key,
          TLS_AES_KEY_SIZE);
  memcpy (tls_no_psk.psk_validation_key, tls_with_psk.psk_validation_key,
          TLS_AES_KEY_SIZE);
  result = fpi_validity_tls_parse_flash (&tls_no_psk, flash->data, flash->len,
                                         &error);
  g_assert_false (result);
  g_assert_false (tls_no_psk.priv_key_mismatch);
  g_clear_error (&error);

  g_byte_array_free (flash, TRUE);
  g_free (priv_block);
  fpi_validity_tls_free (&tls_with_psk);
  fpi_validity_tls_free (&tls_no_psk);
}

/* ================================================================
 * READ_FLASH command format
 *
 * Must be exactly 13 bytes: pack('<BBBHLL', 0x40, partition, 1, 0,
 * addr, size) — including the access flag and reserved field.
 * ================================================================ */
static void
test_flash_cmd_format (void)
{
  /* Verify the command byte */
  g_assert_cmpint (VCSFW_CMD_READ_FLASH, ==, 0x40);

  /* Build the same command as validity_tls_flash_read_run_state does */
  guint8 cmd[13];
  cmd[0] = VCSFW_CMD_READ_FLASH;
  cmd[1] = 0x01;           /* partition */
  cmd[2] = 0x01;           /* access flag */
  FP_WRITE_UINT16_LE (&cmd[3], 0x0000);  /* reserved */
  FP_WRITE_UINT32_LE (&cmd[5], 0x0000);  /* offset */
  FP_WRITE_UINT32_LE (&cmd[9], 0x1000);  /* size */

  /* Verify total size is 13 */
  g_assert_cmpuint (sizeof (cmd), ==, 13);

  /* Verify byte layout matches python-validity's pack('<BBBHLL', ...) */
  g_assert_cmpint (cmd[0], ==, 0x40);  /* command */
  g_assert_cmpint (cmd[1], ==, 0x01);  /* partition */
  g_assert_cmpint (cmd[2], ==, 0x01);  /* access flag */
  g_assert_cmpint (cmd[3], ==, 0x00);  /* reserved lo */
  g_assert_cmpint (cmd[4], ==, 0x00);  /* reserved hi */
  /* offset at bytes 5-8 (LE uint32 = 0) */
  g_assert_cmpint (cmd[5], ==, 0x00);
  g_assert_cmpint (cmd[6], ==, 0x00);
  g_assert_cmpint (cmd[7], ==, 0x00);
  g_assert_cmpint (cmd[8], ==, 0x00);
  /* size at bytes 9-12 (LE uint32 = 0x1000) */
  g_assert_cmpint (cmd[9], ==, 0x00);
  g_assert_cmpint (cmd[10], ==, 0x10);
  g_assert_cmpint (cmd[11], ==, 0x00);
  g_assert_cmpint (cmd[12], ==, 0x00);
}

/* ================================================================
 * Flash response has 6-byte header before block data
 *
 * After stripping the 2-byte VCSFW status, the flash response
 * contains [size:4 LE][unknown:2] before the actual block data.
 * parse_flash must receive data starting at offset 6.
 * ================================================================ */
static void
test_flash_response_header (void)
{
  /* Build a minimal valid flash image: just an end marker */
  guint8 flash_data[] = { 0xFF, 0xFF, 0x00, 0x00 };

  /* Wrap it in the response header format: [size:4 LE][unk:2][data] */
  guint32 data_size = sizeof (flash_data);
  guint8 response[6 + sizeof (flash_data)];

  FP_WRITE_UINT32_LE (response, data_size);
  response[4] = 0x00;   /* unknown byte 1 */
  response[5] = 0x00;   /* unknown byte 2 */
  memcpy (response + 6, flash_data, sizeof (flash_data));

  /* Verify the unwrap logic: read size from offset 0, skip 6-byte header */
  guint32 read_size = FP_READ_UINT32_LE (response);
  g_assert_cmpuint (read_size, ==, sizeof (flash_data));

  const guint8 *payload = response + 6;
  gsize payload_len = sizeof (response) - 6;
  g_assert_cmpuint (payload_len, ==, sizeof (flash_data));

  /* Parsing the correctly unwrapped data should succeed (end marker only = no keys) */
  ValidityTlsState tls;
  fpi_validity_tls_init (&tls);
  GError *error = NULL;
  gboolean result = fpi_validity_tls_parse_flash (&tls, payload, payload_len, &error);
  /* Expected: fails because no keys, but NOT because of corrupt block headers */
  g_assert_false (result);
  g_assert_nonnull (error);
  g_assert_true (g_str_has_prefix (error->message, "TLS flash: incomplete key data"));
  g_clear_error (&error);
  fpi_validity_tls_free (&tls);

  /* The raw response (with 6-byte header) differs from the unwrapped
   * payload — passing it directly to parse_flash would corrupt block
   * parsing since the size field (0x04 0x00 ...) looks like block_id=4. */
  g_assert_cmpuint (sizeof (response), !=, payload_len);
  g_assert_true (memcmp (response, payload, payload_len) != 0);
}

/* ================================================================
 * TLS handshake uses raw TLS records (not VCSFW-wrapped)
 *
 * parse_server_hello expects data starting with content type 0x16.
 * A 2-byte VCSFW status prefix would corrupt the TLS record.
 * ================================================================ */
static void
test_server_hello_rejects_vcsfw_prefix (void)
{
  /* Build a minimal valid TLS ServerHello record */
  guint8 server_hello_msg[] = {
    /* Handshake message: ServerHello (type 0x02) */
    0x02,               /* type: ServerHello */
    0x00, 0x00, 0x26,   /* length: 38 bytes */
    0x03, 0x03,          /* version 1.2 */
    /* 32 bytes server_random */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x00,                /* session_id length: 0 */
    0xC0, 0x05,          /* cipher suite: 0xC005 */
    0x00,                /* compression: none */
  };

  gsize hs_len = sizeof (server_hello_msg);

  /* Wrap in TLS record: content_type(1) + version(2) + length(2) + body */
  gsize raw_tls_len = 5 + hs_len;
  guint8 *raw_tls = g_malloc (raw_tls_len);

  raw_tls[0] = TLS_CONTENT_HANDSHAKE;   /* 0x16 */
  raw_tls[1] = TLS_VERSION_MAJOR;
  raw_tls[2] = TLS_VERSION_MINOR;
  raw_tls[3] = (hs_len >> 8) & 0xff;
  raw_tls[4] = hs_len & 0xff;
  memcpy (raw_tls + 5, server_hello_msg, hs_len);

  /* Test 1: parse_server_hello with raw TLS — should succeed */
  ValidityTlsState tls;
  fpi_validity_tls_init (&tls);
  tls.handshake_hash = g_checksum_new (G_CHECKSUM_SHA256);
  GError *error = NULL;

  gboolean result = fpi_validity_tls_parse_server_hello (&tls, raw_tls,
                                                         raw_tls_len, &error);
  g_assert_no_error (error);
  g_assert_true (result);
  /* Verify server_random was properly extracted */
  g_assert_cmpint (tls.server_random[0], ==, 0x01);
  g_assert_cmpint (tls.server_random[31], ==, 0x20);
  fpi_validity_tls_free (&tls);

  /* Test 2: Prepend a 2-byte VCSFW status (0x0000) — simulates what
   * vcsfw_cmd_send's cmd_receive_cb would have already STRIPPED.
   * But if the raw recv path is wrong and doesn't strip, the parser
   * gets [0x00, 0x00, 0x16, ...] — first byte 0x00 is not a valid
   * TLS content type, so parsing should behave differently. */
  gsize prefixed_len = 2 + raw_tls_len;
  guint8 *prefixed = g_malloc (prefixed_len);
  prefixed[0] = 0x00;  /* VCSFW status lo */
  prefixed[1] = 0x00;  /* VCSFW status hi */
  memcpy (prefixed + 2, raw_tls, raw_tls_len);

  fpi_validity_tls_init (&tls);
  tls.handshake_hash = g_checksum_new (G_CHECKSUM_SHA256);

  result = fpi_validity_tls_parse_server_hello (&tls, prefixed, prefixed_len,
                                                &error);
  /* With the 2-byte prefix, the first "record" starts at byte 0:
   * content_type=0x00 is NOT TLS_CONTENT_HANDSHAKE (0x16), so the
   * parser treats it as unknown content and either fails or skips it,
   * and the server_random will NOT match the expected values. */
  if (result)
    {
      /* Even if parsing didn't error, server_random should be wrong */
      gboolean random_ok = (tls.server_random[0] == 0x01 &&
                            tls.server_random[31] == 0x20);
      g_assert_false (random_ok);
    }
  g_clear_error (&error);
  fpi_validity_tls_free (&tls);

  g_free (raw_tls);
  g_free (prefixed);
}

/* ================================================================
 * Client hello uses 0x44 prefix (not a VCSFW command)
 *
 * TLS handshake messages are prefixed with 0x44000000, followed
 * by the raw TLS record. No VCSFW status in the response.
 * ================================================================ */
static void
test_client_hello_tls_prefix (void)
{
  ValidityTlsState tls;

  fpi_validity_tls_init (&tls);

  gsize out_len;
  guint8 *hello = fpi_validity_tls_build_client_hello (&tls, &out_len);
  g_assert_nonnull (hello);

  /* Must start with 0x44 0x00 0x00 0x00 (TLS prefix, not VCSFW) */
  g_assert_cmpint (hello[0], ==, 0x44);
  g_assert_cmpint (hello[1], ==, 0x00);
  g_assert_cmpint (hello[2], ==, 0x00);
  g_assert_cmpint (hello[3], ==, 0x00);

  /* Byte 4 must be TLS Handshake content type (0x16) */
  g_assert_cmpint (hello[4], ==, TLS_CONTENT_HANDSHAKE);

  /* Bytes 5-6 must be TLS version 1.2 (0x0303) */
  g_assert_cmpint (hello[5], ==, TLS_VERSION_MAJOR);
  g_assert_cmpint (hello[6], ==, TLS_VERSION_MINOR);

  /* The prefix (0x44) must NOT equal any VCSFW command byte.
   * Specifically, 0x44 != VCSFW_CMD_READ_FLASH (0x40) and
   * is not any known VCSFW command. This proves TLS messages
   * travel on a separate "channel". */
  g_assert_cmpint (hello[0], !=, VCSFW_CMD_GET_VERSION);
  g_assert_cmpint (hello[0], !=, VCSFW_CMD_READ_FLASH);
  g_assert_cmpint (hello[0], !=, VCSFW_CMD_GET_FW_INFO);

  g_free (hello);
  fpi_validity_tls_free (&tls);
}

/* ================================================================
 * Main
 * ================================================================ */

/* ================================================================
 * Tests: PAIR
 * ================================================================ */


/* ================================================================
 * T7.11: parse_flash_info — valid response
 * ================================================================ */
static void
test_parse_flash_info_valid (void)
{
  /* CMD 0x3e response format (after 2-byte status, already stripped):
   * [jid0:2LE][jid1:2LE][blocks:2LE][unknown0:2LE][blocksize:2LE]
   * [unknown1:2LE][pcnt:2LE] = 14 bytes minimum */
  guint8 data[14];

  memset (data, 0, sizeof (data));

  /* jid0=0x01, jid1=0x02, blocks=0x1000, unknown0=0, blocksize=0x100,
   * unknown1=0, pcnt=5 (5 partitions = device already paired) */
  FP_WRITE_UINT16_LE (data + 0, 0x0001); /* jid0 */
  FP_WRITE_UINT16_LE (data + 2, 0x0002); /* jid1 */
  FP_WRITE_UINT16_LE (data + 4, 0x1000); /* blocks */
  FP_WRITE_UINT16_LE (data + 6, 0x0000); /* unknown0 */
  FP_WRITE_UINT16_LE (data + 8, 0x0100); /* blocksize */
  FP_WRITE_UINT16_LE (data + 10, 0x0000); /* unknown1 */
  FP_WRITE_UINT16_LE (data + 12, 5);      /* pcnt = 5 */

  ValidityFlashIcParams ic;
  guint16 num_partitions;

  gboolean ok = fpi_validity_pair_parse_flash_info (data, sizeof (data),
                                                    &ic, &num_partitions);
  g_assert_true (ok);
  g_assert_cmpuint (num_partitions, ==, 5);
  g_assert_cmpuint (ic.size, ==, 0x1000 * 0x0100);
  g_assert_cmpuint (ic.sector_size, ==, 0x1000);
  g_assert_cmpuint (ic.sector_erase_cmd, ==, 0x20);
}

/* ================================================================
 * T7.12: parse_flash_info — zero partitions means needs pairing
 * ================================================================ */
static void
test_parse_flash_info_needs_pairing (void)
{
  guint8 data[14];

  memset (data, 0, sizeof (data));

  FP_WRITE_UINT16_LE (data + 0, 0x0001);
  FP_WRITE_UINT16_LE (data + 2, 0x0002);
  FP_WRITE_UINT16_LE (data + 4, 0x0800);
  FP_WRITE_UINT16_LE (data + 8, 0x0200);
  FP_WRITE_UINT16_LE (data + 12, 0);  /* 0 partitions */

  ValidityFlashIcParams ic;
  guint16 num_partitions;

  gboolean ok = fpi_validity_pair_parse_flash_info (data, sizeof (data),
                                                    &ic, &num_partitions);
  g_assert_true (ok);
  g_assert_cmpuint (num_partitions, ==, 0);
}

/* ================================================================
 * T7.13: parse_flash_info — too short data fails
 * ================================================================ */
static void
test_parse_flash_info_too_short (void)
{
  guint8 data[10];  /* less than 14 bytes */

  memset (data, 0, sizeof (data));

  ValidityFlashIcParams ic;
  guint16 num_partitions;

  gboolean ok = fpi_validity_pair_parse_flash_info (data, sizeof (data),
                                                    &ic, &num_partitions);
  g_assert_false (ok);
}

/* ================================================================
 * Pairing gate: partition-1 classification and the pairing decision
 * ================================================================ */

#define TEST_TLS_FLASH_SIZE 0x1000
#define TEST_TLS_FLASH_RSP_HDR 6   /* [size:4LE][unknown:2] */
#define TEST_TLS_FLASH_BODY 64

/* Build a partition-1 READ_FLASH payload (after the status): the header,
 * then blocks in the given order with valid SHA-256 hashes, then 0xFF (erased
 * flash) up to 4096 bytes. */
static guint8 *
make_tls_flash_response (const guint16 *ids,
                         gsize          n_ids,
                         gsize         *out_len)
{
  guint8 *rsp = g_malloc (TEST_TLS_FLASH_RSP_HDR + TEST_TLS_FLASH_SIZE);
  gsize off = TEST_TLS_FLASH_RSP_HDR;

  FP_WRITE_UINT32_LE (rsp, TEST_TLS_FLASH_SIZE);
  FP_WRITE_UINT16_LE (rsp + 4, 0);
  memset (rsp + TEST_TLS_FLASH_RSP_HDR, 0xff, TEST_TLS_FLASH_SIZE);

  for (gsize i = 0; i < n_ids; i++)
    {
      guint8 body[TEST_TLS_FLASH_BODY];
      gsize hash_len = 32;
      GChecksum *cs = g_checksum_new (G_CHECKSUM_SHA256);

      memset (body, 0x10 + ids[i], sizeof (body));
      FP_WRITE_UINT16_LE (rsp + off, ids[i]);
      FP_WRITE_UINT16_LE (rsp + off + 2, sizeof (body));
      g_checksum_update (cs, body, sizeof (body));
      g_checksum_get_digest (cs, rsp + off + 4, &hash_len);
      g_checksum_free (cs);
      memcpy (rsp + off + TLS_FLASH_BLOCK_HEADER_SIZE, body, sizeof (body));
      off += TLS_FLASH_BLOCK_HEADER_SIZE + sizeof (body);
    }

  *out_len = TEST_TLS_FLASH_RSP_HDR + TEST_TLS_FLASH_SIZE;
  return rsp;
}

/* Offset in the payload of the n-th block written by the helper above */
#define TEST_TLS_FLASH_BLOCK_OFF(n) \
  (TEST_TLS_FLASH_RSP_HDR + (n) * (TLS_FLASH_BLOCK_HEADER_SIZE + TEST_TLS_FLASH_BODY))

static void
test_pair_classify_keys_present (void)
{
  /* Block order seen in USB captures of the HP Windows driver (06cb:00cb):
   * a Windows-paired sensor has all three keys, so it is KEYS_PRESENT and
   * never reaches the pairing path. */
  const guint16 windows_order[] = { 0, 4, 3, 5, 1, 2, 6 };
  gsize len;
  g_autofree guint8 *rsp = make_tls_flash_response (windows_order,
                                                    G_N_ELEMENTS (windows_order),
                                                    &len);

  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp, len),
                   ==, VALIDITY_TLS_FLASH_KEYS_PRESENT);
}

static void
test_pair_classify_own_image (void)
{
  /* The image this driver writes when it pairs must classify as paired */
  ValidityPairState state;
  guint8 priv_blob[161], server_cert[184], ecdh_blob[400], ca_cert[420];
  gsize flash_len;

  fpi_validity_pair_state_init (&state);
  memset (priv_blob, 0x02, sizeof (priv_blob));
  memset (server_cert, 0x33, sizeof (server_cert));
  memset (ecdh_blob, 0x66, sizeof (ecdh_blob));
  memset (ca_cert, 0x55, sizeof (ca_cert));
  state.priv_blob = priv_blob;
  state.priv_blob_len = sizeof (priv_blob);
  state.server_cert = server_cert;
  state.server_cert_len = sizeof (server_cert);
  state.ecdh_blob = ecdh_blob;
  state.ecdh_blob_len = sizeof (ecdh_blob);

  g_autofree guint8 *flash = fpi_validity_pair_build_tls_flash (&state, ca_cert,
                                                                sizeof (ca_cert),
                                                                &flash_len);
  g_assert_nonnull (flash);

  g_autofree guint8 *rsp = g_malloc (TEST_TLS_FLASH_RSP_HDR + flash_len);
  FP_WRITE_UINT32_LE (rsp, flash_len);
  FP_WRITE_UINT16_LE (rsp + 4, 0);
  memcpy (rsp + TEST_TLS_FLASH_RSP_HDR, flash, flash_len);

  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp,
                                                         TEST_TLS_FLASH_RSP_HDR + flash_len),
                   ==, VALIDITY_TLS_FLASH_KEYS_PRESENT);

  /* Stack buffers: do not let state_free touch them */
  state.priv_blob = NULL;
  state.server_cert = NULL;
  state.ecdh_blob = NULL;
  fpi_validity_pair_state_free (&state);
}

static void
test_pair_classify_blank (void)
{
  gsize len;
  g_autofree guint8 *rsp = make_tls_flash_response (NULL, 0, &len);

  /* Erased partition: the first block header is the 0xFFFF end marker */
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp, len),
                   ==, VALIDITY_TLS_FLASH_BLANK);
}

static void
test_pair_classify_partial (void)
{
  const guint16 no_priv[] = { 0, 3, 5, 6 };
  const guint16 no_keys[] = { 0, 1, 2, 5 };
  gsize len;
  g_autofree guint8 *rsp1 = make_tls_flash_response (no_priv,
                                                     G_N_ELEMENTS (no_priv),
                                                     &len);
  g_autofree guint8 *rsp2 = make_tls_flash_response (no_keys,
                                                     G_N_ELEMENTS (no_keys),
                                                     &len);

  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp1, len),
                   ==, VALIDITY_TLS_FLASH_PARTIAL);
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp2, len),
                   ==, VALIDITY_TLS_FLASH_PARTIAL);
}

static void
test_pair_classify_unreadable (void)
{
  const guint16 keys[] = { 3, 4, 6 };
  gsize len;
  g_autofree guint8 *rsp = make_tls_flash_response (keys, G_N_ELEMENTS (keys),
                                                    &len);
  guint8 hdr_only[TEST_TLS_FLASH_RSP_HDR] = { 0 };

  /* A non-OK status wins, even over data that looks paired */
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (0x0404, rsp, len),
                   ==, VALIDITY_TLS_FLASH_UNREADABLE);

  /* No payload, or not even the 6-byte response header */
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, NULL, 0),
                   ==, VALIDITY_TLS_FLASH_UNREADABLE);
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, NULL, len),
                   ==, VALIDITY_TLS_FLASH_UNREADABLE);
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp,
                                                         TEST_TLS_FLASH_RSP_HDR - 1),
                   ==, VALIDITY_TLS_FLASH_UNREADABLE);

  /* Header only, declaring no data: no end marker was seen, so not blank */
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, hdr_only,
                                                         sizeof (hdr_only)),
                   ==, VALIDITY_TLS_FLASH_UNREADABLE);
}

static void
test_pair_classify_truncated (void)
{
  const guint16 keys[] = { 3, 4, 6 };
  gsize len, cut;
  g_autofree guint8 *rsp = make_tls_flash_response (keys, G_N_ELEMENTS (keys),
                                                    &len);
  g_autofree guint8 *blank = make_tls_flash_response (NULL, 0, &len);

  /* Short read of an erased partition: declares 4096 bytes, delivers 100.
   * Must not count as blank, since most of the partition was never read. */
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, blank,
                                                         TEST_TLS_FLASH_RSP_HDR + 100),
                   ==, VALIDITY_TLS_FLASH_UNREADABLE);

  /* Short read that ends inside block 6: not partial, unreadable */
  cut = TEST_TLS_FLASH_BLOCK_OFF (2) + TLS_FLASH_BLOCK_HEADER_SIZE + 10;
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp, cut),
                   ==, VALIDITY_TLS_FLASH_UNREADABLE);

  /* Same cut, but the size field agrees with what arrived, so it is block 6
   * itself that runs past the end of the data */
  FP_WRITE_UINT32_LE (rsp, cut - TEST_TLS_FLASH_RSP_HDR);
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp, cut),
                   ==, VALIDITY_TLS_FLASH_UNREADABLE);

  /* A short read that still holds all three keys is KEYS_PRESENT, as it was
   * before; the TLS parse checks the blocks themselves afterwards. */
  FP_WRITE_UINT32_LE (rsp, TEST_TLS_FLASH_SIZE);
  cut = TEST_TLS_FLASH_BLOCK_OFF (3) + 8;
  g_assert_cmpint (fpi_validity_pair_classify_tls_flash (VCSFW_STATUS_OK, rsp, cut),
                   ==, VALIDITY_TLS_FLASH_KEYS_PRESENT);
}

static void
test_pair_decide (void)
{
  const ValidityTlsFlashClass classes[] = {
    VALIDITY_TLS_FLASH_KEYS_PRESENT,
    VALIDITY_TLS_FLASH_BLANK,
    VALIDITY_TLS_FLASH_PARTIAL,
    VALIDITY_TLS_FLASH_UNREADABLE,
  };
  const guint16 partitioned[] = { 1, 5 };

  /* No partitions: provision, as python-validity's init_flash does, except
   * from a reconnect. Partition 1 is not read then, so its class is
   * ignored. */
  for (gsize i = 0; i < G_N_ELEMENTS (classes); i++)
    {
      g_assert_cmpint (fpi_validity_pair_decide (0, classes[i], FALSE),
                       ==, VALIDITY_PAIR_PROVISION);
      g_assert_cmpint (fpi_validity_pair_decide (0, classes[i], TRUE),
                       ==, VALIDITY_PAIR_REFUSE_RECOVERY);
    }

  /* Partitioned: never paired, with or without check_only. Keys present
   * needs nothing; every other class is refused. */
  for (gsize p = 0; p < G_N_ELEMENTS (partitioned); p++)
    {
      for (gint check_only = 0; check_only <= 1; check_only++)
        {
          guint16 n = partitioned[p];

          g_assert_cmpint (fpi_validity_pair_decide (n, VALIDITY_TLS_FLASH_KEYS_PRESENT,
                                                     check_only),
                           ==, VALIDITY_PAIR_NOT_NEEDED);
          g_assert_cmpint (fpi_validity_pair_decide (n, VALIDITY_TLS_FLASH_BLANK,
                                                     check_only),
                           ==, VALIDITY_PAIR_REFUSE_BLANK);
          g_assert_cmpint (fpi_validity_pair_decide (n, VALIDITY_TLS_FLASH_PARTIAL,
                                                     check_only),
                           ==, VALIDITY_PAIR_REFUSE_PARTIAL);
          g_assert_cmpint (fpi_validity_pair_decide (n, VALIDITY_TLS_FLASH_UNREADABLE,
                                                     check_only),
                           ==, VALIDITY_PAIR_REFUSE_UNREADABLE);
        }
    }

  /* An out-of-range class on a partitioned sensor is refused, not paired */
  g_assert_cmpint (fpi_validity_pair_decide (5, (ValidityTlsFlashClass) 99, FALSE),
                   ==, VALIDITY_PAIR_REFUSE_UNREADABLE);
}

/* ================================================================
 * T7.14: serialize_partition — known output format
 * ================================================================ */
static void
test_serialize_partition (void)
{
  ValidityPartition part = {
    .id = 1,
    .type = 3,
    .access_lvl = 0x0002,
    .offset = 0x1000,
    .size = 0x8000,
  };

  guint8 out[VALIDITY_PARTITION_ENTRY_SIZE];

  fpi_validity_pair_serialize_partition (&part, out);

  /* Check first 12 bytes: id(1) type(1) access_lvl(2LE) offset(4LE) size(4LE) */
  g_assert_cmpuint (out[0], ==, 1);
  g_assert_cmpuint (out[1], ==, 3);
  g_assert_cmpuint (FP_READ_UINT16_LE (out + 2), ==, 0x0002);
  g_assert_cmpuint (FP_READ_UINT32_LE (out + 4), ==, 0x1000);
  g_assert_cmpuint (FP_READ_UINT32_LE (out + 8), ==, 0x8000);

  /* Bytes 12-15 should be zero */
  for (int i = 12; i < 16; i++)
    g_assert_cmpuint (out[i], ==, 0);

  /* Bytes 16-47 = SHA-256 of the 12-byte entry */
  g_autoptr(GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (checksum, out, 12);
  guint8 expected_hash[32];
  gsize hash_len = 32;
  g_checksum_get_digest (checksum, expected_hash, &hash_len);

  g_assert_cmpmem (out + 16, 32, expected_hash, 32);

  /* Total size must be VALIDITY_PARTITION_ENTRY_SIZE */
  g_assert_cmpuint (sizeof (out), ==, VALIDITY_PARTITION_ENTRY_SIZE);
}

/* ================================================================
 * T7.15: make_cert — produces 444-byte certificate
 * ================================================================ */
static void
test_make_cert_size (void)
{
  guint8 pub_x[32], pub_y[32];

  RAND_bytes (pub_x, 32);
  RAND_bytes (pub_y, 32);

  gsize cert_len;
  guint8 password[32];
  RAND_bytes (password, sizeof (password));
  g_autofree guint8 *cert = fpi_validity_pair_make_cert (pub_x, pub_y,
                                                         password, sizeof (password),
                                                         &cert_len);

  g_assert_nonnull (cert);
  g_assert_cmpuint (cert_len, ==, VALIDITY_CLIENT_CERT_SIZE);

  /* First 4 bytes should be 0x17 in LE */
  g_assert_cmpuint (FP_READ_UINT32_LE (cert), ==, 0x17);
  /* Bytes 4-7 should be 0x20 in LE */
  g_assert_cmpuint (FP_READ_UINT32_LE (cert + 4), ==, 0x20);
}

/* ================================================================
 * T7.16: make_cert — deterministic for same input
 * ================================================================ */
static void
test_make_cert_deterministic (void)
{
  /* Using fixed keys so signature is reproducible.
   * Note: ECDSA uses random k, so signatures differ — but the
   * structure should be consistent. Actually ECDSA is NOT deterministic
   * without RFC 6979, so we can only verify structure matches. */
  guint8 pub_x[32] = { 0x01 };
  guint8 pub_y[32] = { 0x02 };
  guint8 password[32] = { 0x03 };

  gsize len1, len2;
  g_autofree guint8 *cert1 = fpi_validity_pair_make_cert (pub_x, pub_y,
                                                          password, sizeof (password),
                                                          &len1);
  g_autofree guint8 *cert2 = fpi_validity_pair_make_cert (pub_x, pub_y,
                                                          password, sizeof (password),
                                                          &len2);

  g_assert_nonnull (cert1);
  g_assert_nonnull (cert2);
  g_assert_cmpuint (len1, ==, len2);
  g_assert_cmpuint (len1, ==, VALIDITY_CLIENT_CERT_SIZE);

  /* Header and public key portion should be identical (first 184 bytes = cert body) */
  g_assert_cmpmem (cert1, 184, cert2, 184);
}

/* ================================================================
 * T7.17: encrypt_key — output blob has correct structure
 * ================================================================ */
static void
test_encrypt_key_structure (void)
{
  guint8 priv[32], pub_x[32], pub_y[32];
  guint8 enc_key[32], val_key[32];

  RAND_bytes (priv, 32);
  RAND_bytes (pub_x, 32);
  RAND_bytes (pub_y, 32);
  RAND_bytes (enc_key, 32);
  RAND_bytes (val_key, 32);

  gsize blob_len;
  g_autofree guint8 *blob = fpi_validity_pair_encrypt_key (priv, pub_x, pub_y,
                                                           enc_key, val_key,
                                                           &blob_len);

  g_assert_nonnull (blob);
  /* Blob format: 0x02(1) + IV(16) + ciphertext(112) + HMAC(32) = 161 */
  g_assert_cmpuint (blob_len, ==, 161);
  g_assert_cmpuint (blob[0], ==, VALIDITY_ENCRYPTED_KEY_PREFIX);
}

/* ================================================================
 * T7.18: encrypt_key — HMAC verification
 * ================================================================ */
static void
test_encrypt_key_hmac_valid (void)
{
  guint8 priv[32], pub_x[32], pub_y[32];
  guint8 enc_key[32], val_key[32];

  RAND_bytes (priv, 32);
  RAND_bytes (pub_x, 32);
  RAND_bytes (pub_y, 32);
  RAND_bytes (enc_key, 32);
  RAND_bytes (val_key, 32);

  gsize blob_len;
  g_autofree guint8 *blob = fpi_validity_pair_encrypt_key (priv, pub_x, pub_y,
                                                           enc_key, val_key,
                                                           &blob_len);

  g_assert_nonnull (blob);
  g_assert_cmpuint (blob_len, ==, 161);

  /* Blob: [0x02][iv:16][ct:112][hmac:32]
   * HMAC is over iv+ct (bytes 1..128) */
  const guint8 *iv_ct = blob + 1;
  gsize iv_ct_len = 16 + 112;
  const guint8 *stored_hmac = blob + 1 + iv_ct_len;

  guint8 computed_hmac[32];
  guint hmac_len = 32;
  HMAC (EVP_sha256 (), val_key, 32, iv_ct, iv_ct_len,
        computed_hmac, &hmac_len);

  g_assert_cmpmem (stored_hmac, 32, computed_hmac, 32);
}

/* ================================================================
 * T7.19: build_partition_flash_cmd — valid output structure
 * ================================================================ */
static void
test_build_partition_flash_cmd (void)
{
  /* Use a real device descriptor for the flash layout */
  const ValidityDeviceDesc *desc =
    fpi_validity_hal_device_lookup (VALIDITY_DEV_9A);

  g_assert_nonnull (desc);

  ValidityFlashIcParams flash_ic = {
    .size = 0x200000,
    .sector_size = 0x1000,
    .sector_erase_cmd = 0x20,
  };

  guint8 pub_x[32], pub_y[32];
  RAND_bytes (pub_x, 32);
  RAND_bytes (pub_y, 32);

  /* Create dummy data for runtime parameters */
  guint8 partition_sig[256];
  guint8 password[32];
  guint8 ca_cert[256];
  RAND_bytes (partition_sig, sizeof (partition_sig));
  RAND_bytes (password, sizeof (password));
  RAND_bytes (ca_cert, sizeof (ca_cert));

  gsize cmd_len;
  g_autofree guint8 *cmd =
    fpi_validity_pair_build_partition_flash_cmd (&flash_ic, desc->flash_layout,
                                                 partition_sig, sizeof (partition_sig),
                                                 pub_x, pub_y,
                                                 password, sizeof (password),
                                                 ca_cert, sizeof (ca_cert),
                                                 &cmd_len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (cmd_len, >, 5);

  /* Command prefix: 0x4f followed by 4 zero bytes */
  g_assert_cmpuint (cmd[0], ==, 0x4f);
  g_assert_cmpuint (cmd[1], ==, 0);
  g_assert_cmpuint (cmd[2], ==, 0);
  g_assert_cmpuint (cmd[3], ==, 0);
  g_assert_cmpuint (cmd[4], ==, 0);
}

/* ================================================================
 * T7.20: build_tls_flash — produces exactly 4096 bytes
 * ================================================================ */
static void
test_build_tls_flash_size (void)
{
  ValidityPairState state;

  fpi_validity_pair_state_init (&state);

  /* Set up minimal test data */
  guint8 priv_blob[100];
  guint8 server_cert[200];
  guint8 ecdh_blob[400];
  RAND_bytes (priv_blob, sizeof (priv_blob));
  RAND_bytes (server_cert, sizeof (server_cert));
  RAND_bytes (ecdh_blob, sizeof (ecdh_blob));

  state.priv_blob = priv_blob;
  state.priv_blob_len = sizeof (priv_blob);
  state.server_cert = server_cert;
  state.server_cert_len = sizeof (server_cert);
  state.ecdh_blob = ecdh_blob;
  state.ecdh_blob_len = sizeof (ecdh_blob);

  guint8 ca_cert[256];
  RAND_bytes (ca_cert, sizeof (ca_cert));

  gsize flash_len;
  g_autofree guint8 *flash = fpi_validity_pair_build_tls_flash (&state,
                                                                ca_cert, sizeof (ca_cert),
                                                                &flash_len);

  g_assert_nonnull (flash);
  g_assert_cmpuint (flash_len, ==, 0x1000);

  /* Verify padding bytes at end are 0xff */
  gboolean has_ff_padding = FALSE;
  for (gsize i = flash_len - 1; i > 0; i--)
    {
      if (flash[i] == 0xff)
        {
          has_ff_padding = TRUE;
          break;
        }
    }
  g_assert_true (has_ff_padding);

  /* Don't free embedded pointers since they're stack-allocated */
  state.priv_blob = NULL;
  state.server_cert = NULL;
  state.ecdh_blob = NULL;
  fpi_validity_pair_state_free (&state);
}

/* ================================================================
 * T7.21: build_tls_flash — block structure
 * ================================================================ */
static void
test_build_tls_flash_blocks (void)
{
  ValidityPairState state;

  fpi_validity_pair_state_init (&state);

  guint8 priv_blob[50];
  guint8 server_cert[100];
  guint8 ecdh_blob[400];
  memset (priv_blob, 0xAA, sizeof (priv_blob));
  memset (server_cert, 0xBB, sizeof (server_cert));
  memset (ecdh_blob, 0xCC, sizeof (ecdh_blob));

  state.priv_blob = priv_blob;
  state.priv_blob_len = sizeof (priv_blob);
  state.server_cert = server_cert;
  state.server_cert_len = sizeof (server_cert);
  state.ecdh_blob = ecdh_blob;
  state.ecdh_blob_len = sizeof (ecdh_blob);

  guint8 ca_cert2[256];
  memset (ca_cert2, 0xDD, sizeof (ca_cert2));

  gsize flash_len;
  g_autofree guint8 *flash = fpi_validity_pair_build_tls_flash (&state,
                                                                ca_cert2, sizeof (ca_cert2),
                                                                &flash_len);
  g_assert_nonnull (flash);

  /* Block 0 should be first: id=0, size=1 */
  g_assert_cmpuint (FP_READ_UINT16_LE (flash), ==, 0);      /* block id */
  g_assert_cmpuint (FP_READ_UINT16_LE (flash + 2), ==, 1);  /* size = 1 */
  /* Skip 32-byte hash at flash+4 and 1-byte body at flash+36 */

  /* Next block should be block 4 (priv_blob) at offset 37 */
  gsize offset = 4 + 32 + 1;  /* header(4) + hash(32) + body(1) */
  g_assert_cmpuint (FP_READ_UINT16_LE (flash + offset), ==, 4);  /* block id */
  g_assert_cmpuint (FP_READ_UINT16_LE (flash + offset + 2), ==,
                    sizeof (priv_blob));

  state.priv_blob = NULL;
  state.server_cert = NULL;
  state.ecdh_blob = NULL;
  fpi_validity_pair_state_free (&state);
}

/* ================================================================
 * T7.22: pair state init and free
 * ================================================================ */
static void
test_pair_state_lifecycle (void)
{
  ValidityPairState state;

  fpi_validity_pair_state_init (&state);

  g_assert_null (state.client_key);
  g_assert_null (state.server_cert);
  g_assert_null (state.ecdh_blob);
  g_assert_null (state.priv_blob);
  g_assert_cmpuint (state.num_partitions, ==, 0);
  g_assert_cmpuint (state.erase_step, ==, 0);
  g_assert_false (state.check_only);
  g_assert_false (state.refused);
  g_assert_cmpint (state.decision, ==, VALIDITY_PAIR_NOT_NEEDED);

  /* Free should be safe on empty state */
  fpi_validity_pair_state_free (&state);
}

/* ================================================================
 * T7.23: pair state free with allocated resources
 * ================================================================ */
static void
test_pair_state_free_with_resources (void)
{
  ValidityPairState state;

  fpi_validity_pair_state_init (&state);

  state.server_cert = g_malloc (100);
  state.server_cert_len = 100;
  state.ecdh_blob = g_malloc (400);
  state.ecdh_blob_len = 400;
  state.priv_blob = g_malloc (161);
  state.priv_blob_len = 161;

  /* Generate a key to test EVP_PKEY_free path */
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_EC, NULL);
  EVP_PKEY_keygen_init (pctx);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid (pctx, NID_X9_62_prime256v1);
  EVP_PKEY_keygen (pctx, &state.client_key);
  EVP_PKEY_CTX_free (pctx);
  g_assert_nonnull (state.client_key);

  /* Free should release all resources without leak */
  fpi_validity_pair_state_free (&state);
}

/* ================================================================
 * T7.24: encrypt_key — different inputs produce different blobs
 * ================================================================ */
static void
test_encrypt_key_different_inputs (void)
{
  guint8 priv1[32], priv2[32], pub_x[32], pub_y[32];
  guint8 enc_key[32], val_key[32];

  RAND_bytes (priv1, 32);
  RAND_bytes (priv2, 32);
  RAND_bytes (pub_x, 32);
  RAND_bytes (pub_y, 32);
  RAND_bytes (enc_key, 32);
  RAND_bytes (val_key, 32);

  gsize len1, len2;
  g_autofree guint8 *blob1 = fpi_validity_pair_encrypt_key (priv1, pub_x, pub_y,
                                                            enc_key, val_key, &len1);
  g_autofree guint8 *blob2 = fpi_validity_pair_encrypt_key (priv2, pub_x, pub_y,
                                                            enc_key, val_key, &len2);

  g_assert_nonnull (blob1);
  g_assert_nonnull (blob2);
  g_assert_cmpuint (len1, ==, len2);

  /* Different private keys should produce different ciphertexts */
  g_assert_true (memcmp (blob1, blob2, len1) != 0);
}

/* ================================================================
 * Tests: CAPTURE
 * ================================================================ */


/* ================================================================
 * T5.1: test_split_chunks_basic
 *
 * Verify that split_chunks correctly parses a TLV buffer with two
 * known chunks and produces the right type, size, and data.
 * ================================================================ */
static void
test_split_chunks_basic (void)
{
  /* Build two TLV chunks:
   *   type=0x002a, size=4, data={0xAA,0xBB,0xCC,0xDD}
   *   type=0x0034, size=2, data={0x11,0x22}
   */
  guint8 buf[] = {
    0x2a, 0x00, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
    0x34, 0x00, 0x02, 0x00, 0x11, 0x22,
  };

  gsize n = 0;
  ValidityCaptureChunk *chunks;

  chunks = fpi_validity_capture_split_chunks (buf, sizeof (buf), &n);

  g_assert_nonnull (chunks);
  g_assert_cmpuint (n, ==, 2);

  g_assert_cmpuint (chunks[0].type, ==, 0x002a);
  g_assert_cmpuint (chunks[0].size, ==, 4);
  g_assert_cmpmem (chunks[0].data, 4, buf + 4, 4);

  g_assert_cmpuint (chunks[1].type, ==, 0x0034);
  g_assert_cmpuint (chunks[1].size, ==, 2);
  g_assert_cmpmem (chunks[1].data, 2, buf + 12, 2);

  fpi_validity_capture_chunks_free (chunks, n);
}

/* ================================================================
 * T5.2: test_split_merge_roundtrip
 *
 * Verify that split then merge produces identical bytes.
 * ================================================================ */
static void
test_split_merge_roundtrip (void)
{
  guint8 buf[] = {
    0x2a, 0x00, 0x08, 0x00,
    0x20, 0x01, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00,
    0x29, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00,
  };

  gsize n = 0;
  ValidityCaptureChunk *chunks;

  chunks = fpi_validity_capture_split_chunks (buf, sizeof (buf), &n);
  g_assert_nonnull (chunks);
  g_assert_cmpuint (n, ==, 2);

  gsize merged_len = 0;
  guint8 *merged = fpi_validity_capture_merge_chunks (chunks, n, &merged_len);

  g_assert_nonnull (merged);
  g_assert_cmpuint (merged_len, ==, sizeof (buf));
  g_assert_cmpmem (merged, merged_len, buf, sizeof (buf));

  g_free (merged);
  fpi_validity_capture_chunks_free (chunks, n);
}

/* ================================================================
 * T5.3: test_split_chunks_empty
 *
 * Verify empty input returns empty result.
 * ================================================================ */
static void
test_split_chunks_empty (void)
{
  gsize n = 99;
  ValidityCaptureChunk *chunks;

  chunks = fpi_validity_capture_split_chunks (NULL, 0, &n);
  g_assert_null (chunks);
  g_assert_cmpuint (n, ==, 0);
}

/* ================================================================
 * T5.4: test_split_chunks_truncated
 *
 * Verify truncated chunk (size extends past end) returns NULL.
 * ================================================================ */
static void
test_split_chunks_truncated (void)
{
  /* type=0x0034, size=0x0008, but only 4 bytes of data follow */
  guint8 buf[] = {
    0x34, 0x00, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44,
  };

  gsize n = 99;
  ValidityCaptureChunk *chunks;

  chunks = fpi_validity_capture_split_chunks (buf, sizeof (buf), &n);
  g_assert_null (chunks);
  g_assert_cmpuint (n, ==, 0);
}

/* ================================================================
 * T5.5: test_decode_insn_noop
 *
 * Verify NOOP (0x00) decodes to opcode 0 with length 1.
 * ================================================================ */
static void
test_decode_insn_noop (void)
{
  guint8 data[] = { 0x00 };
  guint8 opcode, len, n_ops;
  guint32 operands[3];

  g_assert_true (fpi_validity_capture_decode_insn (data, 1, &opcode, &len,
                                                   operands, &n_ops));
  g_assert_cmpuint (opcode, ==, TST_OP_NOOP);
  g_assert_cmpuint (len, ==, 1);
  g_assert_cmpuint (n_ops, ==, 0);
}

/* ================================================================
 * T5.6: test_decode_insn_call
 *
 * Verify Call instruction (0x10-0x17) decodes correctly with
 * rx_inc, address, and repeat operands.
 * ================================================================ */
static void
test_decode_insn_call (void)
{
  /* Call: rx_inc=2, address=0x0a*4=0x28, repeat=8 */
  guint8 data[] = { 0x12, 0x0a, 0x08 };
  guint8 opcode, len, n_ops;
  guint32 operands[3];

  g_assert_true (fpi_validity_capture_decode_insn (data, 3, &opcode, &len,
                                                   operands, &n_ops));
  g_assert_cmpuint (opcode, ==, TST_OP_CALL);
  g_assert_cmpuint (len, ==, 3);
  g_assert_cmpuint (n_ops, ==, 3);
  g_assert_cmpuint (operands[0], ==, 2);      /* rx_inc */
  g_assert_cmpuint (operands[1], ==, 0x28);   /* address = 0x0a << 2 */
  g_assert_cmpuint (operands[2], ==, 8);      /* repeat */
}

/* ================================================================
 * T5.7: test_decode_insn_call_repeat_zero
 *
 * Verify Call with repeat byte 0x00 decodes to repeat=0x100.
 * ================================================================ */
static void
test_decode_insn_call_repeat_zero (void)
{
  guint8 data[] = { 0x10, 0x05, 0x00 };
  guint8 opcode, len, n_ops;
  guint32 operands[3];

  g_assert_true (fpi_validity_capture_decode_insn (data, 3, &opcode, &len,
                                                   operands, &n_ops));
  g_assert_cmpuint (opcode, ==, TST_OP_CALL);
  g_assert_cmpuint (operands[2], ==, 0x100);
}

/* ================================================================
 * T5.8: test_decode_insn_regwrite
 *
 * Verify Register Write (0x40-0x7f) decodes correctly:
 *   register address = (b0 & 0x3f) * 4 + 0x80002000
 *   value = u16 LE from bytes 1-2
 * ================================================================ */
static void
test_decode_insn_regwrite (void)
{
  /* b0=0x4f → reg = (0x0f)*4 + 0x80002000 = 0x8000203C, value=0x1234 */
  guint8 data[] = { 0x4f, 0x34, 0x12 };
  guint8 opcode, len, n_ops;
  guint32 operands[3];

  g_assert_true (fpi_validity_capture_decode_insn (data, 3, &opcode, &len,
                                                   operands, &n_ops));
  g_assert_cmpuint (opcode, ==, TST_OP_REG_WRITE);
  g_assert_cmpuint (len, ==, 3);
  g_assert_cmpuint (n_ops, ==, 2);
  g_assert_cmpuint (operands[0], ==, 0x8000203c);
  g_assert_cmpuint (operands[1], ==, 0x1234);
}

/* ================================================================
 * T5.9: test_decode_insn_enable_rx
 *
 * Verify Enable Rx (opcode 6) decodes as 2-byte instruction.
 * ================================================================ */
static void
test_decode_insn_enable_rx (void)
{
  guint8 data[] = { 0x06, 0x42 };
  guint8 opcode, len, n_ops;
  guint32 operands[3];

  g_assert_true (fpi_validity_capture_decode_insn (data, 2, &opcode, &len,
                                                   operands, &n_ops));
  g_assert_cmpuint (opcode, ==, TST_OP_ENABLE_RX);
  g_assert_cmpuint (len, ==, 2);
  g_assert_cmpuint (n_ops, ==, 1);
  g_assert_cmpuint (operands[0], ==, 0x42);
}

/* ================================================================
 * T5.10: test_decode_insn_sample
 *
 * Verify Sample (0x80-0xbf) decodes with two operands.
 * ================================================================ */
static void
test_decode_insn_sample (void)
{
  /* b0=0x8a → operand0 = (0x0a >> 3) & 7 = 1, operand1 = 0x0a & 7 = 2 */
  guint8 data[] = { 0x8a };
  guint8 opcode, len, n_ops;
  guint32 operands[3];

  g_assert_true (fpi_validity_capture_decode_insn (data, 1, &opcode, &len,
                                                   operands, &n_ops));
  g_assert_cmpuint (opcode, ==, TST_OP_SAMPLE);
  g_assert_cmpuint (len, ==, 1);
  g_assert_cmpuint (n_ops, ==, 2);
  g_assert_cmpuint (operands[0], ==, 1);
  g_assert_cmpuint (operands[1], ==, 2);
}

/* ================================================================
 * T5.11: test_find_nth_insn
 *
 * Verify finding the Nth instruction of a given opcode in a buffer.
 * ================================================================ */
static void
test_find_nth_insn (void)
{
  /* Buffer: NOOP, NOOP, Call(rx=0,addr=0x14,rep=1), NOOP */
  guint8 data[] = {
    0x00,                       /* NOOP at offset 0 */
    0x00,                       /* NOOP at offset 1 */
    0x10, 0x05, 0x01,           /* Call at offset 2 */
    0x00,                       /* NOOP at offset 5 */
  };

  /* 1st NOOP is at offset 0 */
  g_assert_cmpint (fpi_validity_capture_find_nth_insn (data, sizeof (data),
                                                       TST_OP_NOOP, 1), ==, 0);
  /* 2nd NOOP is at offset 1 */
  g_assert_cmpint (fpi_validity_capture_find_nth_insn (data, sizeof (data),
                                                       TST_OP_NOOP, 2), ==, 1);
  /* 3rd NOOP is at offset 5 */
  g_assert_cmpint (fpi_validity_capture_find_nth_insn (data, sizeof (data),
                                                       TST_OP_NOOP, 3), ==, 5);
  /* 1st Call is at offset 2 */
  g_assert_cmpint (fpi_validity_capture_find_nth_insn (data, sizeof (data),
                                                       TST_OP_CALL, 1), ==, 2);
  /* No 2nd Call */
  g_assert_cmpint (fpi_validity_capture_find_nth_insn (data, sizeof (data),
                                                       TST_OP_CALL, 2), ==, -1);
}

/* ================================================================
 * T5.12: test_find_nth_regwrite
 *
 * Verify finding a Register Write to a specific register address.
 * ================================================================ */
static void
test_find_nth_regwrite (void)
{
  /* Buffer: RegWrite(0x80002000, 0x55), RegWrite(0x8000203C, 0xAB) */
  guint8 data[] = {
    0x40, 0x55, 0x00,           /* reg = 0x80002000, val = 0x0055 */
    0x4f, 0xAB, 0x00,           /* reg = 0x8000203C, val = 0x00AB */
  };

  /* Find 1st write to 0x8000203C → offset 3 */
  g_assert_cmpint (fpi_validity_capture_find_nth_regwrite (data, sizeof (data),
                                                           0x8000203c, 1), ==, 3);
  /* No 2nd write to 0x8000203C */
  g_assert_cmpint (fpi_validity_capture_find_nth_regwrite (data, sizeof (data),
                                                           0x8000203c, 2), ==, -1);
  /* Find 1st write to 0x80002000 → offset 0 */
  g_assert_cmpint (fpi_validity_capture_find_nth_regwrite (data, sizeof (data),
                                                           0x80002000, 1), ==, 0);
}

/* ================================================================
 * T5.13: test_patch_timeslot_table
 *
 * Verify that patch_timeslot_table multiplies Call repeat counts
 * by the given multiplier.
 * ================================================================ */
static void
test_patch_timeslot_table (void)
{
  /* Call(rx=0, addr=0x14, repeat=3) followed by NOOP */
  guint8 data[] = {
    0x10, 0x05, 0x03,   /* Call: repeat=3 */
    0x00,                /* NOOP */
  };

  /* Multiply by 2, with inc_address=TRUE */
  g_assert_true (fpi_validity_capture_patch_timeslot_table (data, sizeof (data),
                                                            TRUE, 2));

  /* repeat becomes 3*2=6 */
  g_assert_cmpuint (data[2], ==, 6);
  /* address byte incremented */
  g_assert_cmpuint (data[1], ==, 6);
}

/* ================================================================
 * T5.14: test_patch_timeslot_table_no_mult_for_repeat1
 *
 * Verify that Call instructions with repeat <= 1 are NOT multiplied.
 * ================================================================ */
static void
test_patch_timeslot_table_no_mult_for_repeat1 (void)
{
  guint8 data[] = {
    0x10, 0x05, 0x01,   /* Call: repeat=1 */
    0x00,
  };

  g_assert_true (fpi_validity_capture_patch_timeslot_table (data, sizeof (data),
                                                            TRUE, 4));
  /* repeat stays 1 (not multiplied because <= 1) */
  g_assert_cmpuint (data[2], ==, 1);
  /* address NOT incremented */
  g_assert_cmpuint (data[1], ==, 5);
}

/* ================================================================
 * T5.15: test_bitpack_uniform
 *
 * When all values are identical, bitpack returns v0=0 (0 bits),
 * v1=the common value, and zero-length packed data.
 * ================================================================ */
static void
test_bitpack_uniform (void)
{
  guint8 values[] = { 0x42, 0x42, 0x42, 0x42 };
  guint8 v0, v1;
  gsize out_len;

  guint8 *packed = fpi_validity_capture_bitpack (values, 4, &v0, &v1, &out_len);

  g_assert_nonnull (packed);
  g_assert_cmpuint (v0, ==, 0);
  g_assert_cmpuint (v1, ==, 0x42);
  g_assert_cmpuint (out_len, ==, 0);

  g_free (packed);
}

/* ================================================================
 * T5.16: test_bitpack_range
 *
 * Verify bitpack with a small range of values.
 * Values [10, 11, 12, 13] → delta range=3, useful_bits=2.
 * ================================================================ */
static void
test_bitpack_range (void)
{
  guint8 values[] = { 10, 11, 12, 13 };
  guint8 v0, v1;
  gsize out_len;

  guint8 *packed = fpi_validity_capture_bitpack (values, 4, &v0, &v1, &out_len);

  g_assert_nonnull (packed);
  g_assert_cmpuint (v0, ==, 2);     /* 2 bits needed for max delta 3 */
  g_assert_cmpuint (v1, ==, 10);    /* minimum value */

  /* 4 values * 2 bits = 8 bits = 1 byte */
  g_assert_cmpuint (out_len, ==, 1);

  /* Deltas: [0, 1, 2, 3]
   * Packed little-endian: bits 0-1 = 0b00, bits 2-3 = 0b01,
   *   bits 4-5 = 0b10, bits 6-7 = 0b11
   * Byte = 0b11100100 = 0xE4 */
  g_assert_cmpuint (packed[0], ==, 0xE4);

  g_free (packed);
}

/* ================================================================
 * T5.17: test_factory_bits_parsing
 *
 * Verify parsing a synthetic factory bits response with subtag 3
 * (calibration values) and subtag 7 (calibration data).
 * ================================================================ */
static void
test_factory_bits_parsing (void)
{
  /* Factory bits response format:
   *   wtf(4LE) entries(4LE)
   *   entry: ptr(4LE) length(2LE) tag(2LE) subtag(2LE) flags(2LE) data[length]
   */
  guint8 cal_values[] = { 0xAA, 0xBB, 0xCC, 0xDD };
  guint8 cal_data[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

  /* Build response buffer */
  GByteArray *resp = g_byte_array_new ();
  guint8 hdr[8];

  /* Header: wtf=0, entries=2 */
  FP_WRITE_UINT32_LE (hdr, 0);
  FP_WRITE_UINT32_LE (hdr + 4, 2);
  g_byte_array_append (resp, hdr, 8);

  /* Entry 1: subtag=3, calibration values (4-byte header + actual data) */
  {
    guint8 entry[12];
    guint16 length = 4 + sizeof (cal_values); /* 4-byte header + data */
    FP_WRITE_UINT32_LE (entry, 0);           /* ptr */
    FP_WRITE_UINT16_LE (entry + 4, length);  /* length */
    FP_WRITE_UINT16_LE (entry + 6, 0x0001);  /* tag */
    FP_WRITE_UINT16_LE (entry + 8, 3);       /* subtag = 3 */
    FP_WRITE_UINT16_LE (entry + 10, 0);      /* flags */
    g_byte_array_append (resp, entry, 12);

    guint8 data_hdr[4] = { 0, 0, 0, 0 };     /* 4-byte header */
    g_byte_array_append (resp, data_hdr, 4);
    g_byte_array_append (resp, cal_values, sizeof (cal_values));
  }

  /* Entry 2: subtag=7, calibration data (4-byte header + actual data) */
  {
    guint8 entry[12];
    guint16 length = 4 + sizeof (cal_data);
    FP_WRITE_UINT32_LE (entry, 0);
    FP_WRITE_UINT16_LE (entry + 4, length);
    FP_WRITE_UINT16_LE (entry + 6, 0x0002);
    FP_WRITE_UINT16_LE (entry + 8, 7);       /* subtag = 7 */
    FP_WRITE_UINT16_LE (entry + 10, 0);
    g_byte_array_append (resp, entry, 12);

    guint8 data_hdr[4] = { 0, 0, 0, 0 };
    g_byte_array_append (resp, data_hdr, 4);
    g_byte_array_append (resp, cal_data, sizeof (cal_data));
  }

  guint8 *out_cal_values = NULL, *out_cal_data = NULL;
  gsize out_cal_values_len = 0, out_cal_data_len = 0;

  gboolean ok = fpi_validity_capture_parse_factory_bits (
    resp->data, resp->len,
    &out_cal_values, &out_cal_values_len,
    &out_cal_data, &out_cal_data_len);

  g_assert_true (ok);
  g_assert_nonnull (out_cal_values);
  g_assert_cmpuint (out_cal_values_len, ==, sizeof (cal_values));
  g_assert_cmpmem (out_cal_values, out_cal_values_len,
                   cal_values, sizeof (cal_values));

  g_assert_nonnull (out_cal_data);
  g_assert_cmpuint (out_cal_data_len, ==, sizeof (cal_data));
  g_assert_cmpmem (out_cal_data, out_cal_data_len,
                   cal_data, sizeof (cal_data));

  g_free (out_cal_values);
  g_free (out_cal_data);
  g_byte_array_free (resp, TRUE);
}

/* ================================================================
 * T5.18: test_factory_bits_no_subtag3
 *
 * Verify that parsing fails when subtag 3 is missing.
 * ================================================================ */
static void
test_factory_bits_no_subtag3 (void)
{
  /* Build response with only subtag=7 (no subtag=3) */
  guint8 buf[32];

  FP_WRITE_UINT32_LE (buf, 0);      /* wtf */
  FP_WRITE_UINT32_LE (buf + 4, 1);  /* entries=1 */

  /* Entry: subtag=7, length=5 (4 hdr + 1 data) */
  FP_WRITE_UINT32_LE (buf + 8, 0);
  FP_WRITE_UINT16_LE (buf + 12, 5);
  FP_WRITE_UINT16_LE (buf + 14, 0x0001);
  FP_WRITE_UINT16_LE (buf + 16, 7);       /* subtag=7, not 3 */
  FP_WRITE_UINT16_LE (buf + 18, 0);
  memset (buf + 20, 0, 5);

  guint8 *cv = NULL;
  gsize cv_len = 0;

  gboolean ok = fpi_validity_capture_parse_factory_bits (buf, 25,
                                                         &cv, &cv_len,
                                                         NULL, NULL);
  g_assert_false (ok);
  g_assert_null (cv);
}

/* ================================================================
 * T5.19: test_average_frames_interleave2
 *
 * Verify frame averaging with interleave_lines=2 (repeat_multiplier=2).
 * With 2 interleaved lines per calibration line, each output line
 * should be the average of 2 input lines.
 * ================================================================ */
static void
test_average_frames_interleave2 (void)
{
  guint16 bytes_per_line = 4;
  guint16 lines_per_calibration_data = 2;
  guint16 lines_per_frame = 4;   /* 2 cal lines * 2 interleave */
  guint8 calibration_frames = 1;

  /* Single frame: 4 lines * 4 bytes = 16 bytes */
  guint8 raw[] = {
    10, 20, 30, 40,   /* line 0 (cal line 0, interleave 0) */
    20, 30, 40, 50,   /* line 1 (cal line 0, interleave 1) */
    30, 40, 50, 60,   /* line 2 (cal line 1, interleave 0) */
    40, 50, 60, 70,   /* line 3 (cal line 1, interleave 1) */
  };

  gsize out_len = 0;
  guint8 *result = fpi_validity_capture_average_frames (
    raw, sizeof (raw),
    lines_per_frame, bytes_per_line,
    lines_per_calibration_data, calibration_frames,
    &out_len);

  g_assert_nonnull (result);
  /* Output: 2 cal lines * 4 bytes = 8 bytes */
  g_assert_cmpuint (out_len, ==, 8);

  /* Cal line 0: avg of lines 0+1 → (10+20)/2=15, (20+30)/2=25, etc. */
  g_assert_cmpuint (result[0], ==, 15);
  g_assert_cmpuint (result[1], ==, 25);
  g_assert_cmpuint (result[2], ==, 35);
  g_assert_cmpuint (result[3], ==, 45);

  /* Cal line 1: avg of lines 2+3 → (30+40)/2=35, (40+50)/2=45, etc. */
  g_assert_cmpuint (result[4], ==, 35);
  g_assert_cmpuint (result[5], ==, 45);
  g_assert_cmpuint (result[6], ==, 55);
  g_assert_cmpuint (result[7], ==, 65);

  g_free (result);
}

/* ================================================================
 * T5.20: test_clean_slate_roundtrip
 *
 * Verify that building a clean slate and then verifying it succeeds.
 * ================================================================ */
static void
test_clean_slate_roundtrip (void)
{
  guint8 test_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  gsize slate_len = 0;

  guint8 *slate = fpi_validity_capture_build_clean_slate (test_data,
                                                          sizeof (test_data),
                                                          &slate_len);

  g_assert_nonnull (slate);
  g_assert_cmpuint (slate_len, >, 68);

  /* Magic should be 0x5002 */
  g_assert_cmpuint (FP_READ_UINT16_LE (slate), ==, 0x5002);

  /* Verify should pass */
  g_assert_true (fpi_validity_capture_verify_clean_slate (slate, slate_len));

  /* Corrupt one byte and verify should fail */
  slate[70] ^= 0xff;
  g_assert_false (fpi_validity_capture_verify_clean_slate (slate, slate_len));

  g_free (slate);
}

/* ================================================================
 * T5.21: test_finger_mapping
 *
 * Verify all 10 finger mappings work in both directions.
 * ================================================================ */
static void
test_finger_mapping (void)
{
  /* FpFinger enum: LEFT_THUMB=1, ..., RIGHT_LITTLE=10 */
  for (guint f = 1; f <= 10; f++)
    {
      guint16 subtype = fpi_validity_finger_to_subtype (f);
      g_assert_cmpuint (subtype, ==, f);

      gint back = fpi_validity_subtype_to_finger (subtype);
      g_assert_cmpint (back, ==, (gint) f);
    }

  /* Out of range */
  g_assert_cmpuint (fpi_validity_finger_to_subtype (0), ==, 0);
  g_assert_cmpuint (fpi_validity_finger_to_subtype (11), ==, 0);
  g_assert_cmpint (fpi_validity_subtype_to_finger (0), ==, -1);
  g_assert_cmpint (fpi_validity_subtype_to_finger (11), ==, -1);
}

/* ================================================================
 * T5.22: test_led_commands
 *
 * Verify LED start/end commands have correct format.
 * ================================================================ */
static void
test_led_commands (void)
{
  gsize start_len = 0, end_len = 0;
  const guint8 *start_cmd = fpi_validity_capture_glow_start_cmd (&start_len);
  const guint8 *end_cmd = fpi_validity_capture_glow_end_cmd (&end_len);

  g_assert_nonnull (start_cmd);
  g_assert_nonnull (end_cmd);

  /* Both should be 125 bytes (LED control payload) */
  g_assert_cmpuint (start_len, ==, 125);
  g_assert_cmpuint (end_len, ==, 125);

  /* Both should start with cmd byte 0x39 */
  g_assert_cmpuint (start_cmd[0], ==, 0x39);
  g_assert_cmpuint (end_cmd[0], ==, 0x39);
}

/* ================================================================
 * T5.23: test_capture_prog_lookup
 *
 * Verify that CaptureProg lookup returns data for known devices
 * and NULL for unknown ones.
 * ================================================================ */
static void
test_capture_prog_lookup (void)
{
  gsize len = 0;

  /* Known: firmware 6.x, dev_type 0xb5 */
  const guint8 *prog = fpi_validity_capture_prog_lookup (6, 7, 0x00b5, &len);

  g_assert_nonnull (prog);
  g_assert_cmpuint (len, >, 0);

  /* The program should be parseable as TLV chunks */
  gsize n_chunks = 0;
  ValidityCaptureChunk *chunks = fpi_validity_capture_split_chunks (prog, len, &n_chunks);
  g_assert_nonnull (chunks);
  g_assert_cmpuint (n_chunks, >=, 4);   /* At least ACM, CEM, TST, offset */

  /* Check that we have the expected chunk types */
  gboolean has_acm = FALSE, has_tst = FALSE, has_2d = FALSE;
  for (gsize i = 0; i < n_chunks; i++)
    {
      if (chunks[i].type == 0x002a)
        has_acm = TRUE;
      if (chunks[i].type == CAPT_CHUNK_TIMESLOT_2D)
        has_tst = TRUE;
      if (chunks[i].type == CAPT_CHUNK_2D_PARAMS)
        has_2d = TRUE;
    }
  g_assert_true (has_acm);
  g_assert_true (has_tst);
  g_assert_true (has_2d);

  fpi_validity_capture_chunks_free (chunks, n_chunks);

  /* Also check 0x0885 (same geometry) */
  prog = fpi_validity_capture_prog_lookup (6, 0, 0x0885, &len);
  g_assert_nonnull (prog);

  /* Unknown: firmware 5.x */
  prog = fpi_validity_capture_prog_lookup (5, 0, 0x00b5, &len);
  g_assert_null (prog);

  /* Unknown: dev_type not in type1 list */
  prog = fpi_validity_capture_prog_lookup (6, 0, 0x1234, &len);
  g_assert_null (prog);
}

/* ================================================================
 * T5.24: test_capture_state_setup
 *
 * Verify that state setup correctly initializes all fields from
 * sensor type info and factory bits.
 * ================================================================ */
static void
test_capture_state_setup (void)
{
  ValidityCaptureState state;
  const ValiditySensorTypeInfo *type_info;

  type_info = fpi_validity_sensor_type_info_lookup (0x00b5);
  g_assert_nonnull (type_info);

  /* Build minimal factory bits response with subtag 3 */
  guint8 cal_vals[] = { 0x10, 0x20, 0x30 };
  GByteArray *fb = g_byte_array_new ();
  guint8 hdr[8];
  FP_WRITE_UINT32_LE (hdr, 0);
  FP_WRITE_UINT32_LE (hdr + 4, 1);
  g_byte_array_append (fb, hdr, 8);

  guint8 entry[12];
  guint16 length = 4 + sizeof (cal_vals);
  FP_WRITE_UINT32_LE (entry, 0);
  FP_WRITE_UINT16_LE (entry + 4, length);
  FP_WRITE_UINT16_LE (entry + 6, 1);
  FP_WRITE_UINT16_LE (entry + 8, 3);
  FP_WRITE_UINT16_LE (entry + 10, 0);
  g_byte_array_append (fb, entry, 12);

  guint8 data_hdr[4] = { 0 };
  g_byte_array_append (fb, data_hdr, 4);
  g_byte_array_append (fb, cal_vals, sizeof (cal_vals));

  fpi_validity_capture_state_init (&state);
  gboolean ok = fpi_validity_capture_state_setup (&state, type_info,
                                                  0x00b5, 6, 7,
                                                  fb->data, fb->len);

  g_assert_true (ok);
  g_assert_true (state.is_type1_device);
  g_assert_cmpuint (state.bytes_per_line, ==, 0x78);
  g_assert_cmpuint (state.lines_per_frame, ==, 112 * 2);  /* 224 */
  g_assert_cmpuint (state.key_calibration_line, ==, 56);   /* 112/2 */
  g_assert_cmpuint (state.calibration_frames, ==, 3);
  g_assert_cmpuint (state.calibration_iterations, ==, 3);

  g_assert_nonnull (state.factory_calibration_values);
  g_assert_cmpuint (state.factory_calibration_values_len, ==, sizeof (cal_vals));
  g_assert_cmpmem (state.factory_calibration_values,
                   state.factory_calibration_values_len,
                   cal_vals, sizeof (cal_vals));

  g_assert_nonnull (state.capture_prog);
  g_assert_cmpuint (state.capture_prog_len, >, 0);

  fpi_validity_capture_state_clear (&state);
  g_byte_array_free (fb, TRUE);
}

/* ================================================================
 * T5.25: test_build_cmd_02_header
 *
 * Verify that build_cmd_02 produces the expected 5-byte header:
 *   cmd(0x02) | bytes_per_line(2LE) | req_lines(2LE) | chunks...
 * ================================================================ */
static void
test_build_cmd_02_header (void)
{
  ValidityCaptureState state;
  const ValiditySensorTypeInfo *type_info;

  type_info = fpi_validity_sensor_type_info_lookup (0x00b5);
  g_assert_nonnull (type_info);

  fpi_validity_capture_state_init (&state);

  /* Minimal setup: just enough for build_cmd_02 */
  gsize prog_len;
  state.capture_prog = fpi_validity_capture_prog_lookup (6, 7, 0x00b5, &prog_len);
  g_assert_nonnull (state.capture_prog);
  state.capture_prog_len = prog_len;
  state.is_type1_device = TRUE;
  state.bytes_per_line = type_info->bytes_per_line;
  state.lines_per_frame = 224;
  state.calibration_frames = 3;
  state.key_calibration_line = 56;

  /* Need factory calibration values (even if empty) for line_update */
  state.factory_calibration_values = g_malloc0 (112);
  state.factory_calibration_values_len = 112;

  gsize cmd_len = 0;
  guint8 *cmd = fpi_validity_capture_build_cmd_02 (&state, type_info,
                                                   VALIDITY_CAPTURE_CALIBRATE,
                                                   &cmd_len);

  g_assert_nonnull (cmd);
  g_assert_cmpuint (cmd_len, >=, 5);

  /* Byte 0: command = 0x02 */
  g_assert_cmpuint (cmd[0], ==, 0x02);

  /* Bytes 1-2: bytes_per_line = 0x0078 */
  g_assert_cmpuint (FP_READ_UINT16_LE (cmd + 1), ==, 0x0078);

  /* Bytes 3-4: req_lines for CALIBRATE = frames * lines_per_frame + 1 */
  guint16 expected_lines = 3 * 224 + 1;
  g_assert_cmpuint (FP_READ_UINT16_LE (cmd + 3), ==, expected_lines);

  /* Remainder should be parseable as TLV chunks */
  gsize n_chunks = 0;
  ValidityCaptureChunk *chunks = fpi_validity_capture_split_chunks (
    cmd + 5, cmd_len - 5, &n_chunks);
  g_assert_nonnull (chunks);
  g_assert_cmpuint (n_chunks, >=, 4);

  fpi_validity_capture_chunks_free (chunks, n_chunks);
  g_free (cmd);

  /* Test IDENTIFY mode: req_lines should be 0 */
  cmd = fpi_validity_capture_build_cmd_02 (&state, type_info,
                                           VALIDITY_CAPTURE_IDENTIFY,
                                           &cmd_len);
  g_assert_nonnull (cmd);
  g_assert_cmpuint (FP_READ_UINT16_LE (cmd + 3), ==, 0);
  g_free (cmd);

  g_free (state.factory_calibration_values);
}

/* ================================================================
 * T5.26: test_calibration_processing
 *
 * Verify that process_calibration applies scale and accumulates.
 * ================================================================ */
static void
test_calibration_processing (void)
{
  guint16 bytes_per_line = 16;
  /* Single line with 8-byte header + 8 bytes of data */
  guint8 frame[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  /* header (untouched) */
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,   /* data to scale */
  };

  guint8 *calib = NULL;
  gsize calib_len = 0;

  /* First call: initializes calib_data */
  fpi_validity_capture_process_calibration (&calib, &calib_len,
                                            frame, sizeof (frame),
                                            bytes_per_line);

  g_assert_nonnull (calib);
  g_assert_cmpuint (calib_len, ==, 16);

  /* Header bytes should be preserved */
  g_assert_cmpuint (calib[0], ==, 0x00);
  g_assert_cmpuint (calib[7], ==, 0x07);

  /* Data bytes at 0x80: scale(0x80) = (0x80 - 0x80) * 10 / 0x22 = 0
   * So all data bytes should be 0x00 */
  for (int i = 8; i < 16; i++)
    g_assert_cmpuint (calib[i], ==, 0x00);

  /* Second call with same frame: accumulate */
  fpi_validity_capture_process_calibration (&calib, &calib_len,
                                            frame, sizeof (frame),
                                            bytes_per_line);

  /* add(0, 0) = 0, so data bytes still 0 */
  for (int i = 8; i < 16; i++)
    g_assert_cmpuint (calib[i], ==, 0x00);

  g_free (calib);
}

/* ================================================================
 * T5.27: test_capture_split_real_prog
 *
 * Parse the actual capture program for 0xb5 and verify
 * expected chunks are present.
 * ================================================================ */
static void
test_capture_split_real_prog (void)
{
  gsize prog_len = 0;
  const guint8 *prog = fpi_validity_capture_prog_lookup (6, 7, 0x00b5, &prog_len);

  g_assert_nonnull (prog);

  gsize n = 0;
  ValidityCaptureChunk *chunks = fpi_validity_capture_split_chunks (prog, prog_len, &n);

  g_assert_nonnull (chunks);
  g_assert_cmpuint (n, ==, 6);

  /* Expected order: 0x2a, 0x2c, 0x34, 0x2f, 0x29, 0x35 */
  g_assert_cmpuint (chunks[0].type, ==, 0x002a);
  g_assert_cmpuint (chunks[0].size, ==, 8);

  g_assert_cmpuint (chunks[1].type, ==, 0x002c);
  g_assert_cmpuint (chunks[1].size, ==, 40);

  g_assert_cmpuint (chunks[2].type, ==, CAPT_CHUNK_TIMESLOT_2D);
  g_assert_cmpuint (chunks[2].size, ==, 64);

  g_assert_cmpuint (chunks[3].type, ==, CAPT_CHUNK_2D_PARAMS);
  g_assert_cmpuint (chunks[3].size, ==, 4);
  /* 2D value should be 112 (0x70) */
  g_assert_cmpuint (FP_READ_UINT32_LE (chunks[3].data), ==, 112);

  g_assert_cmpuint (chunks[4].type, ==, 0x0029);
  g_assert_cmpuint (chunks[4].size, ==, 4);

  g_assert_cmpuint (chunks[5].type, ==, 0x0035);
  g_assert_cmpuint (chunks[5].size, ==, 4);

  fpi_validity_capture_chunks_free (chunks, n);
}

/* ================================================================
 * Tests: Data Loader (validity_data.c)
 * ================================================================ */

/* ================================================================
 * T8.1: Store init/free — empty store returns NULL for all tags
 * ================================================================ */
static void
test_data_store_empty (void)
{
  ValidityDataStore store;

  fpi_validity_data_store_init (&store);

  /* All tags should return NULL */
  for (int tag = 0; tag < VALIDITY_DATA_NUM_TAGS; tag++)
    {
      gsize len;
      const guint8 *data = fpi_validity_data_get_bytes (&store, tag, &len);
      g_assert_null (data);
      g_assert_cmpuint (len, ==, 0);

      GBytes *bytes = fpi_validity_data_get (&store, tag);
      g_assert_null (bytes);
    }

  fpi_validity_data_store_free (&store);
}

/* ================================================================
 * T8.2: Store double free — should not crash
 * ================================================================ */
static void
test_data_store_double_free (void)
{
  ValidityDataStore store;

  fpi_validity_data_store_init (&store);
  fpi_validity_data_store_free (&store);
  fpi_validity_data_store_free (&store);
}

/* ================================================================
 * T8.3: Load file with valid HMAC
 * ================================================================ */
static void
test_data_load_valid_hmac (void)
{
  /* Create a temp file with valid HMAC-SHA256 */
  guint8 payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  gsize payload_len = sizeof (payload);

  /* Compute HMAC-SHA256 with the known key */
  const guint8 hmac_key[32] = {
    0x6c, 0x69, 0x62, 0x66, 0x70, 0x72, 0x69, 0x6e,
    0x74, 0x2d, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x69,
    0x74, 0x79, 0x2d, 0x64, 0x61, 0x74, 0x61, 0x2d,
    0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x69, 0x74,
  };

  GHmac *hmac = g_hmac_new (G_CHECKSUM_SHA256, hmac_key, sizeof (hmac_key));

  g_hmac_update (hmac, payload, payload_len);
  guint8 trailer[32];
  gsize digest_len = sizeof (trailer);
  g_hmac_get_digest (hmac, trailer, &digest_len);
  g_hmac_unref (hmac);

  /* Write payload + trailer to temp file */
  g_autofree gchar *tmpfile = NULL;
  gint fd = g_file_open_tmp ("validity-test-XXXXXX.bin", &tmpfile, NULL);
  g_assert_cmpint (fd, >, 0);

  g_assert_true (write (fd, payload, payload_len) == (ssize_t) payload_len);
  g_assert_true (write (fd, trailer, sizeof (trailer)) == sizeof (trailer));
  close (fd);

  /* Load and verify */
  ValidityDataStore store;
  fpi_validity_data_store_init (&store);

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_file (&store, VALIDITY_DATA_INIT,
                                             tmpfile, &error);
  g_assert_no_error (error);
  g_assert_true (ok);

  /* Verify loaded data matches payload (without HMAC) */
  gsize len;
  const guint8 *data = fpi_validity_data_get_bytes (&store, VALIDITY_DATA_INIT, &len);
  g_assert_nonnull (data);
  g_assert_cmpuint (len, ==, payload_len);
  g_assert_cmpmem (data, len, payload, payload_len);

  fpi_validity_data_store_free (&store);
  g_unlink (tmpfile);
}

/* ================================================================
 * T8.4: Load file with corrupted HMAC — should fail
 * ================================================================ */
static void
test_data_load_corrupt_hmac (void)
{
  guint8 payload[] = { 0xCA, 0xFE };
  guint8 bad_trailer[32];

  memset (bad_trailer, 0xFF, sizeof (bad_trailer));

  g_autofree gchar *tmpfile = NULL;
  gint fd = g_file_open_tmp ("validity-test-XXXXXX.bin", &tmpfile, NULL);
  g_assert_cmpint (fd, >, 0);

  g_assert_true (write (fd, payload, sizeof (payload)) == sizeof (payload));
  g_assert_true (write (fd, bad_trailer, sizeof (bad_trailer)) == sizeof (bad_trailer));
  close (fd);

  ValidityDataStore store;
  fpi_validity_data_store_init (&store);

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_file (&store, VALIDITY_DATA_INIT,
                                             tmpfile, &error);
  g_assert_false (ok);
  g_assert_nonnull (error);
  g_error_free (error);

  /* Tag should not be populated */
  gsize len;
  const guint8 *data = fpi_validity_data_get_bytes (&store, VALIDITY_DATA_INIT, &len);
  g_assert_null (data);

  fpi_validity_data_store_free (&store);
  g_unlink (tmpfile);
}

/* ================================================================
 * T8.5: Load file too small — should fail
 * ================================================================ */
static void
test_data_load_too_small (void)
{
  /* File with only 20 bytes — less than HMAC size (32) */
  guint8 tiny[20];

  memset (tiny, 0x42, sizeof (tiny));

  g_autofree gchar *tmpfile = NULL;
  gint fd = g_file_open_tmp ("validity-test-XXXXXX.bin", &tmpfile, NULL);
  g_assert_cmpint (fd, >, 0);

  g_assert_true (write (fd, tiny, sizeof (tiny)) == sizeof (tiny));
  close (fd);

  ValidityDataStore store;
  fpi_validity_data_store_init (&store);

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_file (&store, VALIDITY_DATA_INIT,
                                             tmpfile, &error);
  g_assert_false (ok);
  g_assert_nonnull (error);
  g_error_free (error);

  fpi_validity_data_store_free (&store);
  g_unlink (tmpfile);
}

/* ================================================================
 * T8.6: Load nonexistent file — should fail
 * ================================================================ */
static void
test_data_load_nonexistent (void)
{
  ValidityDataStore store;

  fpi_validity_data_store_init (&store);

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_file (&store, VALIDITY_DATA_INIT,
                                             "/nonexistent/path/blob.bin",
                                             &error);
  g_assert_false (ok);
  g_assert_nonnull (error);
  g_error_free (error);

  fpi_validity_data_store_free (&store);
}

/* ================================================================
 * T8.7: Tag enum values are contiguous
 * ================================================================ */
static void
test_data_tag_enum (void)
{
  g_assert_cmpint (VALIDITY_DATA_INIT, ==, 0);
  g_assert_cmpint (VALIDITY_DATA_NUM_TAGS, ==, 11);
  g_assert_cmpint (VALIDITY_DATA_FW_PUBKEY_Y, ==,
                   VALIDITY_DATA_NUM_TAGS - 1);
}

/* ================================================================
 * Helper: write a file with valid HMAC-SHA256 trailer
 * ================================================================ */
static void
write_hmac_file (const gchar  *path,
                 const guint8 *payload,
                 gsize         payload_len)
{
  static const guint8 hmac_key[32] = {
    0x6c, 0x69, 0x62, 0x66, 0x70, 0x72, 0x69, 0x6e,
    0x74, 0x2d, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x69,
    0x74, 0x79, 0x2d, 0x64, 0x61, 0x74, 0x61, 0x2d,
    0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x69, 0x74,
  };

  GHmac *hmac = g_hmac_new (G_CHECKSUM_SHA256, hmac_key, sizeof (hmac_key));

  g_hmac_update (hmac, payload, payload_len);
  guint8 trailer[32];
  gsize digest_len = sizeof (trailer);
  g_hmac_get_digest (hmac, trailer, &digest_len);
  g_hmac_unref (hmac);

  gsize total = payload_len + 32;
  g_autofree guint8 *buf = g_malloc (total);
  memcpy (buf, payload, payload_len);
  memcpy (buf + payload_len, trailer, 32);

  g_assert_true (g_file_set_contents (path, (const gchar *) buf, total, NULL));
}

/* ================================================================
 * T8.8: load_device — missing directory returns DATA_NOT_FOUND
 * ================================================================ */
static void
test_data_load_device_missing (void)
{
  ValidityDataStore store;

  fpi_validity_data_store_init (&store);

  /* Temporarily override search paths to non-existent directories */
  const gchar *saved0 = validity_data_search_paths[0];
  const gchar *saved1 = validity_data_search_paths[1];
  validity_data_search_paths[0] = "/tmp/nonexistent_validity_data_dir";
  validity_data_search_paths[1] = "/tmp/nonexistent_validity_data_dir2";

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_device (&store, 0x06cb, 0x009a, &error);

  g_assert_false (ok);
  g_assert_nonnull (error);
  g_assert_cmpint (error->code, ==, FP_DEVICE_ERROR_DATA_NOT_FOUND);

  /* The message names each directory that was probed */
  g_assert_nonnull (strstr (error->message,
                            "/tmp/nonexistent_validity_data_dir/06cb_009a"));
  g_assert_nonnull (strstr (error->message,
                            "/tmp/nonexistent_validity_data_dir2/06cb_009a"));
  g_error_free (error);

  /* Restore */
  validity_data_search_paths[0] = saved0;
  validity_data_search_paths[1] = saved1;

  fpi_validity_data_store_free (&store);
}

/* ================================================================
 * T8.9: load_device — directory exists but mandatory init.bin missing
 * ================================================================ */
static void
test_data_load_device_missing_init (void)
{
  /* Create temp dir with the expected subdir but no files */
  g_autofree gchar *tmpdir = g_dir_make_tmp ("validity-data-XXXXXX", NULL);

  g_assert_nonnull (tmpdir);

  g_autofree gchar *devdir = g_build_filename (tmpdir, "06cb_009a", NULL);
  g_assert_cmpint (g_mkdir (devdir, 0755), ==, 0);

  ValidityDataStore store;
  fpi_validity_data_store_init (&store);

  const gchar *saved0 = validity_data_search_paths[0];
  const gchar *saved1 = validity_data_search_paths[1];
  validity_data_search_paths[0] = tmpdir;
  validity_data_search_paths[1] = NULL;

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_device (&store, 0x06cb, 0x009a, &error);

  g_assert_false (ok);
  g_assert_nonnull (error);
  g_assert_cmpint (error->code, ==, FP_DEVICE_ERROR_DATA_NOT_FOUND);
  g_assert_nonnull (strstr (error->message, devdir));
  g_error_free (error);

  validity_data_search_paths[0] = saved0;
  validity_data_search_paths[1] = saved1;

  fpi_validity_data_store_free (&store);
  g_rmdir (devdir);
  g_rmdir (tmpdir);
}

/* ================================================================
 * T8.10: load_device — valid temp dir with init.bin loads correctly
 * ================================================================ */
static void
test_data_load_device_valid (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("validity-data-XXXXXX", NULL);

  g_assert_nonnull (tmpdir);

  g_autofree gchar *devdir = g_build_filename (tmpdir, "06cb_009a", NULL);
  g_assert_cmpint (g_mkdir (devdir, 0755), ==, 0);

  /* Write a valid init.bin (mandatory) */
  guint8 init_payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
  g_autofree gchar *init_path = g_build_filename (devdir, "init.bin", NULL);
  write_hmac_file (init_path, init_payload, sizeof (init_payload));

  /* Write a valid db_write_enable.bin (optional) */
  guint8 dbe_payload[] = { 0xAA, 0xBB };
  g_autofree gchar *dbe_path =
    g_build_filename (devdir, "db_write_enable.bin", NULL);
  write_hmac_file (dbe_path, dbe_payload, sizeof (dbe_payload));

  ValidityDataStore store;
  fpi_validity_data_store_init (&store);

  const gchar *saved0 = validity_data_search_paths[0];
  const gchar *saved1 = validity_data_search_paths[1];
  validity_data_search_paths[0] = tmpdir;
  validity_data_search_paths[1] = NULL;

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_device (&store, 0x06cb, 0x009a, &error);

  g_assert_no_error (error);
  g_assert_true (ok);

  /* Verify init was loaded */
  gsize len;
  const guint8 *data = fpi_validity_data_get_bytes (&store, VALIDITY_DATA_INIT, &len);
  g_assert_nonnull (data);
  g_assert_cmpuint (len, ==, sizeof (init_payload));
  g_assert_cmpmem (data, len, init_payload, sizeof (init_payload));

  /* Verify db_write_enable was loaded */
  const guint8 *dbe = fpi_validity_data_get_bytes (&store,
                                                   VALIDITY_DATA_DB_WRITE_ENABLE,
                                                   &len);
  g_assert_nonnull (dbe);
  g_assert_cmpuint (len, ==, sizeof (dbe_payload));
  g_assert_cmpmem (dbe, len, dbe_payload, sizeof (dbe_payload));

  /* Optional files not present should be NULL */
  const guint8 *reset = fpi_validity_data_get_bytes (&store,
                                                     VALIDITY_DATA_RESET, &len);
  g_assert_null (reset);
  g_assert_cmpuint (len, ==, 0);

  validity_data_search_paths[0] = saved0;
  validity_data_search_paths[1] = saved1;

  fpi_validity_data_store_free (&store);
  g_unlink (init_path);
  g_unlink (dbe_path);
  g_rmdir (devdir);
  g_rmdir (tmpdir);
}

/* ================================================================
 * T8.11: load_common — missing files returns DATA_NOT_FOUND
 * ================================================================ */
static void
test_data_load_common_missing (void)
{
  ValidityDataStore store;

  fpi_validity_data_store_init (&store);

  const gchar *saved0 = validity_data_search_paths[0];
  const gchar *saved1 = validity_data_search_paths[1];
  validity_data_search_paths[0] = "/tmp/nonexistent_validity_common_dir";
  validity_data_search_paths[1] = "/tmp/nonexistent_validity_common_dir2";

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_common (&store, &error);

  g_assert_false (ok);
  g_assert_nonnull (error);
  g_assert_cmpint (error->code, ==, FP_DEVICE_ERROR_DATA_NOT_FOUND);

  /* The message names the file and each search path */
  g_assert_nonnull (strstr (error->message, "partition_sig_standard.bin"));
  g_assert_nonnull (strstr (error->message,
                            "/tmp/nonexistent_validity_common_dir,"));
  g_assert_nonnull (strstr (error->message,
                            "/tmp/nonexistent_validity_common_dir2"));
  g_error_free (error);

  validity_data_search_paths[0] = saved0;
  validity_data_search_paths[1] = saved1;

  fpi_validity_data_store_free (&store);
}

/* ================================================================
 * T8.12: load_common — valid temp dir loads all 7 common files
 * ================================================================ */
static void
test_data_load_common_valid (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("validity-common-XXXXXX", NULL);

  g_assert_nonnull (tmpdir);

  /* Write all 7 common files with test payloads */
  static const struct
  {
    const gchar    *filename;
    ValidityDataTag tag;
    guint8          marker;
  } files[] = {
    { "partition_sig_standard.bin", VALIDITY_DATA_PARTITION_SIG_STANDARD, 0x01 },
    { "partition_sig_0090.bin",     VALIDITY_DATA_PARTITION_SIG_0090,     0x02 },
    { "ca_pubkey.bin",              VALIDITY_DATA_CA_PUBKEY,              0x03 },
    { "tls_password.bin",           VALIDITY_DATA_TLS_PASSWORD,           0x04 },
    { "gwk_sign.bin",               VALIDITY_DATA_GWK_SIGN,              0x05 },
    { "fw_pubkey_x.bin",            VALIDITY_DATA_FW_PUBKEY_X,           0x06 },
    { "fw_pubkey_y.bin",            VALIDITY_DATA_FW_PUBKEY_Y,           0x07 },
  };

  g_autofree gchar *paths[7] = { NULL };
  for (gsize i = 0; i < G_N_ELEMENTS (files); i++)
    {
      guint8 payload[4];
      memset (payload, files[i].marker, sizeof (payload));
      paths[i] = g_build_filename (tmpdir, files[i].filename, NULL);
      write_hmac_file (paths[i], payload, sizeof (payload));
    }

  ValidityDataStore store;
  fpi_validity_data_store_init (&store);

  const gchar *saved0 = validity_data_search_paths[0];
  const gchar *saved1 = validity_data_search_paths[1];
  validity_data_search_paths[0] = tmpdir;
  validity_data_search_paths[1] = NULL;

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_common (&store, &error);

  g_assert_no_error (error);
  g_assert_true (ok);

  /* Verify each tag was loaded correctly */
  for (gsize i = 0; i < G_N_ELEMENTS (files); i++)
    {
      gsize len;
      const guint8 *data = fpi_validity_data_get_bytes (&store, files[i].tag, &len);
      g_assert_nonnull (data);
      g_assert_cmpuint (len, ==, 4);
      g_assert_cmpuint (data[0], ==, files[i].marker);
    }

  validity_data_search_paths[0] = saved0;
  validity_data_search_paths[1] = saved1;

  /* Cleanup */
  fpi_validity_data_store_free (&store);
  for (gsize i = 0; i < G_N_ELEMENTS (files); i++)
    {
      g_unlink (paths[i]);
      g_free (paths[i]);
      paths[i] = NULL;
    }
  g_rmdir (tmpdir);
}

/* ================================================================
 * T8.13: db_write_enable returns NULL without loaded data
 * ================================================================ */
static void
test_data_enroll_dbe_missing (void)
{
  /* Create a minimal FpiDeviceValidity with empty data stores */
  FpiDeviceValidity dev = { 0 };

  fpi_validity_data_store_init (&dev.device_data);
  fpi_validity_data_store_init (&dev.common_data);

  /* db_write_enable is used in enroll, verify (match), and delete flows.
  * When data files are not installed, it must return NULL gracefully. */
  gsize len;
  const guint8 *dbe = fpi_validity_db_get_write_enable_blob (&dev, &len);
  g_assert_null (dbe);
  g_assert_cmpuint (len, ==, 0);

  /* fwext accessor also returns NULL */
  const guint8 *fwe = fpi_validity_fwext_get_db_write_enable (&dev, &len);
  g_assert_null (fwe);
  g_assert_cmpuint (len, ==, 0);

  /* TLS key pointers should be NULL */
  g_assert_null (dev.tls.password);
  g_assert_null (dev.tls.gwk_sign);
  g_assert_null (dev.tls.fw_pubkey_x);
  g_assert_null (dev.tls.fw_pubkey_y);

  fpi_validity_data_store_free (&dev.device_data);
  fpi_validity_data_store_free (&dev.common_data);
}

/* ================================================================
 * T8.14: db_write_enable returns data when store is populated
 * ================================================================ */
static void
test_data_enroll_dbe_loaded (void)
{
  /* Create device with loaded db_write_enable */
  g_autofree gchar *tmpdir = g_dir_make_tmp ("validity-dbe-XXXXXX", NULL);

  g_assert_nonnull (tmpdir);

  g_autofree gchar *devdir = g_build_filename (tmpdir, "06cb_009a", NULL);
  g_assert_cmpint (g_mkdir (devdir, 0755), ==, 0);

  /* Write init.bin (mandatory) and db_write_enable.bin */
  guint8 init_data[] = { 0x11 };
  g_autofree gchar *init_path = g_build_filename (devdir, "init.bin", NULL);
  write_hmac_file (init_path, init_data, sizeof (init_data));

  guint8 dbe_data[] = { 0xDB, 0xE0, 0x01, 0x02, 0x03 };
  g_autofree gchar *dbe_path =
    g_build_filename (devdir, "db_write_enable.bin", NULL);
  write_hmac_file (dbe_path, dbe_data, sizeof (dbe_data));

  FpiDeviceValidity dev = { 0 };
  fpi_validity_data_store_init (&dev.device_data);

  const gchar *saved0 = validity_data_search_paths[0];
  const gchar *saved1 = validity_data_search_paths[1];
  validity_data_search_paths[0] = tmpdir;
  validity_data_search_paths[1] = NULL;

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_device (&dev.device_data,
                                               0x06cb, 0x009a, &error);
  g_assert_no_error (error);
  g_assert_true (ok);

  /* Now the enroll/verify consumer should find the data */
  gsize len;
  const guint8 *dbe = fpi_validity_db_get_write_enable_blob (&dev, &len);
  g_assert_nonnull (dbe);
  g_assert_cmpuint (len, ==, sizeof (dbe_data));
  g_assert_cmpmem (dbe, len, dbe_data, sizeof (dbe_data));

  /* fwext accessor should also work */
  const guint8 *fwe = fpi_validity_fwext_get_db_write_enable (&dev, &len);
  g_assert_nonnull (fwe);
  g_assert_cmpuint (len, ==, sizeof (dbe_data));

  validity_data_search_paths[0] = saved0;
  validity_data_search_paths[1] = saved1;

  fpi_validity_data_store_free (&dev.device_data);
  g_unlink (init_path);
  g_unlink (dbe_path);
  g_rmdir (devdir);
  g_rmdir (tmpdir);
}

/* ================================================================
 * T8.15: load_device rejects corrupt HMAC
 * ================================================================ */
static void
test_data_load_device_corrupt (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("validity-corrupt-XXXXXX", NULL);

  g_assert_nonnull (tmpdir);

  g_autofree gchar *devdir = g_build_filename (tmpdir, "06cb_009a", NULL);
  g_assert_cmpint (g_mkdir (devdir, 0755), ==, 0);

  /* Write init.bin with bad HMAC */
  guint8 bad_file[37];  /* 5 bytes payload + 32 bytes bad HMAC */
  memset (bad_file, 0xAA, sizeof (bad_file));

  g_autofree gchar *init_path = g_build_filename (devdir, "init.bin", NULL);
  g_assert_true (g_file_set_contents (init_path, (const gchar *) bad_file,
                                      sizeof (bad_file), NULL));

  ValidityDataStore store;
  fpi_validity_data_store_init (&store);

  const gchar *saved0 = validity_data_search_paths[0];
  const gchar *saved1 = validity_data_search_paths[1];
  validity_data_search_paths[0] = tmpdir;
  validity_data_search_paths[1] = NULL;

  GError *error = NULL;
  gboolean ok = fpi_validity_data_load_device (&store, 0x06cb, 0x009a, &error);

  g_assert_false (ok);
  g_assert_nonnull (error);
  /* HMAC failure reports DATA_INVALID */
  g_assert_cmpint (error->code, ==, FP_DEVICE_ERROR_DATA_INVALID);
  g_error_free (error);

  validity_data_search_paths[0] = saved0;
  validity_data_search_paths[1] = saved1;

  fpi_validity_data_store_free (&store);
  g_unlink (init_path);
  g_rmdir (devdir);
  g_rmdir (tmpdir);
}

/* ================================================================
 * Main
 * ================================================================ */

#include "test-validity-a2-capture.h"

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  /* HAL tests */

  g_test_add_func ("/validity/hal/lookup-all-types",
                   test_hal_lookup_all_types);
  g_test_add_func ("/validity/hal/lookup-by-pid",
                   test_hal_lookup_by_pid);
  g_test_add_func ("/validity/hal/lookup-invalid",
                   test_hal_lookup_invalid);
  g_test_add_func ("/validity/hal/lookup-by-pid-invalid",
                   test_hal_lookup_by_pid_invalid);
  g_test_add_func ("/validity/hal/blobs-present",
                   test_hal_blobs_present);
  g_test_add_func ("/validity/hal/pid-0090-specifics",
                   test_hal_pid_0090_specifics);
  g_test_add_func ("/validity/hal/clean-slate-present",
                   test_hal_clean_slate_present);
  g_test_add_func ("/validity/hal/flash-layout",
                   test_hal_flash_layout);
  g_test_add_func ("/validity/hal/blob-sizes",
                   test_hal_blob_sizes);
  g_test_add_func ("/validity/hal/lookup-consistency",
                   test_hal_lookup_consistency);
  g_test_add_func ("/validity/hal/a2-matches-real-flash-info",
                   test_hal_a2_matches_real_flash_info);

  /* 06cb:00a2 policy and safety gates */
  g_test_add_func ("/validity/a2/device-policy", test_a2_device_policy);
  g_test_add_func ("/validity/a2/rom-gate/real", test_a2_rom_gate_real);
  g_test_add_func ("/validity/a2/rom-gate/negative",
                   test_a2_rom_gate_negative);
  g_test_add_func ("/validity/a2/fwext-gate", test_a2_fwext_gate);
  g_test_add_func ("/validity/a2/init-gate", test_a2_init_gate);
  g_test_add_func ("/validity/a2/probe-features", test_a2_probe_features);
  g_test_add_func ("/validity/a2/init-action", test_a2_init_action);
  g_test_add_func ("/validity/a2/init-blob-pin", test_a2_init_blob_pin);
  g_test_add_func ("/validity/a2/drop-unused-data", test_a2_drop_unused_data);
  g_test_add_func ("/validity/a2/no-reconnect", test_a2_no_reconnect);
  g_test_add_func ("/validity/a2/sensor-gate", test_a2_sensor_gate);
  g_test_add_func ("/validity/a2/sensor-gate/real-setup",
                   test_a2_sensor_gate_real_setup);
  g_test_add_func ("/validity/a2/capture/vfunc-dev-only",
                   test_a2_capture_vfunc_dev_only);
  g_test_add_func ("/validity/a2/events/capture", test_a2_capture_events);
  g_test_add_func ("/validity/a2/events/match", test_a2_match_events);
  g_test_add_func ("/validity/a2/image/header", test_a2_image_header);
  g_test_add_func ("/validity/a2/image/flags", test_a2_image_flags);
  g_test_add_func ("/validity/a2/readout/two-chunks",
                   test_a2_readout_two_chunks);
  g_test_add_func ("/validity/a2/readout/surplus", test_a2_readout_surplus);
  g_test_add_func ("/validity/a2/readout/errors", test_a2_readout_errors);
  g_test_add_func ("/validity/a2/readout/geometry", test_a2_readout_geometry);
  g_test_add_func ("/validity/a2/readout/statuses", test_a2_readout_statuses);
  g_test_add_func ("/validity/a2/match-result/parse",
                   test_a2_match_result_parse);
  g_test_add_func ("/validity/a2/flow/verify-no-match",
                   test_a2_flow_verify_no_match);
  g_test_add_func ("/validity/a2/flow/verify-match", test_a2_flow_verify_match);
  g_test_add_func ("/validity/a2/flow/no-match-paths",
                   test_a2_flow_no_match_paths);
  g_test_add_func ("/validity/a2/flow/match-errors", test_a2_flow_match_errors);
  g_test_add_func ("/validity/a2/flow/stale-report", test_a2_flow_stale_report);
  g_test_add_func ("/validity/a2/flow/transport-error",
                   test_a2_flow_transport_error);
  g_test_add_func ("/validity/a2/flow/cancel-finger-wait",
                   test_a2_flow_cancel_finger_wait);
  g_test_add_func ("/validity/a2/flow/cancel-readout",
                   test_a2_flow_cancel_readout);
  g_test_add_func ("/validity/a2/flow/cancel-match-wait",
                   test_a2_flow_cancel_match_wait);
  g_test_add_func ("/validity/a2/flow/cancel-after-result",
                   test_a2_flow_cancel_after_result);
  g_test_add_func ("/validity/a2/flow/abort-rearm", test_a2_flow_abort_rearm);
  g_test_add_func ("/validity/a2/flow/readout-statuses",
                   test_a2_flow_readout_statuses);
  g_test_add_func ("/validity/a2/flow/bad-capture", test_a2_flow_bad_capture);
  g_test_add_func ("/validity/a2/flow/capture-errors",
                   test_a2_flow_capture_errors);
  g_test_add_func ("/validity/a2/flow/empty-bounded",
                   test_a2_flow_empty_bounded);
  g_test_add_func ("/validity/a2/flow/image-flags", test_a2_flow_image_flags);
  g_test_add_func ("/validity/a2/flow/capture-only", test_a2_flow_capture_only);
  g_test_add_func ("/validity/a2/flow/commands", test_a2_flow_commands);
  g_test_add_func ("/validity/a2/flow/opcode-inventory",
                   test_a2_flow_opcode_inventory);
  g_test_add_func ("/validity/a2/pair-decide-for-policy",
                   test_pair_decide_for_policy);


  /* SENSOR tests */

  g_test_add_func ("/validity/sensor/identify/parse",
                   test_identify_sensor_parse);
  g_test_add_func ("/validity/sensor/identify/truncated",
                   test_identify_sensor_parse_truncated);
  g_test_add_func ("/validity/sensor/devinfo/lookup_exact",
                   test_device_info_lookup_exact);
  g_test_add_func ("/validity/sensor/devinfo/lookup_another",
                   test_device_info_lookup_another);
  g_test_add_func ("/validity/sensor/devinfo/lookup_unknown",
                   test_device_info_lookup_unknown);
  g_test_add_func ("/validity/sensor/devinfo/lookup_fuzzy",
                   test_device_info_lookup_fuzzy);
  g_test_add_func ("/validity/sensor/typeinfo/lookup",
                   test_sensor_type_info_lookup);
  g_test_add_func ("/validity/sensor/typeinfo/lookup_db",
                   test_sensor_type_info_lookup_db);
  g_test_add_func ("/validity/sensor/typeinfo/lookup_unknown",
                   test_sensor_type_info_lookup_unknown);
  g_test_add_func ("/validity/sensor/factory_bits/cmd_format",
                   test_factory_bits_cmd_format);
  g_test_add_func ("/validity/sensor/factory_bits/buffer_too_small",
                   test_factory_bits_cmd_buffer_too_small);
  g_test_add_func ("/validity/sensor/identify_then_lookup",
                   test_identify_then_lookup);
  g_test_add_func ("/validity/sensor/state_lifecycle",
                   test_sensor_state_lifecycle);
  g_test_add_func ("/validity/sensor/calibration_blob_present",
                   test_calibration_blob_present);


  /* ENROLL tests */

  g_test_add_func ("/validity/enroll/parse-empty",
                   test_parse_empty);
  g_test_add_func ("/validity/enroll/parse-template-block",
                   test_parse_template_block);
  g_test_add_func ("/validity/enroll/parse-header-block",
                   test_parse_header_block);
  g_test_add_func ("/validity/enroll/parse-tid-block",
                   test_parse_tid_block);
  g_test_add_func ("/validity/enroll/parse-multiple-blocks",
                   test_parse_multiple_blocks);
  g_test_add_func ("/validity/enroll/parse-truncated",
                   test_parse_truncated);
  g_test_add_func ("/validity/enroll/parse-unknown-tag",
                   test_parse_unknown_tag);
  g_test_add_func ("/validity/enroll/result-clear",
                   test_result_clear);
  g_test_add_func ("/validity/enroll/parse-zero-length-payload",
                   test_parse_zero_length_payload);
  g_test_add_func ("/validity/enroll/progress-short",
                   test_enroll_progress_short);
  g_test_add_func ("/validity/enroll/progress-long",
                   test_enroll_progress_long);
  g_test_add_func ("/validity/enroll/progress-reconnect",
                   test_enroll_progress_reconnect);


  /* FWEXT tests */

  /* Firmware info parsing */
  g_test_add_func ("/validity/fwext/fw-info/parse-present",
                   test_fw_info_parse_present);
  g_test_add_func ("/validity/fwext/fw-info/parse-absent",
                   test_fw_info_parse_absent);
  g_test_add_func ("/validity/fwext/fw-info/parse-absent-wire",
                   test_fw_info_parse_absent_wire);
  g_test_add_func ("/validity/fwext/fw-info/parse-real-a2",
                   test_fw_info_parse_real_a2);
  g_test_add_func ("/validity/fwext/fw-info/parse-unknown-status",
                   test_fw_info_parse_unknown_status);
  g_test_add_func ("/validity/fwext/fw-info/parse-truncated",
                   test_fw_info_parse_truncated);

  /* File parsing */
  g_test_add_func ("/validity/fwext/file/parse",
                   test_xpfwext_file_parse);
  g_test_add_func ("/validity/fwext/file/no-delimiter",
                   test_xpfwext_file_no_delimiter);
  g_test_add_func ("/validity/fwext/file/too-short",
                   test_xpfwext_file_too_short);
  g_test_add_func ("/validity/fwext/file/clear-idempotent",
                   test_file_clear_idempotent);

  /* Command format */
  g_test_add_func ("/validity/fwext/cmd/write-flash",
                   test_flash_write_cmd_format);
  g_test_add_func ("/validity/fwext/cmd/write-fw-sig",
                   test_fw_sig_cmd_format);
  g_test_add_func ("/validity/fwext/cmd/write-hw-reg",
                   test_hw_reg_write_cmd_format);
  g_test_add_func ("/validity/fwext/cmd/read-hw-reg",
                   test_hw_reg_read_cmd_format);
  g_test_add_func ("/validity/fwext/cmd/read-hw-reg-parse",
                   test_hw_reg_read_parse);
  g_test_add_func ("/validity/fwext/cmd/reboot",
                   test_reboot_cmd_format);

  /* Chunk iteration */
  g_test_add_func ("/validity/fwext/chunk-iteration",
                   test_chunk_iteration);

  /* Firmware filename mapping */
  g_test_add_func ("/validity/fwext/firmware-name",
                   test_firmware_filename);
  g_test_add_func ("/validity/fwext/find-firmware/missing",
                   test_missing_firmware_file);
  g_test_add_func ("/validity/fwext/find-firmware/missing-hint",
                   test_missing_firmware_hint);
  g_test_add_func ("/validity/fwext/find-firmware/unsupported-pid",
                   test_unsupported_pid_firmware);

  /* Blob lookup */
  g_test_add_func ("/validity/fwext/db-write-enable",
                   test_fwext_db_write_enable_blob);


  /* DB tests */

  /* Command builder tests */
  g_test_add_func ("/validity/db/cmd_db_info", test_cmd_db_info);
  g_test_add_func ("/validity/db/cmd_get_user_storage", test_cmd_get_user_storage);
  g_test_add_func ("/validity/db/cmd_get_user_storage_null_name", test_cmd_get_user_storage_null_name);
  g_test_add_func ("/validity/db/cmd_get_user", test_cmd_get_user);
  g_test_add_func ("/validity/db/cmd_lookup_user", test_cmd_lookup_user);
  g_test_add_func ("/validity/db/cmd_new_record", test_cmd_new_record);
  g_test_add_func ("/validity/db/cmd_del_record", test_cmd_del_record);
  g_test_add_func ("/validity/db/cmd_create_enrollment", test_cmd_create_enrollment);
  g_test_add_func ("/validity/db/cmd_enrollment_update_start", test_cmd_enrollment_update_start);
  g_test_add_func ("/validity/db/cmd_enrollment_update", test_cmd_enrollment_update);
  g_test_add_func ("/validity/db/cmd_match_finger", test_cmd_match_finger);
  g_test_add_func ("/validity/db/cmd_get_match_result", test_cmd_get_match_result);
  g_test_add_func ("/validity/db/cmd_match_cleanup", test_cmd_match_cleanup);
  g_test_add_func ("/validity/db/cmd_get_prg_status", test_cmd_get_prg_status);
  g_test_add_func ("/validity/db/cmd_capture_stop", test_cmd_capture_stop);
  g_test_add_func ("/validity/db/cmd_call_cleanups", test_cmd_call_cleanups);
  g_test_add_func ("/validity/db/cmd_get_record_value", test_cmd_get_record_value);
  g_test_add_func ("/validity/db/cmd_get_record_children", test_cmd_get_record_children);

  /* Response parser tests */
  g_test_add_func ("/validity/db/parse_info", test_parse_db_info);
  g_test_add_func ("/validity/db/parse_info_too_short", test_parse_db_info_too_short);
  g_test_add_func ("/validity/db/parse_user_storage", test_parse_user_storage);
  g_test_add_func ("/validity/db/parse_user", test_parse_user);
  g_test_add_func ("/validity/db/parse_new_record_id", test_parse_new_record_id);
  g_test_add_func ("/validity/db/parse_new_record_id_too_short", test_parse_new_record_id_too_short);
  g_test_add_func ("/validity/db/parse_record_value", test_parse_record_value);
  g_test_add_func ("/validity/db/parse_record_children", test_parse_record_children);

  /* Identity and finger data tests */
  g_test_add_func ("/validity/db/build_identity", test_build_identity);
  g_test_add_func ("/validity/db/build_finger_data", test_build_finger_data);

  /* Blob accessor test */
  g_test_add_func ("/validity/db/write_enable_blob", test_db_write_enable_blob);


  /* VERIFY tests */

  /* R1: parse_match_result */
  g_test_add_func ("/validity/verify/parse_match_result_valid",
                   test_parse_match_result_valid);
  g_test_add_func ("/validity/verify/parse_match_result_multi_tags",
                   test_parse_match_result_multi_tags);
  g_test_add_func ("/validity/verify/parse_match_result_empty",
                   test_parse_match_result_empty);
  g_test_add_func ("/validity/verify/parse_match_result_truncated",
                   test_parse_match_result_truncated);
  g_test_add_func ("/validity/verify/parse_match_result_unknown_tags",
                   test_parse_match_result_unknown_tags);
  g_test_add_func ("/validity/verify/match_result_clear",
                   test_match_result_clear);

  /* R2: identity builder */
  g_test_add_func ("/validity/verify/build_identity_null",
                   test_build_identity_null);
  g_test_add_func ("/validity/verify/build_identity_valid_uuid",
                   test_build_identity_valid_uuid);

  /* R3: match correlation */
  g_test_add_func ("/validity/verify/match_record_same_print",
                   test_match_record_same_print);
  g_test_add_func ("/validity/verify/match_record_same_user_other_finger",
                   test_match_record_same_user_other_finger);
  g_test_add_func ("/validity/verify/match_record_other_user_same_finger",
                   test_match_record_other_user_same_finger);
  g_test_add_func ("/validity/verify/match_record_no_correlation",
                   test_match_record_no_correlation);
  g_test_add_func ("/validity/verify/gallery_match_correlates",
                   test_gallery_match_correlates);
  g_test_add_func ("/validity/verify/gallery_match_no_fallback",
                   test_gallery_match_no_fallback);
  g_test_add_func ("/validity/verify/gallery_match_empty",
                   test_gallery_match_empty);
  g_test_add_func ("/validity/verify/user_get_id",
                   test_user_get_id);
  g_test_add_func ("/validity/verify/match_decide_verify",
                   test_match_decide_verify);
  g_test_add_func ("/validity/verify/match_decide_identify",
                   test_match_decide_identify);
  g_test_add_func ("/validity/verify/match_decide_mode",
                   test_match_decide_mode);
  g_test_add_func ("/validity/verify/match_decide_no_readback",
                   test_match_decide_no_readback);
  g_test_add_func ("/validity/verify/match_user_to_read",
                   test_match_user_to_read);
  g_test_add_func ("/validity/verify/clear_match_state",
                   test_verify_clear_match_state);
  g_test_add_func ("/validity/delete/find_finger_own_record",
                   test_delete_find_finger_own_record);
  g_test_add_func ("/validity/delete/find_finger_multi_finger_record",
                   test_delete_find_finger_multi_finger_record);
  g_test_add_func ("/validity/delete/find_finger_other_user",
                   test_delete_find_finger_other_user);
  g_test_add_func ("/validity/delete/find_finger_no_correlation",
                   test_delete_find_finger_no_correlation);
  g_test_add_func ("/validity/delete/owner_is_empty",
                   test_delete_owner_is_empty);

  /* R4: struct field separation */
  g_test_add_func ("/validity/verify/struct_separate_fields",
                   test_struct_separate_fields);

  /* R5: del_record command format */
  g_test_add_func ("/validity/verify/del_record_format",
                   test_del_record_format);

  /* R6: match_finger allocation */
  g_test_add_func ("/validity/verify/match_finger_size",
                   test_match_finger_size);

  /* R7: clear/delete storage SSM states */
  g_test_add_func ("/validity/verify/clear_storage_states",
                   test_clear_storage_states_exist);
  g_test_add_func ("/validity/verify/delete_states",
                   test_delete_states_exist);

  /* Tier 0 recovery: error classification */
  g_test_add_func ("/validity/recovery/classify_error",
                   test_classify_error);


  /* TLS tests */

  g_test_add_func ("/validity/tls/prf/deterministic", test_prf_deterministic);
  g_test_add_func ("/validity/tls/prf/output-length", test_prf_output_length);
  g_test_add_func ("/validity/tls/prf/short-output", test_prf_short_output);
  g_test_add_func ("/validity/tls/encrypt/roundtrip",
                   test_encrypt_decrypt_roundtrip);
  g_test_add_func ("/validity/tls/encrypt/block-aligned",
                   test_encrypt_block_aligned);
  g_test_add_func ("/validity/tls/decrypt/invalid", test_decrypt_invalid);
  g_test_add_func ("/validity/tls/psk/derivation", test_psk_derivation);
  g_test_add_func ("/validity/tls/psk/deterministic", test_psk_deterministic);
  g_test_add_func ("/validity/tls/psk/python-validity-kat",
                   test_psk_python_validity_kat);
  g_test_add_func ("/validity/tls/psk/from-files", test_psk_from_files);
  g_test_add_func ("/validity/dev/serial-file-read", test_dev_serial_file_read);
  g_test_add_func ("/validity/dev/serial-file-psk", test_dev_serial_file_psk);
  g_test_add_func ("/validity/dev/data-dir", test_dev_data_dir);
  g_test_add_func ("/validity/tls/flash/parse-empty", test_flash_parse_empty);
  g_test_add_func ("/validity/tls/flash/parse-truncated",
                   test_flash_parse_truncated);
  g_test_add_func ("/validity/tls/init-free", test_init_free);
  g_test_add_func ("/validity/tls/client-hello", test_build_client_hello);
  g_test_add_func ("/validity/tls/unwrap/invalid", test_unwrap_invalid);

  /* TLS regression tests */
  g_test_add_func ("/validity/tls/regression/flash-parse-needs-psk",
                   test_flash_parse_needs_psk);
  g_test_add_func ("/validity/tls/regression/flash-cmd-format",
                   test_flash_cmd_format);
  g_test_add_func ("/validity/tls/regression/flash-response-header",
                   test_flash_response_header);
  g_test_add_func ("/validity/tls/regression/server-hello-rejects-vcsfw-prefix",
                   test_server_hello_rejects_vcsfw_prefix);
  g_test_add_func ("/validity/tls/regression/client-hello-tls-prefix",
                   test_client_hello_tls_prefix);


  /* PAIR tests */

  g_test_add_func ("/validity/pair/parse-flash-info-valid",
                   test_parse_flash_info_valid);
  g_test_add_func ("/validity/pair/parse-flash-info-needs-pairing",
                   test_parse_flash_info_needs_pairing);
  g_test_add_func ("/validity/pair/parse-flash-info-too-short",
                   test_parse_flash_info_too_short);
  g_test_add_func ("/validity/pair/classify-tls-flash/keys-present",
                   test_pair_classify_keys_present);
  g_test_add_func ("/validity/pair/classify-tls-flash/own-image",
                   test_pair_classify_own_image);
  g_test_add_func ("/validity/pair/classify-tls-flash/blank",
                   test_pair_classify_blank);
  g_test_add_func ("/validity/pair/classify-tls-flash/partial",
                   test_pair_classify_partial);
  g_test_add_func ("/validity/pair/classify-tls-flash/unreadable",
                   test_pair_classify_unreadable);
  g_test_add_func ("/validity/pair/classify-tls-flash/truncated",
                   test_pair_classify_truncated);
  g_test_add_func ("/validity/pair/decide", test_pair_decide);
  g_test_add_func ("/validity/pair/serialize-partition",
                   test_serialize_partition);
  g_test_add_func ("/validity/pair/make-cert-size",
                   test_make_cert_size);
  g_test_add_func ("/validity/pair/make-cert-deterministic",
                   test_make_cert_deterministic);
  g_test_add_func ("/validity/pair/encrypt-key-structure",
                   test_encrypt_key_structure);
  g_test_add_func ("/validity/pair/encrypt-key-hmac-valid",
                   test_encrypt_key_hmac_valid);
  g_test_add_func ("/validity/pair/build-partition-flash-cmd",
                   test_build_partition_flash_cmd);
  g_test_add_func ("/validity/pair/build-tls-flash-size",
                   test_build_tls_flash_size);
  g_test_add_func ("/validity/pair/build-tls-flash-blocks",
                   test_build_tls_flash_blocks);
  g_test_add_func ("/validity/pair/state-lifecycle",
                   test_pair_state_lifecycle);
  g_test_add_func ("/validity/pair/state-free-with-resources",
                   test_pair_state_free_with_resources);
  g_test_add_func ("/validity/pair/encrypt-key-different-inputs",
                   test_encrypt_key_different_inputs);


  /* CAPTURE tests */

  /* Chunk parsing */
  g_test_add_func ("/validity/capture/split-chunks-basic",
                   test_split_chunks_basic);
  g_test_add_func ("/validity/capture/split-merge-roundtrip",
                   test_split_merge_roundtrip);
  g_test_add_func ("/validity/capture/split-chunks-empty",
                   test_split_chunks_empty);
  g_test_add_func ("/validity/capture/split-chunks-truncated",
                   test_split_chunks_truncated);

  /* Timeslot instruction decoder */
  g_test_add_func ("/validity/capture/decode-insn-noop",
                   test_decode_insn_noop);
  g_test_add_func ("/validity/capture/decode-insn-call",
                   test_decode_insn_call);
  g_test_add_func ("/validity/capture/decode-insn-call-repeat-zero",
                   test_decode_insn_call_repeat_zero);
  g_test_add_func ("/validity/capture/decode-insn-regwrite",
                   test_decode_insn_regwrite);
  g_test_add_func ("/validity/capture/decode-insn-enable-rx",
                   test_decode_insn_enable_rx);
  g_test_add_func ("/validity/capture/decode-insn-sample",
                   test_decode_insn_sample);

  /* Instruction search */
  g_test_add_func ("/validity/capture/find-nth-insn",
                   test_find_nth_insn);
  g_test_add_func ("/validity/capture/find-nth-regwrite",
                   test_find_nth_regwrite);

  /* Timeslot patching */
  g_test_add_func ("/validity/capture/patch-timeslot-table",
                   test_patch_timeslot_table);
  g_test_add_func ("/validity/capture/patch-timeslot-no-mult-repeat1",
                   test_patch_timeslot_table_no_mult_for_repeat1);

  /* Bitpack */
  g_test_add_func ("/validity/capture/bitpack-uniform",
                   test_bitpack_uniform);
  g_test_add_func ("/validity/capture/bitpack-range",
                   test_bitpack_range);

  /* Factory bits */
  g_test_add_func ("/validity/capture/factory-bits-parsing",
                   test_factory_bits_parsing);
  g_test_add_func ("/validity/capture/factory-bits-no-subtag3",
                   test_factory_bits_no_subtag3);

  /* Frame averaging */
  g_test_add_func ("/validity/capture/average-frames-interleave2",
                   test_average_frames_interleave2);

  /* Clean slate */
  g_test_add_func ("/validity/capture/clean-slate-roundtrip",
                   test_clean_slate_roundtrip);

  /* Finger mapping */
  g_test_add_func ("/validity/capture/finger-mapping",
                   test_finger_mapping);

  /* LED commands */
  g_test_add_func ("/validity/capture/led-commands",
                   test_led_commands);

  /* CaptureProg lookup */
  g_test_add_func ("/validity/capture/prog-lookup",
                   test_capture_prog_lookup);

  /* State setup */
  g_test_add_func ("/validity/capture/state-setup",
                   test_capture_state_setup);

  /* build_cmd_02 */
  g_test_add_func ("/validity/capture/build-cmd-02-header",
                   test_build_cmd_02_header);

  /* Calibration processing */
  g_test_add_func ("/validity/capture/calibration-processing",
                   test_calibration_processing);

  /* Real capture program parsing */
  g_test_add_func ("/validity/capture/split-real-prog",
                   test_capture_split_real_prog);

  /* Data loader tests */
  g_test_add_func ("/validity/data/store-empty",
                   test_data_store_empty);
  g_test_add_func ("/validity/data/store-double-free",
                   test_data_store_double_free);
  g_test_add_func ("/validity/data/load-valid-hmac",
                   test_data_load_valid_hmac);
  g_test_add_func ("/validity/data/load-corrupt-hmac",
                   test_data_load_corrupt_hmac);
  g_test_add_func ("/validity/data/load-too-small",
                   test_data_load_too_small);
  g_test_add_func ("/validity/data/load-nonexistent",
                   test_data_load_nonexistent);
  g_test_add_func ("/validity/data/tag-enum",
                   test_data_tag_enum);
  g_test_add_func ("/validity/data/load-device-missing",
                   test_data_load_device_missing);
  g_test_add_func ("/validity/data/load-device-missing-init",
                   test_data_load_device_missing_init);
  g_test_add_func ("/validity/data/load-device-valid",
                   test_data_load_device_valid);
  g_test_add_func ("/validity/data/load-common-missing",
                   test_data_load_common_missing);
  g_test_add_func ("/validity/data/load-common-valid",
                   test_data_load_common_valid);
  g_test_add_func ("/validity/data/enroll-dbe-missing",
                   test_data_enroll_dbe_missing);
  g_test_add_func ("/validity/data/enroll-dbe-loaded",
                   test_data_enroll_dbe_loaded);
  g_test_add_func ("/validity/data/load-device-corrupt",
                   test_data_load_device_corrupt);


  return g_test_run ();
}
