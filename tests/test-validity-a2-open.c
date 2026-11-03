/*
 * 06cb:00a2: the probe, open and action-refusal wiring of the validity
 * driver, run against a scripted sensor
 *
 * Copyright (C) 2026 libfprint contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * test-validity.c checks the 00a2 gates as pure functions. This test runs
 * the code that calls them: validity.c (probe, the open SSM, the gate,
 * init and refusal callbacks) and vcsfw_protocol.c are compiled into this
 * file with every USB call renamed to the scripted sensor below, and the
 * data-package loaders renamed to an in-memory package. Everything else
 * (policy, gates, pairing, TLS, verify, enroll) is the driver code from
 * libfprint-drivers. Nothing here can reach a USB device: the device
 * object is FP_DEVICE_TYPE_VIRTUAL and has no GUsbDevice, and every GUsb
 * call in validity.c is replaced.
 *
 * The 01, 19 and 43 02 replies are those of the real E480 sensor (see
 * test-validity.c); the sensor answers every later command (3e, 40) with
 * an I/O error, so an open ends right after the init.
 */

/* Rename before anything declares them (the headers then declare the
 * replacements with the same prototypes) */
#define fpi_usb_transfer_submit a2t_usb_submit
#define fpi_usb_transfer_submit_sync a2t_usb_submit_sync
#define fpi_device_get_usb_device a2t_get_usb_device
#define g_usb_device_open a2t_usb_open
#define g_usb_device_close a2t_usb_close
#define g_usb_device_reset a2t_usb_reset
#define g_usb_device_claim_interface a2t_usb_claim
#define g_usb_device_release_interface a2t_usb_release
#define g_usb_device_get_configuration a2t_usb_get_configuration
#define fpi_validity_data_load_device a2t_load_device
#define fpi_validity_data_load_common a2t_load_common
#define fpi_validity_a2_init_blob_ok a2t_init_blob_ok

#include "drivers/validity/validity.c"
#include "drivers/validity/vcsfw_protocol.c"

#undef fpi_usb_transfer_submit
#undef fpi_usb_transfer_submit_sync
#undef fpi_device_get_usb_device
#undef g_usb_device_open
#undef g_usb_device_close
#undef g_usb_device_reset
#undef g_usb_device_claim_interface
#undef g_usb_device_release_interface
#undef g_usb_device_get_configuration
#undef fpi_validity_data_load_device
#undef fpi_validity_data_load_common
#undef fpi_validity_a2_init_blob_ok

#include <stdlib.h>
#include <string.h>
#include "fp-print.h"
#include "drivers/validity/validity_sensor.h"

/* ================================================================
 * Real replies (wire bytes, status included)
 * ================================================================ */

static const guint8 real_01[38] = {
  0x00, 0x00, 0xf0, 0xb0, 0x5e, 0x54, 0xa4, 0x00, 0x00, 0x00, 0x06, 0x07,
  0x01, 0x30, 0x00, 0x01, 0x00, 0x00, 0xbc, 0xbb, 0x8b, 0x68, 0x49, 0x61,
  0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0xd1,
  0x00, 0x07,
};

static const guint8 real_19[68] = {
  0x00, 0x00, 0x02, 0x00, 0x21, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x94, 0x49, 0x24,
  0x00, 0x00, 0x00, 0x00, 0xb0, 0xcd, 0x7e, 0x50, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const guint8 real_4302[96] = {
  0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x07, 0x00, 0x6e, 0xcf, 0x2e, 0x5e,
  0x01, 0x00, 0x34, 0x46, 0x02, 0x00, 0x07, 0x00, 0xc0, 0x3f, 0x00, 0x00,
  0x01, 0x00, 0x84, 0x08, 0x01, 0x00, 0x07, 0x00, 0x30, 0x05, 0x00, 0x00,
  0x02, 0x00, 0x84, 0x28, 0x03, 0x00, 0x12, 0x00, 0x40, 0x10, 0x00, 0x00,
  0x01, 0x00, 0x86, 0x47, 0x00, 0x00, 0x01, 0x00, 0x50, 0x5a, 0x00, 0x00,
  0x02, 0x00, 0x23, 0x77, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x2f, 0x00, 0x00,
  0x02, 0x00, 0x00, 0x37, 0x00, 0x00, 0x01, 0x00, 0x30, 0x07, 0x02, 0x00,
};

/* ================================================================
 * Scripted sensor
 * ================================================================ */

typedef struct
{
  /* what the sensor answers */
  GBytes  *rom;                 /* 01 */
  GBytes  *fw;                  /* 43 02 */
  guint8   init_reply[2];       /* 06<init> */
  gboolean init_reply_lost;     /* the IN transfer after the init fails */

  /* the in-memory data package */
  GBytes *blobs[VALIDITY_DATA_NUM_TAGS];
  gchar  *init_sha256;          /* digest the init check accepts */

  /* what happened */
  GString  *wire;               /* one token per OUT command */
  GBytes   *pending;            /* reply for the next IN transfer */
  gboolean  pending_error;
  guint     init_sent;
  guint     init_checks;
  gboolean  unused_blobs_at_init; /* reset/clean_slate/dbwe still loaded */
  guint     resets;
  guint     opens;
  guint     liveness_checks;
  FpDevice *dev;
} A2tSensor;

static A2tSensor sensor;

#define SYNTH_INIT_LEN 581

static guint8 *
synth_init (guint8 seed)
{
  guint8 *b = g_malloc (SYNTH_INIT_LEN);

  b[0] = 0x06;
  for (gsize i = 1; i < SYNTH_INIT_LEN; i++)
    b[i] = (guint8) (i * 7 + seed);
  return b;
}

static void
sensor_reset (void)
{
  for (gsize i = 0; i < G_N_ELEMENTS (sensor.blobs); i++)
    g_clear_pointer (&sensor.blobs[i], g_bytes_unref);
  g_clear_pointer (&sensor.rom, g_bytes_unref);
  g_clear_pointer (&sensor.fw, g_bytes_unref);
  g_clear_pointer (&sensor.pending, g_bytes_unref);
  g_clear_pointer (&sensor.init_sha256, g_free);
  if (sensor.wire)
    g_string_free (sensor.wire, TRUE);
  memset (&sensor, 0, sizeof (sensor));

  sensor.wire = g_string_new ("");
  sensor.rom = g_bytes_new_static (real_01, sizeof (real_01));
  sensor.fw = g_bytes_new_static (real_4302, sizeof (real_4302));

  /* The package: a synthetic init the (renamed) pin accepts, and the
   * three blobs 00a2 must never keep */
  {
    guint8 *init = synth_init (1);

    sensor.init_sha256 = g_compute_checksum_for_data (G_CHECKSUM_SHA256, init,
                                                      SYNTH_INIT_LEN);
    sensor.blobs[VALIDITY_DATA_INIT] = g_bytes_new_take (init, SYNTH_INIT_LEN);
  }
  sensor.blobs[VALIDITY_DATA_RESET] = g_bytes_new_static ("\x06R", 2);
  sensor.blobs[VALIDITY_DATA_INIT_CLEAN_SLATE] = g_bytes_new_static ("\x06C", 2);
  sensor.blobs[VALIDITY_DATA_DB_WRITE_ENABLE] = g_bytes_new_static ("\x06W", 2);
}

static gchar *
wire_take (void)
{
  gchar *w = g_strstrip (g_strdup (sensor.wire->str));

  g_string_truncate (sensor.wire, 0);
  return w;
}

typedef struct
{
  FpiUsbTransfer        *transfer;
  FpiUsbTransferCallback callback;
  gpointer               user_data;
  GError                *error;
} A2tDone;

static gboolean
a2t_done_idle (gpointer data)
{
  A2tDone *d = data;

  d->callback (d->transfer, d->transfer->device, d->user_data, d->error);
  fpi_usb_transfer_unref (d->transfer);
  g_free (d);
  return G_SOURCE_REMOVE;
}

static GError *
io_error (const gchar *what)
{
  return g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO, what);
}

/* An OUT command: record it and prepare the reply */
static GError *
sensor_command (const guint8 *cmd,
                gsize         len)
{
  g_clear_pointer (&sensor.pending, g_bytes_unref);
  sensor.pending_error = FALSE;

  if (cmd[0] == 0x43 && len == 2)
    g_string_append (sensor.wire, "4302 ");
  else if (cmd[0] == 0x06)
    g_string_append_printf (sensor.wire, "06(%" G_GSIZE_FORMAT ") ", len);
  else
    g_string_append_printf (sensor.wire, "%02x ", cmd[0]);

  switch (cmd[0])
    {
    case 0x01:
      sensor.pending = g_bytes_ref (sensor.rom);
      return NULL;

    case 0x19:
      sensor.pending = g_bytes_new_static (real_19, sizeof (real_19));
      return NULL;

    case 0x43:
      sensor.pending = g_bytes_ref (sensor.fw);
      return NULL;

    case 0x06:
      sensor.init_sent++;
      sensor.pending = g_bytes_new (sensor.init_reply, 2);
      sensor.pending_error = sensor.init_reply_lost;
      return NULL;

    default:
      /* 3e, 40, ...: the end of the scripted part */
      return io_error ("scripted I/O error");
    }
}

/* An IN transfer: the prepared reply */
static GError *
sensor_reply (FpiUsbTransfer *transfer)
{
  gsize n = 0;
  const guint8 *p;

  if (sensor.pending_error || !sensor.pending)
    {
      transfer->actual_length = -1;
      return io_error ("scripted IN failure");
    }

  p = g_bytes_get_data (sensor.pending, &n);
  g_assert_cmpuint (n, <=, (gsize) transfer->length);
  memcpy (transfer->buffer, p, n);
  transfer->actual_length = n;
  g_clear_pointer (&sensor.pending, g_bytes_unref);
  return NULL;
}

void
a2t_usb_submit (FpiUsbTransfer        *transfer,
                guint                  timeout_ms,
                GCancellable          *cancellable,
                FpiUsbTransferCallback callback,
                gpointer               user_data)
{
  A2tDone *d = g_new0 (A2tDone, 1);

  /* Only the plain command endpoints are reachable before TLS */
  g_assert_cmpint (transfer->type, ==, FP_TRANSFER_BULK);
  d->transfer = transfer;
  d->callback = callback;
  d->user_data = user_data;

  if (transfer->endpoint == VALIDITY_EP_CMD_OUT)
    {
      d->error = sensor_command (transfer->buffer, transfer->length);
      transfer->actual_length = d->error ? -1 : transfer->length;
    }
  else
    {
      g_assert_cmpint (transfer->endpoint, ==, VALIDITY_EP_CMD_IN);
      d->error = sensor_reply (transfer);
    }

  g_idle_add (a2t_done_idle, d);
}

gboolean
a2t_usb_submit_sync (FpiUsbTransfer *transfer,
                     guint           timeout_ms,
                     GError        **error)
{
  GError *e;

  g_assert_cmpint (transfer->type, ==, FP_TRANSFER_BULK);
  if (transfer->endpoint == VALIDITY_EP_CMD_OUT)
    {
      e = sensor_command (transfer->buffer, transfer->length);
      transfer->actual_length = e ? -1 : transfer->length;
    }
  else
    {
      g_assert_cmpint (transfer->endpoint, ==, VALIDITY_EP_CMD_IN);
      e = sensor_reply (transfer);
    }

  if (e)
    {
      g_propagate_error (error, e);
      return FALSE;
    }
  return TRUE;
}

GUsbDevice *
a2t_get_usb_device (FpDevice *device)
{
  return NULL;
}

gboolean
a2t_usb_open (GUsbDevice *self, GError **error)
{
  sensor.opens++;
  return TRUE;
}

gboolean
a2t_usb_close (GUsbDevice *self, GError **error)
{
  return TRUE;
}

gboolean
a2t_usb_reset (GUsbDevice *self, GError **error)
{
  sensor.resets++;
  return TRUE;
}

gboolean
a2t_usb_claim (GUsbDevice *self, gint iface,
               GUsbDeviceClaimInterfaceFlags flags, GError **error)
{
  return TRUE;
}

gboolean
a2t_usb_release (GUsbDevice *self, gint iface,
                 GUsbDeviceClaimInterfaceFlags flags, GError **error)
{
  return TRUE;
}

gint
a2t_usb_get_configuration (GUsbDevice *self, GError **error)
{
  /* only the reconnect path asks (is the device alive?), which 00a2 never
   * takes; the tests check that it was not asked */
  sensor.liveness_checks++;
  g_set_error_literal (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE,
                       "not expected");
  return -1;
}

/* ================================================================
 * In-memory data package
 * ================================================================ */

gboolean
a2t_load_device (ValidityDataStore *store,
                 guint16            vid,
                 guint16            pid,
                 GError           **error)
{
  g_assert_cmphex (vid, ==, 0x06cb);
  g_assert_cmphex (pid, ==, 0x00a2);

  /* Like the real loader, minus the files: whatever the package has. A
   * missing init.bin is left to the open's own check. */
  for (gsize tag = VALIDITY_DATA_INIT; tag <= VALIDITY_DATA_DB_WRITE_ENABLE;
       tag++)
    if (sensor.blobs[tag])
      store->entries[tag] = g_bytes_ref (sensor.blobs[tag]);
  return TRUE;
}

gboolean
a2t_load_common (ValidityDataStore *store,
                 GError           **error)
{
  for (gsize tag = VALIDITY_DATA_PARTITION_SIG_STANDARD;
       tag < VALIDITY_DATA_NUM_TAGS; tag++)
    store->entries[tag] = g_bytes_new_static ("common", 6);
  return TRUE;
}

/* The init pin, with the synthetic package's digest instead of the real
 * one (test-validity.c checks the pinned values) */
gboolean
a2t_init_blob_ok (const guint8 *data,
                  gsize         len,
                  GError      **error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (sensor.dev);

  sensor.init_checks++;
  sensor.unused_blobs_at_init =
    self->device_data.entries[VALIDITY_DATA_RESET] != NULL ||
    self->device_data.entries[VALIDITY_DATA_INIT_CLEAN_SLATE] != NULL;

  return fpi_validity_a2_init_blob_check (data, len, SYNTH_INIT_LEN,
                                          sensor.init_sha256, error);
}

/* ================================================================
 * Test device: the validity driver as a virtual device
 * ================================================================ */

typedef struct
{
  FpiDeviceValidity parent;
} A2tDevice;
typedef struct
{
  FpiDeviceValidityClass parent_class;
} A2tDeviceClass;

static GType a2t_device_get_type (void);
G_DEFINE_TYPE (A2tDevice, a2t_device, FPI_TYPE_DEVICE_VALIDITY)

static const FpIdEntry a2t_ids[] = {
  { .virtual_envvar = "FP_VIRTUAL_VALIDITY_A2_TEST" },
  { .virtual_envvar = NULL }
};

/* Without a probe (most tests), take the type the way probe does */
static void
a2t_open (FpDevice *device)
{
  FPI_DEVICE_VALIDITY (device)->dev_type = fpi_device_get_driver_data (device);
  FP_DEVICE_CLASS (a2t_device_parent_class)->open (device);
}

static void
a2t_device_init (A2tDevice *self)
{
}

static void
a2t_device_class_init (A2tDeviceClass *klass)
{
  FpDeviceClass *dc = FP_DEVICE_CLASS (klass);

  dc->id = "validity-a2-test";
  dc->full_name = "validity 00a2 open test";
  dc->type = FP_DEVICE_TYPE_VIRTUAL;
  dc->id_table = a2t_ids;
  dc->open = a2t_open;
  fpi_device_class_auto_initialize_features (dc);
}

static FpDevice *
a2t_device_new (guint dev_type)
{
  FpDevice *dev = g_object_new (a2t_device_get_type (),
                                "fpi-driver-data", (guint64) dev_type,
                                NULL);

  sensor.dev = dev;
  return dev;
}

/* Open once; the error (NULL on success) and the wire */
static GError *
open_once (FpDevice *dev,
           gchar   **wire)
{
  GError *error = NULL;

  sensor.init_sent = 0;
  sensor.init_checks = 0;
  g_string_truncate (sensor.wire, 0);
  if (!fp_device_open_sync (dev, NULL, &error))
    g_assert_nonnull (error);
  *wire = wire_take ();
  return error;
}

static GBytes *
mutated_01 (gsize  idx,
            guint8 val)
{
  guint8 *r = g_memdup2 (real_01, sizeof (real_01));

  r[idx] = val;
  return g_bytes_new_take (r, sizeof (real_01));
}

static void
setup_real_open (void)
{
  sensor_reset ();
  g_unsetenv ("FP_DEVICE_EMULATION");
  g_unsetenv ("FP_VALIDITY_DMI_SERIAL_FILE");
}

/* ================================================================
 * Open
 * ================================================================ */

/* The real replies: the gates pass, the pinned init goes out once and is
 * accepted, the blobs 00a2 never sends were dropped before it; the open
 * then ends at the first unscripted command. Every open USB-resets the
 * sensor first (it keeps a closed TLS session in RAM otherwise), so a
 * second open on the same instance sends the init again. */
static void
test_open_real_replies (void)
{
  g_autoptr(FpDevice) dev = NULL;
  g_autofree gchar *w1 = NULL;
  g_autofree gchar *w2 = NULL;
  g_autoptr(GError) e1 = NULL;
  g_autoptr(GError) e2 = NULL;

  setup_real_open ();
  dev = a2t_device_new (VALIDITY_DEV_A2);

  e1 = open_once (dev, &w1);
  g_assert_cmpstr (w1, ==, "01 19 4302 06(581) 3e 40");
  g_assert_nonnull (e1);        /* at the scripted 40 */
  g_assert_cmpint (FPI_DEVICE_VALIDITY (dev)->init_state, ==,
                   VALIDITY_INIT_ACCEPTED);
  g_assert_cmpuint (sensor.init_sent, ==, 1);
  g_assert_cmpuint (sensor.init_checks, ==, 1);
  g_assert_false (sensor.unused_blobs_at_init);
  g_assert_cmpuint (sensor.resets, ==, 1);

  e2 = open_once (dev, &w2);
  g_assert_cmpstr (w2, ==, "01 19 4302 06(581) 3e 40");
  g_assert_cmpuint (sensor.init_sent, ==, 1);
  g_assert_cmpuint (sensor.init_checks, ==, 1);
  g_assert_nonnull (e2);
  g_assert_cmpint (FPI_DEVICE_VALIDITY (dev)->init_state, ==,
                   VALIDITY_INIT_ACCEPTED);
  g_assert_cmpuint (sensor.resets, ==, 2);
  g_assert_cmpuint (sensor.liveness_checks, ==, 0);
  sensor_reset ();
}

/* Any 01 reply but the supported state: refused, nothing sent after 01 */
static void
test_open_rom_gate (void)
{
  static const struct
  {
    gsize        idx;
    guint8       val;
    const gchar *what;
  } cases[] = {
    { 37, 0x02, "provisioning state is 2" },    /* blank */
    { 37, 0x06, "provisioning state is 6" },
    { 34, 0x02, "security state is 02 d1" },    /* not patched */
    { 17, 0x01, "byte 17 is 0x01" },            /* patch loaded */
    { 25, 0x03, "byte 25 is 0x03" },            /* no production key */
    { 11, 0x08, "ROM 6.8" },
    { 13, 0x31, "product 0x31" },
    { 12, 0x00, "byte 12 is 0x00" },
    { 0, 0x01, "status 0x0001" },
  };

  for (gsize i = 0; i <= G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(FpDevice) dev = NULL;
      g_autofree gchar *w = NULL;
      g_autoptr(GError) e = NULL;

      setup_real_open ();
      g_clear_pointer (&sensor.rom, g_bytes_unref);
      if (i < G_N_ELEMENTS (cases))
        sensor.rom = mutated_01 (cases[i].idx, cases[i].val);
      else
        sensor.rom = g_bytes_new (real_01, sizeof (real_01) - 1);
      dev = a2t_device_new (VALIDITY_DEV_A2);

      e = open_once (dev, &w);
      g_assert_cmpstr (w, ==, "01");
      g_assert_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
      if (i < G_N_ELEMENTS (cases))
        g_assert_nonnull (strstr (e->message, cases[i].what));
      else
        g_assert_nonnull (strstr (e->message, "37 bytes"));
      g_assert_cmpuint (sensor.init_checks, ==, 0);
      g_assert_cmpint (FPI_DEVICE_VALIDITY (dev)->init_state, ==,
                       VALIDITY_INIT_NOT_SENT);
    }
  sensor_reset ();
}

/* 43 02 without a fwext (wire b0 04) or with another error: refused
 * before the init */
static void
test_open_fwext_gate (void)
{
  static const guint8 replies[][2] = { { 0xb0, 0x04 }, { 0x01, 0x04 } };

  for (gsize i = 0; i < G_N_ELEMENTS (replies); i++)
    {
      g_autoptr(FpDevice) dev = NULL;
      g_autofree gchar *w = NULL;
      g_autoptr(GError) e = NULL;

      setup_real_open ();
      g_clear_pointer (&sensor.fw, g_bytes_unref);
      sensor.fw = g_bytes_new (replies[i], 2);
      dev = a2t_device_new (VALIDITY_DEV_A2);

      e = open_once (dev, &w);
      g_assert_cmpstr (w, ==, "01 19 4302");
      g_assert_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
      g_assert_cmpuint (sensor.init_checks, ==, 0);
    }
  sensor_reset ();
}

/* An init blob that is not the pinned one (here: another synthetic blob),
 * or none at all: refused before anything is sent after 43 02, and the
 * instance may still try again later (nothing was sent) */
static void
test_open_init_pin (void)
{
  for (gint variant = 0; variant < 2; variant++)
    {
      g_autoptr(FpDevice) dev = NULL;
      g_autofree gchar *w = NULL;
      g_autoptr(GError) e = NULL;

      setup_real_open ();
      g_clear_pointer (&sensor.blobs[VALIDITY_DATA_INIT], g_bytes_unref);
      if (variant == 0)
        sensor.blobs[VALIDITY_DATA_INIT] = g_bytes_new_take (synth_init (2),
                                                             SYNTH_INIT_LEN);
      dev = a2t_device_new (VALIDITY_DEV_A2);

      e = open_once (dev, &w);
      g_assert_cmpstr (w, ==, "01 19 4302");
      g_assert_cmpuint (sensor.init_sent, ==, 0);
      g_assert_cmpint (FPI_DEVICE_VALIDITY (dev)->init_state, ==,
                       VALIDITY_INIT_NOT_SENT);
      if (variant == 0)
        {
          g_assert_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
          g_assert_cmpuint (sensor.init_checks, ==, 1);
        }
      else
        {
          g_assert_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND);
          g_assert_cmpuint (sensor.init_checks, ==, 0);
        }
    }
  sensor_reset ();
}

/* The sensor rejects the init (04be) or its reply is lost: the open fails,
 * and a later open on the same instance refuses without sending it again
 * (or anything after 43 02) */
static void
test_open_init_rejected_or_lost (void)
{
  for (gint lost = 0; lost <= 1; lost++)
    {
      g_autoptr(FpDevice) dev = NULL;
      g_autofree gchar *w1 = NULL;
      g_autofree gchar *w2 = NULL;
      g_autoptr(GError) e1 = NULL;
      g_autoptr(GError) e2 = NULL;

      setup_real_open ();
      if (lost)
        {
          sensor.init_reply_lost = TRUE;
        }
      else
        {
          sensor.init_reply[0] = 0xbe;
          sensor.init_reply[1] = 0x04;
        }
      dev = a2t_device_new (VALIDITY_DEV_A2);

      e1 = open_once (dev, &w1);
      g_assert_cmpstr (w1, ==, "01 19 4302 06(581)");
      g_assert_nonnull (e1);
      if (!lost)
        g_assert_nonnull (strstr (e1->message, "0x04be"));
      g_assert_cmpint (FPI_DEVICE_VALIDITY (dev)->init_state, ==,
                       lost ? VALIDITY_INIT_SENT : VALIDITY_INIT_REJECTED);

      e2 = open_once (dev, &w2);
      g_assert_cmpstr (w2, ==, "01 19 4302");
      g_assert_cmpuint (sensor.init_sent, ==, 0);
      g_assert_nonnull (e2);
      g_assert_nonnull (strstr (e2->message, lost ? "no reply" : "rejected"));
      /* one reset per open; the refusal still holds after the reset */
      g_assert_cmpuint (sensor.resets, ==, 2);
      g_assert_cmpuint (sensor.liveness_checks, ==, 0);
    }
  sensor_reset ();
}

/* ================================================================
 * Probe
 * ================================================================ */

typedef struct
{
  gboolean done;
  GError  *error;
} ProbeResult;

static void
probe_done_cb (GObject      *source,
               GAsyncResult *res,
               gpointer      user_data)
{
  ProbeResult *r = user_data;

  g_async_initable_init_finish (G_ASYNC_INITABLE (source), res, &r->error);
  r->done = TRUE;
}

/* What FpContext does for a new device: GAsyncInitable -> FpDevice::probe */
static GError *
probe_once (FpDevice *dev)
{
  ProbeResult r = { 0 };

  g_async_initable_init_async (G_ASYNC_INITABLE (dev), G_PRIORITY_DEFAULT,
                               NULL, probe_done_cb, &r);
  while (!r.done)
    g_main_context_iteration (NULL, TRUE);
  return r.error;
}

/* Probe USB-resets the sensor and sends 01 and nothing else (00a2 as the
 * other models: it clears a TLS session left in the sensor's RAM); 00a2 advertises neither storage delete nor clear,
 * and image capture only in a developer build */
static void
test_probe (void)
{
  for (gint permissive = 0; permissive <= 1; permissive++)
    {
      g_autoptr(FpDevice) dev = NULL;
      g_autoptr(GError) error = NULL;
      g_autofree gchar *w = NULL;
      FpDeviceFeature f;

      setup_real_open ();
      dev = a2t_device_new (permissive ? VALIDITY_DEV_9A : VALIDITY_DEV_A2);

      error = probe_once (dev);
      g_assert_no_error (error);
      w = wire_take ();
      g_assert_cmpstr (w, ==, "01");
      g_assert_cmpuint (sensor.opens, ==, 1);
      g_assert_cmpuint (sensor.resets, ==, 1);
      g_assert_cmpstr (fp_device_get_device_id (dev), ==, "bcbb8b684961");

      f = fp_device_get_features (dev);
      g_assert_true (f & FP_DEVICE_FEATURE_IDENTIFY);
      g_assert_true (f & FP_DEVICE_FEATURE_VERIFY);
      g_assert_true (f & FP_DEVICE_FEATURE_STORAGE);
      g_assert_true (f & FP_DEVICE_FEATURE_STORAGE_LIST);
      g_assert_true (!!(f & FP_DEVICE_FEATURE_STORAGE_DELETE) == permissive);
      g_assert_true (!!(f & FP_DEVICE_FEATURE_STORAGE_CLEAR) == permissive);
      g_assert_true (!!(f & FP_DEVICE_FEATURE_CAPTURE) ==
                     (!permissive && fpi_validity_dev_overrides_built ()));
    }
  sensor_reset ();
}

/* ================================================================
 * Actions 00a2 refuses
 * ================================================================ */

/* In emulation the open stops after the gates (01, 19, 43 02) and keeps
 * an in-memory store. Enroll, clear_storage and delete must still be
 * refused by the driver, before the emulation branch and without a
 * command. Without a probe all features are advertised, so the calls
 * reach the driver. */
static void
test_actions_refused (void)
{
  g_autoptr(FpDevice) dev = NULL;
  g_autoptr(FpPrint) template = NULL;
  g_autoptr(FpPrint) print = NULL;
  g_autofree gchar *w = NULL;
  g_autoptr(GError) error = NULL;

  setup_real_open ();
  g_setenv ("FP_DEVICE_EMULATION", "1", TRUE);
  dev = a2t_device_new (VALIDITY_DEV_A2);

  g_assert_true (fp_device_open_sync (dev, NULL, &error));
  g_assert_no_error (error);
  w = wire_take ();
  g_assert_cmpstr (w, ==, "01 19 4302");
  g_assert_true (fp_device_has_feature (dev, FP_DEVICE_FEATURE_STORAGE_DELETE));

  template = g_object_ref_sink (fp_print_new (dev));
  fp_print_set_finger (template, FP_FINGER_RIGHT_INDEX);
  print = fp_device_enroll_sync (dev, template, NULL, NULL, NULL, &error);
  g_assert_null (print);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_assert_nonnull (strstr (error->message, "db_write_enable.bin"));
  g_clear_error (&error);

  g_assert_false (fp_device_clear_storage_sync (dev, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  g_assert_nonnull (strstr (error->message, "Clearing the sensor storage"));
  g_clear_error (&error);

  g_assert_false (fp_device_delete_print_sync (dev, template, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  g_assert_nonnull (strstr (error->message, "Deleting prints"));
  g_clear_error (&error);

  g_clear_pointer (&w, g_free);
  w = wire_take ();
  g_assert_cmpstr (w, ==, "");

  g_assert_true (fp_device_close_sync (dev, NULL, &error));
  g_assert_no_error (error);
  g_unsetenv ("FP_DEVICE_EMULATION");
  sensor_reset ();
}

/* After a probe, delete and clear are not advertised, so the core does not
 * call the driver at all (delete is a no-op, clear is refused) */
static void
test_actions_not_advertised (void)
{
  g_autoptr(FpDevice) dev = NULL;
  g_autoptr(FpPrint) template = NULL;
  g_autofree gchar *w = NULL;
  g_autoptr(GError) error = NULL;

  setup_real_open ();
  dev = a2t_device_new (VALIDITY_DEV_A2);
  error = probe_once (dev);
  g_assert_no_error (error);
  w = wire_take ();
  g_assert_cmpstr (w, ==, "01");

  g_setenv ("FP_DEVICE_EMULATION", "1", TRUE);
  g_assert_true (fp_device_open_sync (dev, NULL, &error));
  g_assert_no_error (error);
  g_clear_pointer (&w, g_free);
  w = wire_take ();
  g_assert_cmpstr (w, ==, "01 19 4302");

  template = g_object_ref_sink (fp_print_new (dev));
  g_assert_true (fp_device_delete_print_sync (dev, template, NULL, &error));
  g_assert_no_error (error);
  g_assert_false (fp_device_clear_storage_sync (dev, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  g_clear_error (&error);
  g_clear_pointer (&w, g_free);
  w = wire_take ();
  g_assert_cmpstr (w, ==, "");

  g_assert_true (fp_device_close_sync (dev, NULL, &error));
  g_unsetenv ("FP_DEVICE_EMULATION");
  sensor_reset ();
}

/* ================================================================
 * Single open states that the scripted sensor cannot reach (they need a
 * TLS session): run one state function of the real open SSM and see where
 * it sends the SSM
 * ================================================================ */

typedef void (*OpenStateFunc) (FpiSsm            *ssm,
                               FpiDeviceValidity *self);

static struct
{
  gint          state;          /* the open state @func implements */
  OpenStateFunc func;
  gboolean      ran;
  gint          next_state;     /* -1: none (failed or completed) */
  gboolean      done;
  GError       *error;
} one;

static void
one_state_run (FpiSsm   *ssm,
               FpDevice *dev)
{
  if (!one.ran)
    {
      /* get to the state first, so that next/jump work as in the open */
      if (fpi_ssm_get_cur_state (ssm) != one.state)
        {
          fpi_ssm_jump_to_state (ssm, one.state);
          return;
        }
      one.ran = TRUE;
      one.func (ssm, FPI_DEVICE_VALIDITY (dev));
      return;
    }

  /* the function moved the SSM on: note where, and stop there */
  one.next_state = fpi_ssm_get_cur_state (ssm);
  fpi_ssm_mark_completed (ssm);
}

static void
one_state_done (FpiSsm   *ssm,
                FpDevice *dev,
                GError   *error)
{
  one.done = TRUE;
  one.error = error;
}

/* Returns the error the state failed with (NULL if it moved on or
 * completed); *next_state gets the state it moved to, or -1 */
static GError *
run_one_state (FpDevice     *dev,
               gint          state,
               OpenStateFunc func,
               gint         *next_state)
{
  FpiSsm *ssm;

  memset (&one, 0, sizeof (one));
  one.state = state;
  one.func = func;
  one.next_state = -1;
  ssm = fpi_ssm_new (dev, one_state_run, OPEN_NUM_STATES);
  FPI_DEVICE_VALIDITY (dev)->open_ssm = ssm;
  fpi_ssm_start (ssm, one_state_done);
  while (!one.done)
    g_main_context_iteration (NULL, TRUE);
  FPI_DEVICE_VALIDITY (dev)->open_ssm = NULL;
  *next_state = one.next_state;
  return one.error;
}

/* The sensor state the a2 capture code was written for (type 0x199, ROM
 * 6.7 capture setup, factory values and a calibration) */
static void
set_sensor_ready (FpiDeviceValidity *self,
                  gboolean           calibrated)
{
  const ValidityDeviceInfo *info = fpi_validity_device_info_lookup (0x0190, 0x006a);

  g_assert_nonnull (info);
  fpi_validity_tls_init (&self->tls);
  fpi_validity_sensor_state_init (&self->sensor);
  fpi_validity_capture_state_init (&self->capture);
  self->tls.secure_rx = TRUE;
  self->sensor.device_info = info;
  self->sensor.type_info = fpi_validity_sensor_type_info_lookup (info->type);
  self->sensor.real_sensor_type = info->type;
  g_assert_true (fpi_validity_capture_state_setup (&self->capture,
                                                   self->sensor.type_info,
                                                   info->type, 6, 7, NULL, 0));
  self->capture.factory_calibration_values = g_malloc0 (112);
  self->capture.factory_calibration_values_len = 112;
  if (calibrated)
    {
      self->capture.calib_data_len = 112 * 0x78;
      self->capture.calib_data = g_malloc0 (self->capture.calib_data_len);
    }
}

static void
clear_sensor (FpiDeviceValidity *self)
{
  fpi_validity_capture_state_clear (&self->capture);
  fpi_validity_sensor_state_clear (&self->sensor);
  fpi_validity_tls_free (&self->tls);
}

/* OPEN_DONE: with a session, 00a2 needs the calibrated 0x199 sensor */
static void
test_state_open_done (void)
{
  g_autoptr(FpDevice) dev = NULL;
  FpiDeviceValidity *self;
  gint next = 0;

  setup_real_open ();
  dev = a2t_device_new (VALIDITY_DEV_A2);
  self = FPI_DEVICE_VALIDITY (dev);
  self->dev_type = VALIDITY_DEV_A2;

  set_sensor_ready (self, TRUE);
  g_assert_no_error (run_one_state (dev, OPEN_DONE, open_done, &next));
  g_assert_cmpint (next, ==, -1);
  clear_sensor (self);

  /* not calibrated */
  set_sensor_ready (self, FALSE);
  {
    g_autoptr(GError) e = run_one_state (dev, OPEN_DONE, open_done, &next);

    g_assert_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  }
  clear_sensor (self);

  /* the other sensor type an FM-3380-001 can report (0xb5) */
  set_sensor_ready (self, TRUE);
  self->sensor.device_info = fpi_validity_device_info_lookup (0x0190, 0x005f);
  g_assert_nonnull (self->sensor.device_info);
  self->sensor.real_sensor_type = self->sensor.device_info->type;
  {
    g_autoptr(GError) e = run_one_state (dev, OPEN_DONE, open_done, &next);

    g_assert_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
    g_assert_nonnull (strstr (e->message, "not sensor type 0x199"));
  }
  clear_sensor (self);
  sensor_reset ();
}

/* Calibration (02 CALIBRATE) never starts for another sensor */
static void
test_state_calibrate_build (void)
{
  g_autoptr(FpDevice) dev = NULL;
  FpiDeviceValidity *self;
  gint next = 0;

  setup_real_open ();
  dev = a2t_device_new (VALIDITY_DEV_A2);
  self = FPI_DEVICE_VALIDITY (dev);
  self->dev_type = VALIDITY_DEV_A2;

  set_sensor_ready (self, FALSE);
  g_assert_no_error (run_one_state (dev, OPEN_CALIBRATE_BUILD,
                                    open_calibrate_build, &next));
  g_assert_cmpint (next, ==, OPEN_CALIBRATE_SEND);
  clear_sensor (self);

  set_sensor_ready (self, FALSE);
  self->sensor.real_sensor_type = 0x0969;     /* 0x199 profile, other silicon */
  {
    g_autoptr(GError) e = run_one_state (dev, OPEN_CALIBRATE_BUILD,
                                         open_calibrate_build, &next);

    g_assert_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
    g_assert_cmpint (next, ==, -1);
  }
  clear_sensor (self);
  g_assert_cmpstr (sensor.wire->str, ==, "");
  sensor_reset ();
}

/* No fwext upload, even if the open got there without one (the 43 02 gate
 * normally stops it first) */
static void
test_state_upload_fwext (void)
{
  g_autoptr(FpDevice) dev = NULL;
  FpiDeviceValidity *self;
  gint next = 0;

  setup_real_open ();
  dev = a2t_device_new (VALIDITY_DEV_A2);
  self = FPI_DEVICE_VALIDITY (dev);
  self->dev_type = VALIDITY_DEV_A2;
  fpi_validity_tls_init (&self->tls);
  self->tls.secure_rx = TRUE;
  self->fwext_loaded = FALSE;

  {
    g_autoptr(GError) e = run_one_state (dev, OPEN_UPLOAD_FWEXT,
                                         open_upload_fwext, &next);

    g_assert_error (e, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
    g_assert_nonnull (strstr (e->message, "never uploads"));
    g_assert_cmpint (next, ==, -1);
  }
  g_assert_cmpstr (sensor.wire->str, ==, "");

  self->fwext_loaded = TRUE;
  g_assert_no_error (run_one_state (dev, OPEN_UPLOAD_FWEXT,
                                    open_upload_fwext, &next));
  g_assert_cmpint (next, ==, OPEN_UPLOAD_FWEXT + 1);
  fpi_validity_tls_free (&self->tls);
  sensor_reset ();
}

/* ================================================================ */

/* The driver warns (fp_warn) on the error paths these tests drive on
 * purpose, so warnings of its log domain are not fatal here. Every other
 * warning still aborts, and so does every critical. */
static void
log_handler (const gchar   *log_domain,
             GLogLevelFlags log_level,
             const gchar   *message,
             gpointer       user_data)
{
  g_log_default_handler (log_domain, log_level, message, user_data);
  if ((log_level & G_LOG_LEVEL_WARNING) &&
      g_strcmp0 (log_domain, "libfprint-validity") != 0)
    {
      g_printerr ("Unexpected warning in log domain %s\n", log_domain);
      abort ();
    }
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_log_set_always_fatal (G_LOG_FATAL_MASK | G_LOG_LEVEL_CRITICAL);
  g_log_set_default_handler (log_handler, NULL);

  g_test_add_func ("/validity/a2-open/real-replies", test_open_real_replies);
  g_test_add_func ("/validity/a2-open/rom-gate", test_open_rom_gate);
  g_test_add_func ("/validity/a2-open/fwext-gate", test_open_fwext_gate);
  g_test_add_func ("/validity/a2-open/init-pin", test_open_init_pin);
  g_test_add_func ("/validity/a2-open/init-rejected-or-lost",
                   test_open_init_rejected_or_lost);
  g_test_add_func ("/validity/a2-open/probe", test_probe);
  g_test_add_func ("/validity/a2-open/actions-refused", test_actions_refused);
  g_test_add_func ("/validity/a2-open/actions-not-advertised",
                   test_actions_not_advertised);
  g_test_add_func ("/validity/a2-open/state/open-done", test_state_open_done);
  g_test_add_func ("/validity/a2-open/state/calibrate-build",
                   test_state_calibrate_build);
  g_test_add_func ("/validity/a2-open/state/upload-fwext",
                   test_state_upload_fwext);

  return g_test_run ();
}
