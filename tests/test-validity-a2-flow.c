/*
 * 06cb:00a2: the verify, identify and capture SSM of the validity driver,
 * run against a scripted sensor
 *
 * Copyright (C) 2026 libfprint contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * test-validity.c drives the pure flow of fpi_validity_a2_capture.c. This test
 * runs the driver code that performs it: fpi_validity_a2_verify.c (the SSM, the
 * EP 0x83 callback, cancellation, completion) is compiled into this file
 * with the TLS command send and the USB transfer renamed to the scripted
 * sensor below, and the actions go through the real FpDevice API and
 * validity_verify()/validity_identify(). The device object is
 * FP_DEVICE_TYPE_VIRTUAL; its open only sets the state a real open leaves
 * (TLS up, sensor 0x199 identified and calibrated). Nothing here can reach
 * a USB device.
 *
 * Wire notation: one token per TLS command (first byte), W = EP 0x83 wait
 * without a timeout (finger), Wt = EP 0x83 wait with the match timeout.
 */

#define fpi_vcsfw_tls_cmd_send a2f_tls_cmd_send
#define fpi_usb_transfer_submit a2f_usb_submit

#include "drivers/validity/validity_a2_verify.c"
#include "drivers/validity/validity_a2_enroll.c"

#undef fpi_vcsfw_tls_cmd_send
#undef fpi_usb_transfer_submit

#include <stdlib.h>
#include <string.h>
#include "fp-print.h"
#include "fpi-print.h"
#include "drivers/validity/validity_db.h"
#include "drivers/validity/validity_sensor.h"
#include "drivers/validity/validity_tls.h"

#define FRAME_PIXELS (112 * 112)
#define FRAME_LEN (12 + FRAME_PIXELS)
#define ID_RIGHT_INDEX "FP1-20260723-7-5E6F7A8B-alice"

/* ================================================================
 * Scripted sensor
 * ================================================================ */

typedef struct
{
  const guint8 (*events)[5];      /* EP 0x83 reports, in order */
  guint       n_events;
  gint        cancel_at_cmd;      /* cancel while the Nth command is in flight */
  gint        cancel_at_wait;     /* cancel when the Nth wait is submitted */
  gint        fail_cmd_at;        /* the Nth command fails (transport) */
  gint        fail_wait_at;       /* the Nth wait fails with... */
  gint        fail_wait_code;     /* ...this G_USB_DEVICE_ERROR (default IO) */
  guint16     status_5e;
  guint16     status_60;
  guint32     handle;
  guint32     frame_flags;
  gsize       chunk;              /* bytes per 51 reply (default 8192) */
  gboolean    bad_51_len;         /* 51 length field != data */
  guint16     status_51_second;   /* status of every second 51 */
  GByteArray *result60;
  GByteArray *user4a;
  gboolean    enroll_mode;
  gboolean    suspend_at_wait;
  guint32     free_space;
  gboolean    full_before_store;
  gboolean    missing_storage;
  gboolean    bad_info;
  gboolean    bad_readback;
  guint16     store_status;
  gboolean    short_store_reply;
  gboolean    uncalibrated;       /* open leaves no calibration */
} Scn;

static struct
{
  Scn      *scn;
  GString  *wire;
  guint     cmd_no;
  guint     cmd_sent;
  guint     wait_no;
  guint     ev_idx;
  gsize     read_off;
  guint     reads;
  guint     match_timeout_ms;   /* timeout of the first match wait */
  guint8   *frame;
  FpDevice *dev;
  GBytes   *identity;
  guint     db_queries;
  guint     stores;
  guint     users;
  guint     progress;
  guint     live_write_enable_blobs;
  gboolean  final_before_readback;
  gboolean  readback_done;
  gboolean  suspend_done;
  GError   *suspend_error;
} sim;

static void moh_test_start (FpDevice *device);
static void moh_progress (FpDevice *device,
                          gint      completed,
                          FpPrint  *print,
                          gpointer  user_data,
                          GError   *error);

static guint8
px (gsize i)
{
  return (guint8) ((i * 7 + 3) & 0xff);
}

static void
sim_make_frame (guint32 flags)
{
  g_free (sim.frame);
  sim.frame = g_malloc0 (FRAME_LEN);
  sim.frame[0] = 112;
  sim.frame[2] = 112;
  sim.frame[4] = 0x4d;
  sim.frame[5] = 0x01;
  sim.frame[6] = 8;
  sim.frame[8] = flags & 0xff;
  sim.frame[9] = (flags >> 8) & 0xff;
  sim.frame[10] = (flags >> 16) & 0xff;
  sim.frame[11] = (flags >> 24) & 0xff;
  for (gsize i = 0; i < FRAME_PIXELS; i++)
    sim.frame[12 + i] = px (i);
}

static void
put_u32 (GByteArray *a, guint32 v)
{
  guint8 b[4] = { v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, v >> 24 };

  g_byte_array_append (a, b, 4);
}

/* The sensor's reply to one TLS command */
static void
chip_reply (const guint8 *cmd,
            gsize         len,
            guint16      *status,
            GByteArray   *payload)
{
  *status = 0;

  switch (cmd[0])
    {
    case 0x02:
      /* a new capture program: the image starts again */
      sim.read_off = 0;
      sim.reads = 0;
      return;

    case 0x51:
      {
        gsize chunk = sim.scn->chunk ? sim.scn->chunk : 8192;
        gsize n = MIN (chunk, FRAME_LEN - sim.read_off);

        g_assert_cmpmem (cmd, len, "\x51\x00\x20\x00\x00", 5);
        sim.reads++;
        if (sim.reads % 2 == 0 && sim.scn->status_51_second)
          {
            *status = sim.scn->status_51_second;
            return;
          }
        put_u32 (payload, (guint32) n);
        g_byte_array_append (payload, sim.frame + sim.read_off,
                             sim.scn->bad_51_len ? n - 1 : n);
        sim.read_off += n;
        return;
      }

    case 0x5e:
      g_assert_cmpmem (cmd, len,
                       "\x5e\x02\xff\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00", 13);
      *status = sim.scn->status_5e;
      if (*status == 0)
        put_u32 (payload, sim.scn->handle);
      return;

    case 0x60:
    case 0x62:
      {
        guint32 h = cmd[1] | (cmd[2] << 8) | (cmd[3] << 16) | ((guint32) cmd[4] << 24);

        g_assert_cmpuint (len, ==, 5);
        /* 60 and 62 carry the handle 5e returned (0 if it was refused) */
        g_assert_cmphex (h, ==, sim.scn->status_5e ? 0 : sim.scn->handle);
        if (cmd[0] == 0x60)
          {
            *status = sim.scn->status_60;
            if (*status == 0 && sim.scn->result60)
              g_byte_array_append (payload, sim.scn->result60->data,
                                   sim.scn->result60->len);
          }
        return;
      }

    case 0x06:
      g_assert_true (sim.scn->enroll_mode);
      return;

    case 0x45:
      {
        guint32 space = sim.scn->free_space ? sim.scn->free_space : 523264;
        sim.db_queries++;
        if (sim.scn->bad_info)
          return;
        if (sim.scn->full_before_store && sim.db_queries == 2)
          space = 1024;
        put_u32 (payload, 1);
        put_u32 (payload, 0);
        put_u32 (payload, 524288);
        put_u32 (payload, 524288 - space);
        put_u32 (payload, space);
        g_byte_array_append (payload, (const guint8 *) "\x02\x00\x00\x00", 4);
        return;
      }

    case 0x4b:
      {
        const guint8 hdr[] = { 0x23, 1, 0, 0, 11, 0, 0, 0 };
        if (sim.scn->missing_storage)
          {
            *status = 0x04b3;
            return;
          }
        g_byte_array_append (payload, hdr, sizeof hdr);
        g_byte_array_append (payload, (const guint8 *) "StgWindsor", 11);
        return;
      }

    case 0x47:
      {
        guint16 type = cmd[3] | (cmd[4] << 8);
        guint16 parent = cmd[1] | (cmd[2] << 8);
        guint16 storage = cmd[5] | (cmd[6] << 8);
        guint16 size = cmd[7] | (cmd[8] << 8);
        g_assert_cmpuint (storage, ==, 0x123);
        if (type == 5)
          {
            sim.users++;
            g_assert_cmpuint (parent, ==, 0x123);
            g_assert_cmpuint (len, ==, 9 + size);
            g_clear_pointer (&sim.identity, g_bytes_unref);
            sim.identity = g_bytes_new (cmd + 9, size);
            g_byte_array_append (payload, (const guint8 *) "\x34\x02", 2);
          }
        else
          {
            sim.stores++;
            g_assert_cmpuint (sim.stores, ==, 1);
            g_assert_cmpuint (type, ==, 6);
            g_assert_cmpuint (parent, ==, 0x234);
            g_assert_cmpuint (size, ==, VALIDITY_MOH_ENVELOPE_SIZE);
            g_assert_cmpuint (len, ==, 9 + size + 1);
            g_assert_cmpuint (cmd[len - 1], ==, 0);
            *status = sim.scn->store_status;
            if (!sim.scn->short_store_reply)
              g_byte_array_append (payload, (const guint8 *) "\x45\x03", 2);
          }
        return;
      }

    case 0x1a:
      return;

    case 0x4a:
      if (sim.scn->enroll_mode)
        {
          gsize n;
          const guint8 *id = g_bytes_get_data (sim.identity, &n);
          guint16 subtype = fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX);
          guint8 hdr[] = { 0x34, 2, 1, 0, 0, 0, n & 255, n >> 8 };
          guint8 finger[] = { 0x45, 3, subtype & 255, subtype >> 8, 0x23, 1, 0x60, 0x5a };
          sim.readback_done = TRUE;
          if (sim.scn->bad_readback)
            finger[0]++;
          g_byte_array_append (payload, hdr, sizeof hdr);
          g_byte_array_append (payload, finger, sizeof finger);
          g_byte_array_append (payload, id, n);
          return;
        }
      if (sim.scn->user4a)
        g_byte_array_append (payload, sim.scn->user4a->data,
                             sim.scn->user4a->len);
      return;

    case 0x39:
    case 0x04:
      return;

    default:
      g_error ("the 00a2 flow sent an unexpected command 0x%02x", cmd[0]);
    }
}

static gboolean
cancel_action_idle (gpointer data)
{
  GCancellable *c = fpi_device_get_cancellable (FP_DEVICE (data));

  g_assert_nonnull (c);
  g_cancellable_cancel (c);
  return G_SOURCE_REMOVE;
}

static void
suspend_done_cb (GObject *device, GAsyncResult *result, gpointer data)
{
  fp_device_suspend_finish (FP_DEVICE (device), result, &sim.suspend_error);
  sim.suspend_done = TRUE;
}

static gboolean
suspend_action_idle (gpointer data)
{
  fp_device_suspend (FP_DEVICE (data), NULL, suspend_done_cb, NULL);
  return G_SOURCE_REMOVE;
}

typedef struct
{
  FpiDeviceValidity *self;
  FpiSsm            *parent;
  GBytes            *cmd;
} TlsPending;

static gboolean
tls_pending_done (gpointer data)
{
  TlsPending *p = data;
  gsize len = 0;
  const guint8 *cmd = g_bytes_get_data (p->cmd, &len);
  guint16 status = 0;

  g_autoptr(GByteArray) payload = g_byte_array_new ();
  FpiDeviceValidity *self = p->self;

  sim.cmd_no++;
  g_string_append_printf (sim.wire, "%02x ", cmd[0]);

  if (sim.scn->fail_cmd_at == (gint) sim.cmd_no)
    {
      fpi_ssm_mark_failed (p->parent,
                           g_error_new_literal (G_USB_DEVICE_ERROR,
                                                G_USB_DEVICE_ERROR_IO,
                                                "scripted I/O error"));
    }
  else
    {
      chip_reply (cmd, len, &status, payload);
      self->cmd_response_status = status;
      g_clear_pointer (&self->cmd_response_data, g_free);
      self->cmd_response_len = payload->len;
      if (payload->len > 0)
        self->cmd_response_data = g_memdup2 (payload->data, payload->len);
      fpi_ssm_next_state (p->parent);
    }

  g_bytes_unref (p->cmd);
  g_free (p);
  return G_SOURCE_REMOVE;
}

/* Replaces vcsfw_tls_cmd_send(): the reply arrives from the main loop, as
 * over USB, then the SSM moves to its RECV state */
void
a2f_tls_cmd_send (FpiDeviceValidity *self,
                  FpiSsm            *parent_ssm,
                  const guint8      *cmd,
                  gsize              cmd_len,
                  VcsfwCmdCallback   callback)
{
  TlsPending *p = g_new0 (TlsPending, 1);

  g_assert_null (callback);
  g_assert_nonnull (parent_ssm);
  sim.cmd_sent++;
  if (sim.scn->cancel_at_cmd == (gint) sim.cmd_sent)
    g_idle_add (cancel_action_idle, sim.dev);
  p->self = self;
  p->parent = parent_ssm;
  p->cmd = g_bytes_new (cmd, cmd_len);
  g_idle_add (tls_pending_done, p);
}

typedef struct
{
  FpiUsbTransfer        *transfer;
  FpiUsbTransferCallback cb;
  gpointer               user_data;
  GCancellable          *cancellable;
  gulong                 handler;
  guint                  timeout_src;
  gboolean               done;
  guint8                 report[5];
} EvPending;

static void
ev_finish (EvPending *p,
           GError    *error)
{
  if (p->done)
    {
      g_clear_error (&error);
      return;
    }
  p->done = TRUE;
  if (p->handler && p->cancellable)
    g_cancellable_disconnect (p->cancellable, p->handler);
  if (p->timeout_src)
    g_source_remove (p->timeout_src);

  if (error)
    {
      p->transfer->actual_length = -1;
    }
  else
    {
      memcpy (p->transfer->buffer, p->report, 5);
      p->transfer->actual_length = 5;
    }
  p->cb (p->transfer, p->transfer->device, p->user_data, error);
  fpi_usb_transfer_unref (p->transfer);
  g_clear_object (&p->cancellable);
  /* a cancel handler may still be queued; it sees done and returns */
}

static gboolean
ev_deliver_idle (gpointer data)
{
  ev_finish (data, NULL);
  g_free (data);
  return G_SOURCE_REMOVE;
}

static gboolean
ev_error_idle (gpointer data)
{
  EvPending *p = data;
  gint code = sim.scn->fail_wait_code ? sim.scn->fail_wait_code :
              G_USB_DEVICE_ERROR_IO;

  ev_finish (p, g_error_new_literal (G_USB_DEVICE_ERROR, code,
                                     "scripted interrupt error"));
  g_free (p);
  return G_SOURCE_REMOVE;
}

static gboolean
ev_cancel_idle (gpointer data)
{
  EvPending *p = data;

  ev_finish (p, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                     "Transfer was cancelled"));
  g_free (p);
  return G_SOURCE_REMOVE;
}

static gboolean
ev_timeout_cb (gpointer data)
{
  EvPending *p = data;

  p->timeout_src = 0;
  ev_finish (p, g_error_new_literal (G_USB_DEVICE_ERROR,
                                     G_USB_DEVICE_ERROR_TIMED_OUT,
                                     "Transfer timed out"));
  g_free (p);
  return G_SOURCE_REMOVE;
}

static void
ev_cancelled_cb (GCancellable *c,
                 gpointer      data)
{
  EvPending *p = data;

  /* deliver from the main loop; the timeout source (if any) is removed
   * there, and the pending struct is freed by whichever finishes it */
  if (p->timeout_src)
    {
      g_source_remove (p->timeout_src);
      p->timeout_src = 0;
    }
  g_idle_add (ev_cancel_idle, p);
}

/* Replaces fpi_usb_transfer_submit() for the EP 0x83 waits */
void
a2f_usb_submit (FpiUsbTransfer        *transfer,
                guint                  timeout_ms,
                GCancellable          *cancellable,
                FpiUsbTransferCallback callback,
                gpointer               user_data)
{
  EvPending *p = g_new0 (EvPending, 1);

  g_assert_cmpint (transfer->type, ==, FP_TRANSFER_INTERRUPT);
  g_assert_cmpuint (transfer->endpoint, ==, VALIDITY_EP_INT_IN);

  sim.wait_no++;
  if (sim.scn->suspend_at_wait && sim.wait_no == 2)
    g_idle_add (suspend_action_idle, sim.dev);
  g_string_append_printf (sim.wire, "W%s ", timeout_ms ? "t" : "");
  if (timeout_ms && !sim.match_timeout_ms)
    sim.match_timeout_ms = timeout_ms;
  p->transfer = transfer;
  p->cb = callback;
  p->user_data = user_data;
  p->cancellable = cancellable ? g_object_ref (cancellable) : NULL;

  if (sim.scn->cancel_at_wait == (gint) sim.wait_no)
    g_idle_add (cancel_action_idle, sim.dev);

  if (cancellable && g_cancellable_is_cancelled (cancellable))
    {
      g_idle_add (ev_cancel_idle, p);
      return;
    }

  if (sim.scn->fail_wait_at == (gint) sim.wait_no)
    {
      g_idle_add (ev_error_idle, p);
      return;
    }

  if (sim.ev_idx < sim.scn->n_events)
    {
      memcpy (p->report, sim.scn->events[sim.ev_idx++], 5);
      g_idle_add (ev_deliver_idle, p);
      return;
    }

  /* nothing scripted: silent until cancelled or timed out (scaled down
   * 100x so the 10 s match timeout takes 100 ms) */
  if (cancellable)
    p->handler = g_cancellable_connect (cancellable,
                                        G_CALLBACK (ev_cancelled_cb), p, NULL);
  if (timeout_ms)
    p->timeout_src = g_timeout_add (MAX (1, timeout_ms / 100), ev_timeout_cb, p);
}

/* ================================================================
 * Test device: the validity driver as a virtual device, opened into the
 * state a real 00a2 open leaves
 * ================================================================ */

typedef struct
{
  FpiDeviceValidity parent;
} A2fDevice;
typedef struct
{
  FpiDeviceValidityClass parent_class;
} A2fDeviceClass;

static GType a2f_device_get_type (void);
G_DEFINE_TYPE (A2fDevice, a2f_device, FPI_TYPE_DEVICE_VALIDITY)

static const FpIdEntry a2f_ids[] = {
  { .virtual_envvar = "FP_VIRTUAL_VALIDITY_A2_FLOW_TEST" },
  { .virtual_envvar = NULL }
};

static void
a2f_open (FpDevice *device)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (device);
  const ValidityDeviceInfo *info = fpi_validity_device_info_lookup (0x0190, 0x006a);

  fpi_validity_tls_init (&self->tls);
  fpi_validity_sensor_state_init (&self->sensor);
  fpi_validity_capture_state_init (&self->capture);

  self->dev_type = VALIDITY_DEV_A2;
  self->tls.secure_rx = TRUE;
  g_assert_nonnull (info);
  self->sensor.device_info = info;
  self->sensor.type_info = fpi_validity_sensor_type_info_lookup (info->type);
  self->sensor.real_sensor_type = info->type;
  g_assert_true (fpi_validity_capture_state_setup (&self->capture,
                                                   self->sensor.type_info,
                                                   info->type, 6, 7, NULL, 0));
  self->capture.factory_calibration_values = g_malloc0 (112);
  self->capture.factory_calibration_values_len = 112;
  if (!sim.scn->uncalibrated)
    {
      self->capture.calib_data_len = 8 + 112 * 0x78;
      self->capture.calib_data = g_malloc0 (self->capture.calib_data_len);
    }

  fpi_device_open_complete (device, NULL);
}

static void
a2f_close (FpDevice *device)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (device);

  g_clear_pointer (&self->cmd_response_data, g_free);
  self->cmd_response_len = 0;
  fpi_validity_capture_state_clear (&self->capture);
  fpi_validity_sensor_state_clear (&self->sensor);
  fpi_validity_tls_free (&self->tls);
  fpi_validity_data_store_free (&self->device_data);
  fpi_validity_data_store_free (&self->common_data);
  fpi_device_close_complete (device, NULL);
}

static void
a2f_device_init (A2fDevice *self)
{
}

static void
a2f_device_class_init (A2fDeviceClass *klass)
{
  FpDeviceClass *dc = FP_DEVICE_CLASS (klass);

  dc->id = "validity-a2-flow-test";
  dc->full_name = "validity 00a2 flow test";
  dc->type = FP_DEVICE_TYPE_VIRTUAL;
  dc->id_table = a2f_ids;
  dc->enroll = moh_test_start;
  dc->open = a2f_open;
  dc->close = a2f_close;
  fpi_device_class_auto_initialize_features (dc);
}

/* ================================================================
 * Running an action
 * ================================================================ */

static const guint8 EV_START[5] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
static const guint8 EV_FINGER[5] = { 0x02, 0x00, 0x40, 0x10, 0x00 };
static const guint8 EV_READY[5] = { 0x03, 0x42, 0x04, 0x00, 0x40 };
static const guint8 EV_NOMATCH[5] = { 0x04, 0x00, 0x00, 0x00, 0xdb };
static const guint8 EV_MATCH[5] = { 0x03, 0x00, 0x00, 0x00, 0xdb };
static const guint8 EV_BAD0[5] = { 0x03, 0x00, 0x00, 0x00, 0x00 };
static const guint8 EV_ABORT[5] = { 0x03, 0x00, 0x06, 0x00, 0x00 };

/* 00, 02 finger, 03 code 1 (waiting), 03 code 4 (ready): both 03 reports
 * as seen on 00a2 */
static const guint8 capture_evs[4][5] = {
  { 0x00, 0x00, 0x00, 0x00, 0x00 }, { 0x02, 0x00, 0x40, 0x10, 0x00 },
  { 0x03, 0x40, 0x01, 0x00, 0x00 }, { 0x03, 0x42, 0x04, 0x00, 0x40 },
};

typedef enum { ACT_VERIFY, ACT_IDENTIFY, ACT_CAPTURE, ACT_ENROLL } Act;

typedef struct
{
  gboolean ok;
  gboolean match;
  FpPrint *matched;
  FpImage *image;
  GError  *error;
  gchar   *wire;
} Res;

static void
res_clear (Res *r)
{
  g_clear_object (&r->matched);
  g_clear_object (&r->image);
  g_clear_error (&r->error);
  g_clear_pointer (&r->wire, g_free);
  memset (r, 0, sizeof (*r));
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (Res, res_clear)

static GByteArray *
make_result60 (guint32 user_dbid, guint32 tag2, guint16 subtype)
{
  GByteArray *a = g_byte_array_new ();
  guint8 zero[32] = { 0 };
  guint8 u[4] = { user_dbid & 0xff, (user_dbid >> 8) & 0xff, 0, 0 };
  guint8 t2[4] = { tag2 & 0xff, (tag2 >> 8) & 0xff, 0, 0 };
  guint8 st[2] = { subtype & 0xff, subtype >> 8 };

  const struct
  {
    guint16     tag;
    const void *v;
    guint16     len;
  } tags[] = {
    { 1, u, 4 }, { 2, t2, 4 }, { 3, st, 2 }, { 4, zero, 32 }, { 5, zero, 32 },
    { 7, zero, 16 }, { 8, zero, 2 },
  };
  guint16 total;

  g_byte_array_append (a, (const guint8 *) "\0\0", 2);
  for (gsize i = 0; i < G_N_ELEMENTS (tags); i++)
    {
      guint8 h[4] = { tags[i].tag & 0xff, tags[i].tag >> 8,
                      tags[i].len & 0xff, tags[i].len >> 8 };

      g_byte_array_append (a, h, 4);
      g_byte_array_append (a, tags[i].v, tags[i].len);
    }
  total = a->len - 2;
  a->data[0] = total & 0xff;
  a->data[1] = total >> 8;
  return a;
}

static GByteArray *
make_user4a (guint16 subtype)
{
  GByteArray *r = g_byte_array_new ();
  gsize identity_len = 0;
  g_autofree guint8 *identity = fpi_validity_db_build_identity (ID_RIGHT_INDEX,
                                                                &identity_len);
  guint8 h[8] = { 8, 0, 1, 0, 0, 0, identity_len & 0xff, identity_len >> 8 };
  guint8 f[8] = { 9, 0, subtype & 0xff, subtype >> 8, 3, 0, 0, 0 };

  g_byte_array_append (r, h, 8);
  g_byte_array_append (r, f, 8);
  g_byte_array_append (r, identity, identity_len);
  return r;
}

static void
scn_clear (Scn *s)
{
  g_clear_pointer (&s->result60, g_byte_array_unref);
  g_clear_pointer (&s->user4a, g_byte_array_unref);
}

static void
sim_reset_counters (void)
{
  sim.cmd_no = 0;
  sim.cmd_sent = 0;
  sim.wait_no = 0;
  sim.ev_idx = 0;
  sim.read_off = 0;
  sim.reads = 0;
  sim.match_timeout_ms = 0;
}

/* Open the test device, run @act @repeat times (the result of the last
 * run in @res, the wire of all runs separated by "|"), close */
static void
run (Scn     *scn,
     Act      act,
     gboolean empty_gallery,
     gint     repeat,
     Res     *res)
{
  g_autoptr(FpDevice) dev = g_object_new (a2f_device_get_type (), NULL);
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  g_autoptr(FpPrint) print = NULL;
  g_autoptr(GPtrArray) gallery = NULL;
  g_autoptr(GError) error = NULL;

  if (sim.wire)
    g_string_free (sim.wire, TRUE);
  memset (&sim, 0, sizeof (sim));
  sim.scn = scn;
  sim.wire = g_string_new ("");
  sim.dev = dev;
  sim_make_frame (scn->frame_flags);

  g_assert_true (fp_device_open_sync (dev, NULL, &error));
  g_assert_no_error (error);

  print = g_object_ref_sink (fp_print_new (dev));
  fp_print_set_finger (print, FP_FINGER_RIGHT_INDEX);
  if (act != ACT_ENROLL)
    {
      g_object_set (print, "fpi-data", g_variant_new_string (ID_RIGHT_INDEX), NULL);
      fpi_print_set_type (print, FPI_PRINT_RAW);
    }
  gallery = g_ptr_array_new ();
  if (!empty_gallery)
    g_ptr_array_add (gallery, print);

  for (gint i = 0; i < repeat; i++)
    {
      g_autofree gchar *wire = NULL;

      res_clear (res);
      if (i > 0)
        {
          g_string_append (sim.wire, "| ");
          sim_reset_counters ();
        }

      switch (act)
        {
        case ACT_VERIFY:
          res->ok = fp_device_verify_sync (dev, print, cancel, NULL, NULL,
                                           &res->match, &res->matched,
                                           &res->error);
          break;

        case ACT_IDENTIFY:
          res->ok = fp_device_identify_sync (dev, gallery, cancel, NULL, NULL,
                                             &res->matched, NULL, &res->error);
          res->match = res->matched != NULL;
          break;

        case ACT_ENROLL:
          res->matched = fp_device_enroll_sync (dev, print, cancel, moh_progress, NULL, &res->error);
          res->ok = res->matched != NULL;
          break;

        case ACT_CAPTURE:
          res->image = fp_device_capture_sync (dev, TRUE, cancel, &res->error);
          res->ok = res->image != NULL;
          break;
        }
    }

  res->wire = g_strstrip (g_strdup (sim.wire->str));
  if (scn->suspend_at_wait)
    {
      while (!sim.suspend_done)
        g_main_context_iteration (NULL, TRUE);
      g_assert_error (sim.suspend_error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
      g_clear_error (&sim.suspend_error);
      g_assert_true (fp_device_resume_sync (dev, NULL, &error));
      g_assert_no_error (error);
    }
  g_assert_true (fp_device_close_sync (dev, NULL, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (sim.live_write_enable_blobs, ==, 0);
  g_clear_pointer (&sim.frame, g_free);
  g_clear_pointer (&sim.identity, g_bytes_unref);
  sim.dev = NULL;
}

#define CAPTURE_WIRE "39 02 W W W W 51 51"

/* ================================================================
 * Verify / identify
 * ================================================================ */

/* The D5 case: a full image, the sensor has no template, no match; the
 * same again on the same open device */
static void
test_verify_no_match (void)
{
  static guint8 evs[5][5];
  Scn s = { .events = evs, .n_events = 5, .handle = 0x12345678 };

  g_auto(Res) r = { 0 };

  memcpy (evs, capture_evs, sizeof (capture_evs));
  memcpy (evs[4], EV_NOMATCH, 5);

  run (&s, ACT_VERIFY, FALSE, 1, &r);
  g_assert_cmpstr (r.wire, ==, CAPTURE_WIRE " 5e Wt 62 39");
  g_assert_true (r.ok);
  g_assert_false (r.match);
  g_assert_no_error (r.error);
  /* the vendor driver's 10 s, never more */
  g_assert_cmpuint (VALIDITY_A2_MATCH_TIMEOUT_MS, ==, 10000);
  g_assert_cmpuint (sim.match_timeout_ms, >, 0);
  g_assert_cmpuint (sim.match_timeout_ms, <=, 10000);

  run (&s, ACT_VERIFY, FALSE, 2, &r);
  g_assert_cmpstr (r.wire, ==, CAPTURE_WIRE " 5e Wt 62 39 | "
                   CAPTURE_WIRE " 5e Wt 62 39");
  g_assert_true (r.ok);
  g_assert_false (r.match);
}

/* Identify with an empty gallery (how a session with no prints checks
 * the match path): no match */
static void
test_identify_empty_gallery (void)
{
  static guint8 evs[5][5];
  Scn s = { .events = evs, .n_events = 5, .handle = 2 };

  g_auto(Res) r = { 0 };

  memcpy (evs, capture_evs, sizeof (capture_evs));
  memcpy (evs[4], EV_NOMATCH, 5);

  run (&s, ACT_IDENTIFY, TRUE, 1, &r);
  g_assert_cmpstr (r.wire, ==, CAPTURE_WIRE " 5e Wt 62 39");
  g_assert_true (r.ok);
  g_assert_false (r.match);
  g_assert_no_error (r.error);
}

/* A match (after a pending report): 60 and 62 with the handle, 39 end,
 * then the read-only 4a of the record the sensor named */
static void
test_match (void)
{
  guint16 subtype = fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX);

  for (gint identify = 0; identify <= 1; identify++)
    {
      static guint8 evs[6][5];
      Scn s = { .events = evs, .n_events = 6, .handle = 7 };
      g_auto(Res) r = { 0 };

      memcpy (evs, capture_evs, sizeof (capture_evs));
      memcpy (evs[4], (const guint8[5]){ 0x01, 0, 0, 0, 0 }, 5);
      memcpy (evs[5], EV_MATCH, 5);
      s.result60 = make_result60 (8, 0x2c, subtype);
      s.user4a = make_user4a (subtype);

      run (&s, identify ? ACT_IDENTIFY : ACT_VERIFY, FALSE, 1, &r);
      g_assert_cmpstr (r.wire, ==, CAPTURE_WIRE " 5e Wt Wt 60 62 39 4a");
      g_assert_true (r.ok);
      g_assert_true (r.match);
      g_assert_no_error (r.error);
      scn_clear (&s);
    }
}

/* Late capture reports during the match wait are skipped; no early 60 */
static void
test_stale_reports (void)
{
  static guint8 evs[7][5];
  Scn s = { .events = evs, .n_events = 7, .handle = 4 };

  g_auto(Res) r = { 0 };

  memcpy (evs, capture_evs, sizeof (capture_evs));
  memcpy (evs[4], EV_READY, 5);
  memcpy (evs[5], capture_evs[2], 5);
  memcpy (evs[6], EV_NOMATCH, 5);

  run (&s, ACT_VERIFY, FALSE, 1, &r);
  g_assert_cmpstr (r.wire, ==, CAPTURE_WIRE " 5e Wt Wt Wt 62 39");
  g_assert_true (r.ok);
  g_assert_false (r.match);
}

/* A refused 5e or 60 is an error with the status, not a no-match; the
 * cleanup still sends 62 and 39 */
static void
test_match_refused (void)
{
  for (gint at60 = 0; at60 <= 1; at60++)
    {
      static guint8 evs[5][5];
      Scn s = { .events = evs, .n_events = at60 ? 5 : 4, .handle = 9 };
      g_auto(Res) r = { 0 };

      memcpy (evs, capture_evs, sizeof (capture_evs));
      memcpy (evs[4], EV_MATCH, 5);
      if (at60)
        s.status_60 = 0x04b3;
      else
        s.status_5e = 0x0401;

      run (&s, ACT_VERIFY, FALSE, 1, &r);
      g_assert_cmpstr (r.wire, ==, at60 ?
                       CAPTURE_WIRE " 5e Wt 60 62 39" :
                       CAPTURE_WIRE " 5e 62 39");
      g_assert_false (r.ok);
      g_assert_false (r.match);
      g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      g_assert_nonnull (strstr (r.error->message,
                                at60 ? "60 status 0x04b3" : "5e status 0x0401"));
    }
}

/* No match report in time: an error after 62 and 39 */
static void
test_match_timeout (void)
{
  Scn s = { .events = capture_evs, .n_events = 4, .handle = 3 };

  g_auto(Res) r = { 0 };

  run (&s, ACT_VERIFY, FALSE, 1, &r);
  g_assert_cmpstr (r.wire, ==, CAPTURE_WIRE " 5e Wt 62 39");
  g_assert_false (r.ok);
  g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
}

/* Short 51 chunks (4096 each): read on until the image is in */
static void
test_short_chunks (void)
{
  static guint8 evs[5][5];
  Scn s = { .events = evs, .n_events = 5, .chunk = 4096 };

  g_auto(Res) r = { 0 };

  memcpy (evs, capture_evs, sizeof (capture_evs));
  memcpy (evs[4], EV_NOMATCH, 5);

  run (&s, ACT_VERIFY, FALSE, 1, &r);
  g_assert_cmpstr (r.wire, ==, "39 02 W W W W 51 51 51 51 5e Wt 62 39");
  g_assert_true (r.ok);
  g_assert_false (r.match);
}

/* ================================================================
 * Capture problems: retry or re-arm
 * ================================================================ */

static void
test_bad_capture (void)
{
  static guint8 evs[2][5];
  Scn s = { .events = evs, .n_events = 2 };

  g_auto(Res) r = { 0 };

  memcpy (evs[0], EV_START, 5);
  memcpy (evs[1], EV_BAD0, 5);
  run (&s, ACT_VERIFY, FALSE, 1, &r);
  g_assert_cmpstr (r.wire, ==, "39 02 W W 04 39");
  g_assert_false (r.ok);
  g_assert_error (r.error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_GENERAL);
}

/* The sensor aborts the capture: 04, a silent re-arm, then a no-match */
static void
test_abort_rearm (void)
{
  static guint8 evs[6][5];
  Scn s = { .events = evs, .n_events = 6 };

  g_auto(Res) r = { 0 };

  memcpy (evs[0], EV_START, 5);
  memcpy (evs[1], EV_ABORT, 5);
  memcpy (evs[2], EV_START, 5);
  memcpy (evs[3], EV_FINGER, 5);
  memcpy (evs[4], EV_READY, 5);
  memcpy (evs[5], EV_NOMATCH, 5);
  run (&s, ACT_VERIFY, FALSE, 1, &r);
  g_assert_cmpstr (r.wire, ==, "39 02 W W 04 02 W W W 51 51 5e Wt 62 39");
  g_assert_true (r.ok);
  g_assert_false (r.match);
}

/* Recapture flags on every image, or status 4 on every second 51: three
 * silent re-arms, then the user is asked to retry */
static void
test_rearm_bounded (void)
{
  for (gint variant = 0; variant < 2; variant++)
    {
      static guint8 evs[16][5];
      Scn s = { .events = evs, .n_events = 16 };
      g_auto(Res) r = { 0 };

      for (guint i = 0; i < 16; i += 4)
        memcpy (&evs[i], capture_evs, sizeof (capture_evs));
      if (variant == 0)
        s.frame_flags = 0x80200000;
      else
        s.status_51_second = 0x0004;

      run (&s, ACT_VERIFY, FALSE, 1, &r);
      g_assert_false (r.ok);
      g_assert_error (r.error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_GENERAL);
      g_assert_true (g_str_has_suffix (r.wire, "39"));
      g_assert_null (strstr (r.wire, "5e"));
    }
}

/* A 51 length field that does not match its data: 04, then an error */
static void
test_bad_readout (void)
{
  Scn s = { .events = capture_evs, .n_events = 4, .bad_51_len = TRUE };

  g_auto(Res) r = { 0 };

  run (&s, ACT_VERIFY, FALSE, 1, &r);
  g_assert_cmpstr (r.wire, ==, "39 02 W W W W 51 04 39");
  g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
}

/* ================================================================
 * Cancellation
 * ================================================================ */

static void
check_cancelled (Scn         *s,
                 Act          act,
                 const gchar *wire)
{
  g_auto(Res) r = { 0 };

  run (s, act, FALSE, 1, &r);
  g_assert_cmpstr (r.wire, ==, wire);
  g_assert_false (r.ok);
  g_assert_false (r.match);
  g_assert_error (r.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
}

static void
test_cancel (void)
{
  guint16 subtype = fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX);
  static guint8 evs1[1][5];
  static guint8 evs5[5][5];

  memcpy (evs1[0], EV_START, 5);
  memcpy (evs5, capture_evs, sizeof (capture_evs));
  memcpy (evs5[4], EV_MATCH, 5);

  /* in the finger wait: 04, 39 */
  {
    Scn s = { .events = evs1, .n_events = 1, .cancel_at_wait = 2 };

    check_cancelled (&s, ACT_VERIFY, "39 02 W W 04 39");
  }
  /* in the match wait: no 04 (the image was read), 62, 39 */
  {
    Scn s = { .events = capture_evs, .n_events = 4, .cancel_at_wait = 5,
              .handle = 3 };

    check_cancelled (&s, ACT_VERIFY, CAPTURE_WIRE " 5e Wt 62 39");
  }
  /* while a command is in flight: 02, first 51, last 51, 5e */
  {
    Scn s = { .cancel_at_cmd = 2 };

    check_cancelled (&s, ACT_VERIFY, "39 02 04 39");
  }
  {
    Scn s = { .events = capture_evs, .n_events = 4, .cancel_at_cmd = 3 };

    check_cancelled (&s, ACT_VERIFY, "39 02 W W W W 51 04 39");
  }
  {
    Scn s = { .events = capture_evs, .n_events = 4, .cancel_at_cmd = 4 };

    check_cancelled (&s, ACT_VERIFY, CAPTURE_WIRE " 39");
  }
  {
    Scn s = { .events = capture_evs, .n_events = 4, .cancel_at_cmd = 5,
              .handle = 0x42 };

    check_cancelled (&s, ACT_VERIFY, CAPTURE_WIRE " 5e 62 39");
  }
  /* while 60 of a match is in flight: never a match, no 4a */
  {
    Scn s = { .events = evs5, .n_events = 5, .cancel_at_cmd = 6, .handle = 7 };

    s.result60 = make_result60 (8, 0x2c, subtype);
    s.user4a = make_user4a (subtype);
    check_cancelled (&s, ACT_VERIFY, CAPTURE_WIRE " 5e Wt 60 62 39");
    scn_clear (&s);
  }
}

/* ================================================================
 * Transport errors
 * ================================================================ */

/* A TLS command fails: nothing more is sent over that session */
static void
test_tls_error (void)
{
  {
    Scn s = { .events = capture_evs, .n_events = 4, .fail_cmd_at = 3 };
    g_auto(Res) r = { 0 };

    run (&s, ACT_VERIFY, FALSE, 1, &r);
    g_assert_cmpstr (r.wire, ==, "39 02 W W W W 51");
    g_assert_false (r.ok);
    g_assert_error (r.error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO);
  }
  {
    Scn s = { .fail_cmd_at = 1 };
    g_auto(Res) r = { 0 };

    run (&s, ACT_VERIFY, FALSE, 1, &r);
    g_assert_cmpstr (r.wire, ==, "39");
    g_assert_false (r.ok);
    g_assert_nonnull (r.error);
  }
}

/* The EP 0x83 wait fails: the sensor is cleaned up (04, 39) and the
 * error reported; if the device is gone, nothing more is sent */
static void
test_interrupt_error (void)
{
  static guint8 evs[1][5];

  memcpy (evs[0], EV_START, 5);
  {
    Scn s = { .events = evs, .n_events = 1, .fail_wait_at = 2 };
    g_auto(Res) r = { 0 };

    run (&s, ACT_VERIFY, FALSE, 1, &r);
    g_assert_cmpstr (r.wire, ==, "39 02 W W 04 39");
    g_assert_false (r.ok);
    g_assert_error (r.error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO);
    g_assert_nonnull (strstr (r.error->message, "Waiting for the sensor failed"));
  }
  /* in the match wait: 62, 39 */
  {
    Scn s = { .events = capture_evs, .n_events = 4, .fail_wait_at = 5,
              .handle = 6 };
    g_auto(Res) r = { 0 };

    run (&s, ACT_VERIFY, FALSE, 1, &r);
    g_assert_cmpstr (r.wire, ==, CAPTURE_WIRE " 5e Wt 62 39");
    g_assert_error (r.error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO);
  }
  {
    Scn s = { .events = evs, .n_events = 1, .fail_wait_at = 2,
              .fail_wait_code = G_USB_DEVICE_ERROR_NO_DEVICE };
    g_auto(Res) r = { 0 };

    run (&s, ACT_VERIFY, FALSE, 1, &r);
    g_assert_cmpstr (r.wire, ==, "39 02 W W");
    g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_REMOVED);
  }
}

/* ================================================================
 * Gate at the start of an action
 * ================================================================ */

/* Without the calibration the open leaves, nothing is sent */
static void
test_not_calibrated (void)
{
  for (gint act = ACT_VERIFY; act <= ACT_CAPTURE; act++)
    {
      Scn s = { .uncalibrated = TRUE };
      g_auto(Res) r = { 0 };

      if (act == ACT_CAPTURE && !fpi_validity_dev_overrides_built ())
        continue;
      run (&s, act, FALSE, 1, &r);
      g_assert_cmpstr (r.wire, ==, "");
      g_assert_false (r.ok);
      g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
    }
}

/* ================================================================
 * Developer image capture
 * ================================================================ */

static void
test_capture (void)
{
  Scn s = { .events = capture_evs, .n_events = 4 };

  g_auto(Res) r = { 0 };

  run (&s, ACT_CAPTURE, FALSE, 1, &r);

  if (!fpi_validity_dev_overrides_built ())
    {
      /* not in a packaged build: the core refuses, nothing is sent */
      g_assert_cmpstr (r.wire, ==, "");
      g_assert_null (r.image);
      g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
      return;
    }

  g_assert_cmpstr (r.wire, ==, CAPTURE_WIRE " 39");
  g_assert_nonnull (r.image);
  g_assert_no_error (r.error);
  g_assert_cmpint (fp_image_get_width (r.image), ==, 112);
  g_assert_cmpint (fp_image_get_height (r.image), ==, 112);
  {
    gsize n = 0;
    const guint8 *d = fp_image_get_data (r.image, &n);

    g_assert_cmpuint (n, ==, FRAME_PIXELS);
    for (gsize i = 0; i < n; i++)
      g_assert_cmpuint (d[i], ==, px (i));
  }

  /* cancelled while waiting for the finger */
  {
    static guint8 evs[1][5];
    Scn c = { .events = evs, .n_events = 1, .cancel_at_wait = 2 };

    memcpy (evs[0], EV_START, 5);
    check_cancelled (&c, ACT_CAPTURE, "39 02 W W 04 39");
  }
}

/* ================================================================ */

/* Use made-up tables for the transport/SSM tests. The production entry
 * point's pinned table/blob checks are deliberately not relaxed. */
static void
moh_test_blob_released (gpointer data)
{
  guint *live = data;

  g_assert_cmpuint (*live, >, 0);
  (*live)--;
}

static void
moh_test_start (FpDevice *device)
{
  g_autofree gchar *dir = g_test_build_filename (G_TEST_DIST, "validity-moh", "tables-synthetic", NULL);

  g_autoptr(GError) error = NULL;
  g_autoptr(ValidityMohTables) tables = fpi_validity_moh_tables_load_dir (dir, VALIDITY_MOH_TABLES_ALLOW_UNPINNED, &error);
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (device);
  FpPrint *print = NULL;
  MohData *d = g_new0 (MohData, 1);
  FpiSsm *ssm;
  static const guint8 blob[] = { 6, 0 };

  g_assert_no_error (error);
  g_assert_nonnull (tables);
  sim.live_write_enable_blobs++;
  self->device_data.entries[VALIDITY_DATA_DB_WRITE_ENABLE] =
    g_bytes_new_with_free_func (blob, sizeof blob, moh_test_blob_released, &sim.live_write_enable_blobs);
  d->builder = fpi_validity_moh_enroll_new (tables, 6, 1, 0);
  fpi_device_set_nr_enroll_stages (device, 6);
  fpi_device_get_enroll_data (device, &print);
  d->subtype = fpi_validity_finger_to_subtype (fp_print_get_finger (print));
  d->user_id = fpi_print_generate_user_id (print);
  ssm = fpi_ssm_new (device, moh_run, MOH_N_STATES);
  fpi_ssm_set_data (ssm, d, moh_data_free);
  fpi_ssm_start (ssm, moh_done);
}

static void
moh_progress (FpDevice *device, gint completed, FpPrint *print, gpointer user_data, GError *error)
{
  g_assert_cmpuint (completed, >=, sim.progress);
  sim.progress = completed;
  if (completed == 6 && !sim.readback_done)
    sim.final_before_readback = TRUE;
}

static void
moh_events (Scn *s, guint8 events[24][5])
{
  for (guint i = 0; i < 6; i++)
    memcpy (events + 4 * i, capture_evs, sizeof capture_evs);
  s->events = (const guint8 (*)[5]) events;
  s->n_events = 24;
  s->enroll_mode = TRUE;
}

static void
test_moh_success (void)
{
  guint8 events[24][5];
  Scn s = { 0 };

  g_auto(Res) r = { 0 };
  g_autoptr(GString) expected = g_string_new ("45 4b ");
  g_autofree guint8 *serialized = NULL;
  g_autoptr(FpPrint) restored = NULL;
  g_autoptr(GError) error = NULL;
  gsize size;

  moh_events (&s, events);
  run (&s, ACT_ENROLL, FALSE, 1, &r);
  for (guint i = 0; i < 6; i++)
    g_string_append (expected, CAPTURE_WIRE " 39 ");
  g_string_append (expected, "45 06 47 1a 06 47 1a 45 4a");
  g_assert_cmpstr (r.wire, ==, expected->str);
  g_assert_true (r.ok);
  g_assert_no_error (r.error);
  g_assert_cmpuint (sim.users, ==, 1);
  g_assert_cmpuint (sim.stores, ==, 1);
  g_assert_cmpuint (sim.progress, ==, 6);
  g_assert_false (sim.final_before_readback);
  g_assert_true (fp_print_get_device_stored (r.matched));
  g_assert_true (fp_print_serialize (r.matched, &serialized, &size, &error));
  g_assert_no_error (error);
  restored = fp_print_deserialize (serialized, size, &error);
  g_assert_no_error (error);
  g_assert_true (fp_print_equal (r.matched, restored));
}

static void
test_moh_failures (void)
{
  for (guint which = 0; which < 8; which++)
    {
      guint8 events[24][5];
      Scn s = { 0 };
      g_auto(Res) r = { 0 };

      moh_events (&s, events);
      switch (which)
        {
        case 0: s.free_space = 1024;
          break;

        case 1: s.missing_storage = TRUE;
          break;

        case 2: s.bad_info = TRUE;
          break;

        case 3: s.full_before_store = TRUE;
          break;

        case 4: s.store_status = 0x04b5;
          break;

        case 5: s.short_store_reply = TRUE;
          break;

        case 6: s.bad_readback = TRUE;
          break;

        case 7: s.fail_cmd_at = 38;
          break;                           /* template store reply lost */
        }
      run (&s, ACT_ENROLL, FALSE, 1, &r);
      g_assert_false (r.ok);
      g_assert_nonnull (r.error);
      g_assert_cmpuint (sim.progress, <, 6);
      g_assert_cmpuint (sim.stores, <=, 1);
      g_assert_false (sim.final_before_readback);
      if (which <= 3)
        {
          g_assert_cmpuint (sim.users, ==, 0);
          g_assert_cmpuint (sim.stores, ==, 0);
        }
      if (which == 0 || which == 3 || which == 4)
        g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_FULL);
    }
}

static void
test_moh_cancel (void)
{
  for (guint phase = 0; phase < 3; phase++)
    {
      guint8 events[24][5];
      Scn s = { .cancel_at_wait = phase == 0 ? 2 : 0,
                .cancel_at_cmd = phase == 1 ? 35 : phase == 2 ? 38 : 0 };
      g_auto(Res) r = { 0 };

      moh_events (&s, events);
      run (&s, ACT_ENROLL, FALSE, 1, &r);
      if (phase == 2)
        {
          g_assert_no_error (r.error);
          g_assert_true (r.ok);
        }
      else
        {
          g_assert_error (r.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
        }
      if (phase == 0)
        {
          g_assert_cmpstr (r.wire, ==, "45 4b 39 02 W W 04 39");
          g_assert_cmpuint (sim.users, ==, 0);
        }
      else
        {
          g_assert_cmpuint (sim.users, ==, 1);
        }
      if (phase == 2)
        {
          g_assert_cmpuint (sim.stores, ==, 1);
          g_assert_true (sim.readback_done);
          g_assert_true (g_str_has_suffix (r.wire, "47 1a 45 4a"));
        }
      else
        {
          g_assert_cmpuint (sim.stores, ==, 0);
        }
    }
}

static void
test_suspend_wait (void)
{
  static guint8 events[1][5];
  Scn s = { .events = events, .n_events = 1, .suspend_at_wait = TRUE };

  g_auto(Res) r = { 0 };

  memcpy (events[0], EV_START, 5);
  run (&s, ACT_VERIFY, FALSE, 1, &r);
  g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_BUSY);
  g_assert_cmpstr (r.wire, ==, "39 02 W W 04 39");
  g_assert_cmpuint (sim.stores, ==, 0);
}

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

  /* the driver's in-memory emulation store would bypass the flow */
  g_unsetenv ("FP_DEVICE_EMULATION");

  g_test_add_func ("/validity/a2-flow/verify-no-match", test_verify_no_match);
  g_test_add_func ("/validity/a2-flow/identify-empty-gallery",
                   test_identify_empty_gallery);
  g_test_add_func ("/validity/a2-flow/match", test_match);
  g_test_add_func ("/validity/a2-flow/stale-reports", test_stale_reports);
  g_test_add_func ("/validity/a2-flow/match-refused", test_match_refused);
  g_test_add_func ("/validity/a2-flow/match-timeout", test_match_timeout);
  g_test_add_func ("/validity/a2-flow/short-chunks", test_short_chunks);
  g_test_add_func ("/validity/a2-flow/bad-capture", test_bad_capture);
  g_test_add_func ("/validity/a2-flow/abort-rearm", test_abort_rearm);
  g_test_add_func ("/validity/a2-flow/rearm-bounded", test_rearm_bounded);
  g_test_add_func ("/validity/a2-flow/bad-readout", test_bad_readout);
  g_test_add_func ("/validity/a2-flow/cancel", test_cancel);
  g_test_add_func ("/validity/a2-flow/tls-error", test_tls_error);
  g_test_add_func ("/validity/a2-flow/interrupt-error", test_interrupt_error);
  g_test_add_func ("/validity/a2-flow/not-calibrated", test_not_calibrated);
  g_test_add_func ("/validity/a2-flow/capture", test_capture);

  g_test_add_func ("/validity/a2-enroll/success", test_moh_success);
  g_test_add_func ("/validity/a2-enroll/failures", test_moh_failures);
  g_test_add_func ("/validity/a2-enroll/cancel", test_moh_cancel);
  g_test_add_func ("/validity/a2-flow/suspend-wait", test_suspend_wait);
  return g_test_run ();
}
