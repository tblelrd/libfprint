/*
 * 06cb:00a2 capture, image readout and on-chip match flow
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
#include "validity_pack.h"
#include "validity_a2_capture.h"
#include "validity_capture.h"
#include "validity_db.h"
#include "vcsfw_protocol.h"

/* ================================================================
 * Sources
 *
 * - python-validity PR #261 (fork 840cfbe, hardware-tested on 00a2):
 *   sensor.py capture() reads the 12-byte header and then 51 00200000
 *   until rows*cols pixels are in, and skips 04 after a completed capture
 *   on 00a2 (the chip errors); match_finger() sends 5e/60/62.
 * - The vendor driver (synaWudfBioUsb 5.2.326.26, static analysis): the
 *   EP 0x83 decoding for capture (type-3 code at bytes 2..3) and match
 *   (code at bytes 0..1), the 51 framing and status codes, the header
 *   flags rule, 04 only to abort a capture, the 5e handle passed to
 *   5f/60/62, the 60 tag lengths and the tag-2 rule, a 10 s match wait.
 * - Behaviour of the vendor driver that is deliberately not copied: it
 *   reboots the sensor (05) after capture, calibration and match errors,
 *   and rewrites the calibration partition (6). Nothing here does either.
 * Details: refs/re/a2-capture-verify-spec.md in the e480 research notes.
 * ================================================================ */

/* ================================================================
 * EP 0x83 reports
 * ================================================================ */

ValidityA2CaptureEvent
fpi_validity_a2_classify_capture_event (const guint8 *buf,
                                        gsize         len,
                                        guint16      *out_code)
{
  guint16 code;

  if (out_code)
    *out_code = 0;

  if (buf == NULL || len < 1)
    return VALIDITY_A2_CAPT_EV_MALFORMED;

  switch (buf[0])
    {
    case 0:
      return VALIDITY_A2_CAPT_EV_START;

    case 2:
      return VALIDITY_A2_CAPT_EV_FINGER_DOWN;

    case 3:
      break;

    default:
      return VALIDITY_A2_CAPT_EV_OTHER;
    }

  if (len < 4)
    return VALIDITY_A2_CAPT_EV_MALFORMED;

  code = (guint16) (buf[2] | (buf[3] << 8));
  if (out_code)
    *out_code = code;

  switch (code)
    {
    case 4:
    case 7:
      return VALIDITY_A2_CAPT_EV_READY;

    case 1:
    case 2:
    case 3:
    case 5:
    case 9:
      return VALIDITY_A2_CAPT_EV_WAIT;

    case 6:
      return VALIDITY_A2_CAPT_EV_ABORT;

    default:  /* 0, 8, >= 10 */
      return VALIDITY_A2_CAPT_EV_BAD;
    }
}

ValidityA2MatchEvent
fpi_validity_a2_classify_match_event (const guint8 *buf,
                                      gsize         len,
                                      guint16      *out_code,
                                      guint16      *out_detail)
{
  guint16 code;
  guint16 detail = 0;
  ValidityA2MatchEvent ev;

  if (out_code)
    *out_code = 0;
  if (out_detail)
    *out_detail = 0;

  if (buf == NULL || len < 2)
    return VALIDITY_A2_MATCH_EV_MALFORMED;

  code = (guint16) (buf[0] | (buf[1] << 8));

  /* Capture-phase reports are 03 xx cc 00 yy with xx != 0 (both samples
   * seen on 00a2: 03 40 01 00 00, 03 42 04 00 40); every match code seen
   * has byte 1 = 0. One still queued after the image would otherwise read
   * as code 0xxx03, "other: read the result", and send 60 early while the
   * real match report waits for the next action. */
  if (buf[0] == 0x03 && buf[1] != 0x00)
    {
      if (out_code)
        *out_code = code;
      return VALIDITY_A2_MATCH_EV_STALE;
    }

  switch (code)
    {
    case 0:
    case 1:
    case 2:
      ev = VALIDITY_A2_MATCH_EV_PENDING;
      break;

    case 3:
      ev = VALIDITY_A2_MATCH_EV_MATCH;
      break;

    case 4:
      ev = VALIDITY_A2_MATCH_EV_NO_MATCH;
      if (len >= 3)
        detail = buf[2];
      break;

    case 5:
      ev = VALIDITY_A2_MATCH_EV_ERROR;
      if (len >= 4)
        detail = (guint16) (buf[2] | (buf[3] << 8));
      break;

    default:
      ev = VALIDITY_A2_MATCH_EV_OTHER_DONE;
      break;
    }

  if (out_code)
    *out_code = code;
  if (out_detail)
    *out_detail = detail;
  return ev;
}

/* ================================================================
 * Image header and flags
 * ================================================================ */

gboolean
fpi_validity_a2_parse_image_header (const guint8          *data,
                                    gsize                  len,
                                    ValidityA2ImageHeader *out)
{
  g_return_val_if_fail (out != NULL, FALSE);

  memset (out, 0, sizeof (*out));
  if (data == NULL || len < VALIDITY_A2_IMAGE_HEADER_LEN)
    return FALSE;

  out->rows = (guint16) (data[0] | (data[1] << 8));
  out->cols = (guint16) (data[2] | (data[3] << 8));
  out->resolution = (guint16) (data[4] | (data[5] << 8));
  out->bpp = data[6];
  /* data[7] is unused */
  out->flags = (guint32) data[8] | ((guint32) data[9] << 8) |
               ((guint32) data[10] << 16) | ((guint32) data[11] << 24);
  return TRUE;
}

ValidityA2FlagsVerdict
fpi_validity_a2_image_flags_verdict (guint32             flags,
                                     ValidityA2FlagsRule rule)
{
  const guint32 recapture = VALIDITY_A2_IMAGE_FLAG_BIT31 |
                            VALIDITY_A2_IMAGE_FLAG_BIT21;

  if (flags == 0)
    return VALIDITY_A2_FLAGS_USE;

  if ((flags & recapture) == recapture)
    return VALIDITY_A2_FLAGS_RECAPTURE;

  if (rule == VALIDITY_A2_FLAGS_RULE_WINDOWS &&
      !(flags & VALIDITY_A2_IMAGE_FLAG_BIT31))
    return VALIDITY_A2_FLAGS_USE;

  return VALIDITY_A2_FLAGS_REJECT;
}

/* ================================================================
 * 51 readout
 * ================================================================ */

void
fpi_validity_a2_readout_init (ValidityA2Readout *r)
{
  memset (r, 0, sizeof (*r));
}

void
fpi_validity_a2_readout_clear (ValidityA2Readout *r)
{
  if (r->buf)
    {
      memset (r->buf, 0, VALIDITY_A2_READ_MAX_TOTAL);
      g_free (r->buf);
    }
  memset (r, 0, sizeof (*r));
}

static ValidityA2ReadoutStep readout_error (GError     **error,
                                            const gchar *fmt,
                                            ...) G_GNUC_PRINTF (2, 3);

static ValidityA2ReadoutStep
readout_error (GError     **error,
               const gchar *fmt,
               ...)
{
  g_autofree gchar *msg = NULL;
  va_list args;

  va_start (args, fmt);
  msg = g_strdup_vprintf (fmt, args);
  va_end (args);

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "Image readout: %s", msg);
  return VALIDITY_A2_READOUT_ERROR;
}

ValidityA2ReadoutStep
fpi_validity_a2_readout_feed (ValidityA2Readout *r,
                              guint16            status,
                              const guint8      *payload,
                              gsize              payload_len,
                              GError           **error)
{
  guint32 chunk_len;
  gsize expected;

  g_return_val_if_fail (r != NULL, VALIDITY_A2_READOUT_ERROR);

  switch (status)
    {
    case VCSFW_STATUS_OK:
      break;

    case VALIDITY_A2_READ_STATUS_NOT_READY:
    case VALIDITY_A2_READ_STATUS_READY:
      if (++r->polls > VALIDITY_A2_READ_MAX_POLLS)
        return readout_error (error, "the sensor kept answering status 0x%04x",
                              status);
      return VALIDITY_A2_READOUT_POLL;

    case VALIDITY_A2_READ_STATUS_ABORTED:
      return VALIDITY_A2_READOUT_ABORTED;

    default:
      return readout_error (error, "status 0x%04x", status);
    }

  if (payload == NULL || payload_len < 4)
    return readout_error (error, "reply of %" G_GSIZE_FORMAT " bytes has no "
                                 "length field", payload ? payload_len : 0);

  chunk_len = (guint32) payload[0] | ((guint32) payload[1] << 8) |
              ((guint32) payload[2] << 16) | ((guint32) payload[3] << 24);

  if ((gsize) chunk_len != payload_len - 4)
    return readout_error (error, "length field %u does not match the %"
                          G_GSIZE_FORMAT " data bytes", chunk_len,
                          payload_len - 4);

  if (chunk_len > VALIDITY_A2_READ_CHUNK_MAX)
    return readout_error (error, "chunk of %u bytes exceeds the requested %u",
                          chunk_len, VALIDITY_A2_READ_CHUNK_MAX);

  /* Nothing more is coming: the image cannot complete */
  if (chunk_len == 0)
    return readout_error (error, "empty chunk after %" G_GSIZE_FORMAT
                          " bytes", r->len);

  if (r->len + chunk_len > VALIDITY_A2_READ_MAX_TOTAL)
    return readout_error (error, "more than %u bytes",
                          VALIDITY_A2_READ_MAX_TOTAL);

  r->chunks++;
  fp_dbg ("Image readout: chunk %u, %u bytes (%" G_GSIZE_FORMAT " in total)",
          r->chunks, chunk_len, r->len + chunk_len);

  if (r->buf == NULL)
    r->buf = g_malloc0 (VALIDITY_A2_READ_MAX_TOTAL);

  memcpy (r->buf + r->len, payload + 4, chunk_len);
  r->len += chunk_len;

  if (!r->have_header && r->len >= VALIDITY_A2_IMAGE_HEADER_LEN)
    {
      fpi_validity_a2_parse_image_header (r->buf, r->len, &r->header);
      r->have_header = TRUE;

      fp_dbg ("Image header: %ux%u, resolution %u, %u bpp, flags 0x%08x",
              r->header.rows, r->header.cols, r->header.resolution,
              r->header.bpp, r->header.flags);

      /* An empty capture (no finger image) reports no geometry */
      if (r->header.rows == 0 || r->header.cols == 0)
        return VALIDITY_A2_READOUT_EMPTY;

      if (r->header.rows != VALIDITY_A2_IMAGE_ROWS ||
          r->header.cols != VALIDITY_A2_IMAGE_COLS ||
          r->header.bpp != VALIDITY_A2_IMAGE_BPP)
        {
          return readout_error (error, "unexpected image geometry %ux%u, %u bpp "
                                       "(expected %ux%u, %u bpp)",
                                r->header.rows, r->header.cols, r->header.bpp,
                                VALIDITY_A2_IMAGE_ROWS, VALIDITY_A2_IMAGE_COLS,
                                VALIDITY_A2_IMAGE_BPP);
        }
    }

  if (r->have_header)
    {
      expected = VALIDITY_A2_IMAGE_HEADER_LEN +
                 (gsize) r->header.rows * r->header.cols;

      if (r->len >= expected)
        {
          if (r->len > expected)
            fp_info ("Image readout: %" G_GSIZE_FORMAT " bytes beyond the "
                     "image ignored", r->len - expected);
          return VALIDITY_A2_READOUT_DONE;
        }
    }

  /* A chunk shorter than requested does not end the readout: like the
   * hardware-tested python-validity PR #261 loop, read on until the image
   * is in (00a2 was seen to send 8192 + 4364), bounded by the chunk cap */
  if (r->chunks >= VALIDITY_A2_READ_MAX_CHUNKS)
    return readout_error (error, "image not complete after %u chunks "
                                 "(%" G_GSIZE_FORMAT " bytes)", r->chunks, r->len);

  return VALIDITY_A2_READOUT_MORE;
}

const guint8 *
fpi_validity_a2_readout_pixels (const ValidityA2Readout *r,
                                gsize                   *out_len)
{
  gsize n;

  if (out_len)
    *out_len = 0;

  if (r == NULL || r->buf == NULL || !r->have_header)
    return NULL;

  n = (gsize) r->header.rows * r->header.cols;
  if (n == 0 || r->len < VALIDITY_A2_IMAGE_HEADER_LEN + n)
    return NULL;

  if (out_len)
    *out_len = n;
  return r->buf + VALIDITY_A2_IMAGE_HEADER_LEN;
}

/* ================================================================
 * 60 match result (strict)
 * ================================================================ */

static gboolean match_result_error (GError     **error,
                                    const gchar *fmt,
                                    ...) G_GNUC_PRINTF (2, 3);

static gboolean
match_result_error (GError     **error,
                    const gchar *fmt,
                    ...)
{
  g_autofree gchar *msg = NULL;
  va_list args;

  va_start (args, fmt);
  msg = g_strdup_vprintf (fmt, args);
  va_end (args);

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "Malformed match result: %s", msg);
  return FALSE;
}

static gboolean
parse_match_result (const guint8        *data,
                    gsize                data_len,
                    ValidityMatchResult *result,
                    GError             **error)
{
  /* Fixed value length per known tag; -1 = any length, value ignored */
  static const gint tag_len[] = { -1, 4, 4, 2, 32, 32, -1, 16, 2 };
  guint32 seen = 0;
  guint16 total_len;
  gsize off;

  if (data == NULL || data_len < 2)
    return match_result_error (error, "%" G_GSIZE_FORMAT " bytes",
                               data ? data_len : 0);

  total_len = (guint16) (data[0] | (data[1] << 8));
  if ((gsize) total_len != data_len - 2)
    return match_result_error (error, "length field %u, %" G_GSIZE_FORMAT
                               " bytes follow", total_len, data_len - 2);

  off = 2;
  while (off < data_len)
    {
      guint16 tag, len;
      const guint8 *value;

      if (data_len - off < 4)
        return match_result_error (error, "%" G_GSIZE_FORMAT " stray bytes",
                                   data_len - off);

      tag = (guint16) (data[off] | (data[off + 1] << 8));
      len = (guint16) (data[off + 2] | (data[off + 3] << 8));
      off += 4;

      if (data_len - off < len)
        return match_result_error (error, "tag %u needs %u bytes, %"
                                   G_GSIZE_FORMAT " left", tag, len,
                                   data_len - off);
      value = data + off;
      off += len;

      if (tag >= G_N_ELEMENTS (tag_len) || tag_len[tag] < 0)
        {
          fp_dbg ("Match result: skipping tag %u (%u bytes)", tag, len);
          continue;
        }

      if (len != tag_len[tag])
        return match_result_error (error, "tag %u has %u bytes, not %d",
                                   tag, len, tag_len[tag]);

      if (seen & (1u << tag))
        return match_result_error (error, "tag %u repeated", tag);
      seen |= 1u << tag;

      switch (tag)
        {
        case 1:
          result->user_dbid = (guint32) value[0] | ((guint32) value[1] << 8) |
                              ((guint32) value[2] << 16) |
                              ((guint32) value[3] << 24);
          break;

        case 2:
          result->tag2 = (guint32) value[0] | ((guint32) value[1] << 8) |
                         ((guint32) value[2] << 16) |
                         ((guint32) value[3] << 24);
          break;

        case 3:
          result->subtype = (guint16) (value[0] | (value[1] << 8));
          break;

        case 4:
          g_clear_pointer (&result->hash, g_free);
          result->hash = g_memdup2 (value, len);
          result->hash_len = len;
          break;

        default:  /* 5, 7, 8: length checked, value not used */
          break;
        }
    }

  result->matched = (seen & (1u << 1)) && (seen & (1u << 2)) &&
                    (seen & (1u << 3)) && result->tag2 != 0;
  return TRUE;
}

/* @result is overwritten (not freed first); on failure it is left empty */
gboolean
fpi_validity_a2_parse_match_result (const guint8        *data,
                                    gsize                data_len,
                                    ValidityMatchResult *result,
                                    GError             **error)
{
  g_return_val_if_fail (result != NULL, FALSE);

  memset (result, 0, sizeof (*result));
  if (parse_match_result (data, data_len, result, error))
    return TRUE;

  fpi_validity_match_result_clear (result);
  return FALSE;
}

/* ================================================================
 * Flow
 * ================================================================ */

const gchar *
fpi_validity_a2_op_name (ValidityA2Op op)
{
  switch (op)
    {
    case VALIDITY_A2_OP_NONE:
      return "none";

    case VALIDITY_A2_OP_GLOW_START:
      return "39 glow start";

    case VALIDITY_A2_OP_CAPTURE:
      return "02 capture";

    case VALIDITY_A2_OP_WAIT_CAPTURE_EVENT:
      return "wait capture event";

    case VALIDITY_A2_OP_READ_IMAGE:
      return "51 read image";

    case VALIDITY_A2_OP_CAPTURE_STOP:
      return "04 capture stop";

    case VALIDITY_A2_OP_MATCH_START:
      return "5e match";

    case VALIDITY_A2_OP_WAIT_MATCH_EVENT:
      return "wait match event";

    case VALIDITY_A2_OP_GET_RESULT:
      return "60 match result";

    case VALIDITY_A2_OP_MATCH_CLEANUP:
      return "62 match cleanup";

    case VALIDITY_A2_OP_GLOW_END:
      return "39 glow end";

    case VALIDITY_A2_OP_GET_USER:
      return "4a get user";

    case VALIDITY_A2_OP_DELAY:
      return "delay";

    case VALIDITY_A2_OP_DONE:
      return "done";
    }

  return "?";
}

void
fpi_validity_a2_flow_init (ValidityA2Flow     *flow,
                           gboolean            match,
                           ValidityA2FlagsRule flags_rule)
{
  memset (flow, 0, sizeof (*flow));
  flow->match = match;
  flow->flags_rule = flags_rule;
  flow->next_op = VALIDITY_A2_OP_GLOW_START;
  flow->retry = FP_DEVICE_RETRY_GENERAL;
  fpi_validity_a2_readout_init (&flow->readout);
}

void
fpi_validity_a2_flow_clear (ValidityA2Flow *flow)
{
  fpi_validity_a2_readout_clear (&flow->readout);
  fpi_validity_match_result_clear (&flow->result);
  fpi_validity_user_clear (&flow->user);
  g_clear_error (&flow->error);
  memset (flow, 0, sizeof (*flow));
}

/* Enter the cleanup tail with @outcome (takes @error). The first outcome
 * wins; later calls only drop their error. */
static void
flow_finish (ValidityA2Flow   *flow,
             ValidityA2Outcome outcome,
             GError           *error)
{
  if (flow->finishing)
    {
      g_clear_error (&error);
      return;
    }

  flow->finishing = TRUE;
  flow->outcome = outcome;
  flow->error = error;
  flow->next_op = VALIDITY_A2_OP_NONE;

  /* The pixels are not needed past this point (except as the result of an
   * image capture) */
  if (outcome != VALIDITY_A2_OUTCOME_IMAGE)
    fpi_validity_a2_readout_clear (&flow->readout);
}

static void
flow_fail (ValidityA2Flow *flow,
           const gchar    *msg)
{
  flow_finish (flow, VALIDITY_A2_OUTCOME_ERROR,
               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", msg));
}

static void
flow_retry (ValidityA2Flow *flow,
            FpDeviceRetry   retry)
{
  if (!flow->finishing)
    flow->retry = retry;
  flow_finish (flow, VALIDITY_A2_OUTCOME_RETRY, NULL);
}

static void
flow_delay_then (ValidityA2Flow *flow,
                 guint           delay_ms,
                 ValidityA2Op    op)
{
  flow->next_op = VALIDITY_A2_OP_DELAY;
  flow->delay_ms = delay_ms;
  flow->after_delay = op;
}

/* Capture again without involving the user (bounded), else ask for a
 * retry. The capture must not be armed any more (drained or stopped). */
static void
flow_rearm_or_retry (ValidityA2Flow *flow,
                     const gchar    *why)
{
  fpi_validity_a2_readout_clear (&flow->readout);

  if (flow->silent_rearms < VALIDITY_A2_MAX_SILENT_REARMS)
    {
      flow->silent_rearms++;
      fp_info ("Capture: %s -- capturing again (%u/%u)", why,
               flow->silent_rearms, VALIDITY_A2_MAX_SILENT_REARMS);
      flow_delay_then (flow, VALIDITY_A2_REARM_DELAY_MS,
                       VALIDITY_A2_OP_CAPTURE);
      return;
    }

  fp_info ("Capture: %s -- asking for another scan", why);
  flow_retry (flow, FP_DEVICE_RETRY_GENERAL);
}

/* Stop the armed capture with 04, then re-arm or ask for a retry */
static void
flow_stop_then_rearm (ValidityA2Flow *flow)
{
  flow->rearm_after_stop = TRUE;
  flow->next_op = VALIDITY_A2_OP_CAPTURE_STOP;
}

static ValidityA2Op
flow_cleanup_next (ValidityA2Flow *flow)
{
  if (flow->capture_armed)
    return VALIDITY_A2_OP_CAPTURE_STOP;
  if (flow->match_open)
    return VALIDITY_A2_OP_MATCH_CLEANUP;
  if (flow->glow_on)
    return VALIDITY_A2_OP_GLOW_END;
  if (flow->outcome == VALIDITY_A2_OUTCOME_MATCH && !flow->user_requested &&
      flow->result.user_dbid <= G_MAXUINT16)
    return VALIDITY_A2_OP_GET_USER;
  return VALIDITY_A2_OP_DONE;
}

ValidityA2Op
fpi_validity_a2_flow_next (ValidityA2Flow *flow,
                           guint          *delay_ms)
{
  ValidityA2Op op;

  if (delay_ms)
    *delay_ms = 0;

  if (flow->finishing)
    op = flow_cleanup_next (flow);
  else
    op = flow->next_op;

  if (op == VALIDITY_A2_OP_DELAY)
    {
      if (delay_ms)
        *delay_ms = flow->delay_ms;
      flow->next_op = flow->after_delay;
      flow->after_delay = VALIDITY_A2_OP_NONE;
      flow->issued = VALIDITY_A2_OP_NONE;
      return op;
    }

  /* Whatever the sensor answers, these commands are on the wire now */
  switch (op)
    {
    case VALIDITY_A2_OP_GLOW_START:
      flow->glow_on = TRUE;
      break;

    case VALIDITY_A2_OP_CAPTURE:
      flow->capture_armed = TRUE;
      flow->captures++;
      fpi_validity_a2_readout_clear (&flow->readout);
      break;

    case VALIDITY_A2_OP_CAPTURE_STOP:
      flow->capture_armed = FALSE;
      flow->stops++;
      break;

    case VALIDITY_A2_OP_MATCH_START:
      flow->match_open = TRUE;
      flow->match_handle = 0;
      break;

    case VALIDITY_A2_OP_MATCH_CLEANUP:
      flow->match_open = FALSE;
      break;

    case VALIDITY_A2_OP_GLOW_END:
      flow->glow_on = FALSE;
      flow->finger_present = FALSE;
      break;

    case VALIDITY_A2_OP_GET_USER:
      flow->user_requested = TRUE;
      break;

    case VALIDITY_A2_OP_NONE:
    case VALIDITY_A2_OP_WAIT_CAPTURE_EVENT:
    case VALIDITY_A2_OP_READ_IMAGE:
    case VALIDITY_A2_OP_WAIT_MATCH_EVENT:
    case VALIDITY_A2_OP_GET_RESULT:
    case VALIDITY_A2_OP_DELAY:
    case VALIDITY_A2_OP_DONE:
      break;
    }

  flow->issued = op;
  if (!flow->finishing)
    flow->next_op = VALIDITY_A2_OP_NONE;   /* set again by the reply/event */
  return op;
}

static void
flow_readout_reply (ValidityA2Flow *flow,
                    guint16         status,
                    const guint8   *data,
                    gsize           data_len)
{
  GError *error = NULL;
  ValidityA2ReadoutStep step;

  step = fpi_validity_a2_readout_feed (&flow->readout, status, data, data_len,
                                       &error);
  switch (step)
    {
    case VALIDITY_A2_READOUT_MORE:
      flow->next_op = VALIDITY_A2_OP_READ_IMAGE;
      return;

    case VALIDITY_A2_READOUT_POLL:
      flow_delay_then (flow, VALIDITY_A2_READ_POLL_DELAY_MS,
                       VALIDITY_A2_OP_READ_IMAGE);
      return;

    case VALIDITY_A2_READOUT_EMPTY:
      flow_stop_then_rearm (flow);
      return;

    case VALIDITY_A2_READOUT_ABORTED:
      fp_info ("Capture: the sensor aborted the image readout");
      flow_stop_then_rearm (flow);
      return;

    case VALIDITY_A2_READOUT_ERROR:
      flow_finish (flow, VALIDITY_A2_OUTCOME_ERROR, error);
      return;

    case VALIDITY_A2_READOUT_DONE:
      break;
    }

  /* The whole image is in: the capture is over on the sensor side, and no
   * 04 follows (00a2 errors on it, the vendor driver never sends it) */
  flow->capture_armed = FALSE;
  flow->header = flow->readout.header;

  switch (fpi_validity_a2_image_flags_verdict (flow->header.flags,
                                               flow->flags_rule))
    {
    case VALIDITY_A2_FLAGS_USE:
      if (flow->header.flags != 0)
        fp_info ("Capture: image flags 0x%08x, image used",
                 flow->header.flags);
      if (flow->match)
        {
          /* Matching happens on the sensor; the host copy is not needed */
          fpi_validity_a2_readout_clear (&flow->readout);
          flow->next_op = VALIDITY_A2_OP_MATCH_START;
        }
      else
        {
          flow_finish (flow, VALIDITY_A2_OUTCOME_IMAGE, NULL);
        }
      return;

    case VALIDITY_A2_FLAGS_RECAPTURE:
      flow_rearm_or_retry (flow, "the sensor flagged the image for recapture");
      return;

    case VALIDITY_A2_FLAGS_REJECT:
      fp_info ("Capture: image flags 0x%08x -- asking for another scan",
               flow->header.flags);
      flow_retry (flow, FP_DEVICE_RETRY_GENERAL);
      return;
    }
}

static void
flow_match_result_reply (ValidityA2Flow *flow,
                         guint16         status,
                         const guint8   *data,
                         gsize           data_len)
{
  GError *error = NULL;

  /* A refused 60 is not a "no match": with the wrong handle every real
   * match would silently read as one. No status is known to mean
   * "nothing matched" here; add one only after a device session shows it. */
  if (status != VCSFW_STATUS_OK)
    {
      g_autofree gchar *msg =
        g_strdup_printf ("The sensor rejected the match result request "
                         "(60 status 0x%04x)", status);
      flow_fail (flow, msg);
      return;
    }

  fpi_validity_match_result_clear (&flow->result);
  if (!fpi_validity_a2_parse_match_result (data, data_len, &flow->result, &error))
    {
      fpi_validity_match_result_clear (&flow->result);
      flow_finish (flow, VALIDITY_A2_OUTCOME_ERROR, error);
      return;
    }

  if (!flow->result.matched)
    {
      fp_info ("Match result: no match (tag 2 = 0x%08x)", flow->result.tag2);
      flow_finish (flow, VALIDITY_A2_OUTCOME_NO_MATCH, NULL);
      return;
    }

  fp_info ("Match result: user record %u, finger subtype %u",
           flow->result.user_dbid, flow->result.subtype);
  flow_finish (flow, VALIDITY_A2_OUTCOME_MATCH, NULL);
}

void
fpi_validity_a2_flow_reply (ValidityA2Flow *flow,
                            guint16         status,
                            const guint8   *data,
                            gsize           data_len)
{
  ValidityA2Op op = flow->issued;

  flow->issued = VALIDITY_A2_OP_NONE;

  /* Replies to the cleanup tail: statuses do not matter, except that the
   * user record has to parse */
  if (flow->finishing)
    {
      if (op == VALIDITY_A2_OP_GET_USER)
        {
          fpi_validity_user_clear (&flow->user);
          flow->user_read = status == VCSFW_STATUS_OK && data != NULL &&
                            fpi_validity_db_parse_user (data, data_len, &flow->user);
          if (!flow->user_read)
            {
              fpi_validity_user_clear (&flow->user);
              fp_warn ("Could not read the matched user record "
                       "(status 0x%04x)", status);
            }
        }
      else if (status != VCSFW_STATUS_OK)
        {
          fp_dbg ("%s: status 0x%04x (ignored)", fpi_validity_a2_op_name (op),
                  status);
        }
      return;
    }

  switch (op)
    {
    case VALIDITY_A2_OP_GLOW_START:
      /* The LED pattern is cosmetic; its status is not checked */
      flow->next_op = VALIDITY_A2_OP_CAPTURE;
      break;

    case VALIDITY_A2_OP_CAPTURE:
      if (status != VCSFW_STATUS_OK)
        {
          g_autofree gchar *msg =
            g_strdup_printf ("The sensor rejected the capture program "
                             "(status 0x%04x)", status);
          flow_fail (flow, msg);
          break;
        }
      flow->next_op = VALIDITY_A2_OP_WAIT_CAPTURE_EVENT;
      break;

    case VALIDITY_A2_OP_READ_IMAGE:
      flow_readout_reply (flow, status, data, data_len);
      break;

    case VALIDITY_A2_OP_CAPTURE_STOP:
      /* A stop before re-arming; its status does not matter */
      if (flow->rearm_after_stop)
        {
          flow->rearm_after_stop = FALSE;
          flow_rearm_or_retry (flow, "no usable image");
        }
      else
        {
          flow_fail (flow, "internal error: unexpected capture stop");
        }
      break;

    case VALIDITY_A2_OP_MATCH_START:
      /* A refused 5e is an error, not a "no match" (see the 60 reply);
       * the cleanup still sends 62 and 39 end */
      if (status != VCSFW_STATUS_OK)
        {
          g_autofree gchar *msg =
            g_strdup_printf ("The sensor rejected the match start "
                             "(5e status 0x%04x)", status);
          flow_fail (flow, msg);
          break;
        }
      if (data != NULL && data_len >= 4)
        flow->match_handle = (guint32) data[0] | ((guint32) data[1] << 8) |
                             ((guint32) data[2] << 16) |
                             ((guint32) data[3] << 24);
      else
        flow->match_handle = 0;
      fp_dbg ("Match handle 0x%08x (%" G_GSIZE_FORMAT " reply bytes)",
              flow->match_handle, data_len);
      flow->next_op = VALIDITY_A2_OP_WAIT_MATCH_EVENT;
      break;

    case VALIDITY_A2_OP_GET_RESULT:
      flow_match_result_reply (flow, status, data, data_len);
      break;

    case VALIDITY_A2_OP_NONE:
    case VALIDITY_A2_OP_WAIT_CAPTURE_EVENT:
    case VALIDITY_A2_OP_WAIT_MATCH_EVENT:
    case VALIDITY_A2_OP_MATCH_CLEANUP:
    case VALIDITY_A2_OP_GLOW_END:
    case VALIDITY_A2_OP_GET_USER:
    case VALIDITY_A2_OP_DELAY:
    case VALIDITY_A2_OP_DONE:
      /* 62, 39 end and 4a only run in the cleanup tail (handled above) */
      flow_fail (flow, "internal error: reply without a command");
      break;
    }
}

void
fpi_validity_a2_flow_event (ValidityA2Flow *flow,
                            const guint8   *buf,
                            gsize           len)
{
  ValidityA2Op op = flow->issued;
  guint16 code = 0, detail = 0;

  flow->issued = VALIDITY_A2_OP_NONE;

  if (flow->finishing)
    return;

  if (op == VALIDITY_A2_OP_WAIT_CAPTURE_EVENT)
    {
      switch (fpi_validity_a2_classify_capture_event (buf, len, &code))
        {
        case VALIDITY_A2_CAPT_EV_START:
        case VALIDITY_A2_CAPT_EV_WAIT:
        case VALIDITY_A2_CAPT_EV_OTHER:
          flow->next_op = VALIDITY_A2_OP_WAIT_CAPTURE_EVENT;
          return;

        case VALIDITY_A2_CAPT_EV_FINGER_DOWN:
          flow->finger_present = TRUE;
          flow->next_op = VALIDITY_A2_OP_WAIT_CAPTURE_EVENT;
          return;

        case VALIDITY_A2_CAPT_EV_READY:
          flow->finger_present = TRUE;
          fpi_validity_a2_readout_clear (&flow->readout);
          flow->next_op = VALIDITY_A2_OP_READ_IMAGE;
          return;

        case VALIDITY_A2_CAPT_EV_ABORT:
          fp_info ("Capture: the sensor aborted the capture (code %u)", code);
          flow_stop_then_rearm (flow);
          return;

        case VALIDITY_A2_CAPT_EV_BAD:
          fp_info ("Capture: bad capture (code %u) -- asking for another scan",
                   code);
          flow_retry (flow, FP_DEVICE_RETRY_GENERAL);
          return;

        case VALIDITY_A2_CAPT_EV_MALFORMED:
          flow_fail (flow, "Malformed capture event from the sensor");
          return;
        }
    }

  if (op == VALIDITY_A2_OP_WAIT_MATCH_EVENT)
    {
      switch (fpi_validity_a2_classify_match_event (buf, len, &code, &detail))
        {
        case VALIDITY_A2_MATCH_EV_PENDING:
          flow->next_op = VALIDITY_A2_OP_WAIT_MATCH_EVENT;
          return;

        case VALIDITY_A2_MATCH_EV_STALE:
          /* still bounded by the caller's match deadline */
          fp_info ("Match wait: ignoring a late capture report "
                   "(%02x %02x ...)", buf[0], buf[1]);
          flow->next_op = VALIDITY_A2_OP_WAIT_MATCH_EVENT;
          return;

        case VALIDITY_A2_MATCH_EV_MATCH:
        case VALIDITY_A2_MATCH_EV_OTHER_DONE:
          fp_dbg ("Match event code %u -- reading the result", code);
          flow->next_op = VALIDITY_A2_OP_GET_RESULT;
          return;

        case VALIDITY_A2_MATCH_EV_NO_MATCH:
          fp_info ("Match: no match (%u template(s) compared)", detail);
          flow_finish (flow, VALIDITY_A2_OUTCOME_NO_MATCH, NULL);
          return;

        case VALIDITY_A2_MATCH_EV_ERROR:
          /* E.g. 0x050b "nothing to match against"; never a match */
          fp_info ("Match: the sensor reported error status 0x%04x -- "
                   "no match", detail);
          flow_finish (flow, VALIDITY_A2_OUTCOME_NO_MATCH, NULL);
          return;

        case VALIDITY_A2_MATCH_EV_MALFORMED:
          flow_fail (flow, "Malformed match event from the sensor");
          return;
        }
    }

  flow_fail (flow, "internal error: event without a wait");
}

void
fpi_validity_a2_flow_cancel (ValidityA2Flow *flow)
{
  flow->issued = VALIDITY_A2_OP_NONE;

  if (flow->finishing)
    {
      /* Keep the cleanup going; only drop the final read of a matched
       * user record, the result is not reported any more */
      if (flow->outcome != VALIDITY_A2_OUTCOME_ERROR &&
          flow->outcome != VALIDITY_A2_OUTCOME_CANCELLED)
        {
          flow->outcome = VALIDITY_A2_OUTCOME_CANCELLED;
          flow->user_requested = TRUE;
        }
      return;
    }

  flow_finish (flow, VALIDITY_A2_OUTCOME_CANCELLED, NULL);
}

void
fpi_validity_a2_flow_timeout (ValidityA2Flow *flow)
{
  ValidityA2Op op = flow->issued;

  flow->issued = VALIDITY_A2_OP_NONE;

  if (op == VALIDITY_A2_OP_WAIT_MATCH_EVENT)
    flow_fail (flow, "The sensor did not report a match result in time");
  else
    flow_fail (flow, "Timed out waiting for the sensor");
}

void
fpi_validity_a2_flow_transport_error (ValidityA2Flow *flow,
                                      GError         *error)
{
  flow->issued = VALIDITY_A2_OP_NONE;
  flow_finish (flow, VALIDITY_A2_OUTCOME_ERROR, error);
}

guint8 *
fpi_validity_a2_flow_build_cmd (const ValidityA2Flow *flow,
                                ValidityA2Op          op,
                                gsize                *out_len)
{
  const guint8 *stat;
  gsize len = 0;

  *out_len = 0;

  switch (op)
    {
    case VALIDITY_A2_OP_GLOW_START:
      stat = fpi_validity_capture_glow_start_cmd (&len);
      *out_len = len;
      return g_memdup2 (stat, len);

    case VALIDITY_A2_OP_GLOW_END:
      stat = fpi_validity_capture_glow_end_cmd (&len);
      *out_len = len;
      return g_memdup2 (stat, len);

    case VALIDITY_A2_OP_READ_IMAGE:
      return validity_pack_new (out_len, "bw", VCSFW_CMD_GET_PRG_STATUS,
                                (guint32) VALIDITY_A2_READ_CHUNK_MAX);

    case VALIDITY_A2_OP_CAPTURE_STOP:
      return validity_pack_new (out_len, "b", VCSFW_CMD_CAPTURE_STOP);

    case VALIDITY_A2_OP_MATCH_START:
      /* mode 2 (identify against the template database), 0xff, storage 0
      * and user 0 (any), 1, no data -- python-validity match_finger() */
      return validity_pack_new (out_len, "bbbhhhw", VCSFW_CMD_MATCH_FINGER,
                                0x02, 0xff, 0, 0, 1, (guint32) 0);

    case VALIDITY_A2_OP_GET_RESULT:
      return validity_pack_new (out_len, "bw", VCSFW_CMD_GET_MATCH_RESULT,
                                flow->match_handle);

    case VALIDITY_A2_OP_MATCH_CLEANUP:
      return validity_pack_new (out_len, "bw", VCSFW_CMD_MATCH_CLEANUP,
                                flow->match_handle);

    case VALIDITY_A2_OP_GET_USER:
      if (flow->result.user_dbid > G_MAXUINT16)
        return NULL;
      return fpi_validity_db_build_cmd_get_user ((guint16) flow->result.user_dbid,
                                                 out_len);

    case VALIDITY_A2_OP_CAPTURE:          /* built by the caller */
    case VALIDITY_A2_OP_NONE:
    case VALIDITY_A2_OP_WAIT_CAPTURE_EVENT:
    case VALIDITY_A2_OP_WAIT_MATCH_EVENT:
    case VALIDITY_A2_OP_DELAY:
    case VALIDITY_A2_OP_DONE:
      return NULL;
    }

  return NULL;
}
