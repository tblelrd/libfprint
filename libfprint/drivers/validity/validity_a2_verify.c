/*
 * 06cb:00a2 verify, identify and diagnostic image capture
 *
 * Runs the flow of fpi_validity_a2_capture.c against the sensor: commands go
 * over TLS (vcsfw_tls_cmd_send), events are read from EP 0x83. The flow
 * decides every step; this file only performs them.
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
#include "fpi-image.h"
#include "fpi-print.h"
#include "validity.h"
#include "validity_a2.h"
#include "validity_a2_capture.h"
#include "validity_data.h"
#include "vcsfw_protocol.h"

typedef enum {
  A2_ACTION_VERIFY = 0,
  A2_ACTION_IDENTIFY,
  A2_ACTION_CAPTURE,
  A2_ACTION_ENROLL,
} A2Action;

typedef enum {
  A2_SSM_STEP = 0,    /* ask the flow what to do and do it */
  A2_SSM_RECV,        /* a command reply is in: feed it to the flow */
  A2_SSM_NUM_STATES,
} A2SsmState;

typedef struct
{
  A2Action              action;
  ValidityA2Flow        flow;
  guint8               *capture_cmd; /* the 02 IDENTIFY program */
  gsize                 capture_cmd_len;
  gint64                match_deadline; /* monotonic us; 0 until the match wait */
  ValidityA2CaptureDone capture_done;
  gpointer              capture_data;
} A2SsmData;

static void
a2_ssm_data_free (gpointer data)
{
  A2SsmData *d = data;

  fpi_validity_a2_flow_clear (&d->flow);
  g_free (d->capture_cmd);
  g_free (d);
}

/* Drop the last reply; a 51 reply holds image pixels */
static void
a2_clear_response (FpiDeviceValidity *self)
{
  if (self->cmd_response_data)
    memset (self->cmd_response_data, 0, self->cmd_response_len);
  g_clear_pointer (&self->cmd_response_data, g_free);
  self->cmd_response_len = 0;
}

/* ================================================================
 * EP 0x83
 * ================================================================ */

static void
a2_event_cb (FpiUsbTransfer *transfer,
             FpDevice       *device,
             gpointer        user_data,
             GError         *error)
{
  FpiSsm *ssm = user_data;
  A2SsmData *d = fpi_ssm_get_data (ssm);
  gboolean was_present = d->flow.finger_present;

  if (error)
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
          g_error_matches (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_CANCELLED))
        {
          fp_dbg ("Wait for the sensor cancelled");
          fpi_validity_a2_flow_cancel (&d->flow);
          g_error_free (error);
        }
      else if (g_error_matches (error, G_USB_DEVICE_ERROR,
                                G_USB_DEVICE_ERROR_TIMED_OUT) &&
               d->flow.issued == VALIDITY_A2_OP_WAIT_MATCH_EVENT)
        {
          fpi_validity_a2_flow_timeout (&d->flow);
          g_error_free (error);
        }
      else if (g_error_matches (error, G_USB_DEVICE_ERROR,
                                G_USB_DEVICE_ERROR_NO_DEVICE))
        {
          /* The sensor is gone: nothing can be sent any more */
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      else
        {
          /* The interrupt pipe failed, the TLS session did not: stop the
          * capture and the match on the sensor (04 / 62 / 39 end) rather
          * than leave it armed with the LED on, then report the error */
          fp_warn ("Waiting for the sensor failed: %s -- cleaning up",
                   error->message);
          g_prefix_error (&error, "Waiting for the sensor failed: ");
          fpi_validity_a2_flow_transport_error (&d->flow, error);
        }

      fpi_ssm_jump_to_state (ssm, A2_SSM_STEP);
      return;
    }

  if (transfer->actual_length >= 5)
    fp_dbg ("EP 0x83: %02x %02x %02x %02x %02x (%" G_GSSIZE_FORMAT " bytes)",
            transfer->buffer[0], transfer->buffer[1], transfer->buffer[2],
            transfer->buffer[3], transfer->buffer[4], transfer->actual_length);
  else
    fp_dbg ("EP 0x83: %" G_GSSIZE_FORMAT " bytes", transfer->actual_length);

  fpi_validity_a2_flow_event (&d->flow, transfer->buffer,
                              transfer->actual_length > 0 ?
                              (gsize) transfer->actual_length : 0);

  if (d->flow.finger_present && !was_present)
    fpi_device_report_finger_status_changes (device,
                                             FP_FINGER_STATUS_PRESENT,
                                             FP_FINGER_STATUS_NONE);

  fpi_ssm_jump_to_state (ssm, A2_SSM_STEP);
}

static void
a2_wait_event (FpiDeviceValidity *self,
               FpiSsm            *ssm,
               guint              timeout_ms)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (self));

  fpi_usb_transfer_fill_interrupt (transfer, VALIDITY_EP_INT_IN,
                                   VALIDITY_USB_INT_DATA_SIZE);
  /* The finger wait has no timeout (the user decides); the action's
   * cancellable ends it, and the flow then cleans up */
  fpi_usb_transfer_submit (transfer, timeout_ms,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           a2_event_cb, ssm);
}

/* ================================================================
 * SSM
 * ================================================================ */

static void
a2_step (FpiSsm            *ssm,
         FpiDeviceValidity *self)
{
  A2SsmData *d = fpi_ssm_get_data (ssm);
  ValidityA2Op op;
  guint delay_ms = 0;

  /* A cancel that arrived while a command was in flight (commands are not
   * cancellable, so the sensor never sees half an exchange) */
  if (fpi_device_action_is_cancelled (FP_DEVICE (self)))
    fpi_validity_a2_flow_cancel (&d->flow);

  op = fpi_validity_a2_flow_next (&d->flow, &delay_ms);
  fp_dbg ("00a2 flow: %s", fpi_validity_a2_op_name (op));

  switch (op)
    {
    case VALIDITY_A2_OP_CAPTURE:
      fpi_vcsfw_tls_cmd_send (self, ssm, d->capture_cmd, d->capture_cmd_len, NULL);
      return;

    case VALIDITY_A2_OP_WAIT_CAPTURE_EVENT:
      a2_wait_event (self, ssm, 0);
      return;

    case VALIDITY_A2_OP_WAIT_MATCH_EVENT:
      {
        gint64 now = g_get_monotonic_time ();

        if (d->match_deadline == 0)
          d->match_deadline = now +
                              (gint64) VALIDITY_A2_MATCH_TIMEOUT_MS * 1000;

        if (now >= d->match_deadline)
          {
            fpi_validity_a2_flow_timeout (&d->flow);
            fpi_ssm_jump_to_state (ssm, A2_SSM_STEP);
            return;
          }

        a2_wait_event (self, ssm,
                       (guint) MAX (1, (d->match_deadline - now) / 1000));
      }
      return;

    case VALIDITY_A2_OP_DELAY:
      fpi_ssm_jump_to_state_delayed (ssm, A2_SSM_STEP, delay_ms);
      return;

    case VALIDITY_A2_OP_DONE:
      fpi_ssm_mark_completed (ssm);
      return;

    case VALIDITY_A2_OP_NONE:
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "00a2 capture flow "
                                                     "stalled"));
      return;

    case VALIDITY_A2_OP_GLOW_START:
    case VALIDITY_A2_OP_READ_IMAGE:
    case VALIDITY_A2_OP_CAPTURE_STOP:
    case VALIDITY_A2_OP_MATCH_START:
    case VALIDITY_A2_OP_GET_RESULT:
    case VALIDITY_A2_OP_MATCH_CLEANUP:
    case VALIDITY_A2_OP_GLOW_END:
    case VALIDITY_A2_OP_GET_USER:
      {
        gsize len = 0;
        g_autofree guint8 *cmd = fpi_validity_a2_flow_build_cmd (&d->flow, op,
                                                                 &len);

        if (!cmd)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                           "00a2 capture flow: "
                                                           "cannot build %s",
                                                           fpi_validity_a2_op_name (op)));
            return;
          }

        fpi_vcsfw_tls_cmd_send (self, ssm, cmd, len, NULL);
      }
      return;
    }
}

static void
a2_run_state (FpiSsm   *ssm,
              FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  A2SsmData *d = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case A2_SSM_STEP:
      a2_step (ssm, self);
      break;

    case A2_SSM_RECV:
      fpi_validity_a2_flow_reply (&d->flow, self->cmd_response_status,
                                  self->cmd_response_data,
                                  self->cmd_response_len);
      a2_clear_response (self);
      fpi_ssm_jump_to_state (ssm, A2_SSM_STEP);
      break;
    }
}

/* ================================================================
 * Completion
 * ================================================================ */

static void
a2_complete_error (FpDevice *dev,
                   A2Action  action,
                   GError   *error)
{
  switch (action)
    {
    case A2_ACTION_VERIFY:
      fpi_device_verify_complete (dev, error);
      break;

    case A2_ACTION_IDENTIFY:
      fpi_device_identify_complete (dev, error);
      break;

    case A2_ACTION_CAPTURE:
      fpi_device_capture_complete (dev, NULL, error);
      break;

    case A2_ACTION_ENROLL:
      g_assert_not_reached (); /* handled by the internal capture callback */
    }
}

static void
a2_complete_retry (FpDevice     *dev,
                   A2Action      action,
                   FpDeviceRetry retry)
{
  switch (action)
    {
    case A2_ACTION_VERIFY:
      fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
                                fpi_device_retry_new (retry));
      fpi_device_verify_complete (dev, NULL);
      break;

    case A2_ACTION_IDENTIFY:
      fpi_device_identify_report (dev, NULL, NULL,
                                  fpi_device_retry_new (retry));
      fpi_device_identify_complete (dev, NULL);
      break;

    case A2_ACTION_CAPTURE:
      fpi_device_capture_complete (dev, NULL, fpi_device_retry_new (retry));
      break;

    case A2_ACTION_ENROLL:
      g_assert_not_reached ();
    }
}

/* Report a match only for the print(s) whose chip record and finger the
 * sensor named (validity_match_decide); everything else is no match */
static void
a2_complete_match (FpDevice             *dev,
                   A2Action              action,
                   const ValidityA2Flow *flow)
{
  const ValidityMatchResult *match = NULL;
  ValidityUser no_user = { 0 };
  const ValidityUser *user = &no_user;
  FpPrint *print = NULL;
  GPtrArray *gallery = NULL;
  FpPrint *gallery_match = NULL;
  FpiMatchResult result;

  if (flow->outcome == VALIDITY_A2_OUTCOME_MATCH)
    {
      match = &flow->result;
      if (flow->user_read)
        user = &flow->user;
    }

  if (action == A2_ACTION_IDENTIFY)
    fpi_device_get_identify_data (dev, &gallery);
  else
    fpi_device_get_verify_data (dev, &print);

  result = fpi_validity_match_decide (action == A2_ACTION_IDENTIFY, print, gallery,
                                      match, user, &gallery_match);

  if (match && result != FPI_MATCH_SUCCESS)
    fp_info ("The sensor matched user record %u (finger %u), which is not "
             "the print being checked -- no match",
             match->user_dbid, match->subtype);
  else if (match)
    fp_info ("Matched user record %u (finger %u)", match->user_dbid,
             match->subtype);
  else
    fp_info ("No match");

  if (action == A2_ACTION_IDENTIFY)
    {
      fpi_device_identify_report (dev, gallery_match, NULL, NULL);
      fpi_device_identify_complete (dev, NULL);
    }
  else
    {
      fpi_device_verify_report (dev, result, NULL, NULL);
      fpi_device_verify_complete (dev, NULL);
    }
}

static void
a2_complete_image (FpDevice       *dev,
                   ValidityA2Flow *flow)
{
  const guint8 *pixels;
  gsize n = 0;
  FpImage *image;

  pixels = fpi_validity_a2_readout_pixels (&flow->readout, &n);
  if (!pixels || n != (gsize) flow->header.rows * flow->header.cols)
    {
      fpi_device_capture_complete (dev, NULL,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                             "No image was read"));
      return;
    }

  /* Row-major, rows x cols (112 x 112) */
  image = fp_image_new (flow->header.cols, flow->header.rows);
  memcpy (image->data, pixels, n);
  /* The header's resolution field is 333 on 00a2: dots per inch */
  image->ppmm = (flow->header.resolution ? flow->header.resolution : 333) /
                25.4;

  fp_info ("Captured a %ux%u image", flow->header.cols, flow->header.rows);
  fpi_device_capture_complete (dev, image, NULL);
}

static void
a2_ssm_done (FpiSsm   *ssm,
             FpDevice *dev,
             GError   *error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  A2SsmData *d = fpi_ssm_get_data (ssm);
  ValidityA2Flow *flow = &d->flow;

  a2_clear_response (self);

  if (d->capture_done)
    {
      d->capture_done (dev, flow, error ? fpi_validity_map_removed_error (error) : NULL,
                       d->capture_data);
      return;
    }

  /* A TLS command failed (or the sensor is gone): no cleanup is possible
   * over a session that may be broken, and there is no reconnect on this
   * model (validity_a2.c). An EP 0x83 failure ran the cleanup and ends
   * below as OUTCOME_ERROR. */
  if (error)
    {
      fp_warn ("00a2 %s failed: %s",
               d->action == A2_ACTION_CAPTURE ? "capture" : "match",
               error->message);
      a2_complete_error (dev, d->action, fpi_validity_map_removed_error (error));
      return;
    }

  fp_dbg ("00a2 flow done: outcome %d, %u capture(s), %u stop(s), "
          "match handle 0x%08x", flow->outcome, flow->captures, flow->stops,
          flow->match_handle);

  switch (flow->outcome)
    {
    case VALIDITY_A2_OUTCOME_CANCELLED:
      a2_complete_error (dev, d->action,
                         g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                              "Operation was cancelled"));
      return;

    case VALIDITY_A2_OUTCOME_ERROR:
      a2_complete_error (dev, d->action,
                         flow->error ? g_steal_pointer (&flow->error) :
                         fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;

    case VALIDITY_A2_OUTCOME_RETRY:
      a2_complete_retry (dev, d->action, flow->retry);
      return;

    case VALIDITY_A2_OUTCOME_MATCH:
    case VALIDITY_A2_OUTCOME_NO_MATCH:
      if (d->action != A2_ACTION_CAPTURE)
        {
          a2_complete_match (dev, d->action, flow);
          return;
        }
      break;

    case VALIDITY_A2_OUTCOME_IMAGE:
      if (d->action == A2_ACTION_CAPTURE)
        {
          a2_complete_image (dev, flow);
          return;
        }
      break;

    case VALIDITY_A2_OUTCOME_NONE:
      break;
    }

  a2_complete_error (dev, d->action,
                     fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                               "00a2 capture flow ended "
                                               "without a result"));
}

static void
a2_start (FpDevice             *device,
          A2Action              action,
          ValidityA2CaptureDone capture_done,
          gpointer              capture_data)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (device);
  const ValidityDevicePolicy *policy = fpi_validity_device_policy (self->dev_type);
  GError *error = NULL;
  A2SsmData *d;
  FpiSsm *ssm;

  /* The open established TLS and calibrated the sensor (RAM only); refuse
   * if any of it is missing rather than send a program without them */
  if (!self->tls.secure_rx ||
      !self->sensor.type_info ||
      !fpi_validity_a2_sensor_gate (self->sensor.device_info ?
                                    self->sensor.device_info->type : 0,
                                    self->sensor.real_sensor_type,
                                    &self->capture, TRUE, &error))
    {
      if (!error)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                          "The sensor is not ready to capture");
      if (capture_done)
        capture_done (device, NULL, error, capture_data);
      else
        a2_complete_error (device, action, error);
      return;
    }

  d = g_new0 (A2SsmData, 1);
  d->action = action;
  d->capture_done = capture_done;
  d->capture_data = capture_data;
  fpi_validity_a2_flow_init (&d->flow, action == A2_ACTION_VERIFY || action == A2_ACTION_IDENTIFY,
                             policy->strict_image_flags ?
                             VALIDITY_A2_FLAGS_RULE_STRICT :
                             VALIDITY_A2_FLAGS_RULE_WINDOWS);

  /* Built once: a re-arm sends the same program */
  d->capture_cmd = fpi_validity_capture_build_cmd_02 (&self->capture,
                                                      self->sensor.type_info,
                                                      action == A2_ACTION_ENROLL ?
                                                      VALIDITY_CAPTURE_ENROLL : VALIDITY_CAPTURE_IDENTIFY,
                                                      &d->capture_cmd_len);
  if (!d->capture_cmd)
    {
      a2_ssm_data_free (d);
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Could not build the capture program");
      if (capture_done)
        capture_done (device, NULL, error, capture_data);
      else
        a2_complete_error (device, action, error);
      return;
    }

  ssm = fpi_ssm_new (device, a2_run_state, A2_SSM_NUM_STATES);
  fpi_ssm_set_data (ssm, d, a2_ssm_data_free);
  fpi_ssm_start (ssm, a2_ssm_done);
}

void
fpi_validity_a2_verify (FpDevice *device)
{
  a2_start (device, A2_ACTION_VERIFY, NULL, NULL);
}

void
fpi_validity_a2_identify (FpDevice *device)
{
  a2_start (device, A2_ACTION_IDENTIFY, NULL, NULL);
}

/* Diagnostic image capture (FpDevice::capture). The vfunc is only set in
 * developer builds (meson -Dvalidity_dev=true) and probe clears the
 * feature for every model whose policy does not allow it; this re-checks
 * both. The image is the one verify sends to the on-chip matcher (the
 * IDENTIFY capture program), returned to the caller and never logged. */
void
fpi_validity_a2_capture (FpDevice *device)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (device);
  gboolean wait_for_finger = FALSE;

  fpi_device_get_capture_data (device, &wait_for_finger);

  if (!fpi_validity_dev_overrides_built () ||
      !fpi_validity_device_policy (self->dev_type)->allow_image_capture)
    {
      fpi_device_capture_complete (device, NULL,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                             "Image capture is "
                                                             "not supported"));
      return;
    }

  if (!wait_for_finger)
    {
      fpi_device_capture_complete (device, NULL,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                             "This sensor only "
                                                             "captures when a "
                                                             "finger is placed"));
      return;
    }

  a2_start (device, A2_ACTION_CAPTURE, NULL, NULL);
}

void
fpi_validity_a2_capture_enroll (FpDevice             *device,
                                ValidityA2CaptureDone done,
                                gpointer              user_data)
{
  g_return_if_fail (done != NULL);
  a2_start (device, A2_ACTION_ENROLL, done, user_data);
}
