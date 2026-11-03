/*
 * Host enrollment for the owned 06cb:00a2 sensor.
 *
 * Capture six placements with the tested streaming flow, build a template,
 * then create a user and store one type-6 record. No provisioning, erase,
 * on-chip enroll, automatic reconnect or retry of a persistent command.
 *
 * Copyright (C) 2026 libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "validity"

#include "drivers_api.h"
#include "fpi-print.h"
#include "validity.h"
#include "validity_a2_capture.h"
#include "validity_moh.h"
#include "vcsfw_protocol.h"

typedef enum {
  MOH_INFO, MOH_INFO_RECV,
  MOH_STORAGE, MOH_STORAGE_RECV,
  MOH_CAPTURE,
  MOH_BUILD,
  MOH_SPACE, MOH_SPACE_RECV,
  MOH_ENABLE_USER, MOH_ENABLE_USER_RECV,
  MOH_USER, MOH_USER_RECV,
  MOH_USER_COMMIT, MOH_USER_COMMIT_RECV,
  MOH_ENABLE_FINGER, MOH_ENABLE_FINGER_RECV,
  MOH_STORE, MOH_STORE_RECV,
  MOH_COMMIT, MOH_COMMIT_RECV,
  MOH_AFTER, MOH_AFTER_RECV,
  MOH_READBACK, MOH_READBACK_RECV,
  MOH_DONE,
  MOH_N_STATES,
} MohState;

typedef struct
{
  ValidityMohEnroll *builder;
  GBytes            *envelope;
  gchar             *user_id;
  guint16            storage, user, finger, subtype;
  guint              reported;
  gboolean           user_sent;
  gboolean           store_sent;
} MohData;

static void
moh_data_free (gpointer data)
{
  MohData *d = data;

  fpi_validity_moh_enroll_free (d->builder);
  g_clear_pointer (&d->envelope, g_bytes_unref);
  g_free (d->user_id);
  g_free (d);
}

static void
moh_clear_response (FpiDeviceValidity *self)
{
  if (self->cmd_response_data)
    explicit_bzero (self->cmd_response_data, self->cmd_response_len);
  g_clear_pointer (&self->cmd_response_data, g_free);
  self->cmd_response_len = 0;
}

static gboolean
moh_status_ok (FpiSsm *ssm, FpiDeviceValidity *self)
{
  if (self->cmd_response_status == VCSFW_STATUS_OK)
    return TRUE;

  fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                         self->cmd_response_status == 0x04b5 ? FP_DEVICE_ERROR_DATA_FULL : FP_DEVICE_ERROR_PROTO,
                         "00a2 enrollment state %d: sensor status 0x%04x; command will not be retried",
                         fpi_ssm_get_cur_state (ssm), self->cmd_response_status));
  return FALSE;
}

/* A missing or malformed space query is an error, never permission to write. */
static gboolean
moh_check_space (FpiSsm *ssm, FpiDeviceValidity *self, gboolean before)
{
  ValidityDbInfo info = { 0 };
  GError *error = NULL;

  if (!moh_status_ok (ssm, self))
    return FALSE;
  if (!self->cmd_response_data ||
      !fpi_validity_db_parse_info (self->cmd_response_data, self->cmd_response_len, &info) ||
      info.total == 0 || info.used > info.total || info.free_space > info.total - info.used)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Invalid fingerprint DB space reply");
    }
  else
    {
      fp_info ("00a2 DB %s: free=%u used=%u total=%u records=%u",
               before ? "before store" : "after store",
               info.free_space, info.used, info.total, info.records);
      if (before && info.free_space < VALIDITY_ENROLL_MIN_FREE_BYTES)
        error = fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL);
    }
  fpi_validity_db_info_clear (&info);
  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return FALSE;
    }
  return TRUE;
}

static void
moh_capture_done (FpDevice *device, ValidityA2Flow *flow, GError *error, gpointer data)
{
  FpiSsm *ssm = data;
  MohData *d = fpi_ssm_get_data (ssm);
  ValidityMohEnrollStep step;
  gsize len = 0;

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (flow->outcome == VALIDITY_A2_OUTCOME_CANCELLED || fpi_device_action_is_cancelled (device))
    {
      fpi_ssm_mark_failed (ssm, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                     "Enrollment cancelled"));
      return;
    }
  if (flow->outcome == VALIDITY_A2_OUTCOME_ERROR)
    {
      fpi_ssm_mark_failed (ssm, flow->error ? g_error_copy (flow->error) :
                           fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }
  if (flow->outcome == VALIDITY_A2_OUTCOME_IMAGE)
    {
      const guint8 *pixels = fpi_validity_a2_readout_pixels (&flow->readout, &len);

      /* The capture flow has already applied the vendor flags rule. Benign
      * flags (e.g. 0x80000) must not become a second quality rejection. */
      if (!fpi_validity_moh_enroll_step_image (d->builder, pixels, len,
                                               flow->header.rows, flow->header.cols,
                                               0, &step, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
    }
  else if (flow->outcome == VALIDITY_A2_OUTCOME_RETRY)
    {
      fpi_validity_moh_enroll_step_capture_failed (d->builder, &step);
    }
  else
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  fp_info ("00a2 enrollment: placement %u, %s", step.sections,
           fpi_validity_moh_step_reason_to_string (step.reason));
  switch (step.action)
    {
    case VALIDITY_MOH_STEP_FAIL:
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "Enrollment failed: %s",
                                                          fpi_validity_moh_step_reason_to_string (step.reason)));
      break;

    case VALIDITY_MOH_STEP_RETRY:
      fpi_device_enroll_progress (device, d->reported, NULL,
                                  fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      fpi_ssm_jump_to_state_delayed (ssm, MOH_CAPTURE, 300);
      break;

    case VALIDITY_MOH_STEP_ACCEPT:
    case VALIDITY_MOH_STEP_DONE:
      /* Reserve the last progress stage until store, commit and readback
       * succeeded; fprintd must not see a completed enrollment early. */
      d->reported = MIN (step.sections, fpi_validity_moh_enroll_get_num_frames (d->builder) - 1);
      fpi_device_enroll_progress (device, d->reported, NULL, NULL);
      if (step.action == VALIDITY_MOH_STEP_DONE)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_jump_to_state_delayed (ssm, MOH_CAPTURE, 300);
      break;
    }
}

static void
moh_run (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (device);
  MohData *d = fpi_ssm_get_data (ssm);
  MohState state = fpi_ssm_get_cur_state (ssm);
  g_autofree guint8 *cmd = NULL;
  gsize len = 0;

  /* Exchanges are indivisible. Once the template store was sent, finish
   * commit/readback even if cancellation arrives; never replay the store. */
  if (!d->store_sent && fpi_device_action_is_cancelled (device) &&
      (state == MOH_INFO || state == MOH_STORAGE || state == MOH_CAPTURE ||
       state == MOH_BUILD || state == MOH_SPACE || state == MOH_ENABLE_USER ||
       state == MOH_USER || state == MOH_ENABLE_FINGER || state == MOH_STORE))
    {
      fpi_ssm_mark_failed (ssm, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                     "Enrollment cancelled"));
      return;
    }

  switch (state)
    {
    case MOH_INFO:
    case MOH_SPACE:
    case MOH_AFTER:
      cmd = fpi_validity_db_build_cmd_db_info (&len);
      break;

    case MOH_INFO_RECV:
    case MOH_SPACE_RECV:
    case MOH_AFTER_RECV:
      if (moh_check_space (ssm, self, state != MOH_AFTER_RECV))
        fpi_ssm_next_state (ssm);
      return;

    case MOH_STORAGE:
      cmd = fpi_validity_db_build_cmd_get_user_storage (VALIDITY_STORAGE_NAME, &len);
      break;

    case MOH_STORAGE_RECV:
      {
        ValidityUserStorage storage = { 0 };
        gboolean ok;

        if (!moh_status_ok (ssm, self))
          return;
        ok = self->cmd_response_data &&
             fpi_validity_db_parse_user_storage (self->cmd_response_data, self->cmd_response_len, &storage) &&
             storage.dbid != 0 && g_strcmp0 (storage.name, VALIDITY_STORAGE_NAME) == 0;
        d->storage = storage.dbid;
        fpi_validity_user_storage_clear (&storage);
        if (!ok)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "Existing StgWindsor storage required"));
            return;
          }
        fpi_ssm_next_state (ssm);
        return;
      }

    case MOH_CAPTURE:
      moh_clear_response (self);
      fpi_validity_a2_capture_enroll (device, moh_capture_done, ssm);
      return;

    case MOH_BUILD:
      {
        GError *error = NULL;

        d->envelope = fpi_validity_moh_enroll_build_envelope (d->builder, d->subtype, NULL, NULL, &error);
        if (!d->envelope)
          fpi_ssm_mark_failed (ssm, error);
        else
          fpi_ssm_next_state (ssm);
        return;
      }

    case MOH_ENABLE_USER:
    case MOH_ENABLE_FINGER:
      {
        const guint8 *blob = fpi_validity_db_get_write_enable_blob (self, &len);
        fpi_vcsfw_tls_cmd_send (self, ssm, blob, len, NULL);
        return;
      }

    case MOH_USER:
      {
        gsize identity_len;
        g_autofree guint8 *identity = fpi_validity_db_build_identity (d->user_id, &identity_len);

        cmd = fpi_validity_db_build_cmd_new_record (d->storage, VALIDITY_DB_RECORD_TYPE_USER,
                                                    d->storage, identity, identity_len, &len);
        d->user_sent = TRUE;
        break;
      }

    case MOH_USER_RECV:
    case MOH_STORE_RECV:
      {
        guint16 record = 0;

        if (!moh_status_ok (ssm, self))
          return;
        if (self->cmd_response_len != 2 ||
            !fpi_validity_db_parse_new_record_id (self->cmd_response_data, self->cmd_response_len, &record) ||
            record == 0 || record == d->storage || (state == MOH_STORE_RECV && record == d->user))
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "Invalid new record id; store will not be retried"));
            return;
          }
        if (state == MOH_USER_RECV)
          d->user = record;
        else
          d->finger = record;
        fp_info ("00a2 created %s record %u", state == MOH_USER_RECV ? "user" : "finger", record);
        fpi_ssm_next_state (ssm);
        return;
      }

    case MOH_STORE:
      {
        g_autoptr(GBytes) store = fpi_validity_moh_build_store_cmd (d->user, d->storage, d->envelope);
        const guint8 *bytes = g_bytes_get_data (store, &len);

        d->store_sent = TRUE;
        fpi_vcsfw_tls_cmd_send (self, ssm, bytes, len, NULL);
        return;
      }

    case MOH_USER_COMMIT:
    case MOH_COMMIT:
      cmd = fpi_validity_db_build_cmd_call_cleanups (&len);
      break;

    case MOH_USER_COMMIT_RECV:
    case MOH_COMMIT_RECV:
      /* 0x0491 means there was nothing pending to commit. */
      if (self->cmd_response_status == 0x0491 || moh_status_ok (ssm, self))
        fpi_ssm_next_state (ssm);
      return;

    case MOH_ENABLE_USER_RECV:
    case MOH_ENABLE_FINGER_RECV:
      if (moh_status_ok (ssm, self))
        fpi_ssm_next_state (ssm);
      return;

    case MOH_READBACK:
      cmd = fpi_validity_db_build_cmd_get_user (d->user, &len);
      break;

    case MOH_READBACK_RECV:
      {
        ValidityUser user = { 0 };
        const guint8 *id = NULL;
        gsize id_len = 0;
        gboolean found = FALSE;

        if (!moh_status_ok (ssm, self))
          return;
        if (self->cmd_response_data &&
            fpi_validity_db_parse_user (self->cmd_response_data, self->cmd_response_len, &user) &&
            user.dbid == d->user && fpi_validity_db_user_get_id (&user, &id, &id_len) &&
            id_len == strlen (d->user_id) && memcmp (id, d->user_id, id_len) == 0)
          {
            for (guint i = 0; i < user.finger_count; i++)
              if (user.fingers[i].dbid == d->finger && user.fingers[i].subtype == d->subtype &&
                  user.fingers[i].storage == d->storage)
                found = TRUE;
          }
        fpi_validity_user_clear (&user);
        if (!found)
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "Stored finger missing from user readback; do not repeat enrollment"));
        else
          fpi_ssm_next_state (ssm);
        return;
      }

    case MOH_DONE:
      fpi_ssm_mark_completed (ssm);
      return;

    case MOH_N_STATES:
      g_assert_not_reached ();
    }
  moh_clear_response (self);
  fpi_vcsfw_tls_cmd_send (self, ssm, cmd, len, NULL);
}

static void
moh_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  MohData *d = fpi_ssm_get_data (ssm);
  FpPrint *print = NULL;

  moh_clear_response (FPI_DEVICE_VALIDITY (device));
  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  if (error)
    {
      if (d->user_sent || d->store_sent)
        fp_warn ("00a2 enrollment stopped after DB changes (user %u, finger %u, store sent %d); "
                 "inspect storage before another enrollment", d->user, d->finger, d->store_sent);
      fpi_device_enroll_complete (device, NULL, fpi_validity_map_removed_error (error));
      return;
    }
  fpi_device_get_enroll_data (device, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", g_variant_new_string (d->user_id), NULL);
  fpi_device_enroll_progress (device, fpi_validity_moh_enroll_get_num_frames (d->builder), NULL, NULL);
  fpi_device_enroll_complete (device, g_object_ref (print), NULL);
}

void
fpi_validity_a2_enroll (FpDevice *device)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (device);

  g_autoptr(GError) error = NULL;
  g_auto(GStrv) paths = NULL;
  g_autoptr(ValidityMohTables) tables = NULL;
  g_autofree gchar *sha = NULL;
  const guint8 *blob;
  gsize len;
  FpPrint *print = NULL;
  MohData *d;
  FpiSsm *ssm;

  if (self->dev_type != VALIDITY_DEV_A2 || !fpi_validity_device_policy (self->dev_type)->allow_host_enroll)
    {
      error = fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED);
      goto fail;
    }
  blob = fpi_validity_db_get_write_enable_blob (self, &len);
  sha = blob ? g_compute_checksum_for_data (G_CHECKSUM_SHA256, blob, len) : NULL;
  if (len != 2693 || g_strcmp0 (sha, "cd3fe4e0b3be7af277dceb040bddf53bf001e0dcfffa912c9cd67b2b9c34e371") != 0)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                        "Enrollment needs the pinned 00a2 db_write_enable.bin (2693 bytes)");
      goto fail;
    }
  paths = fpi_validity_data_resolve_search_paths (fpi_validity_data_dev_dir (), &error);
  if (!paths)
    goto fail;
  tables = fpi_validity_moh_tables_load ((const gchar * const *) paths, &error);
  if (!tables)
    goto fail;
  if (!fpi_validity_moh_tables_supports (tables, &error))
    goto fail;

  d = g_new0 (MohData, 1);
  d->builder = fpi_validity_moh_enroll_new (tables, 6, 6, 250);
  fpi_device_set_nr_enroll_stages (device, fpi_validity_moh_enroll_get_num_frames (d->builder));
  fpi_device_get_enroll_data (device, &print);
  d->subtype = fpi_validity_finger_to_subtype (fp_print_get_finger (print));
  d->user_id = fpi_print_generate_user_id (print);
  fp_info ("00a2 host enrollment: fixed-point, %u placements", fpi_validity_moh_enroll_get_num_frames (d->builder));
  ssm = fpi_ssm_new (device, moh_run, MOH_N_STATES);
  fpi_ssm_set_data (ssm, d, moh_data_free);
  fpi_ssm_start (ssm, moh_done);
  return;

fail:
  fpi_device_enroll_complete (device, NULL, g_steal_pointer (&error));
}
