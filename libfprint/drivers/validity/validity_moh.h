/*
 * Fixed-point host enrollment for the owned Synaptics 06cb:00a2 reader.
 * Pure computation: no USB I/O or persistent writes. The production path is
 * the hardware-tested trailer_fixed extractor, frame selection and serializer.
 * Algorithm attribution and MIT notice: COPYING.python-validity.
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

#define VALIDITY_MOH_GRID 3                       /* 3x3 tiles */
#define VALIDITY_MOH_GRID_X 10                    /* tile overlap half-width */
#define VALIDITY_MOH_NMS_MARGIN 10
#define VALIDITY_MOH_PATCH_N 7                    /* descriptor patch radius */
#define VALIDITY_MOH_PATCH_SPAN (2 * VALIDITY_MOH_PATCH_N + 2)
#define VALIDITY_MOH_FRAME_KP_CAP 250
#define VALIDITY_MOH_DESC_LEN 16
#define VALIDITY_MOH_GAUSS_N 7
#define VALIDITY_MOH_BRIEF_PAIRS 128
#define VALIDITY_MOH_AGGR_WINDOWS 29
#define VALIDITY_MOH_N_WIN_SIZES 3
#define VALIDITY_MOH_V30_RECORDS 250
#define VALIDITY_MOH_V30_RECORD_LEN 18            /* [desc:16][x:u8][y:u8] */
#define VALIDITY_MOH_V30_SECTION_BYTES (VALIDITY_MOH_V30_RECORDS * VALIDITY_MOH_V30_RECORD_LEN)
#define VALIDITY_MOH_N_SECTIONS 4
#define VALIDITY_MOH_WS_SIZE 23056
#define VALIDITY_MOH_TID_LEN 32
#define VALIDITY_MOH_ENVELOPE_SIZE 23136
#define VALIDITY_MOH_ENVELOPE_VERSION 3
#define VALIDITY_MOH_ENVELOPE_TRAILING 32
#define VALIDITY_MOH_RECORD_TYPE_FINGER 6
#define VALIDITY_MOH_DLL_MAX_SECTIONS 5           /* p4 capacity, FUN_180001350 / tag 0x6b */
#define VALIDITY_MOH_DLL_CDF_LEN 22               /* 2 x 11 orientation buckets, FUN_180005720 */
#define VALIDITY_MOH_DLL_SECTION_MAX (33 + 18 * VALIDITY_MOH_FRAME_KP_CAP)
#define VALIDITY_MOH_IMG_MIN 32
#define VALIDITY_MOH_IMG_MAX 256
#define VALIDITY_MOH_DATA_SUBDIR "moh"
#define VALIDITY_MOH_FILE_GAUSS "gauss_q.bin"
#define VALIDITY_MOH_FILE_BRIEF "brief_pairs.bin"
#define VALIDITY_MOH_FILE_AGGR "aggr.bin"
#define VALIDITY_MOH_FILE_SCAFFOLD "ws_scaffold.bin"
#define VALIDITY_MOH_FILE_EXP "exp_q16.bin"
#define VALIDITY_MOH_EXP_N 52                     /* FUN_18000fec0 lookup table, int32 */

#define VALIDITY_MOH_DEFAULT_SUBTYPE 0x00f5
#define VALIDITY_MOH_DEFAULT_MIN_FRAME_POOL VALIDITY_MOH_FRAME_KP_CAP
#define VALIDITY_MOH_DEFAULT_MAX_ATTEMPTS 6

typedef enum {
  VALIDITY_MOH_TABLES_PINNED         = 0,

  VALIDITY_MOH_TABLES_ALLOW_UNPINNED = 1 << 0,
} ValidityMohTablesFlags;

typedef struct
{
  gint    x;
  gint    y;
  gdouble orient;
  guint8  desc[VALIDITY_MOH_DESC_LEN];

  gdouble score;
  guint8  cls;
  guint8  coh;
  guint8  o;
  gint32  theta;
} ValidityMohKeypoint;

typedef struct
{
  guint   n_pool;
  gdouble cap_score;
  gdouble med_score;
} ValidityMohFrameStats;

typedef struct
{
  ValidityMohKeypoint   kps[VALIDITY_MOH_FRAME_KP_CAP];
  guint                 n_kps;
  ValidityMohFrameStats stats;
  guint                 h, w;
  guint8                quality;
} ValidityMohFrame;

typedef enum {
  VALIDITY_MOH_FRAME_ACCEPT,
  VALIDITY_MOH_FRAME_RETRY,
  VALIDITY_MOH_FRAME_ACCEPT_WEAK,
  VALIDITY_MOH_FRAME_FAIL,
} ValidityMohVerdict;

typedef enum {
  VALIDITY_MOH_STEP_ACCEPT,
  VALIDITY_MOH_STEP_RETRY,
  VALIDITY_MOH_STEP_DONE,
  VALIDITY_MOH_STEP_FAIL,
} ValidityMohStepAction;

typedef enum {
  VALIDITY_MOH_REASON_NONE,
  VALIDITY_MOH_REASON_WEAK_FRAME,
  VALIDITY_MOH_REASON_CAPTURE_FAILED,
  VALIDITY_MOH_REASON_FLAGGED_IMAGE,
} ValidityMohStepReason;

typedef struct
{
  ValidityMohStepAction action;
  ValidityMohStepReason reason;
  guint                 reject_mask;
  guint                 progress;
  guint                 sections;
  guint                 touch;
  guint8                quality;
} ValidityMohEnrollStep;

/* Production loads pin every payload after authenticating its HMAC. The
 * unpinned flag is for synthetic offline fixtures, never device enrollment. */
typedef struct _ValidityMohTables ValidityMohTables;

typedef struct _ValidityMohEnroll ValidityMohEnroll;

ValidityMohTables *fpi_validity_moh_tables_new_full (const guint8          *gauss_q,
                                                     gsize                  gauss_len,
                                                     const guint8          *brief_pairs,
                                                     gsize                  brief_len,
                                                     const guint8          *aggr,
                                                     gsize                  aggr_len,
                                                     const guint8          *ws_scaffold,
                                                     gsize                  scaffold_len,
                                                     const guint8          *exp_q16,
                                                     gsize                  exp_len,
                                                     ValidityMohTablesFlags flags,
                                                     GError               **error);

ValidityMohTables *fpi_validity_moh_tables_load_dir (const gchar           *dir,
                                                     ValidityMohTablesFlags flags,
                                                     GError               **error);

ValidityMohTables *fpi_validity_moh_tables_load (const gchar * const *base_paths,
                                                 GError             **error);

ValidityMohTables *fpi_validity_moh_tables_ref (ValidityMohTables *tables);

void fpi_validity_moh_tables_unref (ValidityMohTables *tables);

gboolean fpi_validity_moh_tables_supports (const ValidityMohTables *tables,
                                           GError                 **error);

/* Validate exact h*w bytes before reading; clear image-derived buffers
 * when no longer needed. No device I/O is performed by this module. */
gboolean fpi_validity_moh_extract_frame_fixed (const ValidityMohTables *tables,
                                               const guint8            *pixels,
                                               gsize                    pixels_len,
                                               guint                    h,
                                               guint                    w,
                                               ValidityMohFrame        *frame,
                                               GError                 **error);

GBytes *fpi_validity_moh_assemble_template (const ValidityMohFrame * const *frames,
                                            guint                           n_frames,
                                            guint16                         subtype,
                                            GError                        **error);

GBytes *fpi_validity_moh_build_store_cmd (guint16 parent_dbid,
                                          guint16 storage_dbid,
                                          GBytes *envelope);

/* Per placement, retry a weak image up to max_attempts, then retain it.
 * Capture failures exhaust the same bound and fail enrollment. Keep the
 * best four of the requested placements for the final template. */
ValidityMohEnroll *fpi_validity_moh_enroll_new (ValidityMohTables *tables,
                                                guint              num_frames,
                                                guint              max_attempts,
                                                guint              min_frame_pool);

void fpi_validity_moh_enroll_free (ValidityMohEnroll *enroll);

gboolean fpi_validity_moh_enroll_step_image (ValidityMohEnroll     *e,
                                             const guint8          *pixels,
                                             gsize                  pixels_len,
                                             guint                  h,
                                             guint                  w,
                                             guint32                capture_flags,
                                             ValidityMohEnrollStep *step,
                                             GError               **error);

void fpi_validity_moh_enroll_step_capture_failed (ValidityMohEnroll     *e,
                                                  ValidityMohEnrollStep *step);

gboolean fpi_validity_moh_enroll_add_image (ValidityMohEnroll  *e,
                                            const guint8       *pixels,
                                            gsize               pixels_len,
                                            guint               h,
                                            guint               w,
                                            ValidityMohVerdict *verdict,
                                            GError            **error);

ValidityMohVerdict fpi_validity_moh_enroll_capture_failed (ValidityMohEnroll *e);

guint fpi_validity_moh_enroll_get_num_frames (const ValidityMohEnroll *e);

guint fpi_validity_moh_enroll_get_frames_done (const ValidityMohEnroll *e);

guint fpi_validity_moh_enroll_get_attempt (const ValidityMohEnroll *e);

gboolean fpi_validity_moh_enroll_is_complete (const ValidityMohEnroll *e);

const ValidityMohFrame *fpi_validity_moh_enroll_get_frame (const ValidityMohEnroll *e,
                                                           guint                    index);

GBytes *fpi_validity_moh_enroll_build_envelope (ValidityMohEnroll *e,
                                                guint16            subtype,
                                                guint             *selected,
                                                guint             *n_selected,
                                                GError           **error);

const gchar *fpi_validity_moh_step_reason_to_string (ValidityMohStepReason reason);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (ValidityMohTables, fpi_validity_moh_tables_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ValidityMohEnroll, fpi_validity_moh_enroll_free)
