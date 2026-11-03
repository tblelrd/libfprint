/*
 * Host-side template builder ("MOH" enrollment) for Synaptics 06cb:00a2
 *
 * Fixed-point feature extraction and frame selection adapted from
 * python-validity PR #261 by Dmitry Muzyka (840cfbe; frozen integer reference
 * 38d9f38). Incorporated portions retain COPYING.python-validity's MIT notice.
 * Section ordering, trailers and container layout follow the VCSFW format.
 * This is the trailer_fixed path tested on the E480.
 * Tables are loaded from the external validity data package and hash checked.
 * No proprietary driver is loaded or called by this code.
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
#include "validity_data.h"
#include "validity_moh.h"

#include <math.h>
#include <string.h>

/* The reference is evaluated without fused multiply-add; keep the compiler
 * from contracting a*b+c on targets that have FMA (aarch64, -march=haswell).
 * libfprint/meson.build builds this file with -ffp-contract=off
 * -fno-fast-math; the pragmas cover other ways of compiling it. Fast-math
 * reassociates and flushes, which would silently change the templates. */
#if defined(__FAST_MATH__)
#error "validity_moh.c must not be built with -ffast-math (bit-exact floating point)"
#endif
#if defined(__clang__)
#pragma clang fp contract(off)
#elif defined(__GNUC__)
#pragma GCC optimize ("fp-contract=off")
#endif


/* Detector parameters (QM extractor parameter block, as used by the fork) */
#define NMS_T_LO 671
#define NMS_T_HI 168
#define NMS_DEDUP_Q 72064
#define EDGE_MARGIN 3
#define FILL_Q16 0x800000                   /* mid-gray pad: 128 << 16 */
#define ORIENT_BINS 42
#define ORIENT_SMEAR 7
#define ORIENT_RADIUS 6
#define TEMPLATE_ID_STR "Template ID"
#define TEMPLATE_ID_PAD 32

/* Legacy scaffold validation; the production writer builds its own body. */
static const guint v30_regions[VALIDITY_MOH_N_SECTIONS] = { 309, 4913, 9453, 13993 };

/* Aggregation window sizes per size index: {N, (int)(2N/3 + 0.999999), N/2}
 * for patch radius N = 7, the values of moh_native._WIN_SIZES. */
static const gint win_sizes[VALIDITY_MOH_N_WIN_SIZES] = { 7, 5, 3 };

/* sha256 of the payloads make_validity_moh_tables.py cuts from the Windows
 * driver. The tables are identical in every QM build it knows
 * (synaWudfBioUsb.dll 5.2.311 to 5.2.326 of the 00a2 packages, and 5.3.3542
 * of the 009a package); the WS scaffold comes from the PR #261 fork. */
static const gchar *const pinned_sha256[] = {
  "96442a01d5d594d7c47320e28c5da18aa4ee3be8609edc1c5c35559492a075bb",  /* gauss_q.bin */
  "2d8ac95c6371d33329b8a704d1d4527719e4f48c80e8217a0dc93ff7f5cd62d8",  /* brief_pairs.bin */
  "1c8aad7ea3b8fd96853a147b149e3e981dafd734fbcbc6e070a62dae346eb0e0",  /* aggr.bin */
  "837a10ab0eff1c5b94e29a90ef839fa4752aac702b4f11e505d6db4cb5710535",  /* ws_scaffold.bin */
  "d1133dd228736bf011733ff70caef07154f29b7351848a4f95384952964970b5",  /* exp_q16.bin */
};

#define SCAFFOLD_PRE_V30_RECORDS 6

struct _ValidityMohTables
{
  gint     ref_count;
  gint32   gauss_i[VALIDITY_MOH_GAUSS_N][VALIDITY_MOH_GAUSS_N];   /* the same, for the fixed point */
  guint16  pairs[VALIDITY_MOH_BRIEF_PAIRS][2];
  gint     aggr[VALIDITY_MOH_AGGR_WINDOWS][3];   /* size_idx, dx, dy */
  guint8   scaffold[VALIDITY_MOH_WS_SIZE];       /* near-identity patched */
  gboolean pinned;
  /* fixed-point extractor */
  gboolean has_exp;
  gint32   exp_q16[VALIDITY_MOH_EXP_N];          /* FUN_18000fec0 table */
  gint32   cos_q16[360], sin_q16[360];           /* FUN_18000e090 tables, computed */
};

/* ================================================================
 * Wiping
 * ================================================================
 * Tiles, smoothed images, Hessian/DoH maps and gradients describe the finger
 * far more closely than the stored template does, and the WS body, envelope
 * and store command hold the template itself: clear all of them before the
 * memory is handed back. */

typedef struct
{
  gint oy, ox;
  gint th, tw;
} ValidityMohTileGeom;

typedef struct
{
  gdouble score;
  gint    x, y;
} ValidityMohNmsPoint;

typedef struct
{
  gdouble score;
  guint   tile;
  gint64  sx_q16, sy_q16;
  guint8  cls;
} ValidityMohPoolEntry;

#define DLL_P4 VALIDITY_MOH_DLL_MAX_SECTIONS

typedef struct
{
  gsize  len;
  guint8 data[];
} WipedBuf;

typedef struct
{
  ValidityMohPoolEntry e;
  guint                order;   /* detection order: makes the sorts stable */
} PoolItem;

typedef struct
{
  gint   off;
  gint64 tap;
} FxTap;

typedef struct
{
  guint8 b0;                 /* co-located keypoint count of the fit (rec +0x88) */
  guint8 b1;                 /* their mean Hamming distance (rec +0x68), 0x7fff -> 0xff */
  gint32 a, b, tx, ty;       /* similarity: a = cos * 2^16, b = sin * 2^16, t in Q16 */
} DllPose;

typedef struct
{
  guint8  order[DLL_P4];     /* struct[0] */
  guint8  info[DLL_P4][4];   /* struct[1]: [0] component label, [3] frame quality */
  guint8  n;                 /* +0x10 */
  guint8  n_comp;            /* +0x11 */
  DllPose e[DLL_P4][DLL_P4]; /* struct[3]: rows of p4 entries of 0x14 bytes */
} DllPoseTable;

typedef struct
{
  guint32 f154, f150, f144, f130;
} DllState;

typedef struct
{
  guint pool;
  guint index;
} PoolRank;

static guint validity_moh_patch_pre_v30_near_identity (guint8 *ws,
                                                       gsize   ws_len);

static void validity_moh_dll_qsort (gpointer     base,
                                    gsize        n,
                                    gsize        es,
                                    GCompareFunc cmp);

static inline gint32 add32 (gint64 a,
                            gint64 b);

static void validity_moh_dll_normalize (gint32 *a,
                                        gint32 *b);

static guint32 validity_moh_dll_isqrt (guint32 n);

static void
wipe_free (gpointer p, gsize n)
{
  if (p == NULL)
    return;
  explicit_bzero (p, n);
  g_free (p);
}

static void
wiped_buf_free (gpointer p)
{
  WipedBuf *b = p;

  explicit_bzero (b->data, b->len);
  g_free (b);
}

/* A zero-filled GBytes of @len bytes whose memory is wiped when the last
 * reference goes; *@data points at its (writable until shared) contents. */
static GBytes *
bytes_new_wiped (gsize len, guint8 **data)
{
  WipedBuf *b = g_malloc0 (sizeof (WipedBuf) + len);

  b->len = len;
  *data = b->data;
  return g_bytes_new_with_free_func (b->data, len, wiped_buf_free, b);
}

/* Python float % for a positive modulus: result in [0, m), +0.0 for zero */

/* Python int >> 16 (floor) for a possibly negative value */

static inline guint16
rd_u16 (const guint8 *p)
{
  return (guint16) (p[0] | (p[1] << 8));
}

static inline gint32
rd_i32 (const guint8 *p)
{
  return (gint32) ((guint32) p[0] | ((guint32) p[1] << 8) | ((guint32) p[2] << 16) | ((guint32) p[3] << 24));
}

static inline void
wr_u16 (guint8 *p, guint16 v)
{
  p[0] = v & 0xff;
  p[1] = v >> 8;
}

static inline void
wr_i32 (guint8 *p, gint32 v)
{
  guint32 u = (guint32) v;

  p[0] = u & 0xff;
  p[1] = (u >> 8) & 0xff;
  p[2] = (u >> 16) & 0xff;
  p[3] = (u >> 24) & 0xff;
}

static gboolean
check_sha (const guint8 *data, gsize len, guint idx, const gchar *name, GError **error)
{
  g_autofree gchar *hex = g_compute_checksum_for_data (G_CHECKSUM_SHA256, data, len);

  if (g_strcmp0 (hex, pinned_sha256[idx]) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "MOH table %s: sha256 %s is not the expected driver table %s",
                   name, hex, pinned_sha256[idx]);
      return FALSE;
    }
  return TRUE;
}

/* The exp table of FUN_18000fec0: the taps index it with 0..51; a positive
 * centre value keeps the Gaussian's normalising sum positive. */
static gboolean
load_exp (ValidityMohTables *t, const guint8 *exp_q16, gsize exp_len, ValidityMohTablesFlags flags,
          GError **error)
{
  if (exp_len != VALIDITY_MOH_EXP_N * 4)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "MOH exp table has the wrong size (%" G_GSIZE_FORMAT ")", exp_len);
      return FALSE;
    }
  if (!(flags & VALIDITY_MOH_TABLES_ALLOW_UNPINNED) &&
      !check_sha (exp_q16, exp_len, 4, VALIDITY_MOH_FILE_EXP, error))
    return FALSE;
  for (guint i = 0; i < VALIDITY_MOH_EXP_N; i++)
    {
      t->exp_q16[i] = rd_i32 (exp_q16 + 4 * i);
      if (t->exp_q16[i] < 0 || (i == 0 && (t->exp_q16[0] < 16 || t->exp_q16[0] > 65536)) ||
          (i > 0 && t->exp_q16[i] > t->exp_q16[i - 1]))
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                       "MOH exp table entry %u out of range", i);
          return FALSE;
        }
    }
  t->has_exp = TRUE;
  return TRUE;
}

ValidityMohTables *
fpi_validity_moh_tables_new_full (const guint8          *gauss_q,
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
                                  GError               **error)
{
  g_autoptr(ValidityMohTables) t = NULL;
  guint n_patched;

  if (gauss_len != VALIDITY_MOH_GAUSS_N * VALIDITY_MOH_GAUSS_N * 4 ||
      brief_len != VALIDITY_MOH_BRIEF_PAIRS * 4 ||
      aggr_len != VALIDITY_MOH_AGGR_WINDOWS * 6 ||
      scaffold_len != VALIDITY_MOH_WS_SIZE)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "MOH tables have the wrong size (gauss %zu, brief %zu, aggr %zu, scaffold %zu)",
                   gauss_len, brief_len, aggr_len, scaffold_len);
      return NULL;
    }

  if (!(flags & VALIDITY_MOH_TABLES_ALLOW_UNPINNED))
    {
      if (!check_sha (gauss_q, gauss_len, 0, VALIDITY_MOH_FILE_GAUSS, error) ||
          !check_sha (brief_pairs, brief_len, 1, VALIDITY_MOH_FILE_BRIEF, error) ||
          !check_sha (aggr, aggr_len, 2, VALIDITY_MOH_FILE_AGGR, error) ||
          !check_sha (ws_scaffold, scaffold_len, 3, VALIDITY_MOH_FILE_SCAFFOLD, error))
        return NULL;
    }

  t = g_new0 (ValidityMohTables, 1);
  t->ref_count = 1;
  t->pinned = !(flags & VALIDITY_MOH_TABLES_ALLOW_UNPINNED);

  for (guint i = 0; i < VALIDITY_MOH_GAUSS_N * VALIDITY_MOH_GAUSS_N; i++)
    t->gauss_i[i / VALIDITY_MOH_GAUSS_N][i % VALIDITY_MOH_GAUSS_N] = rd_i32 (gauss_q + 4 * i);

  /* round(cos/sin(deg) * 65536), half to even (numpy.round): identical to the
   * driver's tables, which make_validity_moh_tables.py checks at install time */
  for (guint d = 0; d < 360; d++)
    {
      gdouble r = (gdouble) d * (G_PI / 180.0);

      t->cos_q16[d] = (gint32) nearbyint (cos (r) * 65536.0);
      t->sin_q16[d] = (gint32) nearbyint (sin (r) * 65536.0);
    }
  if (exp_q16 != NULL && !load_exp (t, exp_q16, exp_len, flags, error))
    return NULL;

  for (guint i = 0; i < VALIDITY_MOH_AGGR_WINDOWS; i++)
    {
      gint s = (gint16) rd_u16 (aggr + 6 * i);
      gint dx = (gint16) rd_u16 (aggr + 6 * i + 2);
      gint dy = (gint16) rd_u16 (aggr + 6 * i + 4);
      gint w;

      if (s < 0 || s >= VALIDITY_MOH_N_WIN_SIZES)
        goto bad_aggr;
      w = win_sizes[s];
      /* the window must lie inside the (2N+2)^2 sample patch */
      if (dx + VALIDITY_MOH_PATCH_N < 0 || dx + VALIDITY_MOH_PATCH_N + w > VALIDITY_MOH_PATCH_SPAN ||
          dy + VALIDITY_MOH_PATCH_N < 0 || dy + VALIDITY_MOH_PATCH_N + w > VALIDITY_MOH_PATCH_SPAN)
        goto bad_aggr;
      t->aggr[i][0] = s;
      t->aggr[i][1] = dx;
      t->aggr[i][2] = dy;
    }

  for (guint i = 0; i < VALIDITY_MOH_BRIEF_PAIRS; i++)
    {
      t->pairs[i][0] = rd_u16 (brief_pairs + 4 * i);
      t->pairs[i][1] = rd_u16 (brief_pairs + 4 * i + 2);
      if (t->pairs[i][0] >= 2 * VALIDITY_MOH_AGGR_WINDOWS ||
          t->pairs[i][1] >= 2 * VALIDITY_MOH_AGGR_WINDOWS)
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                       "MOH BRIEF pair %u out of range", i);
          return NULL;
        }
    }

  memcpy (t->scaffold, ws_scaffold, VALIDITY_MOH_WS_SIZE);
  /* The patcher is a heuristic scan; a scaffold it does not recognise would
   * silently keep pure-identity transforms (the matcher's "unmatched"
   * sentinel), so the record count is checked (as the fork does). */
  n_patched = validity_moh_patch_pre_v30_near_identity (t->scaffold, VALIDITY_MOH_WS_SIZE);
  if (n_patched != SCAFFOLD_PRE_V30_RECORDS)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "MOH WS scaffold: patched %u pre-v30 records, expected %d",
                   n_patched, SCAFFOLD_PRE_V30_RECORDS);
      return NULL;
    }

  return g_steal_pointer (&t);

bad_aggr:
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
               "MOH aggregation table entry out of range");
  return NULL;
}

/* Read one data-package file and verify its HMAC trailer via the validity
 * data loader (a private store, slot reused as scratch). File errors are
 * reported in the FP_DEVICE_ERROR domain like every other table error: a
 * missing file (partly installed package) is DATA_NOT_FOUND, an unreadable
 * one DATA_INVALID. */
static GBytes *
load_verified (const gchar *dir, const gchar *name, GError **error)
{
  g_autofree gchar *path = g_build_filename (dir, name, NULL);

  g_autoptr(GError) local = NULL;
  ValidityDataStore store;
  GBytes *bytes = NULL;

  fpi_validity_data_store_init (&store);
  if (fpi_validity_data_load_file (&store, VALIDITY_DATA_INIT, path, &local))
    bytes = g_bytes_ref (fpi_validity_data_get (&store, VALIDITY_DATA_INIT));
  else if (g_error_matches (local, G_FILE_ERROR, G_FILE_ERROR_NOENT))
    g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND,
                 "MOH table %s missing in %s (re-run make_validity_moh_tables.py)", name, dir);
  else if (local->domain == G_FILE_ERROR)
    g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                 "MOH table %s: %s", name, local->message);
  else
    g_propagate_error (error, g_steal_pointer (&local));
  fpi_validity_data_store_free (&store);
  return bytes;
}

ValidityMohTables *
fpi_validity_moh_tables_load_dir (const gchar           *dir,
                                  ValidityMohTablesFlags flags,
                                  GError               **error)
{
  g_autoptr(GBytes) gauss = NULL;
  g_autoptr(GBytes) brief = NULL;
  g_autoptr(GBytes) aggr = NULL;
  g_autoptr(GBytes) scaffold = NULL;
  g_autoptr(GBytes) exp = NULL;
  g_autoptr(GError) exp_error = NULL;
  gsize gl, bl, al, sl, el = 0;
  const guint8 *gp, *bp, *ap, *sp, *ep = NULL;

  g_return_val_if_fail (dir != NULL, NULL);

  if (!(gauss = load_verified (dir, VALIDITY_MOH_FILE_GAUSS, error)) ||
      !(brief = load_verified (dir, VALIDITY_MOH_FILE_BRIEF, error)) ||
      !(aggr = load_verified (dir, VALIDITY_MOH_FILE_AGGR, error)) ||
      !(scaffold = load_verified (dir, VALIDITY_MOH_FILE_SCAFFOLD, error)))
    return NULL;
  /* optional: a package made before the fixed-point extractor has no exp table */
  exp = load_verified (dir, VALIDITY_MOH_FILE_EXP, &exp_error);
  if (exp == NULL && !g_error_matches (exp_error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND))
    {
      g_propagate_error (error, g_steal_pointer (&exp_error));
      return NULL;
    }
  if (exp == NULL)
    fp_dbg ("MOH tables in %s have no %s: fixed-point extractor unavailable", dir, VALIDITY_MOH_FILE_EXP);
  else
    ep = g_bytes_get_data (exp, &el);

  gp = g_bytes_get_data (gauss, &gl);
  bp = g_bytes_get_data (brief, &bl);
  ap = g_bytes_get_data (aggr, &al);
  sp = g_bytes_get_data (scaffold, &sl);

  return fpi_validity_moh_tables_new_full (gp, gl, bp, bl, ap, al, sp, sl, ep, el, flags, error);
}

ValidityMohTables *
fpi_validity_moh_tables_load (const gchar * const *base_paths,
                              GError             **error)
{
  const gchar * const *paths = base_paths ? base_paths : (const gchar * const *) validity_data_search_paths;

  g_autoptr(GString) probed = g_string_new (NULL);

  for (const gchar * const *base = paths; *base != NULL; base++)
    {
      g_autofree gchar *dir = g_build_filename (*base, VALIDITY_MOH_DATA_SUBDIR, NULL);
      g_autofree gchar *probe = g_build_filename (dir, VALIDITY_MOH_FILE_SCAFFOLD, NULL);

      if (g_file_test (probe, G_FILE_TEST_IS_REGULAR))
        {
          fp_dbg ("Loading MOH enrollment tables from %s", dir);
          return fpi_validity_moh_tables_load_dir (dir, VALIDITY_MOH_TABLES_PINNED, error);
        }
      if (probed->len > 0)
        g_string_append (probed, ", ");
      g_string_append (probed, dir);
    }

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND,
               "MOH enrollment tables not found (looked in %s); generate them from the "
               "Windows driver with make_validity_moh_tables.py", probed->str);
  return NULL;
}

ValidityMohTables *
fpi_validity_moh_tables_ref (ValidityMohTables *tables)
{
  g_return_val_if_fail (tables != NULL, NULL);
  g_return_val_if_fail (tables->ref_count > 0, NULL);

  g_atomic_int_inc (&tables->ref_count);
  return tables;
}

void
fpi_validity_moh_tables_unref (ValidityMohTables *tables)
{
  if (tables == NULL)
    return;
  g_return_if_fail (tables->ref_count > 0);

  if (g_atomic_int_dec_and_test (&tables->ref_count))
    g_free (tables);
}

gboolean
fpi_validity_moh_tables_supports (const ValidityMohTables *tables, GError **error)
{
  g_return_val_if_fail (tables != NULL, FALSE);
  if (tables->has_exp)
    return TRUE;
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND,
               "MOH table %s is not installed", VALIDITY_MOH_FILE_EXP);
  return FALSE;
}

static void
validity_moh_tile_geom (guint                i,
                        guint                j,
                        guint                h,
                        guint                w,
                        ValidityMohTileGeom *geom)
{
  gint step_y = h / VALIDITY_MOH_GRID;
  gint step_x = w / VALIDITY_MOH_GRID;

  geom->oy = (gint) i * step_y - VALIDITY_MOH_GRID_X;
  geom->ox = (gint) j * step_x - VALIDITY_MOH_GRID_X;
  /* the last row/column absorbs the remainder (58 instead of 57 for 112) */
  geom->th = (i == VALIDITY_MOH_GRID - 1) ? ((gint) h - (VALIDITY_MOH_GRID - 1) * step_y) + 2 * VALIDITY_MOH_GRID_X :
             step_y + 2 * VALIDITY_MOH_GRID_X;
  geom->tw = (j == VALIDITY_MOH_GRID - 1) ? ((gint) w - (VALIDITY_MOH_GRID - 1) * step_x) + 2 * VALIDITY_MOH_GRID_X :
             step_x + 2 * VALIDITY_MOH_GRID_X;
}

static void
validity_moh_tile_q16 (const guint8              *pixels,
                       guint                      h,
                       guint                      w,
                       const ValidityMohTileGeom *g,
                       gint32                    *tile)
{
  for (gint y = 0; y < g->th; y++)
    for (gint x = 0; x < g->tw; x++)
      {
        gint sy = g->oy + y;
        gint sx = g->ox + x;

        if (sy >= 0 && sy < (gint) h && sx >= 0 && sx < (gint) w)
          tile[y * g->tw + x] = (gint32) pixels[sy * w + sx] << 16;
        else
          tile[y * g->tw + x] = FILL_Q16;
      }
}

/* acc[i] = sum over taps (in order) of in[i - off] * tap; out-of-range reads
 * are clamped (use_fill FALSE) or the constant @fill. */

/* kx along x, then ky along y; @out may not alias @in */

/* The driver keeps Ixx (+0x30), Ixy (+0x38) and Iyy (+0x40) next to the
 * response plane (+0x50 = Iyy*Ixx - Ixy^2, FUN_18000ce80) and its NMS reads
 * the class flag from Ixx and Iyy at the maximum (FUN_18000cf90). */

/* numpy.linalg.solve for a 2x2 system: LU with partial pivoting where the
 * multiplier is formed with the pivot's reciprocal (getrf), then forward
 * and back substitution with divisions (getrs). Bit-identical to numpy's
 * OpenBLAS build on 10^5 random systems. FALSE when singular. */

static guint8
validity_moh_dll_coherence (const guint *counts)
{
  gint v[ORIENT_BINS];
  gint sum = 0, mean, var = 0;

  /* FUN_18000d920 shifts every count left by 2, then FUN_18000d850 takes
   * the integer variance: mean = sum / n, sum((v - mean)^2) / n >> 2 */
  for (guint i = 0; i < ORIENT_BINS; i++)
    {
      v[i] = (gint) counts[i] << 2;
      sum += v[i];
    }
  mean = sum / ORIENT_BINS;
  for (guint i = 0; i < ORIENT_BINS; i++)
    var += (v[i] - mean) * (v[i] - mean);
  var = (var / ORIENT_BINS) >> 2;
  return var < 0xff ? (guint8) var : 0xff;
}

static guint8
validity_moh_dll_orient_byte_q16 (gint32 theta)
{
  /* 0.00043713210688081606 = 90 / (pi * 65536) */
  gint o = (gint) ((gdouble) theta * 0.00043713210688081606 + 0.5);

  return o == 180 ? 0 : (guint8) o;
}

static guint8
validity_moh_dll_frame_quality (const ValidityMohKeypoint *kps, guint n_kps)
{
  guint good = 0;

  for (guint i = 0; i < n_kps; i++)
    if (kps[i].coh > 15)
      good++;
  /* divided by the cap, not by n */
  return (guint8) (good * 100 / VALIDITY_MOH_FRAME_KP_CAP);
}

static void
validity_moh_frame_stats (const gdouble         *scores_desc,
                          guint                  n_pool,
                          ValidityMohFrameStats *stats)
{
  guint kept = MIN (n_pool, VALIDITY_MOH_FRAME_KP_CAP);

  stats->n_pool = n_pool;
  stats->cap_score = (n_pool >= VALIDITY_MOH_FRAME_KP_CAP) ? scores_desc[kept - 1] : 0.0;
  if (kept == 0)
    stats->med_score = 0.0;
  else if (kept % 2)
    stats->med_score = scores_desc[kept / 2];
  else
    stats->med_score = (scores_desc[kept / 2] + scores_desc[kept / 2 - 1]) / 2.0;
}

static gboolean
check_image (const guint8 *pixels, gsize pixels_len, guint h, guint w, GError **error)
{
  /* h, w come from the chip's readout header: the buffer length is the
   * only thing that keeps a short readout from being read past its end */
  if (pixels == NULL || h < VALIDITY_MOH_IMG_MIN || w < VALIDITY_MOH_IMG_MIN ||
      h > VALIDITY_MOH_IMG_MAX || w > VALIDITY_MOH_IMG_MAX || pixels_len != (gsize) h * w)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "MOH: unsupported image %ux%u (%" G_GSIZE_FORMAT " bytes)", h, w, pixels_len);
      return FALSE;
    }
  return TRUE;
}

/* ================================================================
 * Fixed-point extractor (TRAILER_FIXED)
 * ================================================================
 * A port of the fork's frozen byte-exact oracle, tests/_moh_native_frozen.py
 * at commit 38d9f38 (branch moh-enrollment-refactor), which reproduces the
 * integer pipeline of the QM extractor in synaWudfBioUsb.dll. Every
 * operation is done as the oracle does it: 32-bit wrap-around where it
 * wraps (its _s32 / _imul32 / _sar32), 64 bits where it computes on numpy
 * int64 or Python ints, floor shifts and truncating divisions. Each stage was
 * checked against the decompiled driver function named with it (refs:
 * libfprint-a2-moh-variant-fixed.md). The driver computes everything in
 * 32-bit ints; for 8-bit images no 64-bit intermediate of the oracle leaves
 * the 32-bit range, so the two agree there.
 *
 * The driver-compatible caps, edge rule, tie order and weight indexing are
 * applied throughout. The convolutions keep the
 * oracle's border handling, which differs from the driver's zero fill only
 * within 4 pixels of a tile edge, where nothing is read (NMS margin 10). */

#define FX_POOL_MAX 500                       /* FUN_180004c10 param[0]: keypoint list size */
#define FX_NMS_MAX (FX_POOL_MAX >> 2)         /* FUN_18000d340 -> FUN_18000cf90 */
#define FX_GAUSS_SIZE 5                       /* FUN_1800101c0 for sigma 1126 (Q10) */
#define FX_SPAN VALIDITY_MOH_PATCH_SPAN

static inline gint32
s32 (gint64 v)
{
  return (gint32) (guint32) (guint64) v;
}

/* floor (v / 2^n): the oracle's >> on Python ints and numpy int64 */
static inline gint64
sar64 (gint64 v, guint n)
{
  return v >= 0 ? v >> n : ~(~v >> n);
}

/* _sar32: wrap to 32 bits, then shift */
static inline gint32
sar32 (gint64 v, guint n)
{
  return (gint32) sar64 (s32 (v), n);
}

/* _imul32 */
static inline gint32
imul32 (gint64 a, gint64 b)
{
  return s32 ((gint64) s32 (a) * s32 (b));
}

/* _idiv32: both operands wrapped, the quotient truncated and not wrapped
 * (2^31 for INT32_MIN / -1); @b must not wrap to 0 */
static inline gint64
idiv32 (gint64 a, gint64 b)
{
  gint64 x = s32 (a), y = s32 (b);
  gint64 q = (x < 0 ? -x : x) / (y < 0 ? -y : y);

  return (x < 0) != (y < 0) ? -q : q;
}

/* FUN_18000fec0: exp table at -(((coef * x >> 2) * x >> 8) / 25 >> 13); the
 * oracle's multiply-shift for / 25 is C's truncating division for every
 * int32, and it clamps the index (the driver does not; n = 5 stays in 0..9) */
static gint32
fx_gauss_tap (const ValidityMohTables *t, gint64 coef, gint32 x)
{
  gint32 v = sar32 (coef * x, 2);
  gint64 i;

  v = sar32 ((gint64) v * x, 8);
  i = -sar64 (v / 25, 13);
  return t->exp_q16[CLAMP (i, 0, VALIDITY_MOH_EXP_N - 1)];
}

static void
validity_moh_fx_gaussian (const ValidityMohTables *tables,
                          guint                    n,
                          gint32                  *taps)
{
  gint32 sigma = sar32 (0x26600 * (gint64) n + 0x59acd, 10);
  gint64 coef, sum = 0, norm;

  g_return_if_fail (tables->has_exp && n % 2 == 1 && n <= 15);
  coef = idiv32 (0xe0000000, (gint64) sigma * sigma);
  for (guint i = 0; i < n; i++)
    {
      taps[i] = sar32 (fx_gauss_tap (tables, coef, 512 * (2 * (gint) i - (gint) n + 1)), 4);
      sum += taps[i];
    }
  /* the centre tap is exp[0] >> 4 >= 1 (load_exp), so sum > 0 */
  norm = sar32 (idiv32 (0x40000000, sum), 3);
  for (guint i = 0; i < n; i++)
    taps[i] = sar32 ((gint64) taps[i] * norm, 15);
}

/* out[i] = sum over taps (zero taps skipped) of (in[i - off] * tap) >> shift;
 * out-of-range reads are clamped, or 0 with @zero_fill (moh_frozen._conv_axis) */
static void
fx_conv_axis (const gint64 *in, gint64 *out, gint th, gint tw, const FxTap *k, guint nk, guint shift,
              gboolean along_x, gboolean zero_fill)
{
  gint n = along_x ? tw : th;

  for (gint y = 0; y < th; y++)
    for (gint x = 0; x < tw; x++)
      {
        gint i = along_x ? x : y;
        gint64 acc = 0;

        for (guint t = 0; t < nk; t++)
          {
            gint src = i - k[t].off;

            if (k[t].tap == 0)
              continue;
            if (src < 0 || src >= n)
              {
                if (zero_fill)
                  continue;
                src = CLAMP (src, 0, n - 1);
              }
            acc += sar64 ((along_x ? in[y * tw + src] : in[src * tw + x]) * k[t].tap, shift);
          }
        out[y * tw + x] = acc;
      }
}

/* apply_sep: x pass then y pass; @scratch holds th * tw */
static void
fx_apply_sep (const gint64 *in, gint64 *out, gint64 *scratch, gint th, gint tw, const FxTap *kx,
              const FxTap *ky, guint nk, guint shift, gboolean zero_fill)
{
  fx_conv_axis (in, scratch, th, tw, kx, nk, shift, TRUE, zero_fill);
  fx_conv_axis (scratch, out, th, tw, ky, nk, shift, FALSE, zero_fill);
}

/* FUN_180010380 (scale 1): (sep (in >> 6, kx, ky, shift 10)) << 6 */
static void
fx_pass (const gint64 *in, gint64 *out, gint64 *s1, gint64 *s2, gint th, gint tw, const FxTap *kx,
         const FxTap *ky, gboolean zero_fill)
{
  gsize n = (gsize) th * tw;

  for (gsize i = 0; i < n; i++)
    s1[i] = sar64 (in[i], 6);
  fx_apply_sep (s1, out, s2, th, tw, kx, ky, 3, 10, zero_fill);
  for (gsize i = 0; i < n; i++)
    out[i] *= 64;
}

/* FUN_180010280 / FUN_18000fd00 at scale 1: derivative [1024, 0, -1024] and
 * smoothing [c, c * 0xd55 rounded >> 10, c] with c = 0x100000 / 0x2aaa
 * (= [96, 320, 96]) at offsets -1, 0, +1 */
static void
fx_kernels (FxTap *dk, FxTap *sk)
{
  gint64 c = idiv32 (0x100000, 0x2aaa);

  dk[0] = (FxTap){ -1, 1024 };
  dk[1] = (FxTap){ 0, 0 };
  dk[2] = (FxTap){ 1, -1024 };
  sk[0] = (FxTap){ -1, c };
  sk[1] = (FxTap){ 0, sar32 (s32 (c * 0xd55) + (1 << 9), 10) };
  sk[2] = (FxTap){ 1, c };
}

static void
fx_gauss_kernel (const ValidityMohTables *t, FxTap *gk)
{
  gint32 taps[FX_GAUSS_SIZE];

  validity_moh_fx_gaussian (t, FX_GAUSS_SIZE, taps);
  for (gint i = 0; i < FX_GAUSS_SIZE; i++)
    gk[i] = (FxTap){ i - FX_GAUSS_SIZE / 2, taps[i] };
}

/* (sep (tile >> 6, gauss, shift 12)) << 6: FUN_18000f250 */
static void
fx_smooth (const ValidityMohTables *t, const gint32 *tile_q16, gint th, gint tw, gint64 *out,
           gboolean zero_fill)
{
  gsize n = (gsize) th * tw;
  gint64 *img = g_new (gint64, n);
  gint64 *scratch = g_new (gint64, n);
  FxTap gk[FX_GAUSS_SIZE];

  fx_gauss_kernel (t, gk);
  for (gsize i = 0; i < n; i++)
    img[i] = sar64 (tile_q16[i], 6);
  fx_apply_sep (img, out, scratch, th, tw, gk, gk, FX_GAUSS_SIZE, 12, zero_fill);
  for (gsize i = 0; i < n; i++)
    out[i] *= 64;
  wipe_free (img, n * sizeof (gint64));
  wipe_free (scratch, n * sizeof (gint64));
}

static void
validity_moh_fx_doh (const ValidityMohTables *tables,
                     const gint32            *tile_q16,
                     guint                    th,
                     guint                    tw,
                     gint64                  *resp,
                     gint64                  *ixx_out,
                     gint64                  *iyy_out,
                     gint64                  *ixy_out)
{
  gsize n = (gsize) th * tw;
  gint64 *sm = g_new (gint64, n), *dx = g_new (gint64, n), *dy = g_new (gint64, n);
  gint64 *ixx = g_new (gint64, n), *iyy = g_new (gint64, n), *ixy = g_new (gint64, n);
  gint64 *s1 = g_new (gint64, n), *s2 = g_new (gint64, n);
  FxTap dk[3], sk[3];

  /* FUN_18000cc20 with v9 = 1 (both scale factors are 1), border clamped */
  fx_kernels (dk, sk);
  fx_smooth (tables, tile_q16, th, tw, sm, FALSE);
  fx_pass (sm, dy, s1, s2, th, tw, sk, dk, FALSE);
  fx_pass (sm, dx, s1, s2, th, tw, dk, sk, FALSE);
  fx_pass (dx, ixy, s1, s2, th, tw, sk, dk, FALSE);
  fx_pass (dx, ixx, s1, s2, th, tw, dk, sk, FALSE);
  fx_pass (dy, iyy, s1, s2, th, tw, sk, dk, FALSE);
  /* FUN_18000ce80 */
  if (resp)
    for (gsize i = 0; i < n; i++)
      resp[i] = sar64 (ixx[i], 12) * sar64 (iyy[i], 12) - sar64 (ixy[i], 12) * sar64 (ixy[i], 12);
  if (ixx_out)
    memcpy (ixx_out, ixx, n * sizeof (gint64));
  if (iyy_out)
    memcpy (iyy_out, iyy, n * sizeof (gint64));
  if (ixy_out)
    memcpy (ixy_out, ixy, n * sizeof (gint64));
  wipe_free (sm, n * sizeof (gint64));
  wipe_free (dx, n * sizeof (gint64));
  wipe_free (dy, n * sizeof (gint64));
  wipe_free (ixx, n * sizeof (gint64));
  wipe_free (iyy, n * sizeof (gint64));
  wipe_free (ixy, n * sizeof (gint64));
  wipe_free (s1, n * sizeof (gint64));
  wipe_free (s2, n * sizeof (gint64));
}

static void
validity_moh_fx_gradient (const ValidityMohTables *tables,
                          const gint32            *tile_q16,
                          guint                    th,
                          guint                    tw,
                          gint32                  *grad_x,
                          gint32                  *grad_y)
{
  gsize n = (gsize) th * tw;
  gint64 *sm = g_new (gint64, n), *g = g_new (gint64, n);
  gint64 *s1 = g_new (gint64, n), *s2 = g_new (gint64, n);
  FxTap dk[3], sk[3];

  /* the first two FUN_18000cc20 passes on the zero-filled smoothing: the
   * buffers at ctx+0x50 +0x20 / +0x28 that FUN_18000e090 samples */
  fx_kernels (dk, sk);
  fx_smooth (tables, tile_q16, th, tw, sm, TRUE);
  fx_pass (sm, g, s1, s2, th, tw, dk, sk, TRUE);
  for (gsize i = 0; i < n; i++)
    grad_x[i] = s32 (g[i]);
  fx_pass (sm, g, s1, s2, th, tw, sk, dk, TRUE);
  for (gsize i = 0; i < n; i++)
    grad_y[i] = s32 (g[i]);
  wipe_free (sm, n * sizeof (gint64));
  wipe_free (g, n * sizeof (gint64));
  wipe_free (s1, n * sizeof (gint64));
  wipe_free (s2, n * sizeof (gint64));
}

static GArray *
validity_moh_fx_nms (const gint64 *resp,
                     guint         th,
                     guint         tw)
{
  GArray *kps = g_array_new (FALSE, FALSE, sizeof (ValidityMohNmsPoint));
  gint64 r2 = (((gint64) NMS_DEDUP_Q >> 6) * ((gint64) NMS_DEDUP_Q >> 6)) >> 20;

  for (gint y = VALIDITY_MOH_NMS_MARGIN; y < (gint) th - VALIDITY_MOH_NMS_MARGIN; y++)
    for (gint x = VALIDITY_MOH_NMS_MARGIN; x < (gint) tw - VALIDITY_MOH_NMS_MARGIN; x++)
      {
        gint64 v = resp[y * tw + x], nbmax = G_MININT64, s;
        guint n_eq = 0;
        gint dup = -1;

        if (v <= NMS_T_LO || v < NMS_T_HI)
          continue;
        for (gint dy = -1; dy <= 1; dy++)
          for (gint dx = -1; dx <= 1; dx++)
            {
              gint64 nv = resp[(y + dy) * tw + x + dx];

              nbmax = MAX (nbmax, nv);
              n_eq += nv == v;
            }
        /* FUN_18000cf90: greater than all 8 neighbours */
        if (v <= nbmax && !(v == nbmax && n_eq == 1))
          continue;
        s = v < 0 ? -v : v;
        /* distance dedup, radius^2 (72064 >> 6)^2 >> 20 = 1: never hits two
         * strict maxima, kept as in the oracle */
        for (guint i = 0; i < kps->len; i++)
          {
            ValidityMohNmsPoint *k = &g_array_index (kps, ValidityMohNmsPoint, i);
            gint64 ddx = k->x - x, ddy = k->y - y;

            if (ddx * ddx + ddy * ddy <= r2)
              {
                dup = i;
                break;
              }
          }
        if (dup < 0)
          {
            ValidityMohNmsPoint p = { (gdouble) s, x, y };
            g_array_append_val (kps, p);
          }
        else if ((gdouble) s > g_array_index (kps, ValidityMohNmsPoint, dup).score)
          {
            ValidityMohNmsPoint p = { (gdouble) s, x, y };
            g_array_index (kps, ValidityMohNmsPoint, dup) = p;
          }
      }
  return kps;
}

static gboolean
validity_moh_fx_subpix (const gint64 *resp,
                        guint         th,
                        guint         tw,
                        gint          x,
                        gint          y,
                        gint64       *sx_q16,
                        gint64       *sy_q16)
{
  gint64 C, L, R, T, B, TL, TR, BL, BR, num_x, num_y, ddx, ddy;
  gint32 dxx, dyy, dxy, dx_neg, dy_neg, a, b, c, d, e, f, det_pos, det_neg;

  if (!(1 <= x && x <= (gint) tw - 2 && 1 <= y && y <= (gint) th - 2))
    return FALSE;
#define RS(yy, xx) ((gint64) s32 (resp[(yy) * (gint) tw + (xx)]))
  C = RS (y, x);
  L = RS (y, x - 1);
  R = RS (y, x + 1);
  T = RS (y - 1, x);
  B = RS (y + 1, x);
  TL = RS (y - 1, x - 1);
  TR = RS (y - 1, x + 1);
  BL = RS (y + 1, x - 1);
  BR = RS (y + 1, x + 1);
#undef RS
  /* FUN_18000d5d0 */
  dxx = sar32 (L + R - 2 * C, 2);
  dyy = sar32 (T + B - 2 * C, 2);
  dxy = sar32 ((gint64) sar32 (BR + TL, 2) - sar32 (BL + TR, 2), 2);
  dx_neg = sar32 (-(gint64) sar32 (R - L, 1), 2);
  dy_neg = sar32 (-(gint64) sar32 (B - T, 1), 2);
  /* FUN_18000d4c0: Cramer on [dxx dxy; dxy dyy] [dx_neg dy_neg], operands >> 4 */
  a = sar32 (dxx, 4);
  b = sar32 (dxy, 4);
  c = b;
  d = sar32 (dyy, 4);
  e = sar32 (dx_neg, 4);
  f = sar32 (dy_neg, 4);
  det_pos = sar32 ((gint64) imul32 (a, d) - imul32 (b, c), 7);
  det_neg = sar32 ((gint64) imul32 (b, c) - imul32 (a, d), 7);
  if (det_pos == 0 || det_neg == 0)
    return FALSE;
  num_x = (gint64) imul32 (d, e) - imul32 (f, c);
  num_y = (gint64) imul32 (b, e) - imul32 (f, a);
  ddx = idiv32 (num_x, det_pos);
  ddy = idiv32 (num_y, det_neg);
  /* removed when the step leaves the pixel (FUN_18000d570) */
  if (!(-0x80 <= ddx && ddx <= 0x80 && -0x80 <= ddy && ddy <= 0x80))
    return FALSE;
  *sx_q16 = ((gint64) x * 128 + ddx) * 512;
  *sy_q16 = ((gint64) y * 128 + ddy) * 512;
  return TRUE;
}

static gboolean
validity_moh_fx_passes_edge (gint64 sx_q16,
                             gint64 sy_q16,
                             gint   oy,
                             gint   ox,
                             guint  h,
                             guint  w)
{
  /* FUN_18000a910: ((origin - pad) << 16) + s >> 16 */
  gint64 gx = sar64 ((gint64) ox * 65536 + sx_q16, 16);
  gint64 gy = sar64 ((gint64) oy * 65536 + sy_q16, 16);
  gint64 gy_hi = (gint64) h - EDGE_MARGIN;

  return EDGE_MARGIN <= gx && gx < (gint64) w - EDGE_MARGIN && EDGE_MARGIN <= gy && gy < gy_hi;
}

static gint32
validity_moh_fx_atan (gint64 y,
                      gint64 x)
{
  gint32 r10 = s32 (x), r11 = s32 (y);
  gint32 r8 = r10 > 0 ? r10 : s32 (-(gint64) r10);
  gint32 r9 = r11 > 0 ? r11 : s32 (-(gint64) r11);
  gint32 eax, ecx, edx, tan;
  gint64 q;

  /* FUN_1800030a0: tan of the smaller over the larger magnitude in Q16, a
   * polynomial atan in degrees << 16, the octant, then (deg >> 8) * 71 >> 4
   * (~ radians << 16) */
  if (r8 < r9)
    {
      eax = r8;
      ecx = r9;
    }
  else
    {
      eax = r9;
      ecx = r8;
    }
  ecx = s32 ((gint64) ecx + 1);
  eax = s32 ((gint64) eax * 256);
  if (ecx == 0)
    return 0;
  q = ((gint64) ABS ((gint64) eax)) / ABS ((gint64) ecx);
  eax = s32 ((eax < 0) != (ecx < 0) ? -q : q);
  eax = s32 ((gint64) eax * 256);
  tan = eax;
  eax = sar32 (eax, 4);
  ecx = sar32 (tan, 6);
  ecx = imul32 (ecx, ecx);
  ecx = sar32 (ecx, 4);
  ecx = sar32 (ecx, 4);
  edx = imul32 (ecx, -0xa29);
  edx = sar32 (edx, 12);
  edx = s32 ((gint64) edx + 0x23a7);
  edx = imul32 (edx, ecx);
  edx = sar32 (edx, 12);
  edx = s32 ((gint64) edx - 0x4aac);
  edx = imul32 (edx, ecx);
  edx = sar32 (edx, 12);
  edx = s32 ((gint64) edx + 0xe522);
  edx = imul32 (edx, eax);
  edx = sar32 (edx, 6);
  if (r8 < r9)
    edx = s32 (0x5a0000 - (gint64) edx);
  if (r10 < 0)
    edx = s32 (0xb40000 - (gint64) edx);
  if (r11 < 0)
    edx = s32 (0x1680000 - (gint64) edx);
  edx = sar32 (edx, 8);
  edx = imul32 (edx, 0x47);
  return sar32 (edx, 4);
}

static gint32
validity_moh_fx_atan2 (gint32 gx,
                       gint32 gy)
{
  /* FUN_180003150: 0x3243f = pi << 16, 0x6487e = 2 pi << 16 */
  if (gx >= 0)
    return gy >= 0 ? validity_moh_fx_atan (gy, gx) :
           s32 (0x6487e - (gint64) validity_moh_fx_atan (-(gint64) gy, gx));
  return gy >= 0 ? s32 (0x3243f - (gint64) validity_moh_fx_atan (gy, -(gint64) gx)) :
         s32 (0x3243f + (gint64) validity_moh_fx_atan (-(gint64) gy, -(gint64) gx));
}

static gint32
validity_moh_fx_angle_bin (gint32 a)
{
  /* the driver's imul 0x6aaaaabd / sar 56 sequence is this division (all int32) */
  return s32 ((gint64) a * 4096) / 0x2666666;
}

static guint
validity_moh_fx_orient_index (gint32 theta)
{
  /* the oracle multiplies first, FUN_18000e090 divides first: no integer
   * theta in 0 .. 0x6487e gives a different index */
  gint64 i = (gint64) ((gdouble) theta * 180.0 / (G_PI * 65536.0)) % 360;

  return (guint) (i < 0 ? i + 360 : i);
}

static gint32
validity_moh_fx_orient (const ValidityMohTables *tables,
                        const gint32            *grad_x,
                        const gint32            *grad_y,
                        guint                    th,
                        guint                    tw,
                        gint64                   sx_q16,
                        gint64                   sy_q16,
                        guint8                  *coherence,
                        guint                   *counts_out)
{
  gint32 hx[ORIENT_BINS] = { 0 }, hy[ORIENT_BINS] = { 0 };
  guint counts[ORIENT_BINS] = { 0 };
  gint64 cx = sar64 (sx_q16 + 0x8000, 16), cy = sar64 (sy_q16 + 0x8000, 16);
  gint32 maxmag = 0;
  guint maxbin = 0;

  for (gint dy = -ORIENT_RADIUS; dy <= ORIENT_RADIUS; dy++)
    for (gint dx = -ORIENT_RADIUS; dx <= ORIENT_RADIUS; dx++)
      {
        gint64 y = cy + dy, x = cx + dx;
        gint32 wgt, ggx, ggy, b;

        if (dy * dy + dx * dx >= ORIENT_RADIUS * ORIENT_RADIUS)
          continue;
        if (!(0 <= y && y < (gint64) th && 0 <= x && x < (gint64) tw))
          continue;
        wgt = tables->gauss_i[ABS (dx)][ABS (dy)];
        ggx = sar32 (imul32 (sar64 (grad_x[y * tw + x], 10), wgt), 4);
        ggy = sar32 (imul32 (sar64 (grad_y[y * tw + x], 10), wgt), 4);
        b = validity_moh_fx_angle_bin (validity_moh_fx_atan (ggy, ggx));
        /* 0..41 for every angle FUN_1800030a0 returns from int32 vectors of
         * this size; the guard only keeps odd inputs inside the array */
        if (b >= 0 && b < ORIENT_BINS)
          counts[b]++;
        for (gint k = 0; k < ORIENT_SMEAR; k++)
          {
            gint sb = ((b + 36 + k) % ORIENT_BINS + ORIENT_BINS) % ORIENT_BINS;

            hx[sb] = s32 ((gint64) hx[sb] + ggx);
            hy[sb] = s32 ((gint64) hy[sb] + ggy);
          }
      }
  for (guint i = 0; i < ORIENT_BINS; i++)
    {
      gint32 a = sar32 (hx[i], 13), b = sar32 (hy[i], 13);
      gint32 m = s32 ((gint64) imul32 (a, a) + imul32 (b, b));

      if (m > maxmag)
        {
          maxmag = m;
          maxbin = i;
        }
    }
  if (coherence)
    *coherence = validity_moh_dll_coherence (counts);
  if (counts_out)
    memcpy (counts_out, counts, sizeof (counts));
  return validity_moh_fx_atan2 (sar32 (hx[maxbin], 10), sar32 (hy[maxbin], 10));
}

static void
validity_moh_fx_sample_rotate (const ValidityMohTables *tables,
                               const gint32            *grad_x,
                               const gint32            *grad_y,
                               guint                    th,
                               guint                    tw,
                               gint64                   sx_q16,
                               gint64                   sy_q16,
                               guint                    orient_index,
                               gint32                  *rgx,
                               gint32                  *rgy)
{
  const gint N = VALIDITY_MOH_PATCH_N;
  gint64 c, s;

  g_return_if_fail (orient_index < 360);
  c = tables->cos_q16[orient_index];
  s = tables->sin_q16[orient_index];
  /* column-major: xL outer, yL inner */
  for (gint xi = 0; xi < FX_SPAN; xi++)
    for (gint yi = 0; yi < FX_SPAN; yi++)
      {
        gint64 xl = xi - N, yl = yi - N;
        gint64 px = sar64 (sx_q16 + xl * c - yl * s + 0x8000, 16);
        gint64 py = sar64 (sy_q16 + xl * s + yl * c + 0x8000, 16);
        gint64 gx = 0x800000, gy = 0x800000, gx8, gy8;

        if (0 <= px && px < (gint64) tw && 0 <= py && py < (gint64) th)
          {
            gx = grad_x[py * tw + px];
            gy = grad_y[py * tw + px];
          }
        gx8 = sar64 (gx, 8);
        gy8 = sar64 (gy, 8);
        rgx[xi * FX_SPAN + yi] = s32 (sar64 (s32 (c * gx8), 8) + sar64 (s32 (s * gy8), 8));
        rgy[xi * FX_SPAN + yi] = s32 (sar64 (s32 (c * gy8), 8) + sar64 (s32 (-(s * gx8)), 8));
      }
}

static void
validity_moh_fx_aggregate (const ValidityMohTables *tables,
                           const gint32            *rgx,
                           const gint32            *rgy,
                           gint32                  *samples)
{
  const gint N = VALIDITY_MOH_PATCH_N;

  for (guint i = 0; i < VALIDITY_MOH_AGGR_WINDOWS; i++)
    {
      gint w = win_sizes[tables->aggr[i][0]];
      gint x0 = tables->aggr[i][1] + N;
      gint y0 = tables->aggr[i][2] + N;
      gint64 sx = 0, sy = 0;

      for (gint xx = 0; xx < w; xx++)
        for (gint k = 0; k < w; k++)
          {
            sx += rgx[(x0 + xx) * FX_SPAN + y0 + k];
            sy += rgy[(x0 + xx) * FX_SPAN + y0 + k];
          }
      samples[2 * i] = s32 (sx);
      samples[2 * i + 1] = s32 (sy);
    }
}

static void
validity_moh_fx_brief (const ValidityMohTables *tables,
                       const gint32            *samples,
                       guint8                  *desc)
{
  memset (desc, 0, VALIDITY_MOH_DESC_LEN);
  for (guint j = 0; j < VALIDITY_MOH_BRIEF_PAIRS; j++)
    if (samples[tables->pairs[j][0]] > samples[tables->pairs[j][1]])
      desc[j / 8] |= 1 << (j % 8);
}

static GArray *
validity_moh_fx_detect_pool (const ValidityMohTables *tables,
                             const guint8            *pixels,
                             guint                    h,
                             guint                    w,
                             guint                   *nms_used)
{
  GArray *pool = g_array_new (FALSE, FALSE, sizeof (ValidityMohPoolEntry));

  for (guint ti = 0; ti < VALIDITY_MOH_GRID; ti++)
    for (guint tj = 0; tj < VALIDITY_MOH_GRID; tj++)
      {
        ValidityMohTileGeom g;
        g_autoptr(GArray) nms = NULL;
        gint32 *tile;
        gint64 *resp, *ixx, *iyy;
        guint n_use;
        gsize n;

        validity_moh_tile_geom (ti, tj, h, w, &g);
        n = (gsize) g.th * g.tw;
        tile = g_new (gint32, n);
        resp = g_new (gint64, n);
        ixx = g_new (gint64, n);
        iyy = g_new (gint64, n);
        validity_moh_tile_q16 (pixels, h, w, &g, tile);
        validity_moh_fx_doh (tables, tile, g.th, g.tw, resp, ixx, iyy, NULL);
        nms = validity_moh_fx_nms (resp, g.th, g.tw);
        n_use = nms->len;
        /* FUN_18000d340: FUN_18000cf90 stops at 125 maxima, and the list
         * takes entries only while it holds fewer than 500 */
        n_use = pool->len >= FX_POOL_MAX ? 0 : MIN (n_use, MIN (FX_NMS_MAX, FX_POOL_MAX - pool->len));
        if (nms_used)
          nms_used[ti * VALIDITY_MOH_GRID + tj] = n_use;

        for (guint k = 0; k < n_use; k++)
          {
            ValidityMohNmsPoint *p = &g_array_index (nms, ValidityMohNmsPoint, k);
            ValidityMohPoolEntry e;
            gsize at = (gsize) p->y * g.tw + p->x;

            if (!validity_moh_fx_subpix (resp, g.th, g.tw, p->x, p->y, &e.sx_q16, &e.sy_q16))
              continue;
            if (!validity_moh_fx_passes_edge (e.sx_q16, e.sy_q16, g.oy, g.ox, h, w))
              continue;
            e.score = p->score;
            e.tile = ti * VALIDITY_MOH_GRID + tj;
            /* FUN_18000cf90 at the NMS pixel */
            e.cls = (ixx[at] < 0 && iyy[at] < 0) ? 0 : 1;
            g_array_append_val (pool, e);
          }
        wipe_free (tile, n * sizeof (gint32));
        wipe_free (resp, n * sizeof (gint64));
        wipe_free (ixx, n * sizeof (gint64));
        wipe_free (iyy, n * sizeof (gint64));
      }
  return pool;
}

/* FUN_18000a7c0: |resp| descending, 0 for ties */
static gint
fx_cmp_a7c0 (gconstpointer pa, gconstpointer pb)
{
  const PoolItem *a = pa, *b = pb;

  return (b->e.score > a->e.score) - (b->e.score < a->e.score);
}

/* FUN_18000a810: tile ascending, then |resp| descending, 0 for ties */
static gint
fx_cmp_a810 (gconstpointer pa, gconstpointer pb)
{
  const PoolItem *a = pa, *b = pb;

  if (a->e.tile != b->e.tile)
    return a->e.tile < b->e.tile ? -1 : 1;
  return fx_cmp_a7c0 (pa, pb);
}

gboolean
fpi_validity_moh_extract_frame_fixed (const ValidityMohTables *tables,
                                      const guint8            *pixels,
                                      gsize                    pixels_len,
                                      guint                    h,
                                      guint                    w,
                                      ValidityMohFrame        *frame,
                                      GError                 **error)
{
  g_autoptr(GArray) pool = NULL;
  g_autofree PoolItem *items = NULL;
  guint n, kept;
  gint32 *gx[VALIDITY_MOH_GRID * VALIDITY_MOH_GRID] = { 0 };
  gint32 *gy[VALIDITY_MOH_GRID * VALIDITY_MOH_GRID] = { 0 };
  gdouble top[VALIDITY_MOH_FRAME_KP_CAP];
  ValidityMohTileGeom geom[VALIDITY_MOH_GRID * VALIDITY_MOH_GRID];
  gint32 rgx[FX_SPAN * FX_SPAN], rgy[FX_SPAN * FX_SPAN];
  gint32 samples[2 * VALIDITY_MOH_AGGR_WINDOWS];

  g_return_val_if_fail (tables != NULL && frame != NULL, FALSE);
  if (!fpi_validity_moh_tables_supports (tables, error) ||
      !check_image (pixels, pixels_len, h, w, error))
    return FALSE;

  memset (frame, 0, sizeof (*frame));
  frame->h = h;
  frame->w = w;

  /* Phase 1: per tile DoH, NMS, subpixel, edge rule */
  pool = validity_moh_fx_detect_pool (tables, pixels, h, w, NULL);
  n = pool->len;
  items = g_new (PoolItem, MAX (n, 1));
  for (guint i = 0; i < n; i++)
    {
      items[i].e = g_array_index (pool, ValidityMohPoolEntry, i);
      items[i].order = i;
    }

  /* Rank by response, compute statistics and retain at most 250 keypoints. */
  validity_moh_dll_qsort (items, n, sizeof (PoolItem), fx_cmp_a7c0);
  kept = MIN (n, VALIDITY_MOH_FRAME_KP_CAP);
  for (guint i = 0; i < kept; i++)
    top[i] = items[i].e.score;
  validity_moh_frame_stats (top, n, &frame->stats);

  /* Phase 3: (tile ascending, |resp| descending): FUN_18000a810 */
  validity_moh_dll_qsort (items, kept, sizeof (PoolItem), fx_cmp_a810);

  /* Phase 4: FUN_18000f350 per keypoint (orientation FUN_18000d920,
   * descriptor FUN_18000e090, O byte), then FUN_18000a910 to the image */
  for (guint i = 0; i < kept; i++)
    {
      PoolItem *it = &items[i];
      guint t = it->e.tile;
      ValidityMohTileGeom *g = &geom[t];
      ValidityMohKeypoint kp = { 0 };
      gint64 gxi, gyi;

      if (gx[t] == NULL)
        {
          gint32 *tile;

          validity_moh_tile_geom (t / VALIDITY_MOH_GRID, t % VALIDITY_MOH_GRID, h, w, g);
          tile = g_new (gint32, g->th * g->tw);
          gx[t] = g_new (gint32, g->th * g->tw);
          gy[t] = g_new (gint32, g->th * g->tw);
          validity_moh_tile_q16 (pixels, h, w, g, tile);
          validity_moh_fx_gradient (tables, tile, g->th, g->tw, gx[t], gy[t]);
          wipe_free (tile, (gsize) g->th * g->tw * sizeof (gint32));
        }

      kp.theta = validity_moh_fx_orient (tables, gx[t], gy[t], g->th, g->tw, it->e.sx_q16, it->e.sy_q16,
                                         &kp.coh, NULL);
      kp.orient = kp.theta / 65536.0;
      kp.o = validity_moh_dll_orient_byte_q16 (kp.theta);
      kp.cls = it->e.cls;
      kp.score = it->e.score;
      validity_moh_fx_sample_rotate (tables, gx[t], gy[t], g->th, g->tw, it->e.sx_q16, it->e.sy_q16,
                                     validity_moh_fx_orient_index (kp.theta), rgx, rgy);
      validity_moh_fx_aggregate (tables, rgx, rgy, samples);
      validity_moh_fx_brief (tables, samples, kp.desc);

      gxi = g->ox + sar64 (it->e.sx_q16, 16);
      gyi = g->oy + sar64 (it->e.sy_q16, 16);
      /* Every entry passed the global edge rule in phase 1. */
      if (EDGE_MARGIN <= gxi && gxi < (gint64) w - EDGE_MARGIN &&
          EDGE_MARGIN <= gyi && gyi < (gint64) h - EDGE_MARGIN)
        {
          kp.x = (gint) gxi;
          kp.y = (gint) gyi;
          frame->kps[frame->n_kps++] = kp;
        }
    }

  for (guint t = 0; t < VALIDITY_MOH_GRID * VALIDITY_MOH_GRID; t++)
    {
      if (gx[t] == NULL)
        continue;
      wipe_free (gx[t], (gsize) geom[t].th * geom[t].tw * sizeof (gint32));
      wipe_free (gy[t], (gsize) geom[t].th * geom[t].tw * sizeof (gint32));
    }
  explicit_bzero (rgx, sizeof (rgx));
  explicit_bzero (rgy, sizeof (rgy));
  explicit_bzero (samples, sizeof (samples));
  frame->quality = validity_moh_dll_frame_quality (frame->kps, frame->n_kps);
  return TRUE;
}

static gboolean
is_rigid (gint32 a, gint32 b)
{
  /* |a^2 + b^2 - ONE^2| < ONE^2 * 0.05 with ONE = 0x10000, exactly */
  guint64 s = (guint64) ((gint64) a * a) + (guint64) ((gint64) b * b);
  const guint64 one2 = G_GUINT64_CONSTANT (1) << 32;
  guint64 d = s >= one2 ? s - one2 : one2 - s;

  return (gdouble) d < (gdouble) one2 * 0.05;
}

static guint
validity_moh_patch_pre_v30_near_identity (guint8 *ws,
                                          gsize   ws_len)
{
  gsize zones[VALIDITY_MOH_N_SECTIONS + 1][2];
  gsize prev = 0;
  guint patched = 0;

  /* the zones between the v30 record areas (anchors are ascending) */
  for (guint i = 0; i < VALIDITY_MOH_N_SECTIONS; i++)
    {
      zones[i][0] = prev;
      zones[i][1] = v30_regions[i];
      prev = v30_regions[i] + VALIDITY_MOH_V30_SECTION_BYTES;
    }
  zones[VALIDITY_MOH_N_SECTIONS][0] = prev;
  zones[VALIDITY_MOH_N_SECTIONS][1] = ws_len;

  for (guint z = 0; z <= VALIDITY_MOH_N_SECTIONS; z++)
    {
      gsize z0 = zones[z][0], z1 = MIN (zones[z][1], ws_len);
      gsize best_n = 0, best_start = 0;

      for (gsize start = z0; start < z1; start++)
        {
          gsize o = start, n = 0;

          while (o + VALIDITY_MOH_V30_RECORD_LEN <= z1)
            {
              if (!is_rigid (rd_i32 (ws + o + 2), rd_i32 (ws + o + 6)))
                break;
              n++;
              o += VALIDITY_MOH_V30_RECORD_LEN;
            }
          if (n > best_n)
            {
              best_n = n;
              best_start = start;
            }
        }
      if (best_n >= 2)
        {
          gsize o = best_start;

          for (gsize k = 0; k < best_n; k++)
            {
              /* a = ONE, b = 0, tx = 1, ty = 1: identity geometry, but not
               * the pure-identity "unmatched" sentinel; keep [x][y] */
              wr_i32 (ws + o + 2, 0x10000);
              wr_i32 (ws + o + 6, 0);
              wr_i32 (ws + o + 10, 1);
              wr_i32 (ws + o + 14, 1);
              o += VALIDITY_MOH_V30_RECORD_LEN;
              patched++;
            }
        }
    }
  return patched;
}

static void
validity_moh_compute_tid (const guint8 *ws_body,
                          gsize         ws_len,
                          guint8       *tid)
{
  guint8 info[sizeof (TEMPLATE_ID_STR) - 1 + TEMPLATE_ID_PAD] = { 0 };
  guint8 key[32], t1[32];
  gsize len;
  GChecksum *sha = g_checksum_new (G_CHECKSUM_SHA256);
  GHmac *hmac;

  memcpy (info, TEMPLATE_ID_STR, sizeof (TEMPLATE_ID_STR) - 1);

  g_checksum_update (sha, ws_body, ws_len);
  len = sizeof (key);
  g_checksum_get_digest (sha, key, &len);
  g_checksum_free (sha);

  hmac = g_hmac_new (G_CHECKSUM_SHA256, key, sizeof (key));
  g_hmac_update (hmac, info, sizeof (info));
  len = sizeof (t1);
  g_hmac_get_digest (hmac, t1, &len);
  g_hmac_unref (hmac);

  hmac = g_hmac_new (G_CHECKSUM_SHA256, key, sizeof (key));
  g_hmac_update (hmac, t1, sizeof (t1));
  g_hmac_update (hmac, info, sizeof (info));
  len = VALIDITY_MOH_TID_LEN;
  g_hmac_get_digest (hmac, tid, &len);
  g_hmac_unref (hmac);
}

static GBytes *
validity_moh_build_envelope (guint16       subtype,
                             const guint8 *ws_body,
                             gsize         ws_len,
                             const guint8 *tid)
{
  gsize payload = 4 + ws_len + 4 + VALIDITY_MOH_TID_LEN;
  gsize total = 8 + payload + VALIDITY_MOH_ENVELOPE_TRAILING;
  guint8 *buf;
  GBytes *env = bytes_new_wiped (total, &buf);
  gsize off;

  wr_u16 (buf + 0, subtype);
  wr_u16 (buf + 2, VALIDITY_MOH_ENVELOPE_VERSION);
  wr_u16 (buf + 4, payload & 0xffff);
  wr_u16 (buf + 6, VALIDITY_MOH_ENVELOPE_TRAILING);
  wr_u16 (buf + 8, 1);
  wr_u16 (buf + 10, ws_len & 0xffff);
  memcpy (buf + 12, ws_body, ws_len);
  off = 12 + ws_len;
  wr_u16 (buf + off, 2);
  wr_u16 (buf + off + 2, VALIDITY_MOH_TID_LEN);
  memcpy (buf + off + 4, tid, VALIDITY_MOH_TID_LEN);
  return env;
}

#define DLL_P3_SECTIONS_DONE 5              /* FUN_180001350 p3: 100 % at 5 sections */
#define DLL_WS_VERSION 0x00050206           /* FUN_1800066f0 with QM version 5,2,6 */
#define DLL_WS_HDR 12                       /* [u32 0][u32 used][u32 version] */
#define DLL_TAG_END 0x0001
#define DLL_TAG_POSE 0x0002
#define DLL_TAG_COUNT 0x0003
#define DLL_TAG_SECTION_BASE 0x0003         /* section k (1-based) is tag k + 3 */
#define DLL_TAG_UPDATES 0x0068
#define DLL_TAG_DIMS 0x0069
#define DLL_TAG_CAPACITY 0x006b
#define DLL_TAG_STATE 0x006c
/* FUN_1800051f0: ((p4 / 2) * 0x14 + 4) * p4 + 0x24 + ((p4 + 3) & ~3) = 264 */
#define DLL_POSE_LEN ((((DLL_P4 / 2) * 0x14 + 4) * DLL_P4) + 0x24 + ((DLL_P4 + 3) & ~3))
#define DLL_ORIENT_BUCKET 15                /* CDF bucket width in O units (30 degrees) */
#define DLL_ORIENT_BUCKETS 11               /* per class */
#define DLL_ORIENT_MAX 179                  /* largest O byte: FUN_18000f350 maps 180 to 0 */
#define DLL_TAG_REDUNDANT 0x006a            /* near-repeat frames (FUN_180005cb0) */
#define DLL_NO_HAM 0x7fff                   /* "no statistic" (FUN_180007980) */

/* ---- FUN_1800095c0: the driver's qsort ------------------------------
 * 4.4BSD qsort (Bentley & McIlroy): insertion sort below 7 elements, median
 * of three (ninther above 40), three-way partition that moves equal keys to
 * the ends, and an insertion sort when a partition pass swapped nothing. */

static inline void
dll_swap (guint8 *a, guint8 *b, gsize n)
{
  for (gsize k = 0; k < n; k++)
    {
      guint8 t = a[k];

      a[k] = b[k];
      b[k] = t;
    }
}

static guint8 *
dll_med3 (guint8 *a, guint8 *b, guint8 *c, GCompareFunc cmp)
{
  return cmp (a, b) < 0 ?
         (cmp (b, c) < 0 ? b : (cmp (a, c) < 0 ? c : a)) :
         (cmp (b, c) > 0 ? b : (cmp (a, c) < 0 ? a : c));
}

static void
dll_insertion_sort (guint8 *a, gsize n, gsize es, GCompareFunc cmp)
{
  for (guint8 *pm = a + es; pm < a + n * es; pm += es)
    for (guint8 *pl = pm; pl > a && cmp (pl - es, pl) > 0; pl -= es)
      dll_swap (pl, pl - es, es);
}

static void
validity_moh_dll_qsort (gpointer base, gsize n, gsize es, GCompareFunc cmp)
{
  guint8 *a = base;

  for (;;)
    {
      guint8 *pa, *pb, *pc, *pd, *pl, *pm, *pn;
      gboolean swapped = FALSE;
      gsize r;
      gint c;

      if (n < 7)
        {
          dll_insertion_sort (a, n, es, cmp);
          return;
        }
      pm = a + (n / 2) * es;
      if (n > 7)
        {
          pl = a;
          pn = a + (n - 1) * es;
          if (n > 40)
            {
              gsize d = (n / 8) * es;

              pl = dll_med3 (pl, pl + d, pl + 2 * d, cmp);
              pm = dll_med3 (pm - d, pm, pm + d, cmp);
              pn = dll_med3 (pn - 2 * d, pn - d, pn, cmp);
            }
          pm = dll_med3 (pl, pm, pn, cmp);
        }
      dll_swap (a, pm, es);
      pa = pb = a + es;
      pc = pd = a + (n - 1) * es;
      for (;;)
        {
          while (pb <= pc && (c = cmp (pb, a)) <= 0)
            {
              if (c == 0)
                {
                  swapped = TRUE;
                  dll_swap (pa, pb, es);
                  pa += es;
                }
              pb += es;
            }
          while (pb <= pc && (c = cmp (pc, a)) >= 0)
            {
              if (c == 0)
                {
                  swapped = TRUE;
                  dll_swap (pc, pd, es);
                  pd -= es;
                }
              pc -= es;
            }
          if (pb > pc)
            break;
          dll_swap (pb, pc, es);
          swapped = TRUE;
          pb += es;
          pc -= es;
        }
      if (!swapped)
        {
          dll_insertion_sort (a, n, es, cmp);
          return;
        }
      pn = a + n * es;
      r = MIN ((gsize) (pa - a), (gsize) (pb - pa));
      if (r > 0)
        dll_swap (a, pb - r, r);
      r = MIN ((gsize) (pd - pc), (gsize) (pn - pd) - es);
      if (r > 0)
        dll_swap (pb, pn - r, r);
      if ((r = (gsize) (pb - pa)) > es)
        validity_moh_dll_qsort (a, r / es, es, cmp);
      if ((r = (gsize) (pd - pc)) <= es)
        return;
      /* iterate on the upper part */
      a = pn - r;
      n = r / es;
    }
}

/* ---- FUN_18000aab0 (final order) -------------------------------------- */

/* FUN_18000a7e0: class descending, then |resp| descending; equal keys give
 * 1, never 0 (the driver compares the integer responses, here the doubles) */
static gint
dll_cmp_class_score (gconstpointer pa, gconstpointer pb)
{
  const ValidityMohKeypoint *a = pa, *b = pb;
  gint d = (gint) b->cls - (gint) a->cls;

  if (d == 0)
    d = (b->score > a->score) - (b->score < a->score);
  return d < 0 ? -1 : 1;
}

/* FUN_18000a940: O ascending */
static gint
dll_cmp_orient (gconstpointer pa, gconstpointer pb)
{
  const ValidityMohKeypoint *a = pa, *b = pb;

  return (a->o > b->o) - (a->o < b->o);
}

static void
validity_moh_dll_section_order (const ValidityMohKeypoint *kps,
                                guint                      n_kps,
                                ValidityMohKeypoint       *out,
                                guint                     *split)
{
  guint s = 0;

  /* input: the (tile, |resp| desc) order the descriptors were computed in
   * (FUN_18000a810), which is the extractor's output order */
  memcpy (out, kps, n_kps * sizeof (ValidityMohKeypoint));
  validity_moh_dll_qsort (out, n_kps, sizeof (ValidityMohKeypoint), dll_cmp_class_score);
  /* the first class-0 record ends the class-1 run */
  while (s < n_kps && out[s].cls != 0)
    s++;
  validity_moh_dll_qsort (out, s, sizeof (ValidityMohKeypoint), dll_cmp_orient);
  validity_moh_dll_qsort (out + s, n_kps - s, sizeof (ValidityMohKeypoint), dll_cmp_orient);
  *split = s;
}

/* ---- FUN_180005720 / FUN_1800057e0 ------------------------------------ */

/* cdf[base + k] = index of the first record of [start, end) whose bucket
 * O / 15 exceeds k; @end where none does. Records must be O-sorted.
 * Both extractors give O <= 179 (bucket 11 at most, "past cdf[10]"); the
 * driver writes its 22-byte table without a bound, so a larger byte in a
 * caller-built frame is counted as bucket 11 here instead of being written
 * past the table. The public entry points refuse such frames
 * (dll_frame_check); this keeps validity_moh_serialize_dll_section and
 * validity_moh_dll_orient_cdf, which have no error return, memory safe. */
static void
dll_cdf_half (const ValidityMohKeypoint *recs, guint8 *cdf, guint base, guint start, guint end)
{
  guint cur = 0, prev = 0;

  for (guint i = start; i < end; i++)
    {
      cur = MIN ((guint) recs[i].o / DLL_ORIENT_BUCKET, (guint) DLL_ORIENT_BUCKETS);
      for (guint k = prev; k < cur; k++)
        cdf[base + k] = (guint8) i;
      prev = cur;
    }
  for (guint k = cur; k < DLL_ORIENT_BUCKETS; k++)
    cdf[base + k] = (guint8) end;
}

static void
validity_moh_dll_orient_cdf (const ValidityMohKeypoint *recs,
                             guint                      split,
                             guint                      n,
                             guint8                    *cdf)
{
  dll_cdf_half (recs, cdf, 0, 0, split);
  dll_cdf_half (recs, cdf, DLL_ORIENT_BUCKETS, split, n);
}

static gsize
validity_moh_serialize_dll_section (const ValidityMohFrame *frame,
                                    guint8                 *out)
{
  guint n = MIN (frame->n_kps, VALIDITY_MOH_FRAME_KP_CAP);
  gsize recs_size = MAX (n, 1) * sizeof (ValidityMohKeypoint);
  ValidityMohKeypoint *recs = g_malloc (recs_size);
  guint split = 0;
  guint8 *p = out;

  validity_moh_dll_section_order (frame->kps, n, recs, &split);
  memset (p, 0, 8);                 /* feature object +0x20, zeroed by FUN_1800061c0 */
  p += 8;
  *p++ = (guint8) n;                /* the true count */
  for (guint i = 0; i < n; i++)
    {
      memcpy (p, recs[i].desc, VALIDITY_MOH_DESC_LEN);
      p[16] = recs[i].x & 0xff;
      p[17] = recs[i].y & 0xff;
      p += VALIDITY_MOH_V30_RECORD_LEN;
    }
  *p++ = (guint8) split;
  *p++ = frame->quality;
  /* the driver fills the table only when N != 0 (otherwise it writes 22
   * uninitialised stack bytes, which its parser does not read) */
  if (n != 0)
    validity_moh_dll_orient_cdf (recs, split, n, p);
  else
    memset (p, 0, VALIDITY_MOH_DLL_CDF_LEN);
  p += VALIDITY_MOH_DLL_CDF_LEN;
  wipe_free (recs, recs_size);
  return (gsize) (p - out);
}

/* ---- WS container: TLV store (FUN_180006800 .. FUN_180006a80) --------- */

static inline guint32
rd_u32 (const guint8 *p)
{
  return (guint32) rd_i32 (p);
}

static inline void
wr_u32 (guint8 *p, guint32 v)
{
  wr_i32 (p, (gint32) v);
}

/* FUN_180006890 / FUN_180006800: walk from +12; searching tag 1 finds the end
 * marker. A found TLV's declared payload lies inside the buffer (always so
 * for a WS this module built; validity_moh_dll_enroll_fits takes a foreign
 * one). The end marker declares 4 but has no payload. */
static gboolean
dll_ws_find (const guint8 *ws, guint16 tag, gsize *off)
{
  gsize o = DLL_WS_HDR;

  if (rd_u32 (ws + 4) == 0)
    return FALSE;
  while (o + 4 <= VALIDITY_MOH_WS_SIZE)
    {
      guint16 t = rd_u16 (ws + o);

      if (t == tag)
        {
          if (tag != DLL_TAG_END && o + 4 + (gsize) rd_u16 (ws + o + 2) > VALIDITY_MOH_WS_SIZE)
            return FALSE;
          *off = o;
          return TRUE;
        }
      if (t == DLL_TAG_END)
        return FALSE;
      o += 4 + rd_u16 (ws + o + 2);
    }
  return FALSE;
}

/* FUN_180006720: end marker [01 00 04 00] at +12 + used; used += 4 */
static gboolean
dll_ws_terminate (guint8 *ws)
{
  guint32 used = rd_u32 (ws + 4);

  if (DLL_WS_HDR + (gsize) used + 4 > VALIDITY_MOH_WS_SIZE)
    return FALSE;
  wr_u16 (ws + DLL_WS_HDR + used, DLL_TAG_END);
  wr_u16 (ws + DLL_WS_HDR + used + 2, 4);
  wr_u32 (ws + 4, used + 4);
  return TRUE;
}

/* FUN_1800067e0 + FUN_1800066f0 */
static void
dll_ws_init (guint8 *ws)
{
  wr_u32 (ws, 0);
  wr_u32 (ws + 4, 0);
  dll_ws_terminate (ws);
  wr_u32 (ws + 8, DLL_WS_VERSION);
}

/* FUN_180006a80: replace the TLV in place (moving what follows, FUN_180006970)
 * or insert it in front of the end marker. The length is rounded up to 4;
 * the pad is zero, as in the driver's zeroed source buffers. */
static gboolean
dll_ws_put (guint8 *ws, guint16 tag, const guint8 *data, gsize len)
{
  gsize len_r = (len + 3) & ~(gsize) 3;
  guint32 used = rd_u32 (ws + 4);
  gsize o, end;

  if (len_r > G_MAXUINT16 || !dll_ws_find (ws, DLL_TAG_END, &end))
    return FALSE;
  if (dll_ws_find (ws, tag, &o))
    {
      gsize old = rd_u16 (ws + o + 2);
      gsize next = o + 4 + old;

      if (len_r != old)
        {
          /* everything up to the end marker's data pointer moves */
          if (end + 4 - old + len_r > VALIDITY_MOH_WS_SIZE)
            return FALSE;
          memmove (ws + o + 4 + len_r, ws + next, end + 4 - next);
        }
      used = used - (guint32) old + (guint32) len_r;
    }
  else
    {
      o = end;
      if (o + 4 + len_r + 4 > VALIDITY_MOH_WS_SIZE)
        return FALSE;
      used += (guint32) len_r;
    }
  wr_u16 (ws + o, tag);
  wr_u16 (ws + o + 2, (guint16) len_r);
  memcpy (ws + o + 4, data, len);
  memset (ws + o + 4 + len, 0, len_r - len);
  wr_u32 (ws + 4, used);
  return o != end || dll_ws_terminate (ws);
}

static gboolean
dll_ws_put_u32 (guint8 *ws, guint16 tag, guint32 v)
{
  guint8 b[4];

  wr_u32 (b, v);
  return dll_ws_put (ws, tag, b, sizeof (b));
}

/* FUN_180006930: 0 when absent (or, in a foreign WS, shorter than 4 bytes) */
static guint32
dll_ws_get_u32 (const guint8 *ws, guint16 tag)
{
  gsize o;

  return dll_ws_find (ws, tag, &o) && rd_u16 (ws + o + 2) >= 4 ? rd_u32 (ws + o + 4) : 0;
}

/* ---- tag 2: inter-section pose table (ctx+0x138) ----------------------- */

/* What a failed fit leaves (FUN_180007980): co-located count 0, Hamming
 * 0x7fff, identity pose. FUN_18000b420 calls exactly this pose "not registered". */
static const DllPose dll_pose_none = { 0, 0xff, 0x10000, 0, 0, 0 };

static gboolean
dll_pose_registered (const DllPose *p)
{
  return !(p->a == 0x10000 && p->b == 0 && p->tx == 0 && p->ty == 0);
}

/* FUN_18000b3d0 */
static gboolean
dll_pose_valid (const DllPose *p)
{
  return p->b0 > 30 && p->b1 < 50;
}

/* FUN_180006da0 on the pose; b0/b1 are copied */
static void
validity_moh_dll_pose_inverse (const gint32 *pose,
                               gint32       *out)
{
  gint32 nb = s32 (-(gint64) pose[1]);
  gint32 a2 = sar32 (pose[0], 1), nb2 = sar32 (nb, 1);
  gint32 tx9 = sar32 (pose[2], 9), ty9 = sar32 (pose[3], 9);
  gint32 tx = s32 (-(gint64) sar32 ((gint64) imul32 (tx9, a2) - imul32 (ty9, nb2), 6));
  gint32 ty = s32 (-(gint64) sar32 ((gint64) imul32 (nb2, tx9) + imul32 (ty9, a2), 6));

  out[0] = pose[0];
  out[1] = nb;
  out[2] = tx;
  out[3] = ty;
}

static void
validity_moh_dll_pose_compose (const gint32 *e,
                               const gint32 *p,
                               gint32       *out)
{
  gint32 a = sar32 ((gint64) imul32 (sar32 (e[0], 1), sar32 (p[0], 1)) -
                    imul32 (sar32 (e[1], 1), sar32 (p[1], 1)) + 0x2000, 14);
  gint32 b = sar32 ((gint64) imul32 (sar32 (e[0], 1), sar32 (p[1], 1)) + 0x2000 +
                    imul32 (sar32 (p[0], 1), sar32 (e[1], 1)), 14);
  gint32 tx = add32 (sar32 ((gint64) imul32 (sar32 (p[2], 8), sar32 (e[0], 2)) -
                            imul32 (sar32 (p[3], 8), sar32 (e[1], 2)), 6), e[2]);
  gint32 ty = add32 (sar32 ((gint64) imul32 (sar32 (e[0], 2), sar32 (p[3], 8)) +
                            imul32 (sar32 (p[2], 8), sar32 (e[1], 2)), 6), e[3]);

  validity_moh_dll_normalize (&a, &b);
  out[0] = a;
  out[1] = b;
  out[2] = tx;
  out[3] = ty;
}

static void
dll_pose_inverse (const DllPose *in, DllPose *out)
{
  gint32 p[4] = { in->a, in->b, in->tx, in->ty }, q[4];

  validity_moh_dll_pose_inverse (p, q);
  out->b0 = in->b0;
  out->b1 = in->b1;
  out->a = q[0];
  out->b = q[1];
  out->tx = q[2];
  out->ty = q[3];
}

/* FUN_1800053e0: read back what FUN_1800051f0 wrote (upper triangle), zero
 * the diagonal poses, rebuild the lower triangle as inverses */
static void
dll_pose_load (const guint8 *ws, DllPoseTable *pt)
{
  const guint8 *p;
  gsize o;

  if (!dll_ws_find (ws, DLL_TAG_POSE, &o) || rd_u16 (ws + o + 2) == 0)
    return;
  p = ws + o + 4;
  memcpy (pt->order, p, DLL_P4);
  p += DLL_P4;
  memcpy (pt->info, p, DLL_P4 * 4);
  p += DLL_P4 * 4;
  pt->n = MIN (p[0], DLL_P4);
  pt->n_comp = p[1];
  p += 2;
  for (guint i = 0; i < pt->n; i++)
    for (guint j = i + 1; j < pt->n; j++)
      {
        DllPose *e = &pt->e[i][j];

        e->b0 = p[0];
        e->b1 = p[1];
        e->a = rd_i32 (p + 2);
        e->b = rd_i32 (p + 6);
        e->tx = rd_i32 (p + 10);
        e->ty = rd_i32 (p + 14);
        p += 18;
      }
  for (guint i = 0; i < pt->n; i++)
    pt->e[i][i].a = pt->e[i][i].b = pt->e[i][i].tx = pt->e[i][i].ty = 0;
  for (guint r = 1; r < pt->n; r++)
    for (guint c = 0; c < r; c++)
      dll_pose_inverse (&pt->e[c][r], &pt->e[r][c]);
}

/* Initialize the new section's quality and diagonal. Cross-section records
* use the format's "not registered" value; no host pose matcher is used. */
static void
dll_pose_add (DllPoseTable *pt, guint count, guint8 quality)
{
  guint k = count - 1;
  const DllPose diag = { 0, 0xff, 0, 0, 0, 0 };

  pt->e[k][k] = diag;
  pt->info[k][3] = quality;
  for (guint i = 0; i < k; i++)
    {
      DllPose *e = &pt->e[i][k];

      *e = dll_pose_none;
      dll_pose_inverse (e, &pt->e[k][i]);
    }
}

/* FUN_18000b1f0 on {key, index} byte pairs: key, then index, descending */
static gint
dll_cmp_order (gconstpointer pa, gconstpointer pb)
{
  const guint8 *a = pa, *b = pb;

  if (b[0] != a[0])
    return (gint) b[0] - (gint) a[0];
  return (gint) b[1] - (gint) a[1];
}

/* FUN_18000ba90: depth-first over registered poses, labelling (FUN_18000b370) */
static void
dll_pose_dfs (DllPoseTable *pt, gboolean *visited, guint u, guint8 label)
{
  for (guint v = 0; v < pt->n; v++)
    if (v != u && dll_pose_registered (&pt->e[u][v]) && !visited[v])
      {
        visited[v] = TRUE;
        pt->info[v][0] = label;
        dll_pose_dfs (pt, visited, v, label);
      }
}

/* FUN_18000b450: next hops of the shortest paths (Floyd-Warshall on hop
 * counts) over the entries that are valid by b0/b1 (FUN_18000b3d0, mode 0)
 * or have a registered pose (FUN_18000b420, mode 1); 0xff = no path */
static void
dll_pose_next_hops (const DllPoseTable *pt, gboolean registered_mode, guint8 next[DLL_P4][DLL_P4])
{
  gint dist[DLL_P4][DLL_P4];
  guint n = pt->n;

  for (guint i = 0; i < n; i++)
    for (guint j = 0; j < n; j++)
      {
        gboolean edge = FALSE;

        next[i][j] = 0xff;
        dist[i][j] = 0xff;
        if (i != j)
          edge = registered_mode ? dll_pose_registered (&pt->e[i][j]) : dll_pose_valid (&pt->e[i][j]);
        if (edge)
          {
            next[i][j] = (guint8) j;
            dist[i][j] = 1;
          }
      }
  for (guint k = 0; k < n; k++)
    for (guint i = 0; i < n; i++)
      for (guint j = 0; j < n; j++)
        if (i != j && dist[k][j] + dist[i][k] < dist[i][j])
          {
            dist[i][j] = dist[k][j] + dist[i][k];
            next[i][j] = next[i][k];
          }
}

/* FUN_18000b6e0 for row @r: every section c whose pose from r is not
 * registered gets the composition of the poses along the path (FUN_18000b300,
 * FUN_180006cc0), and c -> r its inverse (FUN_18000b260; b0/b1 stay) */
static void
dll_pose_chain_row (DllPoseTable *pt, guint r, guint8 next[DLL_P4][DLL_P4])
{
  for (guint c = 0; c < pt->n; c++)
    {
      guint path[DLL_P4 + 1];
      guint len = 0, s = r;
      gint32 q[4], step[4], out[4];

      if (c == r || dll_pose_registered (&pt->e[r][c]) || next[r][c] == 0xff)
        continue;
      path[len++] = r;
      while (s != c && len <= DLL_P4)
        {
          s = next[s][c];
          if (s >= pt->n)
            break;
          path[len++] = s;
        }
      if (s != c || len < 2)
        continue;                       /* not reachable for a shortest-path table */
      q[0] = pt->e[path[0]][path[1]].a;
      q[1] = pt->e[path[0]][path[1]].b;
      q[2] = pt->e[path[0]][path[1]].tx;
      q[3] = pt->e[path[0]][path[1]].ty;
      for (guint m = 1; m + 1 < len; m++)
        {
          const DllPose *e = &pt->e[path[m]][path[m + 1]];

          step[0] = e->a;
          step[1] = e->b;
          step[2] = e->tx;
          step[3] = e->ty;
          validity_moh_dll_pose_compose (step, q, out);
          memcpy (q, out, sizeof (q));
        }
      pt->e[r][c].a = q[0];
      pt->e[r][c].b = q[1];
      pt->e[r][c].tx = q[2];
      pt->e[r][c].ty = q[3];
      validity_moh_dll_pose_inverse (q, out);
      pt->e[c][r].a = out[0];
      pt->e[c][r].b = out[1];
      pt->e[c][r].tx = out[2];
      pt->e[c][r].ty = out[3];
    }
}

/* FUN_18000b970: chain along valid entries, then along registered ones */
static void
dll_pose_chain (DllPoseTable *pt)
{
  guint8 next[DLL_P4][DLL_P4];

  dll_pose_next_hops (pt, FALSE, next);
  for (guint r = 0; r < pt->n; r++)
    dll_pose_chain_row (pt, r, next);
  dll_pose_next_hops (pt, TRUE, next);
  for (guint r = 0; r < pt->n; r++)
    dll_pose_chain_row (pt, r, next);
}

/* FUN_1800051f0 head + FUN_18000bd10 */
static void
dll_pose_finalise (DllPoseTable *pt, guint count)
{
  gboolean visited[DLL_P4] = { FALSE };
  guint8 keys[DLL_P4][2];
  guint8 label = 0;

  pt->n = (guint8) count;

  /* FUN_18000b970. With "no fit" entries only no entry
   * is valid or registered and nothing changes. */
  dll_pose_chain (pt);

  /* FUN_18000bbe0: label connected components (registered poses), visiting
   * the sections in the order array of the PREVIOUS append (FUN_18000b390);
   * sections that order does not list and no edge reaches keep their old
   * label */
  for (;;)
    {
      gint next = -1;

      for (guint i = 0; i < pt->n; i++)
        if (pt->order[i] < DLL_P4 && !visited[pt->order[i]])
          {
            next = pt->order[i];
            break;
          }
      if (next < 0)
        break;
      pt->info[next][0] = label;
      visited[next] = TRUE;                 /* FUN_18000bb90 */
      dll_pose_dfs (pt, visited, (guint) next, label);
      label++;
    }
  pt->n_comp = label;

  /* the new order: keys {0, i} sorted by FUN_18000b1f0, i.e. n-1 .. 0 */
  for (guint i = 0; i < pt->n; i++)
    {
      keys[i][0] = 0;
      keys[i][1] = (guint8) i;
    }
  validity_moh_dll_qsort (keys, pt->n, 2, dll_cmp_order);
  for (guint i = 0; i < pt->n; i++)
    pt->order[i] = keys[i][1];
}

/* FUN_1800069e0 (reserve) + FUN_1800051f0 (write): fixed TLV length 264; the
 * bytes past the written part are left as they are (zero in a fresh WS) */
static gboolean
dll_pose_store (guint8 *ws, const DllPoseTable *pt)
{
  gsize o, end;
  guint8 *p;

  if (dll_ws_find (ws, DLL_TAG_POSE, &o))
    {
      /* the driver would move the tail without updating "used"; the length
       * never changes for a fixed p4, so do not emulate that path */
      if (rd_u16 (ws + o + 2) != DLL_POSE_LEN)
        return FALSE;
    }
  else
    {
      if (!dll_ws_find (ws, DLL_TAG_END, &end) || end + 4 + DLL_POSE_LEN + 4 > VALIDITY_MOH_WS_SIZE)
        return FALSE;
      o = end;
      wr_u16 (ws + o, DLL_TAG_POSE);
      wr_u32 (ws + 4, rd_u32 (ws + 4) + DLL_POSE_LEN);
      if (!dll_ws_terminate (ws))
        return FALSE;
    }
  wr_u16 (ws + o + 2, DLL_POSE_LEN);
  p = ws + o + 4;
  memcpy (p, pt->order, DLL_P4);
  p += DLL_P4;
  memcpy (p, pt->info, DLL_P4 * 4);
  p += DLL_P4 * 4;
  *p++ = pt->n;
  *p++ = pt->n_comp;
  for (guint i = 0; i < pt->n; i++)
    for (guint j = i + 1; j < pt->n; j++)
      {
        const DllPose *e = &pt->e[i][j];

        p[0] = e->b0;
        p[1] = e->b1;
        wr_i32 (p + 2, e->a);
        wr_i32 (p + 6, e->b);
        wr_i32 (p + 10, e->tx);
        wr_i32 (p + 14, e->ty);
        p += 18;
      }
  return TRUE;
}

/* ---- tag 0x6c: {ctx+0x154, ctx+0x150, ctx+0x144, ctx+0x130} ------------
 * FUN_180006130 reads it back (all zero when absent, which also clears the
 * image size FUN_180001c40 put there), FUN_180006080 writes it after every
 * frame. +0x144 = WS initialised, +0x130 = frames rejected (quality or
 * redundancy; none here). */

static void
dll_state_load (const guint8 *ws, DllState *st)
{
  gsize o;

  memset (st, 0, sizeof (*st));
  if (!dll_ws_find (ws, DLL_TAG_STATE, &o))
    return;
  st->f154 = rd_u32 (ws + o + 4);
  st->f150 = rd_u32 (ws + o + 8);
  st->f144 = rd_u32 (ws + o + 12);
  st->f130 = rd_u32 (ws + o + 16);
}

static gboolean
dll_state_store (guint8 *ws, const DllState *st)
{
  guint8 b[16];

  wr_u32 (b, st->f154);
  wr_u32 (b + 4, st->f150);
  wr_u32 (b + 8, st->f144);
  wr_u32 (b + 12, st->f130);
  return dll_ws_put (ws, DLL_TAG_STATE, b, sizeof (b));
}

/* A frame offered to the driver-format serializer. The extractors give at
 * most FRAME_KP_CAP keypoints with O bytes 0..179 (the driver's record +0xc
 * never holds more, FUN_18000f350); a caller-built frame (saved frames, tests)
 * may hold anything, and the driver's code has no defined result for it. */
static gboolean
dll_frame_check (const ValidityMohFrame *f, guint index, GError **error)
{
  if (f == NULL)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID, "MOH: frame %u is missing", index);
      return FALSE;
    }
  if (f->n_kps > VALIDITY_MOH_FRAME_KP_CAP)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "MOH: frame %u has %u keypoints (at most %d)", index, f->n_kps, VALIDITY_MOH_FRAME_KP_CAP);
      return FALSE;
    }
  for (guint i = 0; i < f->n_kps; i++)
    if (f->kps[i].o > DLL_ORIENT_MAX)
      {
        g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                     "MOH: frame %u keypoint %u has orientation byte %u (0..%d)", index, i, f->kps[i].o,
                     DLL_ORIENT_MAX);
        return FALSE;
      }
  return TRUE;
}

static gboolean
validity_moh_build_ws_dll (const ValidityMohFrame * const *frames,
                           guint                           n_frames,
                           guint8                         *ws,
                           GError                        **error)
{
  DllPoseTable pt;
  guint8 *sec;
  gboolean ok = TRUE;

  g_return_val_if_fail (ws != NULL, FALSE);
  if (frames == NULL || n_frames == 0 || n_frames > DLL_P4)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "MOH: %u frames for a driver-format template (1..%d)", n_frames, DLL_P4);
      return FALSE;
    }
  for (guint k = 0; k < n_frames; k++)
    if (!dll_frame_check (frames[k], k, error))
      return FALSE;

  /* the host container is allocated zeroed (FUN_1800d8fc0) and so is the
   * pose table (FUN_180006380) */
  memset (ws, 0, VALIDITY_MOH_WS_SIZE);
  memset (&pt, 0, sizeof (pt));
  sec = g_malloc (VALIDITY_MOH_DLL_SECTION_MAX);

  /* FUN_180002240, accept path, once per frame */
  for (guint k = 0; k < n_frames && ok; k++)
    {
      const ValidityMohFrame *f = frames[k];
      DllState st;
      guint32 count;
      gsize sec_len;
      guint8 dims[8];

      dll_state_load (ws, &st);
      if (st.f144 == 0)
        {
          dll_ws_init (ws);
          st.f144 = 1;
        }
      count = dll_ws_get_u32 (ws, DLL_TAG_COUNT);
      /* FUN_1800013d0: a template with p3 sections takes no more (unreachable
       * with n_frames <= p4 = p3) */
      if (count >= DLL_P3_SECTIONS_DONE)
        {
          ok = FALSE;
          break;
        }

      sec_len = validity_moh_serialize_dll_section (f, sec);
      count++;
      dll_pose_load (ws, &pt);
      dll_pose_add (&pt, count, f->quality);
      /* FUN_180005bd0(param_6, param_5): the extent the extractor uses as the
       * row stride first (FUN_18000aab0), i.e. width then height */
      wr_u32 (dims, f->w);
      wr_u32 (dims + 4, f->h);
      dll_pose_finalise (&pt, count);
      ok = dll_pose_store (ws, &pt) &&
           dll_ws_put (ws, DLL_TAG_SECTION_BASE + count, sec, sec_len) &&   /* FUN_1800056c0 */
           dll_ws_put_u32 (ws, DLL_TAG_UPDATES, 0) &&                       /* FUN_180005ba0 */
           dll_ws_put_u32 (ws, DLL_TAG_COUNT, count) &&                     /* FUN_180005b70 */
           dll_ws_put (ws, DLL_TAG_DIMS, dims, sizeof (dims)) &&
           dll_ws_put_u32 (ws, DLL_TAG_CAPACITY, DLL_P4) &&                 /* FUN_180005ce0 */
           dll_state_store (ws, &st);                                        /* FUN_180006080 */
    }
  wipe_free (sec, VALIDITY_MOH_DLL_SECTION_MAX);
  explicit_bzero (&pt, sizeof (pt));
  if (!ok)
    {
      explicit_bzero (ws, VALIDITY_MOH_WS_SIZE);
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "MOH: driver-format template does not fit the %d-byte WS body",
                   VALIDITY_MOH_WS_SIZE);
    }
  return ok;
}

GBytes *
fpi_validity_moh_assemble_template (const ValidityMohFrame * const *frames,
                                    guint n_frames, guint16 subtype, GError **error)
{
  guint8 tid[VALIDITY_MOH_TID_LEN];
  guint8 *ws = g_malloc0 (VALIDITY_MOH_WS_SIZE);
  GBytes *env;

  if (!validity_moh_build_ws_dll (frames, n_frames, ws, error))
    {
      wipe_free (ws, VALIDITY_MOH_WS_SIZE);
      return NULL;
    }
  validity_moh_compute_tid (ws, VALIDITY_MOH_WS_SIZE, tid);
  env = validity_moh_build_envelope (subtype, ws, VALIDITY_MOH_WS_SIZE, tid);
  wipe_free (ws, VALIDITY_MOH_WS_SIZE);
  return env;
}

GBytes *
fpi_validity_moh_build_store_cmd (guint16 parent_dbid,
                                  guint16 storage_dbid,
                                  GBytes *envelope)
{
  gsize len;
  const guint8 *env;
  guint8 *buf;
  GBytes *cmd;

  g_return_val_if_fail (envelope != NULL, NULL);
  env = g_bytes_get_data (envelope, &len);
  g_return_val_if_fail (len <= G_MAXUINT16, NULL);

  cmd = bytes_new_wiped (9 + len + 1, &buf);
  buf[0] = 0x47;
  wr_u16 (buf + 1, parent_dbid);
  wr_u16 (buf + 3, VALIDITY_MOH_RECORD_TYPE_FINGER);
  wr_u16 (buf + 5, storage_dbid);
  wr_u16 (buf + 7, (guint16) len);
  memcpy (buf + 9, env, len);
  buf[9 + len] = 0x00;          /* uncounted trailer byte */
  return cmd;
}

static gint
cmp_rank (gconstpointer a, gconstpointer b)
{
  const PoolRank *ra = a, *rb = b;

  if (ra->pool != rb->pool)
    return ra->pool > rb->pool ? -1 : 1;
  return (ra->index > rb->index) - (ra->index < rb->index);
}

static gint
cmp_uint (gconstpointer a, gconstpointer b)
{
  guint ua = *(const guint *) a, ub = *(const guint *) b;

  return (ua > ub) - (ua < ub);
}

static guint
validity_moh_select_frames (const guint *n_pools,
                            guint        n_frames,
                            guint        n_sections,
                            guint       *selected)
{
  g_autofree PoolRank *rank = NULL;

  if (n_frames <= n_sections)
    {
      for (guint i = 0; i < n_frames; i++)
        selected[i] = i;
      return n_frames;
    }

  rank = g_new (PoolRank, n_frames);
  for (guint i = 0; i < n_frames; i++)
    {
      rank[i].pool = n_pools[i];
      rank[i].index = i;
    }
  qsort (rank, n_frames, sizeof (PoolRank), cmp_rank);
  for (guint i = 0; i < n_sections; i++)
    selected[i] = rank[i].index;
  qsort (selected, n_sections, sizeof (guint), cmp_uint);
  return n_sections;
}

static ValidityMohVerdict
validity_moh_frame_gate (guint n_pool,
                         guint min_frame_pool,
                         guint attempt,
                         guint max_attempts)
{
  if (n_pool >= min_frame_pool)
    return VALIDITY_MOH_FRAME_ACCEPT;
  /* a frame that cannot fill its slots is recaptured; on the last attempt it
   * is kept (the ranking deprioritises it) rather than failing */
  if (attempt + 1 >= max_attempts)
    return VALIDITY_MOH_FRAME_ACCEPT_WEAK;
  return VALIDITY_MOH_FRAME_RETRY;
}

static ValidityMohVerdict
validity_moh_capture_failed_verdict (guint attempt,
                                     guint max_attempts)
{
  return (attempt + 1 >= max_attempts) ? VALIDITY_MOH_FRAME_FAIL : VALIDITY_MOH_FRAME_RETRY;
}

struct _ValidityMohEnroll
{
  ValidityMohTables *tables;
  guint              num_frames;
  guint              max_attempts;
  guint              min_frame_pool;
  guint              done;
  guint              attempt;
  gboolean           failed;
  guint              images;
  ValidityMohFrame  *frames;
};

ValidityMohEnroll *
fpi_validity_moh_enroll_new (ValidityMohTables *tables,
                             guint              num_frames,
                             guint              max_attempts,
                             guint              min_frame_pool)
{
  ValidityMohEnroll *e;

  g_return_val_if_fail (tables != NULL, NULL);
  g_return_val_if_fail (num_frames >= 1, NULL);
  g_return_val_if_fail (max_attempts >= 1, NULL);

  e = g_new0 (ValidityMohEnroll, 1);
  e->tables = fpi_validity_moh_tables_ref (tables);
  e->num_frames = num_frames;
  e->max_attempts = max_attempts;
  e->min_frame_pool = min_frame_pool;
  e->frames = g_new0 (ValidityMohFrame, num_frames);
  return e;
}

void
fpi_validity_moh_enroll_free (ValidityMohEnroll *enroll)
{
  if (enroll == NULL)
    return;
  /* the keypoints are derived from the user's fingerprint: wipe them */
  explicit_bzero (enroll->frames, sizeof (ValidityMohFrame) * enroll->num_frames);
  g_free (enroll->frames);
  fpi_validity_moh_tables_unref (enroll->tables);
  g_free (enroll);
}

static gboolean
enroll_check_open (ValidityMohEnroll *e, GError **error)
{
  gboolean closed = e->failed || e->done >= e->num_frames;

  if (closed)
    g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                 "MOH enrollment session is %s", e->failed ? "failed" : "complete");
  return !closed;
}

/* Never leave a stale success decision when a step fails. */
static gboolean
enroll_step_error (ValidityMohEnrollStep *step)
{
  memset (step, 0, sizeof (*step));
  step->action = VALIDITY_MOH_STEP_FAIL;
  return FALSE;
}

static void
enroll_step_fill (ValidityMohEnroll *e, ValidityMohVerdict v, ValidityMohStepReason reason,
                  ValidityMohEnrollStep *step)
{
  switch (v)
    {
    case VALIDITY_MOH_FRAME_ACCEPT:
    case VALIDITY_MOH_FRAME_ACCEPT_WEAK:
      step->action = e->done >= e->num_frames ? VALIDITY_MOH_STEP_DONE : VALIDITY_MOH_STEP_ACCEPT;
      step->reason = v == VALIDITY_MOH_FRAME_ACCEPT_WEAK ? VALIDITY_MOH_REASON_WEAK_FRAME : VALIDITY_MOH_REASON_NONE;
      break;

    case VALIDITY_MOH_FRAME_RETRY:
      step->action = VALIDITY_MOH_STEP_RETRY;
      step->reason = reason;
      break;

    case VALIDITY_MOH_FRAME_FAIL:
    default:
      step->action = VALIDITY_MOH_STEP_FAIL;
      step->reason = reason;
      break;
    }
  if (step->reason != VALIDITY_MOH_REASON_NONE)
    step->reject_mask = 1u << step->reason;
  step->sections = e->done;
  step->progress = e->done * 100 / e->num_frames;
  step->touch = e->images;
}

static gboolean
enroll_image (ValidityMohEnroll  *e,
              const guint8       *pixels,
              gsize               pixels_len,
              guint               h,
              guint               w,
              ValidityMohVerdict *verdict,
              GError            **error)
{
  ValidityMohVerdict v;

  if (!fpi_validity_moh_extract_frame_fixed (e->tables, pixels, pixels_len, h, w,
                                             &e->frames[e->done], error))
    return FALSE;

  e->images++;
  v = validity_moh_frame_gate (e->frames[e->done].stats.n_pool, e->min_frame_pool,
                               e->attempt, e->max_attempts);
  fp_dbg ("MOH frame %u/%u attempt %u/%u: %u kps, pool %u -> %s",
          e->done + 1, e->num_frames, e->attempt + 1, e->max_attempts,
          e->frames[e->done].n_kps, e->frames[e->done].stats.n_pool,
          v == VALIDITY_MOH_FRAME_ACCEPT ? "accept" :
          v == VALIDITY_MOH_FRAME_RETRY ? "retry" : "accept (weak)");
  if (v == VALIDITY_MOH_FRAME_RETRY)
    {
      e->attempt++;
    }
  else
    {
      e->done++;
      e->attempt = 0;
    }
  *verdict = v;
  return TRUE;
}

static ValidityMohVerdict
enroll_capture_failed (ValidityMohEnroll *e)
{
  ValidityMohVerdict v;

  e->images++;
  v = validity_moh_capture_failed_verdict (e->attempt, e->max_attempts);
  if (v == VALIDITY_MOH_FRAME_FAIL)
    e->failed = TRUE;
  else
    e->attempt++;
  return v;
}

gboolean
fpi_validity_moh_enroll_step_image (ValidityMohEnroll     *e,
                                    const guint8          *pixels,
                                    gsize                  pixels_len,
                                    guint                  h,
                                    guint                  w,
                                    guint32                capture_flags,
                                    ValidityMohEnrollStep *step,
                                    GError               **error)
{
  ValidityMohVerdict v;

  g_return_val_if_fail (e != NULL && step != NULL, FALSE);
  if (!enroll_check_open (e, error))
    return enroll_step_error (step);
  memset (step, 0, sizeof (*step));
  if (capture_flags != 0)
    {
      /* the fork's capture() raises on a non-zero error word: a failed capture */
      v = enroll_capture_failed (e);
      enroll_step_fill (e, v, VALIDITY_MOH_REASON_FLAGGED_IMAGE, step);
      return TRUE;
    }
  if (!enroll_image (e, pixels, pixels_len, h, w, &v, error))
    return enroll_step_error (step);
  step->quality = e->frames[v == VALIDITY_MOH_FRAME_RETRY ? e->done : e->done - 1].quality;
  enroll_step_fill (e, v, VALIDITY_MOH_REASON_WEAK_FRAME, step);
  return TRUE;
}

void
fpi_validity_moh_enroll_step_capture_failed (ValidityMohEnroll     *e,
                                             ValidityMohEnrollStep *step)
{
  ValidityMohVerdict v;

  g_return_if_fail (e != NULL && step != NULL);
  memset (step, 0, sizeof (*step));
  if (!enroll_check_open (e, NULL))
    {
      step->action = VALIDITY_MOH_STEP_FAIL;
      return;
    }
  v = enroll_capture_failed (e);
  enroll_step_fill (e, v, VALIDITY_MOH_REASON_CAPTURE_FAILED, step);
}

gboolean
fpi_validity_moh_enroll_add_image (ValidityMohEnroll  *e,
                                   const guint8       *pixels,
                                   gsize               pixels_len,
                                   guint               h,
                                   guint               w,
                                   ValidityMohVerdict *verdict,
                                   GError            **error)
{
  g_return_val_if_fail (e != NULL && verdict != NULL, FALSE);
  if (!enroll_check_open (e, error))
    return FALSE;
  return enroll_image (e, pixels, pixels_len, h, w, verdict, error);
}

ValidityMohVerdict
fpi_validity_moh_enroll_capture_failed (ValidityMohEnroll *e)
{

  g_return_val_if_fail (e != NULL, VALIDITY_MOH_FRAME_FAIL);
  if (!enroll_check_open (e, NULL))
    return VALIDITY_MOH_FRAME_FAIL;
  return enroll_capture_failed (e);
}

guint
fpi_validity_moh_enroll_get_num_frames (const ValidityMohEnroll *e)
{
  return e->num_frames;
}

guint
fpi_validity_moh_enroll_get_frames_done (const ValidityMohEnroll *e)
{
  return e->done;
}

guint
fpi_validity_moh_enroll_get_attempt (const ValidityMohEnroll *e)
{
  return e->attempt;
}

gboolean
fpi_validity_moh_enroll_is_complete (const ValidityMohEnroll *e)
{
  return !e->failed && e->done >= e->num_frames;
}

const ValidityMohFrame *
fpi_validity_moh_enroll_get_frame (const ValidityMohEnroll *e,
                                   guint                    index)
{
  g_return_val_if_fail (index < fpi_validity_moh_enroll_get_frames_done (e), NULL);
  return &e->frames[index];
}

GBytes *
fpi_validity_moh_enroll_build_envelope (ValidityMohEnroll *e,
                                        guint16            subtype,
                                        guint             *selected,
                                        guint             *n_selected,
                                        GError           **error)
{
  g_autofree guint *pools = NULL;
  guint sel[VALIDITY_MOH_N_SECTIONS];
  const ValidityMohFrame *frames[VALIDITY_MOH_N_SECTIONS];
  guint n;

  g_return_val_if_fail (e != NULL, NULL);
  if (!fpi_validity_moh_enroll_is_complete (e))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "MOH enrollment incomplete (%u/%u frames)", fpi_validity_moh_enroll_get_frames_done (e),
                   fpi_validity_moh_enroll_get_num_frames (e));
      return NULL;
    }

  pools = g_new (guint, e->done);
  for (guint i = 0; i < e->done; i++)
    pools[i] = e->frames[i].stats.n_pool;
  n = validity_moh_select_frames (pools, e->done, VALIDITY_MOH_N_SECTIONS, sel);
  for (guint i = 0; i < n; i++)
    {
      frames[i] = &e->frames[sel[i]];
      if (selected)
        selected[i] = sel[i];
    }
  if (n_selected)
    *n_selected = n;
  return fpi_validity_moh_assemble_template (frames, n, subtype, error);
}

const gchar *
fpi_validity_moh_step_reason_to_string (ValidityMohStepReason reason)
{
  switch (reason)
    {
    case VALIDITY_MOH_REASON_NONE: return "none";

    case VALIDITY_MOH_REASON_WEAK_FRAME: return "weak frame";

    case VALIDITY_MOH_REASON_CAPTURE_FAILED: return "capture failed";

    case VALIDITY_MOH_REASON_FLAGGED_IMAGE: return "flagged image";
    }
  return "unknown";
}

static inline gint32
add32 (gint64 a, gint64 b)
{
  return s32 (s32 (a) + (gint64) s32 (b));
}

static void
validity_moh_dll_normalize (gint32 *a,
                            gint32 *b)
{
  gint32 a2 = sar32 (*a, 1), b2 = sar32 (*b, 1);
  guint32 r = validity_moh_dll_isqrt ((guint32) s32 ((gint64) imul32 (b2, b2) + imul32 (a2, a2))) >> 1;

  if (r == 0)
    {
      *a = a2;
      *b = b2;
      return;
    }
  *a = s32 (idiv32 (imul32 (*a, 1 << 14), (gint32) r));
  *b = s32 (idiv32 (imul32 (*b, 1 << 14), (gint32) r));
}

static guint32
validity_moh_dll_isqrt (guint32 n)
{
  guint32 bit = 0x40000000, res = 0;

  if (n <= 0x3fffffff)
    do
      bit >>= 2;
    while (n < bit);
  for (; bit != 0; bit >>= 2)
    {
      if (bit + res <= n)
        {
          n -= bit + res;
          res += bit * 2;
        }
      res >>= 1;
    }
  return res;
}
