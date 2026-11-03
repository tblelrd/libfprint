/*
 * End-to-end fixed-point template and enrollment regression tests.
 * Expected digests come from an independent Python reference, not this C code.
 * Synthetic images/tables only; external driver-table cases store digests only.
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

#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include "fp-device.h"
#include "drivers/validity/validity_moh.h"
#include "validity-moh-reader.h"

static GKeyFile *golden;
static GKeyFile *images_kf;
static ValidityMohTables *tables_synthetic;
static ValidityMohTables *tables_real;

typedef struct
{
  const gchar *set;
  const gchar *mode;
  const gchar *name;
} Case;

static gchar *
data_path (const gchar *name)
{
  return g_test_build_filename (G_TEST_DIST, "validity-moh", name, NULL);
}

static gchar *
kstr (GKeyFile *kf, const gchar *group, const gchar *key)
{
  g_autoptr(GError) error = NULL;
  gchar *v = g_key_file_get_string (kf, group, key, &error);

  if (v == NULL)
    g_error ("[%s] %s: %s", group, key, error->message);
  return v;
}

static gchar *
gstr (const gchar *group, const gchar *key)
{
  return kstr (golden, group, key);
}

static gint64
gint_ (const gchar *group, const gchar *key)
{
  g_autofree gchar *v = gstr (group, key);

  return g_ascii_strtoll (v, NULL, 10);
}

static gboolean
has_key (const gchar *group, const gchar *key)
{
  return g_key_file_has_key (golden, group, key, NULL);
}

static gchar **
klist (GKeyFile *kf, const gchar *group, const gchar *key, gsize *n)
{
  g_autoptr(GError) error = NULL;
  gchar **v = g_key_file_get_string_list (kf, group, key, n, &error);

  if (v == NULL)
    {
      if (g_key_file_has_key (kf, group, key, NULL))
        {
          *n = 0;
          return g_new0 (gchar *, 1);
        }
      g_error ("[%s] %s: %s", group, key, error->message);
    }
  return v;
}

static gchar **
glist (const gchar *group, const gchar *key, gsize *n)
{
  return klist (golden, group, key, n);
}

static guint8 *
unhex (const gchar *s, gsize *len)
{
  gsize n = strlen (s) / 2;
  guint8 *out = g_malloc (MAX (n, 1));

  for (gsize i = 0; i < n; i++)
    out[i] = (g_ascii_xdigit_value (s[2 * i]) << 4) | g_ascii_xdigit_value (s[2 * i + 1]);
  *len = n;
  return out;
}

static gchar *
tohex (const guint8 *p, gsize n)
{
  GString *s = g_string_sized_new (2 * n + 1);

  for (gsize i = 0; i < n; i++)
    g_string_append_printf (s, "%02x", p[i]);
  return g_string_free (s, FALSE);
}

static gchar *
sha_bytes (const void *p, gsize n)
{
  return g_compute_checksum_for_data (G_CHECKSUM_SHA256, p, n);
}

static gchar *
sha_text (const GString *s)
{
  return g_compute_checksum_for_string (G_CHECKSUM_SHA256, s->str, s->len);
}

static gchar *
fhex (gdouble v)
{
  guint64 b;

  memcpy (&b, &v, sizeof (b));
  return g_strdup_printf ("%016" G_GINT64_MODIFIER "x", b);
}

static void
check_str (const gchar *got, const gchar *group, const gchar *key)
{
  g_autofree gchar *want = gstr (group, key);

  if (g_strcmp0 (got, want) != 0)
    g_error ("[%s] %s: %s != %s", group, key, got, want);
}

static guint8 *
image (const gchar *name, guint *h, guint *w)
{
  g_autofree gchar *group = g_strdup_printf ("image %s", name);
  GKeyFile *kf = golden;
  g_autofree gchar *hex = kstr (kf, group, "pixels");
  g_autofree gchar *hs = kstr (kf, group, "h");
  g_autofree gchar *ws = kstr (kf, group, "w");
  gsize n;
  guint8 *px = unhex (hex, &n);

  *h = atoi (hs);
  *w = atoi (ws);
  g_assert_cmpuint (n, ==, (gsize) * h * *w);
  return px;
}

static ValidityMohTables *
tables_for (const gchar *set)
{
  return g_str_equal (set, "real") ? tables_real : tables_synthetic;
}

static gboolean
skip_if_no_tables (const gchar *set)
{
  if (tables_for (set) == NULL)
    {
      g_test_skip ("driver-derived MOH tables not available (set FP_VALIDITY_MOH_TABLES_DIR)");
      return TRUE;
    }
  return FALSE;
}

static ValidityMohFrame *
extract_fixed (const gchar *set, const gchar *name)
{
  guint h, w;
  g_autofree guint8 *px = image (name, &h, &w);

  g_autoptr(GError) error = NULL;
  ValidityMohFrame *f = g_new0 (ValidityMohFrame, 1);

  g_assert_true (fpi_validity_moh_extract_frame_fixed (tables_for (set), px, (gsize) h * w, h, w, f, &error));
  g_assert_no_error (error);
  return f;
}

static gchar *
kps_digest (const ValidityMohFrame *f)
{
  g_autoptr(GString) s = g_string_new (NULL);

  for (guint i = 0; i < f->n_kps; i++)
    {
      g_autofree gchar *d = tohex (f->kps[i].desc, VALIDITY_MOH_DESC_LEN);

      g_string_append_printf (s, "%d,%d,%d,%s;", f->kps[i].x, f->kps[i].y, f->kps[i].theta, d);
    }
  return sha_text (s);
}

static gchar *
meta_digest (const ValidityMohFrame *f)
{
  g_autoptr(GString) s = g_string_new (NULL);

  for (guint i = 0; i < f->n_kps; i++)
    g_string_append_printf (s, "%u,%u,%u,%" G_GINT64_FORMAT ";", f->kps[i].cls, f->kps[i].coh, f->kps[i].o,
                            (gint64) f->kps[i].score);
  return sha_text (s);
}

static gchar *
stats_digest (const ValidityMohFrameStats *st)
{
  g_autofree gchar *cap = fhex (st->cap_score);
  g_autofree gchar *med = fhex (st->med_score);

  g_autoptr(GString) s = g_string_new (NULL);

  g_string_append_printf (s, "%u,%s,%s", st->n_pool, cap, med);
  return sha_text (s);
}

static void
check_env_golden (GBytes *env, const gchar *group)
{
  gsize len;
  const guint8 *p = g_bytes_get_data (env, &len);
  g_autofree gchar *sha = sha_bytes (p, len);
  g_autofree gchar *tid = tohex (p + 12 + VALIDITY_MOH_WS_SIZE + 4, VALIDITY_MOH_TID_LEN);

  check_str (sha, group, "envelope_sha");
  check_str (tid, group, "tid");
}

static void
check_frame_fields (const ValidityMohFrame *f)
{
  g_assert_cmpuint (f->n_kps, <=, VALIDITY_MOH_FRAME_KP_CAP);
  g_assert_cmpuint (f->n_kps, ==, MIN (f->stats.n_pool, VALIDITY_MOH_FRAME_KP_CAP));
  for (guint i = 0; i < f->n_kps; i++)
    {
      const ValidityMohKeypoint *k = &f->kps[i];

      g_assert_cmpint (k->theta, >=, 0);
      g_assert_cmpint (k->theta, <=, 0x6487e);
      g_assert_cmpfloat (k->orient, ==, k->theta / 65536.0);
      g_assert_cmpuint (k->o, <, 180);
      g_assert_cmpuint (k->cls, <=, 1);
      g_assert_cmpfloat (k->score, >, 671.0);
      g_assert_cmpfloat (k->score, ==, (gdouble) (gint64) k->score);
      g_assert_cmpint (k->x, >=, 3);
      g_assert_cmpint (k->y, >=, 3);
      g_assert_cmpint (k->x, <, (gint) f->w - 3);
      g_assert_cmpint (k->y, <, (gint) f->h - 3);
    }
}

static void
test_frame (gconstpointer data)
{
  const Case *c = data;
  g_autofree gchar *group = g_strdup_printf ("fixed %s/%s/%s", c->set, c->mode, c->name);
  g_autofree ValidityMohFrame *f = NULL;
  g_autofree gchar *kd = NULL, *md = NULL, *sd = NULL;
  const ValidityMohFrame *frames[1];

  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) env = NULL;

  if (skip_if_no_tables (c->set))
    return;
  f = extract_fixed (c->set, c->name);
  frames[0] = f;
  check_frame_fields (f);
  g_assert_cmpint (f->n_kps, ==, gint_ (group, "n_kps"));
  kd = kps_digest (f);
  md = meta_digest (f);
  sd = stats_digest (&f->stats);
  check_str (kd, group, "kps_sha256");
  check_str (md, group, "meta_sha256");
  check_str (sd, group, "stats_sha256");

  if (has_key (group, "n_pool"))
    {
      g_autofree gchar *cap = fhex (f->stats.cap_score);
      g_autofree gchar *med = fhex (f->stats.med_score);

      g_assert_cmpint (f->stats.n_pool, ==, gint_ (group, "n_pool"));
      check_str (cap, group, "cap_score");
      check_str (med, group, "med_score");
      g_assert_cmpint (f->quality, ==, gint_ (group, "quality"));
    }
  env = fpi_validity_moh_assemble_template (frames, 1, VALIDITY_MOH_DEFAULT_SUBTYPE, &error);
  g_assert_no_error (error);
  roundtrip_envelope (env, frames, 1);
  check_env_golden (env, group);
}

static void
test_multi (gconstpointer data)
{
  const Case *c = data;
  g_autofree gchar *group = g_strdup_printf ("fixed-multi %s/%s", c->set, c->name);
  gsize n;

  g_auto(GStrv) names = NULL;
  ValidityMohFrame *fr[VALIDITY_MOH_DLL_MAX_SECTIONS] = { 0 };
  const ValidityMohFrame *frames[VALIDITY_MOH_DLL_MAX_SECTIONS];
  g_autoptr(GBytes) env = NULL;
  g_autoptr(GError) error = NULL;

  if (skip_if_no_tables (c->set))
    return;
  names = glist (group, "images", &n);
  g_assert_cmpuint (n, <=, VALIDITY_MOH_DLL_MAX_SECTIONS);
  for (gsize i = 0; i < n; i++)
    frames[i] = fr[i] = extract_fixed (c->set, names[i]);

  env = fpi_validity_moh_assemble_template (frames, n, VALIDITY_MOH_DEFAULT_SUBTYPE, &error);
  g_assert_no_error (error);
  roundtrip_envelope (env, frames, n);
  if (has_key (group, "ws_sha"))
    {
      const guint8 *ep = g_bytes_get_data (env, NULL);
      g_autofree gchar *ws_sha = sha_bytes (ep + 12, VALIDITY_MOH_WS_SIZE);

      g_assert_cmpint (rd32 (ep + 12 + 4), ==, gint_ (group, "ws_used"));
      check_str (ws_sha, group, "ws_sha");
    }
  check_env_golden (env, group);
  for (gsize i = 0; i < n; i++)
    g_free (fr[i]);
}

static void
test_scenario (gconstpointer data)
{
  const Case *c = data;
  g_autofree gchar *sgroup = g_strdup_printf ("scenario %s/%s", c->set, c->name);
  g_autofree gchar *group = g_strdup_printf ("fixed-scenario %s/%s", c->set, c->name);
  g_autofree gchar *result = NULL;

  g_auto(GStrv) script = NULL;
  g_autoptr(ValidityMohEnroll) e = NULL;
  gsize n_script;
  gint64 mp;
  guint idx = 0;
  gboolean raised = FALSE;

  if (skip_if_no_tables (c->set))
    return;
  script = g_key_file_get_string_list (images_kf, sgroup, "script", &n_script, NULL);
  g_assert_nonnull (script);
  {
    g_autofree gchar *nf = kstr (images_kf, sgroup, "num_frames");
    g_autofree gchar *ma = kstr (images_kf, sgroup, "max_attempts");
    g_autofree gchar *mps = kstr (images_kf, sgroup, "min_frame_pool");

    mp = g_ascii_strtoll (mps, NULL, 10);
    e = fpi_validity_moh_enroll_new (tables_for (c->set), atoi (nf), atoi (ma),
                                     mp < 0 ? VALIDITY_MOH_DEFAULT_MIN_FRAME_POOL : (guint) mp);
  }
  while (!fpi_validity_moh_enroll_is_complete (e))
    {
      /* the fixed-point pools gate differently from the float ones a script
       * was written for: past its end the fake sensor raises, which the
       * fork's session (the reference) counts as a failed capture */
      g_assert_cmpuint (idx, <=, n_script + VALIDITY_MOH_DEFAULT_MAX_ATTEMPTS);
      if (idx >= n_script || g_str_equal (script[idx], "error"))
        {
          idx++;
          if (fpi_validity_moh_enroll_capture_failed (e) == VALIDITY_MOH_FRAME_FAIL)
            {
              raised = TRUE;
              break;
            }
        }
      else
        {
          guint h, w;
          g_autofree guint8 *px = image (script[idx++], &h, &w);
          g_autoptr(GError) error = NULL;
          ValidityMohVerdict v;

          g_assert_true (fpi_validity_moh_enroll_add_image (e, px, (gsize) h * w, h, w, &v, &error));
          g_assert_no_error (error);
        }
    }
  result = gstr (group, "result");
  g_assert_cmpstr (raised ? "raise" : "ok", ==, result);
  if (raised)
    return;

  {
    gsize n_sel;
    g_auto(GStrv) want_sel = glist (group, "selected", &n_sel);
    guint sel[VALIDITY_MOH_N_SECTIONS], nsel = 0;
    const ValidityMohFrame *frames[VALIDITY_MOH_N_SECTIONS];
    g_autoptr(GError) error = NULL;
    g_autoptr(GBytes) env = fpi_validity_moh_enroll_build_envelope (e, VALIDITY_MOH_DEFAULT_SUBTYPE, sel, &nsel,
                                                                    &error);

    g_assert_no_error (error);
    if (has_key (group, "frame_pools"))
      {
        gsize np;
        g_auto(GStrv) pools = glist (group, "frame_pools", &np);

        g_assert_cmpuint (np, ==, fpi_validity_moh_enroll_get_frames_done (e));
        for (guint i = 0; i < np; i++)
          g_assert_cmpuint (fpi_validity_moh_enroll_get_frame (e, i)->stats.n_pool, ==,
                            g_ascii_strtoull (pools[i], NULL, 10));
      }
    g_assert_cmpuint (nsel, ==, n_sel);
    for (guint i = 0; i < nsel; i++)
      {
        g_assert_cmpuint (sel[i], ==, g_ascii_strtoull (want_sel[i], NULL, 10));
        frames[i] = fpi_validity_moh_enroll_get_frame (e, sel[i]);
      }
    roundtrip_envelope (env, frames, nsel);
    check_env_golden (env, group);
  }
}

static void
add_case (GPtrArray *cases, const gchar *path, const gchar *set, const gchar *mode, const gchar *name,
          GTestDataFunc fn)
{
  Case *c = g_new0 (Case, 1);

  c->set = set;
  c->mode = mode;
  c->name = g_strdup (name);
  g_ptr_array_add (cases, c);
  g_test_add_data_func (path, c, fn);
}
static void
test_invalid_inputs (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree ValidityMohFrame *frame = g_new0 (ValidityMohFrame, 1);
  guint8 pixels[112 * 112] = { 0 };
  const ValidityMohFrame *frames[] = { frame };
  g_autoptr(GBytes) envelope = NULL;
  g_autoptr(ValidityMohEnroll) enroll = fpi_validity_moh_enroll_new (tables_synthetic, 1, 2, 0);
  ValidityMohEnrollStep step;

  g_assert_false (fpi_validity_moh_extract_frame_fixed (tables_synthetic, pixels,
                                                        sizeof (pixels) - 1, 112, 112, frame, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_clear_error (&error);
  g_assert_false (fpi_validity_moh_extract_frame_fixed (tables_synthetic, NULL, 0, 112, 112, frame, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_clear_error (&error);
  g_assert_false (fpi_validity_moh_extract_frame_fixed (tables_synthetic, pixels, sizeof (pixels),
                                                        257, 112, frame, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_clear_error (&error);
  frame->n_kps = VALIDITY_MOH_FRAME_KP_CAP + 1;
  envelope = fpi_validity_moh_assemble_template (frames, 1, 7, &error);
  g_assert_null (envelope);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_clear_error (&error);
  frame->n_kps = 1;
  frame->kps[0].o = 180;
  envelope = fpi_validity_moh_assemble_template (frames, 1, 7, &error);
  g_assert_null (envelope);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_clear_error (&error);
  envelope = fpi_validity_moh_enroll_build_envelope (enroll, 7, NULL, NULL, &error);
  g_assert_null (envelope);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL);
  g_clear_error (&error);
  g_assert_true (fpi_validity_moh_enroll_step_image (enroll, pixels, sizeof (pixels), 112, 112, 1, &step, &error));
  g_assert_cmpint (step.action, ==, VALIDITY_MOH_STEP_RETRY);
  g_assert_cmpuint (step.sections, ==, 0);
  fpi_validity_moh_enroll_step_capture_failed (enroll, &step);
  g_assert_cmpint (step.action, ==, VALIDITY_MOH_STEP_FAIL);
  g_assert_false (fpi_validity_moh_enroll_step_image (enroll, pixels, sizeof (pixels), 112, 112, 0, &step, &error));
  g_assert_cmpint (step.action, ==, VALIDITY_MOH_STEP_FAIL);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL);
}

static void
test_table_integrity (void)
{
  const gchar *files[] = { VALIDITY_MOH_FILE_GAUSS, VALIDITY_MOH_FILE_BRIEF,
                           VALIDITY_MOH_FILE_AGGR, VALIDITY_MOH_FILE_SCAFFOLD, VALIDITY_MOH_FILE_EXP };

  g_autoptr(GError) error = NULL;
  g_autofree gchar *source = data_path ("tables-synthetic");
  g_autofree gchar *tmp = g_dir_make_tmp ("libfprint-moh-XXXXXX", &error);
  g_autoptr(ValidityMohTables) tables = NULL;
  g_assert_no_error (error);

  /* A correct HMAC cannot turn the synthetic tables into production tables. */
  tables = fpi_validity_moh_tables_load_dir (source, VALIDITY_MOH_TABLES_PINNED, &error);
  g_assert_null (tables);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_clear_error (&error);
  for (guint i = 0; i < G_N_ELEMENTS (files); i++)
    {
      g_autofree gchar *src = g_build_filename (source, files[i], NULL);
      g_autofree gchar *dst = g_build_filename (tmp, files[i], NULL);
      g_autofree gchar *bytes = NULL;
      gsize len;
      g_assert_true (g_file_get_contents (src, &bytes, &len, &error));
      g_assert_true (g_file_set_contents (dst, bytes, len, &error));
    }
  for (guint i = 0; i < G_N_ELEMENTS (files); i++)
    {
      g_autofree gchar *path = g_build_filename (tmp, files[i], NULL);
      g_autofree gchar *bytes = NULL;
      gsize len;
      g_assert_true (g_file_get_contents (path, &bytes, &len, &error));
      bytes[0] ^= 1;
      g_assert_true (g_file_set_contents (path, bytes, len, &error));
      tables = fpi_validity_moh_tables_load_dir (tmp, VALIDITY_MOH_TABLES_ALLOW_UNPINNED, &error);
      g_assert_null (tables);
      g_assert_nonnull (error);
      g_clear_error (&error);
      bytes[0] ^= 1;
      g_assert_true (g_file_set_contents (path, bytes, len, &error));
    }
  {
    g_autofree gchar *path = g_build_filename (tmp, VALIDITY_MOH_FILE_EXP, NULL);
    g_assert_cmpint (g_unlink (path), ==, 0);
    tables = fpi_validity_moh_tables_load_dir (tmp, VALIDITY_MOH_TABLES_ALLOW_UNPINNED, &error);
    g_assert_no_error (error);
    g_assert_nonnull (tables);
    g_assert_false (fpi_validity_moh_tables_supports (tables, &error));
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND);
    g_clear_error (&error);
  }
  for (guint i = 0; i < G_N_ELEMENTS (files); i++)
    {
      g_autofree gchar *path = g_build_filename (tmp, files[i], NULL);
      g_unlink (path);
    }
  g_assert_cmpint (g_rmdir (tmp), ==, 0);
}

static void
test_table_ranges (void)
{
  const gchar *files[] = { VALIDITY_MOH_FILE_GAUSS, VALIDITY_MOH_FILE_BRIEF,
                           VALIDITY_MOH_FILE_AGGR, VALIDITY_MOH_FILE_SCAFFOLD, VALIDITY_MOH_FILE_EXP };
  gchar *bytes[G_N_ELEMENTS (files)] = { 0 };
  gsize lengths[G_N_ELEMENTS (files)];
  g_autofree gchar *dir = data_path ("tables-synthetic");

  g_autoptr(GError) error = NULL;
  g_autoptr(ValidityMohTables) tables = NULL;

  for (guint i = 0; i < G_N_ELEMENTS (files); i++)
    {
      g_autofree gchar *path = g_build_filename (dir, files[i], NULL);
      g_assert_true (g_file_get_contents (path, &bytes[i], &lengths[i], &error));
      g_assert_cmpuint (lengths[i], >, 32);
      lengths[i] -= 32; /* The loader has already checked these HMAC trailers. */
    }
  for (guint i = 0; i < 5; i++)
    {
      gsize n[5];
      guint8 saved = (guint8) bytes[1][0];
      guint8 saved_aggr = (guint8) bytes[2][0];
      guint8 saved_exp = (guint8) bytes[4][3];

      memcpy (n, lengths, sizeof (n));
      switch (i)
        {
        case 0: n[0]--;
          break;                                /* Truncated Gaussian table. */

        case 1: bytes[1][0] = 0x7f;
          break;                               /* BRIEF index outside the sample vector. */

        case 2: bytes[2][0] = 0x7f;
          break;                               /* Invalid aggregation window size. */

        case 3: n[4]--;
          break;                                /* Truncated exponential table. */

        case 4: bytes[4][3] = 0x7f;
          break;                               /* Exponential center outside its range. */
        }
      tables = fpi_validity_moh_tables_new_full ((guint8 *) bytes[0], n[0], (guint8 *) bytes[1], n[1],
                                                 (guint8 *) bytes[2], n[2], (guint8 *) bytes[3], n[3], (guint8 *) bytes[4], n[4],
                                                 VALIDITY_MOH_TABLES_ALLOW_UNPINNED, &error);
      g_assert_null (tables);
      g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
      g_clear_error (&error);
      bytes[1][0] = saved;
      bytes[2][0] = saved_aggr;
      bytes[4][3] = saved_exp;
    }
  for (guint i = 0; i < G_N_ELEMENTS (files); i++)
    g_free (bytes[i]);
}

static void
case_free (gpointer data)
{
  Case *c = data;

  g_free ((gchar *) c->name);
  g_free (c);
}

int
main (int argc, char **argv)
{
  g_autoptr(GError) error = NULL;
  g_autofree gchar *path = NULL;
  g_autofree gchar *dir = NULL;
  g_autoptr(GPtrArray) cases = g_ptr_array_new_with_free_func (case_free);
  const gchar *sets[] = { "synthetic", "real" };
  const gchar *kinds[] = { "images", "multi", "scenarios" };
  GTestDataFunc tests[] = { test_frame, test_multi, test_scenario };
  const gchar *real = g_getenv ("FP_VALIDITY_MOH_TABLES_DIR");
  int result;

  g_test_init (&argc, &argv, NULL);
  golden = g_key_file_new ();
  path = data_path ("fixed.keyfile");
  g_assert_true (g_key_file_load_from_file (golden, path, G_KEY_FILE_NONE, &error));
  images_kf = golden;
  dir = data_path ("tables-synthetic");
  tables_synthetic = fpi_validity_moh_tables_load_dir (dir, VALIDITY_MOH_TABLES_ALLOW_UNPINNED, &error);
  g_assert_no_error (error);
  g_assert_nonnull (tables_synthetic);
  g_assert_true (fpi_validity_moh_tables_supports (tables_synthetic, &error));
  if (real && *real)
    {
      tables_real = fpi_validity_moh_tables_load_dir (real, VALIDITY_MOH_TABLES_PINNED, &error);
      g_assert_no_error (error);
      g_assert_true (fpi_validity_moh_tables_supports (tables_real, &error));
    }
  g_test_add_func ("/validity-moh/invalid-inputs", test_invalid_inputs);
  g_test_add_func ("/validity-moh/table-integrity", test_table_integrity);
  g_test_add_func ("/validity-moh/table-ranges", test_table_ranges);
  for (guint s = 0; s < G_N_ELEMENTS (sets); s++)
    for (guint k = 0; k < G_N_ELEMENTS (kinds); k++)
      {
        gsize n;
        g_auto(GStrv) names = glist ("meta", kinds[k], &n);
        for (gsize i = 0; i < n; i++)
          {
            g_autofree gchar *test = g_strdup_printf ("/validity-moh/%s/%s/%s", sets[s], kinds[k], names[i]);
            add_case (cases, test, sets[s], "dll", names[i], tests[k]);
          }
      }
  result = g_test_run ();
  g_key_file_unref (golden);
  fpi_validity_moh_tables_unref (tables_synthetic);
  g_clear_pointer (&tables_real, fpi_validity_moh_tables_unref);
  return result;
}
