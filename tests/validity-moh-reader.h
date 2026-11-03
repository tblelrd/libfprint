/*
 * The Windows driver's template reader, re-implemented from the decompiled
 * code of synaWudfBioUsb.dll 5.2.326.26 (not from the writer), for the unit
 * tests of the driver-format MOH variants (TRAILER, TRAILER_FIXED):
 * TLV lookup FUN_180006890/FUN_180006800, u32 tags FUN_180006930, section
 * parser FUN_180005930 (via FUN_180006320), frame-quality reader
 * FUN_180005fc0, pose-table reader FUN_1800053e0, and the matcher's class
 * partition FUN_180003880. roundtrip() checks a WS body against the frames
 * it was built from.
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

#pragma once

#include <glib.h>
#include <string.h>

#include "drivers/validity/validity_moh.h"

static inline guint32
rd32 (const guint8 *p)
{
  return (guint32) p[0] | ((guint32) p[1] << 8) | ((guint32) p[2] << 16) | ((guint32) p[3] << 24);
}

static inline guint16
rd16 (const guint8 *p)
{
  return (guint16) (p[0] | (p[1] << 8));
}

/* ================================================================
 * The driver's reader, re-implemented from the decompiled code
 * ================================================================ */

typedef struct
{
  guint8 desc[16];
  guint  orient;   /* feature record +0x0c */
  guint  x, y;     /* +0x14, +0x18 */
} DllRecord;

typedef struct
{
  guint8    hdr[8];  /* feature +0x20 */
  guint     n;       /* vector +0x08 */
  guint     split;   /* vector +0x0c (byte) */
  guint     quality; /* feature +0x0c */
  DllRecord rec[256];
} DllFeature;

typedef struct
{
  const guint8 *p;
  gsize         left;
} Cursor;

static inline guint8
rd_byte (Cursor *c)
{
  g_assert_cmpuint (c->left, >=, 1);
  c->left--;
  return *c->p++;
}

/* FUN_180006890 (no tags while "used" is 0) + FUN_180006800 (walk; a search
 * for tag 1 finds the end marker, any other search stops there) */
static inline gboolean
dll_find (const guint8 *ws, guint16 tag, const guint8 **data, guint16 *len)
{
  gsize o = 12;

  if (rd32 (ws + 4) == 0)
    return FALSE;
  for (;;)
    {
      guint16 t, l;

      g_assert_cmpuint (o + 4, <=, VALIDITY_MOH_WS_SIZE);
      t = rd16 (ws + o);
      l = rd16 (ws + o + 2);
      if (t == tag)
        {
          *data = ws + o + 4;
          *len = l;
          return TRUE;
        }
      if (t == 1)
        return FALSE;
      o += 4 + l;
    }
}

/* FUN_180006930 */
static inline guint32
dll_u32 (const guint8 *ws, guint16 tag)
{
  const guint8 *d = NULL;
  guint16 l = 0;

  return dll_find (ws, tag, &d, &l) ? rd32 (d) : 0;
}

/* FUN_180005930 */
static inline void
dll_parse_section (const guint8 *d, guint16 len, DllFeature *f)
{
  Cursor c = { d, len };
  guint8 cdf[22];
  guint u, prev;

  for (guint i = 0; i < 8; i++)
    f->hdr[i] = rd_byte (&c);
  f->n = rd_byte (&c);
  for (guint i = 0; i < f->n; i++)
    {
      for (guint k = 0; k < 16; k++)
        f->rec[i].desc[k] = rd_byte (&c);
      f->rec[i].x = rd_byte (&c);
      f->rec[i].y = rd_byte (&c);
    }
  f->split = rd_byte (&c);
  f->quality = rd_byte (&c);
  if (f->n == 0)
    return;            /* the table is not read for an empty section */

  /* class 1, records [0, split): bucket k for [cdf[k-1], cdf[k]); the rest 165 */
  u = 0;
  for (guint k = 0; k < 11; k++)
    {
      cdf[k] = rd_byte (&c);
      for (guint i = u; i < cdf[k]; i++)
        f->rec[i].orient = k * 15;
      u = cdf[k];
    }
  for (guint i = cdf[10]; i < f->split; i++)
    f->rec[i].orient = 0xa5;
  /* class 0, records [split, n) */
  prev = f->split;
  for (guint k = 11; k < 22; k++)
    {
      cdf[k] = rd_byte (&c);
      for (guint i = prev; i < cdf[k]; i++)
        f->rec[i].orient = (k - 11) * 15;
      prev = cdf[k];
    }
  for (guint i = cdf[21]; i < f->n; i++)
    f->rec[i].orient = 0xa5;
}

/* FUN_180006320: dimensions (tag 0x69, FUN_180005c60) then section tag i + 4 */
static inline gboolean
dll_parse_ws_section (const guint8 *ws, guint index, DllFeature *f, guint32 *dim0, guint32 *dim1)
{
  const guint8 *d = NULL;
  guint16 l = 0;

  if (dll_find (ws, 0x69, &d, &l))
    {
      *dim0 = rd32 (d);
      *dim1 = rd32 (d + 4);
    }
  if (!dll_find (ws, index + 4, &d, &l))
    return FALSE;
  memset (f, 0, sizeof (*f));
  dll_parse_section (d, l, f);
  return TRUE;
}

/* FUN_180005fc0: what the enrollment reads back as the frame quality */
static inline guint
dll_section_quality (const guint8 *d, guint16 len)
{
  Cursor c = { d, len };
  guint n;

  for (guint i = 0; i < 8; i++)
    rd_byte (&c);
  n = rd_byte (&c);
  for (guint i = 0; i < n * 18; i++)
    rd_byte (&c);
  rd_byte (&c);
  return rd_byte (&c);
}

typedef struct
{
  guint8 order[5];
  guint8 info[5][4];
  guint  n, n_comp;
  guint8 b0[5][5], b1[5][5];
  gint32 a[5][5], b[5][5], tx[5][5], ty[5][5];
} DllPoseTable;

/* FUN_1800053e0 (upper triangle as stored; the reader rebuilds the rest) */
static inline gboolean
dll_parse_pose (const guint8 *ws, DllPoseTable *pt)
{
  const guint8 *d = NULL;
  guint16 l = 0;
  Cursor c;

  memset (pt, 0, sizeof (*pt));
  if (!dll_find (ws, 2, &d, &l) || l == 0)
    return FALSE;
  c.p = d;
  c.left = l;
  for (guint i = 0; i < 5; i++)
    pt->order[i] = rd_byte (&c);
  for (guint i = 0; i < 5; i++)
    for (guint k = 0; k < 4; k++)
      pt->info[i][k] = rd_byte (&c);
  pt->n = rd_byte (&c);
  pt->n_comp = rd_byte (&c);
  g_assert_cmpuint (pt->n, <=, 5);
  for (guint i = 0; i < pt->n; i++)
    for (guint j = i + 1; j < pt->n; j++)
      {
        guint8 q[16];

        pt->b0[i][j] = rd_byte (&c);
        pt->b1[i][j] = rd_byte (&c);
        for (guint k = 0; k < 16; k++)
          q[k] = rd_byte (&c);
        pt->a[i][j] = (gint32) rd32 (q);
        pt->b[i][j] = (gint32) rd32 (q + 4);
        pt->tx[i][j] = (gint32) rd32 (q + 8);
        pt->ty[i][j] = (gint32) rd32 (q + 12);
      }
  /* what follows the written part is never read */
  return TRUE;
}

/* The round trip: the WS body built from @frames (in this order) must read
 * back as the driver's enrollment would have written it. */
static inline void
roundtrip (const guint8 *ws, const ValidityMohFrame * const *frames, guint n_frames)
{
  guint32 used = rd32 (ws + 4);
  const guint16 first_tags[] = { 2, 4, 0x68, 3, 0x69, 0x6b, 0x6c };
  const guint8 *d = NULL;
  guint16 l = 0;
  gsize o = 12;
  guint t = 0;
  DllPoseTable pt;

  /* container header and the TLV sequence FUN_180002240 produces */
  g_assert_cmphex (rd32 (ws), ==, 0);
  g_assert_cmphex (rd32 (ws + 8), ==, 0x00050206);
  g_assert_cmpuint (12 + used, <=, VALIDITY_MOH_WS_SIZE);
  for (;;)
    {
      guint16 tag = rd16 (ws + o), len = rd16 (ws + o + 2);
      guint16 want = t < G_N_ELEMENTS (first_tags) ? first_tags[t] :
                     (t < G_N_ELEMENTS (first_tags) + n_frames - 1 ? 5 + t - G_N_ELEMENTS (first_tags) : 1);

      g_assert_cmphex (tag, ==, want);
      g_assert_cmpuint (len % 4, ==, 0);
      t++;
      if (tag == 1)
        {
          g_assert_cmpuint (len, ==, 4);
          g_assert_cmpuint (o + 4, ==, 12 + used);   /* "used" ends with the end marker header */
          break;
        }
      o += 4 + len;
    }
  for (gsize i = 12 + used; i < VALIDITY_MOH_WS_SIZE; i++)
    if (ws[i] != 0)
      g_error ("WS byte %" G_GSIZE_FORMAT " past the used part is %02x", i, ws[i]);

  /* bookkeeping (FUN_180005ba0, FUN_180005b70, FUN_180005ce0, FUN_180006080) */
  g_assert_cmpuint (dll_u32 (ws, 3), ==, n_frames);
  g_assert_cmpuint (dll_u32 (ws, 0x68), ==, 0);
  g_assert_cmpuint (dll_u32 (ws, 0x6b), ==, VALIDITY_MOH_DLL_MAX_SECTIONS);
  g_assert_false (dll_find (ws, 0x6a, &d, &l));            /* no redundant frame */
  g_assert_true (dll_find (ws, 0x6c, &d, &l));
  g_assert_cmpuint (l, ==, 16);
  g_assert_cmpuint (rd32 (d), ==, 0);
  g_assert_cmpuint (rd32 (d + 4), ==, 0);
  g_assert_cmpuint (rd32 (d + 8), ==, 1);
  g_assert_cmpuint (rd32 (d + 12), ==, 0);

  /* pose table: no fit anywhere, every section its own component */
  g_assert_true (dll_parse_pose (ws, &pt));
  g_assert_true (dll_find (ws, 2, &d, &l));
  g_assert_cmpuint (l, ==, 264);
  g_assert_cmpuint (pt.n, ==, n_frames);
  g_assert_cmpuint (pt.n_comp, ==, n_frames == 1 ? 1 : n_frames - 1);
  for (guint i = 0; i < 5; i++)
    {
      g_assert_cmpuint (pt.order[i], ==, i < n_frames ? n_frames - 1 - i : 0);
      g_assert_cmpuint (pt.info[i][1], ==, 0);
      g_assert_cmpuint (pt.info[i][2], ==, 0);
      g_assert_cmpuint (pt.info[i][3], ==, i < n_frames ? frames[i]->quality : 0);
    }
  /* labels from the previous append's order (the driver's FUN_18000bbe0) */
  for (guint i = 0; i + 1 < n_frames; i++)
    g_assert_cmpuint (pt.info[i][0], ==, n_frames - 2 - i);
  if (n_frames > 0)
    g_assert_cmpuint (pt.info[n_frames - 1][0], ==, 0);
  for (guint i = 0; i < pt.n; i++)
    for (guint j = i + 1; j < pt.n; j++)
      {
        g_assert_cmpuint (pt.b0[i][j], ==, 0);
        g_assert_cmpuint (pt.b1[i][j], ==, 0xff);
        g_assert_cmpint (pt.a[i][j], ==, 0x10000);
        g_assert_cmpint (pt.b[i][j], ==, 0);
        g_assert_cmpint (pt.tx[i][j], ==, 0);
        g_assert_cmpint (pt.ty[i][j], ==, 0);
      }

  /* sections */
  for (guint s = 0; s < n_frames; s++)
    {
      const ValidityMohFrame *fr = frames[s];
      g_autofree DllFeature *f = g_new0 (DllFeature, 1);
      gboolean used_kp[VALIDITY_MOH_FRAME_KP_CAP] = { FALSE };
      guint32 dim0 = 0, dim1 = 0;
      guint class1 = 0, good = 0;

      g_assert_true (dll_parse_ws_section (ws, s, f, &dim0, &dim1));
      g_assert_cmpuint (dim0, ==, fr->w);
      g_assert_cmpuint (dim1, ==, fr->h);
      g_assert_true (dll_find (ws, s + 4, &d, &l));
      /* the true count, no padding records */
      g_assert_cmpuint (f->n, ==, fr->n_kps);
      g_assert_cmpuint (l, ==, (33 + 18 * fr->n_kps + 3) & ~3u);
      for (guint i = 0; i < 8; i++)
        g_assert_cmpuint (f->hdr[i], ==, 0);
      /* frame quality, FUN_180001900 over the source keypoints */
      for (guint j = 0; j < fr->n_kps; j++)
        {
          class1 += fr->kps[j].cls;
          good += fr->kps[j].coh > 15;
        }
      g_assert_cmpuint (f->quality, ==, good * 100 / 250);
      g_assert_cmpuint (f->quality, ==, fr->quality);
      g_assert_cmpuint (dll_section_quality (d, l), ==, fr->quality);
      g_assert_cmpuint (f->split, ==, class1);

      for (guint i = 0; i < f->n; i++)
        {
          const DllRecord *r = &f->rec[i];
          guint cls = i < f->split ? 1 : 0;   /* FUN_180003880 partition */
          gint hit = -1;

          for (guint j = 0; j < fr->n_kps && hit < 0; j++)
            {
              const ValidityMohKeypoint *k = &fr->kps[j];

              if (!used_kp[j] && (guint) (k->x & 0xff) == r->x && (guint) (k->y & 0xff) == r->y &&
                  memcmp (k->desc, r->desc, 16) == 0 && k->cls == cls &&
                  (guint) (k->o / 15) * 15 == r->orient)
                hit = j;
            }
          if (hit < 0)
            g_error ("section %u record %u (x %u y %u class %u orient %u) has no source keypoint",
                     s, i, r->x, r->y, cls, r->orient);
          used_kp[hit] = TRUE;
          /* within a class the buckets ascend */
          if (i > 0 && (i < f->split) == (i - 1 < f->split))
            g_assert_cmpuint (f->rec[i - 1].orient, <=, r->orient);
        }
    }
  /* nothing beyond the sections written */
  g_assert_false (dll_find (ws, n_frames + 4, &d, &l));
}

static inline void
roundtrip_envelope (GBytes *env, const ValidityMohFrame * const *frames, guint n)
{
  gsize len;
  const guint8 *p = g_bytes_get_data (env, &len);

  g_assert_cmpuint (len, ==, VALIDITY_MOH_ENVELOPE_SIZE);
  g_assert_cmpuint (rd16 (p + 8), ==, 1);
  g_assert_cmpuint (rd16 (p + 10), ==, VALIDITY_MOH_WS_SIZE);
  roundtrip (p + 12, frames, n);
}
