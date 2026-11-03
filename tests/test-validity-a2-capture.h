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

/* Included only by test-validity.c; keep its capture helpers below the
 * formatter debug build's 10,000-line input guard. */
#pragma once

/* ================================================================
 * 06cb:00a2 capture, readout and match flow (fpi_validity_a2_capture.c)
 *
 * All replies below are synthetic. Their framing follows the vendor
 * driver and python-validity PR #261: a 51 reply is status | len u32 |
 * data, the first chunk starts with the 12-byte header 70 00 70 00 4d 01
 * 08 00 <flags u32>, and a 112x112 image arrives as 8192 + 4364 bytes.
 * The pixel values are a counting pattern, not a fingerprint.
 * ================================================================ */

#define A2_FRAME_LEN \
  (VALIDITY_A2_IMAGE_HEADER_LEN + \
   VALIDITY_A2_IMAGE_ROWS * VALIDITY_A2_IMAGE_COLS)

static guint8
a2_pixel (gsize i)
{
  return (guint8) ((i * 7 + 3) & 0xff);
}

/* Header + pixels as the sensor streams them */
static guint8 *
a2_make_frame (guint16 rows,
               guint16 cols,
               guint8  bpp,
               guint32 flags,
               gsize  *out_len)
{
  gsize n = VALIDITY_A2_IMAGE_HEADER_LEN + (gsize) rows * cols;
  guint8 *f = g_malloc0 (n);

  f[0] = rows & 0xff;
  f[1] = rows >> 8;
  f[2] = cols & 0xff;
  f[3] = cols >> 8;
  f[4] = 0x4d;    /* 333 */
  f[5] = 0x01;
  f[6] = bpp;
  f[7] = 0;
  f[8] = flags & 0xff;
  f[9] = (flags >> 8) & 0xff;
  f[10] = (flags >> 16) & 0xff;
  f[11] = (flags >> 24) & 0xff;
  for (gsize i = 0; i < (gsize) rows * cols; i++)
    f[VALIDITY_A2_IMAGE_HEADER_LEN + i] = a2_pixel (i);

  *out_len = n;
  return f;
}

/* Payload (after the status word) of a 51 reply carrying @len bytes */
static GByteArray *
a2_read_payload (const guint8 *data,
                 gsize         len)
{
  GByteArray *p = g_byte_array_new ();
  guint8 hdr[4] = { len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff,
                    (len >> 24) & 0xff };

  g_byte_array_append (p, hdr, sizeof (hdr));
  if (len > 0)
    g_byte_array_append (p, data, len);
  return p;
}

static ValidityA2ReadoutStep
a2_feed_chunk (ValidityA2Readout *r,
               const guint8      *data,
               gsize              len,
               GError           **error)
{
  g_autoptr(GByteArray) p = a2_read_payload (data, len);

  return fpi_validity_a2_readout_feed (r, 0, p->data, p->len, error);
}

/* --- EP 0x83 report classifiers --- */

static void
test_a2_capture_events (void)
{
  static const struct
  {
    guint8                 b[5];
    gsize                  len;
    ValidityA2CaptureEvent ev;
    guint16                code;
  } cases[] = {
    /* observed on 00a2 by others (bulat-chu, PR #261 thread) */
    { { 0x00, 0x00, 0x00, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_START, 0 },
    { { 0x02, 0x00, 0x40, 0x10, 0x00 }, 5, VALIDITY_A2_CAPT_EV_FINGER_DOWN, 0 },
    { { 0x03, 0x40, 0x01, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_WAIT, 1 },
    { { 0x03, 0x42, 0x04, 0x00, 0x40 }, 5, VALIDITY_A2_CAPT_EV_READY, 4 },
    /* the vendor driver's other codes */
    { { 0x03, 0x00, 0x07, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_READY, 7 },
    { { 0x03, 0x00, 0x02, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_WAIT, 2 },
    { { 0x03, 0x00, 0x03, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_WAIT, 3 },
    { { 0x03, 0x00, 0x05, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_WAIT, 5 },
    { { 0x03, 0x00, 0x09, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_WAIT, 9 },
    { { 0x03, 0x00, 0x06, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_ABORT, 6 },
    { { 0x03, 0x00, 0x08, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_BAD, 8 },
    { { 0x03, 0x00, 0x00, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_BAD, 0 },
    { { 0x03, 0x00, 0x0a, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_BAD, 10 },
    /* byte 3 counts: 0x0104 is not "ready" (the old b[2] & 4 test said so) */
    { { 0x03, 0x00, 0x04, 0x01, 0x00 }, 5, VALIDITY_A2_CAPT_EV_BAD, 0x0104 },
    /* bit 2 alone is not "ready": code 5 and 6 */
    { { 0x03, 0x00, 0x05, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_WAIT, 5 },
    { { 0x01, 0x00, 0x00, 0x00, 0x00 }, 5, VALIDITY_A2_CAPT_EV_OTHER, 0 },
    { { 0x03, 0x00, 0x04, 0x00, 0x00 }, 3, VALIDITY_A2_CAPT_EV_MALFORMED, 0 },
    { { 0x00 }, 0, VALIDITY_A2_CAPT_EV_MALFORMED, 0 },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      guint16 code = 0xffff;

      g_assert_cmpint (fpi_validity_a2_classify_capture_event (cases[i].b,
                                                               cases[i].len,
                                                               &code),
                       ==, cases[i].ev);
      g_assert_cmpuint (code, ==, cases[i].code);
    }

  g_assert_cmpint (fpi_validity_a2_classify_capture_event (NULL, 5, NULL), ==,
                   VALIDITY_A2_CAPT_EV_MALFORMED);
}

static void
test_a2_match_events (void)
{
  static const struct
  {
    guint8               b[5];
    gsize                len;
    ValidityA2MatchEvent ev;
    guint16              code;
    guint16              detail;
  } cases[] = {
    { { 0x00, 0x00, 0x00, 0x00, 0x00 }, 5, VALIDITY_A2_MATCH_EV_PENDING, 0, 0 },
    { { 0x01, 0x00, 0x00, 0x00, 0x00 }, 5, VALIDITY_A2_MATCH_EV_PENDING, 1, 0 },
    { { 0x02, 0x00, 0x40, 0x10, 0x00 }, 5, VALIDITY_A2_MATCH_EV_PENDING, 2, 0 },
    { { 0x03, 0x00, 0x00, 0x00, 0xdb }, 5, VALIDITY_A2_MATCH_EV_MATCH, 3, 0 },
    /* observed: no match, 2 templates compared; and 0 templates */
    { { 0x04, 0x00, 0x02, 0x00, 0xdb }, 5, VALIDITY_A2_MATCH_EV_NO_MATCH, 4, 2 },
    { { 0x04, 0x00, 0x00, 0x00, 0xdb }, 5, VALIDITY_A2_MATCH_EV_NO_MATCH, 4, 0 },
    /* observed: error 0x050b (5e without a capture) */
    { { 0x05, 0x00, 0x0b, 0x05, 0xdb }, 5, VALIDITY_A2_MATCH_EV_ERROR, 5, 0x050b },
    { { 0x06, 0x00, 0x00, 0x00, 0xdb }, 5, VALIDITY_A2_MATCH_EV_OTHER_DONE, 6, 0 },
    /* capture reports still queued during the match wait (both samples
     * seen on 00a2): not a match code, keep waiting */
    { { 0x03, 0x42, 0x04, 0x00, 0x40 }, 5, VALIDITY_A2_MATCH_EV_STALE,
      0x4203, 0 },
    { { 0x03, 0x40, 0x01, 0x00, 0x00 }, 5, VALIDITY_A2_MATCH_EV_STALE,
      0x4003, 0 },
    { { 0x03, 0x01 }, 2, VALIDITY_A2_MATCH_EV_STALE, 0x0103, 0 },
    /* other high codes are still "read the result" */
    { { 0x06, 0x01, 0x00, 0x00, 0xdb }, 5, VALIDITY_A2_MATCH_EV_OTHER_DONE,
      0x0106, 0 },
    { { 0x03 }, 1, VALIDITY_A2_MATCH_EV_MALFORMED, 0, 0 },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      guint16 code = 0xffff, detail = 0xffff;

      g_assert_cmpint (fpi_validity_a2_classify_match_event (cases[i].b,
                                                             cases[i].len,
                                                             &code, &detail),
                       ==, cases[i].ev);
      g_assert_cmpuint (code, ==, cases[i].code);
      g_assert_cmpuint (detail, ==, cases[i].detail);
    }
}

/* --- header and flags --- */

static void
test_a2_image_header (void)
{
  static const guint8 hdr[] = { 0x70, 0x00, 0x70, 0x00, 0x4d, 0x01, 0x08, 0x00,
                                0x00, 0x00, 0x08, 0x08 };
  ValidityA2ImageHeader h;

  g_assert_true (fpi_validity_a2_parse_image_header (hdr, sizeof (hdr), &h));
  g_assert_cmpuint (h.rows, ==, 112);
  g_assert_cmpuint (h.cols, ==, 112);
  g_assert_cmpuint (h.resolution, ==, 333);
  g_assert_cmpuint (h.bpp, ==, 8);
  g_assert_cmphex (h.flags, ==, 0x08080000);

  g_assert_false (fpi_validity_a2_parse_image_header (hdr, 11, &h));
  g_assert_cmpuint (h.rows, ==, 0);
}

static void
test_a2_image_flags (void)
{
  static const struct
  {
    guint32                flags;
    ValidityA2FlagsVerdict windows;
    ValidityA2FlagsVerdict strict;
  } cases[] = {
    { 0x00000000, VALIDITY_A2_FLAGS_USE, VALIDITY_A2_FLAGS_USE },
    /* seen on 00a2 by PR #261 ("Scanning problem"): no bit 31 */
    { 0x00080000, VALIDITY_A2_FLAGS_USE, VALIDITY_A2_FLAGS_REJECT },
    { 0x08080000, VALIDITY_A2_FLAGS_USE, VALIDITY_A2_FLAGS_REJECT },
    { 0x08000000, VALIDITY_A2_FLAGS_USE, VALIDITY_A2_FLAGS_REJECT },
    /* bit 31 + bit 21: recapture under both rules */
    { 0x80200000, VALIDITY_A2_FLAGS_RECAPTURE, VALIDITY_A2_FLAGS_RECAPTURE },
    { 0x80200001, VALIDITY_A2_FLAGS_RECAPTURE, VALIDITY_A2_FLAGS_RECAPTURE },
    /* bit 31 alone: a capture-quality error */
    { 0x80000000, VALIDITY_A2_FLAGS_REJECT, VALIDITY_A2_FLAGS_REJECT },
    { 0x80000010, VALIDITY_A2_FLAGS_REJECT, VALIDITY_A2_FLAGS_REJECT },
    /* bit 21 alone */
    { 0x00200000, VALIDITY_A2_FLAGS_USE, VALIDITY_A2_FLAGS_REJECT },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_assert_cmpint (fpi_validity_a2_image_flags_verdict (cases[i].flags,
                                                            VALIDITY_A2_FLAGS_RULE_WINDOWS),
                       ==, cases[i].windows);
      g_assert_cmpint (fpi_validity_a2_image_flags_verdict (cases[i].flags,
                                                            VALIDITY_A2_FLAGS_RULE_STRICT),
                       ==, cases[i].strict);
    }
}

/* --- 51 readout --- */

/* 8192 + 4364 bytes: header + 12544 pixels in two requests */
static void
test_a2_readout_two_chunks (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *frame = NULL;
  ValidityA2Readout r;
  const guint8 *px;
  gsize frame_len, px_len;

  frame = a2_make_frame (112, 112, 8, 0, &frame_len);
  g_assert_cmpuint (frame_len, ==, A2_FRAME_LEN);
  g_assert_cmpuint (frame_len, ==, 8192 + 4364);

  fpi_validity_a2_readout_init (&r);
  g_assert_cmpint (a2_feed_chunk (&r, frame, 8192, &error), ==,
                   VALIDITY_A2_READOUT_MORE);
  g_assert_no_error (error);
  g_assert_true (r.have_header);
  g_assert_null (fpi_validity_a2_readout_pixels (&r, &px_len));
  g_assert_cmpuint (px_len, ==, 0);

  g_assert_cmpint (a2_feed_chunk (&r, frame + 8192, 4364, &error), ==,
                   VALIDITY_A2_READOUT_DONE);
  g_assert_no_error (error);
  g_assert_cmpuint (r.chunks, ==, 2);

  px = fpi_validity_a2_readout_pixels (&r, &px_len);
  g_assert_nonnull (px);
  g_assert_cmpuint (px_len, ==, 112 * 112);
  for (gsize i = 0; i < px_len; i++)
    g_assert_cmpuint (px[i], ==, a2_pixel (i));

  fpi_validity_a2_readout_clear (&r);
  g_assert_null (r.buf);
  g_assert_cmpuint (r.len, ==, 0);
}

/* The first full chunk can complete the image when the sensor sends more */
static void
test_a2_readout_surplus (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *frame = NULL;
  g_autofree guint8 *padded = NULL;
  ValidityA2Readout r;
  gsize frame_len;

  frame = a2_make_frame (112, 112, 8, 0, &frame_len);
  padded = g_malloc0 (2 * 8192);
  memcpy (padded, frame, frame_len);

  fpi_validity_a2_readout_init (&r);
  g_assert_cmpint (a2_feed_chunk (&r, padded, 8192, &error), ==,
                   VALIDITY_A2_READOUT_MORE);
  g_assert_cmpint (a2_feed_chunk (&r, padded + 8192, 8192, &error), ==,
                   VALIDITY_A2_READOUT_DONE);
  g_assert_no_error (error);
  fpi_validity_a2_readout_clear (&r);
}

static void
test_a2_readout_errors (void)
{
  g_autofree guint8 *frame = NULL;
  gsize frame_len;

  frame = a2_make_frame (112, 112, 8, 0, &frame_len);

  /* Short chunks do not end the readout (python-validity PR #261 reads
   * on): 4096 + 4096 + 4364 completes the image */
  {
    g_autoptr(GError) error = NULL;
    ValidityA2Readout r;
    const guint8 *px;
    gsize px_len = 0;

    fpi_validity_a2_readout_init (&r);
    g_assert_cmpint (a2_feed_chunk (&r, frame, 4096, &error), ==,
                     VALIDITY_A2_READOUT_MORE);
    g_assert_cmpint (a2_feed_chunk (&r, frame + 4096, 4096, &error), ==,
                     VALIDITY_A2_READOUT_MORE);
    g_assert_cmpint (a2_feed_chunk (&r, frame + 8192, 4364, &error), ==,
                     VALIDITY_A2_READOUT_DONE);
    g_assert_no_error (error);
    g_assert_cmpuint (r.chunks, ==, 3);
    px = fpi_validity_a2_readout_pixels (&r, &px_len);
    g_assert_cmpuint (px_len, ==, 112 * 112);
    for (gsize i = 0; i < px_len; i++)
      g_assert_cmpuint (px[i], ==, a2_pixel (i));
    fpi_validity_a2_readout_clear (&r);
  }

  /* Header only (12 bytes), then the pixels in one chunk */
  {
    g_autoptr(GError) error = NULL;
    ValidityA2Readout r;

    fpi_validity_a2_readout_init (&r);
    g_assert_cmpint (a2_feed_chunk (&r, frame, 12, &error), ==,
                     VALIDITY_A2_READOUT_MORE);
    g_assert_true (r.have_header);
    g_assert_cmpint (a2_feed_chunk (&r, frame + 12, 8192, &error), ==,
                     VALIDITY_A2_READOUT_MORE);
    g_assert_cmpint (a2_feed_chunk (&r, frame + 12 + 8192,
                                    frame_len - 12 - 8192, &error), ==,
                     VALIDITY_A2_READOUT_DONE);
    g_assert_no_error (error);
    fpi_validity_a2_readout_clear (&r);
  }

  /* An empty chunk, first or after some data: the image cannot complete */
  for (gint after = 0; after <= 1; after++)
    {
      g_autoptr(GError) error = NULL;
      ValidityA2Readout r;

      fpi_validity_a2_readout_init (&r);
      if (after)
        g_assert_cmpint (a2_feed_chunk (&r, frame, 8192, &error), ==,
                         VALIDITY_A2_READOUT_MORE);
      g_assert_cmpint (a2_feed_chunk (&r, NULL, 0, &error), ==,
                       VALIDITY_A2_READOUT_ERROR);
      g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      g_assert_nonnull (strstr (error->message, "empty chunk"));
      fpi_validity_a2_readout_clear (&r);
    }

  /* Small chunks: at most VALIDITY_A2_READ_MAX_CHUNKS, then an error */
  {
    g_autoptr(GError) error = NULL;
    ValidityA2Readout r;
    gsize off = 0;

    fpi_validity_a2_readout_init (&r);
    for (guint i = 1; i < VALIDITY_A2_READ_MAX_CHUNKS; i++, off += 100)
      g_assert_cmpint (a2_feed_chunk (&r, frame + off, 100, &error), ==,
                       VALIDITY_A2_READOUT_MORE);
    g_assert_no_error (error);
    g_assert_cmpint (a2_feed_chunk (&r, frame + off, 100, &error), ==,
                     VALIDITY_A2_READOUT_ERROR);
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
    g_assert_nonnull (strstr (error->message, "not complete after 9 chunks"));
    fpi_validity_a2_readout_clear (&r);
  }

  /* Length field larger / smaller than the data that follows */
  {
    g_autoptr(GByteArray) p = a2_read_payload (frame, 8192);
    ValidityA2Readout r;

    g_byte_array_append (p, (const guint8 *) "\0", 1);   /* 8192 + 1 bytes */
    for (gsize cut = 1; cut <= 2; cut++)
      {
        g_autoptr(GError) error = NULL;

        /* cut 1: exactly 8193 data bytes; cut 2: 8191 */
        fpi_validity_a2_readout_init (&r);
        g_assert_cmpint (fpi_validity_a2_readout_feed (&r, 0, p->data,
                                                       cut == 1 ? p->len :
                                                       p->len - 2, &error),
                         ==, VALIDITY_A2_READOUT_ERROR);
        g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
        fpi_validity_a2_readout_clear (&r);
      }
  }

  /* More than the requested 0x2000 bytes in one reply */
  {
    g_autoptr(GError) error = NULL;
    g_autofree guint8 *big = g_malloc0 (0x2001);
    ValidityA2Readout r;

    memcpy (big, frame, 12);
    fpi_validity_a2_readout_init (&r);
    g_assert_cmpint (a2_feed_chunk (&r, big, 0x2001, &error), ==,
                     VALIDITY_A2_READOUT_ERROR);
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
    fpi_validity_a2_readout_clear (&r);
  }

  /* No length field */
  {
    g_autoptr(GError) error = NULL;
    static const guint8 three[] = { 0x00, 0x20, 0x00 };
    ValidityA2Readout r;

    fpi_validity_a2_readout_init (&r);
    g_assert_cmpint (fpi_validity_a2_readout_feed (&r, 0, three, sizeof (three),
                                                   &error),
                     ==, VALIDITY_A2_READOUT_ERROR);
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
    fpi_validity_a2_readout_clear (&r);
  }

  /* Unknown status */
  {
    g_autoptr(GError) error = NULL;
    ValidityA2Readout r;

    fpi_validity_a2_readout_init (&r);
    g_assert_cmpint (fpi_validity_a2_readout_feed (&r, 0x0005, NULL, 0, &error),
                     ==, VALIDITY_A2_READOUT_ERROR);
    g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
    fpi_validity_a2_readout_clear (&r);
  }
}

/* rows/cols other than 112x112 are refused; 0 rows/cols = empty capture */
static void
test_a2_readout_geometry (void)
{
  static const struct
  {
    guint16               rows, cols;
    guint8                bpp;
    ValidityA2ReadoutStep step;
  } cases[] = {
    { 0, 0, 8, VALIDITY_A2_READOUT_EMPTY },
    { 0, 112, 8, VALIDITY_A2_READOUT_EMPTY },
    { 112, 0, 8, VALIDITY_A2_READOUT_EMPTY },
    { 100, 112, 8, VALIDITY_A2_READOUT_ERROR },
    { 112, 144, 8, VALIDITY_A2_READOUT_ERROR },
    { 112, 112, 16, VALIDITY_A2_READOUT_ERROR },
    { 112, 112, 8, VALIDITY_A2_READOUT_MORE },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(GError) error = NULL;
      g_autofree guint8 *frame = NULL;
      g_autofree guint8 *chunk = g_malloc0 (8192);
      ValidityA2Readout r;
      gsize frame_len;

      frame = a2_make_frame (cases[i].rows, cases[i].cols, cases[i].bpp, 0,
                             &frame_len);
      memcpy (chunk, frame, MIN (frame_len, 8192));

      fpi_validity_a2_readout_init (&r);
      g_assert_cmpint (a2_feed_chunk (&r, chunk,
                                      cases[i].step == VALIDITY_A2_READOUT_EMPTY ?
                                      VALIDITY_A2_IMAGE_HEADER_LEN : 8192,
                                      &error),
                       ==, cases[i].step);
      if (cases[i].step == VALIDITY_A2_READOUT_ERROR)
        g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      else
        g_assert_no_error (error);
      fpi_validity_a2_readout_clear (&r);
    }
}

/* Status 1 and 7 = not ready: poll again, bounded. Status 4 = aborted. */
static void
test_a2_readout_statuses (void)
{
  g_autoptr(GError) error = NULL;
  ValidityA2Readout r;

  fpi_validity_a2_readout_init (&r);
  for (guint i = 0; i < VALIDITY_A2_READ_MAX_POLLS; i++)
    g_assert_cmpint (fpi_validity_a2_readout_feed (&r, i % 2 ? 0x0007 : 0x0001,
                                                   NULL, 0, &error),
                     ==, VALIDITY_A2_READOUT_POLL);
  g_assert_no_error (error);
  g_assert_cmpint (fpi_validity_a2_readout_feed (&r, 0x0001, NULL, 0, &error), ==,
                   VALIDITY_A2_READOUT_ERROR);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
  fpi_validity_a2_readout_clear (&r);
  g_clear_error (&error);

  fpi_validity_a2_readout_init (&r);
  g_assert_cmpint (fpi_validity_a2_readout_feed (&r, 0x0004, NULL, 0, &error), ==,
                   VALIDITY_A2_READOUT_ABORTED);
  g_assert_no_error (error);
  fpi_validity_a2_readout_clear (&r);
}

/* --- 60 match result (strict) --- */

static void
a2_tlv (GByteArray *a,
        guint16     tag,
        const void *value,
        guint16     len)
{
  guint8 h[4] = { tag & 0xff, tag >> 8, len & 0xff, len >> 8 };

  g_byte_array_append (a, h, sizeof (h));
  if (len)
    g_byte_array_append (a, value, len);
}

/* A 60 payload: u16 total + TLV. @tag2 is the "matched" word. */
static GByteArray *
a2_match_payload (guint32 user_dbid,
                  guint32 tag2,
                  guint16 subtype,
                  gint    skip_tag,
                  gint    bad_len_tag)
{
  GByteArray *a = g_byte_array_new ();
  /* every value buffer has room for the +1 of @bad_len_tag */
  guint8 zero[40] = { 0 };
  guint8 hash[40] = { 0 };
  guint8 u[40] = { user_dbid & 0xff, (user_dbid >> 8) & 0xff,
                   (user_dbid >> 16) & 0xff, user_dbid >> 24 };
  guint8 t2[40] = { tag2 & 0xff, (tag2 >> 8) & 0xff, (tag2 >> 16) & 0xff,
                    tag2 >> 24 };
  guint8 st[40] = { subtype & 0xff, subtype >> 8 };

  struct
  {
    guint16     tag;
    const void *v;
    guint16     len;
  } tags[] = {
    { 1, u, 4 }, { 2, t2, 4 }, { 3, st, 2 }, { 4, hash, 32 }, { 5, zero, 32 },
    { 6, zero, 5 }, { 7, zero, 16 }, { 8, zero, 2 },
  };
  guint16 total;

  for (gsize i = 0; i < 32; i++)
    hash[i] = (guint8) (0xa0 + i);

  g_byte_array_append (a, (const guint8 *) "\0\0", 2);
  for (gsize i = 0; i < G_N_ELEMENTS (tags); i++)
    {
      if (tags[i].tag == skip_tag)
        continue;
      a2_tlv (a, tags[i].tag, tags[i].v,
              tags[i].tag == bad_len_tag ? tags[i].len + 1 : tags[i].len);
    }

  total = a->len - 2;
  a->data[0] = total & 0xff;
  a->data[1] = total >> 8;
  return a;
}

static void
test_a2_match_result_parse (void)
{
  ValidityMatchResult res = { 0 };

  /* All tags: a match */
  {
    g_autoptr(GError) error = NULL;
    g_autoptr(GByteArray) p = a2_match_payload (5, 0x11, 7, -1, -1);

    g_assert_true (fpi_validity_a2_parse_match_result (p->data, p->len, &res,
                                                       &error));
    g_assert_no_error (error);
    g_assert_true (res.matched);
    g_assert_cmpuint (res.user_dbid, ==, 5);
    g_assert_cmphex (res.tag2, ==, 0x11);
    g_assert_cmpuint (res.subtype, ==, 7);
    g_assert_cmpuint (res.hash_len, ==, 32);
    g_assert_cmpuint (res.hash[0], ==, 0xa0);
    fpi_validity_match_result_clear (&res);
  }

  /* Tag 2 == 0: the vendor driver's "no match" */
  {
    g_autoptr(GError) error = NULL;
    g_autoptr(GByteArray) p = a2_match_payload (5, 0, 7, -1, -1);

    g_assert_true (fpi_validity_a2_parse_match_result (p->data, p->len, &res,
                                                       &error));
    g_assert_false (res.matched);
    g_assert_cmpuint (res.user_dbid, ==, 5);
    fpi_validity_match_result_clear (&res);
  }

  /* Missing tag 1, 2 or 3: not a match (but well-formed) */
  for (gint tag = 1; tag <= 3; tag++)
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(GByteArray) p = a2_match_payload (5, 0x11, 7, tag, -1);

      g_assert_true (fpi_validity_a2_parse_match_result (p->data, p->len, &res,
                                                         &error));
      g_assert_no_error (error);
      g_assert_false (res.matched);
      fpi_validity_match_result_clear (&res);
    }

  /* Wrong length of any fixed-length tag: malformed */
  for (gint tag = 1; tag <= 8; tag++)
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(GByteArray) p = a2_match_payload (5, 0x11, 7, -1, tag);
      gboolean ok = fpi_validity_a2_parse_match_result (p->data, p->len, &res,
                                                        &error);

      if (tag == 6)
        {
          /* any length */
          g_assert_true (ok);
          g_assert_true (res.matched);
        }
      else
        {
          g_assert_false (ok);
          g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
          g_assert_false (res.matched);
        }
      fpi_validity_match_result_clear (&res);
    }

  /* The leading total-length field one more or one less than the data
   * that follows (the payload itself unchanged) */
  for (gint delta = -1; delta <= 1; delta += 2)
    {
      g_autoptr(GByteArray) p = a2_match_payload (5, 0x11, 7, -1, -1);
      g_autoptr(GError) error = NULL;
      guint16 total = (guint16) (p->data[0] | (p->data[1] << 8));

      total = (guint16) (total + delta);
      p->data[0] = total & 0xff;
      p->data[1] = total >> 8;
      g_assert_false (fpi_validity_a2_parse_match_result (p->data, p->len, &res,
                                                          &error));
      g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      g_assert_nonnull (strstr (error->message, "length field"));
      g_assert_false (res.matched);
      fpi_validity_match_result_clear (&res);
    }

  /* Length field not equal to the data that follows; truncated TLV;
   * stray bytes; repeated tag */
  {
    g_autoptr(GByteArray) p = a2_match_payload (5, 0x11, 7, -1, -1);
    g_autoptr(GError) e1 = NULL;
    g_autoptr(GError) e2 = NULL;
    g_autoptr(GError) e3 = NULL;
    g_autoptr(GError) e4 = NULL;
    g_autoptr(GByteArray) stray = g_byte_array_new ();
    g_autoptr(GByteArray) twice = g_byte_array_new ();
    guint8 u[4] = { 5, 0, 0, 0 };

    g_assert_false (fpi_validity_a2_parse_match_result (p->data, p->len - 1, &res,
                                                        &e1));
    g_assert_error (e1, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);

    /* consistent length field, last TLV cut short */
    p->data[0] -= 3;
    g_assert_false (fpi_validity_a2_parse_match_result (p->data, p->len - 3, &res,
                                                        &e2));
    g_assert_error (e2, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);

    g_byte_array_append (stray, (const guint8 *) "\x03\x00\x01\x00\x00", 5);
    g_assert_false (fpi_validity_a2_parse_match_result (stray->data, stray->len,
                                                        &res, &e3));
    g_assert_error (e3, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);

    g_byte_array_append (twice, (const guint8 *) "\x10\x00", 2);
    a2_tlv (twice, 1, u, 4);
    a2_tlv (twice, 1, u, 4);
    g_assert_false (fpi_validity_a2_parse_match_result (twice->data, twice->len,
                                                        &res, &e4));
    g_assert_error (e4, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
    fpi_validity_match_result_clear (&res);
  }

  /* Empty dictionary, unknown tags: well-formed, no match */
  {
    g_autoptr(GError) error = NULL;
    g_autoptr(GByteArray) a = g_byte_array_new ();
    guint8 v[3] = { 1, 2, 3 };

    g_byte_array_append (a, (const guint8 *) "\x07\x00", 2);
    a2_tlv (a, 0x99, v, 3);
    g_assert_true (fpi_validity_a2_parse_match_result (a->data, a->len, &res,
                                                       &error));
    g_assert_false (res.matched);

    g_assert_true (fpi_validity_a2_parse_match_result ((const guint8 *) "\0\0", 2,
                                                       &res, &error));
    g_assert_false (res.matched);
    g_assert_false (fpi_validity_a2_parse_match_result (NULL, 0, &res, &error));
    fpi_validity_match_result_clear (&res);
  }
}

/* --- flow transcripts --- */

typedef struct
{
  ValidityA2Flow flow;
  GString       *wire;   /* ops in order, e.g. "39+ 02 W 51 51 5e M 62 39- " */
  GPtrArray     *cmds;   /* bytes of every command op (not 02) */
} A2Run;

static const gchar *
a2_op_tag (ValidityA2Op op)
{
  switch (op)
    {
    case VALIDITY_A2_OP_GLOW_START:
      return "39+";

    case VALIDITY_A2_OP_CAPTURE:
      return "02";

    case VALIDITY_A2_OP_WAIT_CAPTURE_EVENT:
      return "W";

    case VALIDITY_A2_OP_READ_IMAGE:
      return "51";

    case VALIDITY_A2_OP_CAPTURE_STOP:
      return "04";

    case VALIDITY_A2_OP_MATCH_START:
      return "5e";

    case VALIDITY_A2_OP_WAIT_MATCH_EVENT:
      return "M";

    case VALIDITY_A2_OP_GET_RESULT:
      return "60";

    case VALIDITY_A2_OP_MATCH_CLEANUP:
      return "62";

    case VALIDITY_A2_OP_GLOW_END:
      return "39-";

    case VALIDITY_A2_OP_GET_USER:
      return "4a";

    case VALIDITY_A2_OP_DELAY:
      return "D";

    case VALIDITY_A2_OP_DONE:
      return "done";

    case VALIDITY_A2_OP_NONE:
      return "NONE";
    }

  return "?";
}

static void
a2_run_init (A2Run   *run,
             gboolean match)
{
  fpi_validity_a2_flow_init (&run->flow, match, VALIDITY_A2_FLAGS_RULE_WINDOWS);
  run->wire = g_string_new ("");
  run->cmds = g_ptr_array_new_with_free_func ((GDestroyNotify) g_byte_array_unref);
}

static void
a2_run_clear (A2Run *run)
{
  fpi_validity_a2_flow_clear (&run->flow);
  g_string_free (run->wire, TRUE);
  g_ptr_array_unref (run->cmds);
}

/* Ask the flow for its next op, which must be @expect; record it */
static void
a2_expect (A2Run       *run,
           ValidityA2Op expect)
{
  ValidityA2Op op = fpi_validity_a2_flow_next (&run->flow, NULL);
  gsize len = 0;
  guint8 *cmd;

  if (op != expect)
    g_error ("flow: expected %s, got %s after \"%s\"", a2_op_tag (expect),
             a2_op_tag (op), run->wire->str);

  g_string_append_printf (run->wire, "%s ", a2_op_tag (op));

  cmd = fpi_validity_a2_flow_build_cmd (&run->flow, op, &len);
  if (cmd)
    {
      GByteArray *b = g_byte_array_new ();

      g_byte_array_append (b, cmd, len);
      g_ptr_array_add (run->cmds, b);
      g_free (cmd);
    }
}

static void
a2_ok (A2Run *run)
{
  fpi_validity_a2_flow_reply (&run->flow, 0, NULL, 0);
}

static void
a2_event5 (A2Run *run,
           guint8 b0,
           guint8 b1,
           guint8 b2,
           guint8 b3,
           guint8 b4)
{
  const guint8 b[5] = { b0, b1, b2, b3, b4 };

  fpi_validity_a2_flow_event (&run->flow, b, sizeof (b));
}

static GByteArray *
a2_last_cmd (A2Run *run)
{
  g_assert_cmpuint (run->cmds->len, >, 0);
  return g_ptr_array_index (run->cmds, run->cmds->len - 1);
}

/* 39 start, 02, events 00 / 02 / 03 code 1 / 03 code 4, 51 x2 */
static void
a2_run_capture (A2Run  *run,
                guint32 flags)
{
  g_autofree guint8 *frame = NULL;
  gsize frame_len;

  frame = a2_make_frame (112, 112, 8, flags, &frame_len);

  a2_expect (run, VALIDITY_A2_OP_GLOW_START);
  a2_ok (run);
  a2_expect (run, VALIDITY_A2_OP_CAPTURE);
  a2_ok (run);
  a2_expect (run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (run, 0x00, 0x00, 0x00, 0x00, 0x00);
  a2_expect (run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (run, 0x02, 0x00, 0x40, 0x10, 0x00);
  a2_expect (run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (run, 0x03, 0x40, 0x01, 0x00, 0x00);
  a2_expect (run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (run, 0x03, 0x42, 0x04, 0x00, 0x40);

  a2_expect (run, VALIDITY_A2_OP_READ_IMAGE);
  {
    g_autoptr(GByteArray) p = a2_read_payload (frame, 8192);
    fpi_validity_a2_flow_reply (&run->flow, 0, p->data, p->len);
  }
  a2_expect (run, VALIDITY_A2_OP_READ_IMAGE);
  {
    g_autoptr(GByteArray) p = a2_read_payload (frame + 8192, 4364);
    fpi_validity_a2_flow_reply (&run->flow, 0, p->data, p->len);
  }
}

static void
a2_reply_handle (A2Run  *run,
                 guint32 h)
{
  const guint8 b[4] = { h & 0xff, (h >> 8) & 0xff, (h >> 16) & 0xff, h >> 24 };

  fpi_validity_a2_flow_reply (&run->flow, 0, b, sizeof (b));
}

/* The D5 case: a complete capture, the chip has no templates (no-match
* event with 0 templates). No 04 anywhere; 62 carries the 5e handle. */
static void
test_a2_flow_verify_no_match (void)
{
  A2Run run;
  GByteArray *cmd;

  a2_run_init (&run, TRUE);
  a2_run_capture (&run, 0);

  a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
  cmd = a2_last_cmd (&run);
  {
    static const guint8 want[] = { 0x5e, 0x02, 0xff, 0x00, 0x00, 0x00, 0x00,
                                   0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
    g_assert_cmpmem (cmd->data, cmd->len, want, sizeof (want));
  }
  /* the image is not kept once the sensor has it */
  g_assert_null (run.flow.readout.buf);
  a2_reply_handle (&run, 0x12345678);

  a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
  a2_event5 (&run, 0x04, 0x00, 0x00, 0x00, 0xdb);

  a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
  cmd = a2_last_cmd (&run);
  {
    static const guint8 want[] = { 0x62, 0x78, 0x56, 0x34, 0x12 };
    g_assert_cmpmem (cmd->data, cmd->len, want, sizeof (want));
  }
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);

  g_assert_cmpstr (run.wire->str, ==,
                   "39+ 02 W W W W 51 51 5e M 62 39- done ");
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_NO_MATCH);
  g_assert_cmpuint (run.flow.captures, ==, 1);
  g_assert_cmpuint (run.flow.stops, ==, 0);
  g_assert_cmphex (run.flow.match_handle, ==, 0x12345678);
  g_assert_false (run.flow.glow_on);
  g_assert_false (run.flow.match_open);
  g_assert_false (run.flow.capture_armed);
  g_assert_true (run.flow.finger_present == FALSE);

  /* libfprint: no match for the print being verified */
  {
    g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
    g_autoptr(FpPrint) print = make_enrolled_print (device,
                                                    FP_FINGER_RIGHT_INDEX,
                                                    ID_RIGHT_INDEX);

    g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, NULL,
                                                &run.flow.user, NULL),
                     ==, FPI_MATCH_FAIL);
  }
  a2_run_clear (&run);
}

/* A match: 60 and 62 carry the handle, then 39 end and a read-only 4a of
 * the record the chip named; the decision is made against that record */
static void
test_a2_flow_verify_match (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_RIGHT_INDEX);
  g_autoptr(FpPrint) other = make_enrolled_print (device, FP_FINGER_RIGHT_INDEX,
                                                  ID_CAROL_RIGHT_INDEX);
  guint16 subtype = fpi_validity_finger_to_subtype (FP_FINGER_RIGHT_INDEX);
  g_autoptr(GByteArray) result = a2_match_payload (8, 0x2c, subtype, -1, -1);
  g_autoptr(GByteArray) user_reply = g_byte_array_new ();
  g_autofree guint8 *identity = NULL;
  gsize identity_len = 0;
  GByteArray *cmd;
  A2Run run;

  /* 4a reply: dbid 8, 1 finger (dbid 9, subtype, storage 3), identity */
  identity = fpi_validity_db_build_identity (ID_RIGHT_INDEX, &identity_len);
  {
    guint8 h[8] = { 8, 0, 1, 0, 0, 0, identity_len & 0xff, identity_len >> 8 };
    guint8 f[8] = { 9, 0, subtype & 0xff, subtype >> 8, 3, 0, 0, 0 };

    g_byte_array_append (user_reply, h, sizeof (h));
    g_byte_array_append (user_reply, f, sizeof (f));
    g_byte_array_append (user_reply, identity, identity_len);
  }

  a2_run_init (&run, TRUE);
  a2_run_capture (&run, 0);
  a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
  a2_reply_handle (&run, 0x00000007);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
  a2_event5 (&run, 0x01, 0x00, 0x00, 0x00, 0x00);     /* pending */
  a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
  a2_event5 (&run, 0x03, 0x00, 0x00, 0x00, 0xdb);     /* match */

  a2_expect (&run, VALIDITY_A2_OP_GET_RESULT);
  cmd = a2_last_cmd (&run);
  {
    static const guint8 want[] = { 0x60, 0x07, 0x00, 0x00, 0x00 };
    g_assert_cmpmem (cmd->data, cmd->len, want, sizeof (want));
  }
  fpi_validity_a2_flow_reply (&run.flow, 0, result->data, result->len);

  a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
  cmd = a2_last_cmd (&run);
  {
    static const guint8 want[] = { 0x62, 0x07, 0x00, 0x00, 0x00 };
    g_assert_cmpmem (cmd->data, cmd->len, want, sizeof (want));
  }
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_GET_USER);
  cmd = a2_last_cmd (&run);
  {
    static const guint8 want[] = { 0x4a, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00 };
    g_assert_cmpmem (cmd->data, cmd->len, want, sizeof (want));
  }
  fpi_validity_a2_flow_reply (&run.flow, 0, user_reply->data, user_reply->len);
  a2_expect (&run, VALIDITY_A2_OP_DONE);

  g_assert_cmpstr (run.wire->str, ==,
                   "39+ 02 W W W W 51 51 5e M M 60 62 39- 4a done ");
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_MATCH);
  g_assert_true (run.flow.user_read);
  g_assert_cmpuint (run.flow.stops, ==, 0);

  g_assert_cmpint (fpi_validity_match_decide (FALSE, print, NULL, &run.flow.result,
                                              &run.flow.user, NULL),
                   ==, FPI_MATCH_SUCCESS);
  g_assert_cmpint (fpi_validity_match_decide (FALSE, other, NULL, &run.flow.result,
                                              &run.flow.user, NULL),
                   ==, FPI_MATCH_FAIL);
  a2_run_clear (&run);
}

/* Match event "error" (e.g. 0x050b) and 60 with tag 2 = 0 are no-match;
 * a refused 5e or 60 is an error naming the status (not a no-match that
 * would hide it). 62 is always sent once 5e was sent, never a 4a. */
static void
test_a2_flow_no_match_paths (void)
{
  /* error event */
  {
    A2Run run;

    a2_run_init (&run, TRUE);
    a2_run_capture (&run, 0);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
    a2_reply_handle (&run, 0);
    a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
    a2_event5 (&run, 0x05, 0x00, 0x0b, 0x05, 0xdb);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_DONE);
    g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_NO_MATCH);
    a2_run_clear (&run);
  }

  /* tag 2 = 0 */
  {
    g_autoptr(GByteArray) result = a2_match_payload (8, 0, 7, -1, -1);
    A2Run run;

    a2_run_init (&run, TRUE);
    a2_run_capture (&run, 0);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
    a2_reply_handle (&run, 3);
    a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
    a2_event5 (&run, 0x03, 0x00, 0x00, 0x00, 0xdb);
    a2_expect (&run, VALIDITY_A2_OP_GET_RESULT);
    fpi_validity_a2_flow_reply (&run.flow, 0, result->data, result->len);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_DONE);
    g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_NO_MATCH);
    g_assert_false (run.flow.user_requested);
    a2_run_clear (&run);
  }

  /* 60 refused: an error with the status, 62 still sent */
  {
    A2Run run;

    a2_run_init (&run, TRUE);
    a2_run_capture (&run, 0);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
    a2_reply_handle (&run, 3);
    a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
    a2_event5 (&run, 0x06, 0x00, 0x00, 0x00, 0xdb);    /* other: read result */
    a2_expect (&run, VALIDITY_A2_OP_GET_RESULT);
    fpi_validity_a2_flow_reply (&run.flow, 0x04b3, NULL, 0);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_DONE);
    g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_ERROR);
    g_assert_error (run.flow.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
    g_assert_nonnull (strstr (run.flow.error->message, "60 status 0x04b3"));
    g_assert_false (run.flow.user_requested);
    g_assert_cmpstr (run.wire->str, ==,
                     "39+ 02 W W W W 51 51 5e M 60 62 39- done ");
    a2_run_clear (&run);
  }

  /* 5e refused: an error with the status, 62 with handle 0 */
  {
    A2Run run;
    GByteArray *cmd;

    a2_run_init (&run, TRUE);
    a2_run_capture (&run, 0);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
    fpi_validity_a2_flow_reply (&run.flow, 0x0401, NULL, 0);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
    cmd = a2_last_cmd (&run);
    {
      static const guint8 want[] = { 0x62, 0x00, 0x00, 0x00, 0x00 };
      g_assert_cmpmem (cmd->data, cmd->len, want, sizeof (want));
    }
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_DONE);
    g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_ERROR);
    g_assert_error (run.flow.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
    g_assert_nonnull (strstr (run.flow.error->message, "5e status 0x0401"));
    g_assert_cmpstr (run.wire->str, ==,
                     "39+ 02 W W W W 51 51 5e 62 39- done ");
    a2_run_clear (&run);
  }

  /* 5e reply without a handle: 0, like python-validity */
  {
    A2Run run;

    a2_run_init (&run, TRUE);
    a2_run_capture (&run, 0);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
    a2_ok (&run);
    g_assert_cmphex (run.flow.match_handle, ==, 0);
    a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
    a2_run_clear (&run);
  }
}

/* A capture report still queued when the match wait starts is skipped;
 * the real match report that follows decides (no early 60) */
static void
test_a2_flow_stale_report (void)
{
  A2Run run;

  a2_run_init (&run, TRUE);
  a2_run_capture (&run, 0);
  a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
  a2_reply_handle (&run, 5);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
  a2_event5 (&run, 0x03, 0x42, 0x04, 0x00, 0x40);   /* late "image ready" */
  a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
  a2_event5 (&run, 0x03, 0x40, 0x01, 0x00, 0x00);   /* late "waiting" */
  a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
  a2_event5 (&run, 0x04, 0x00, 0x00, 0x00, 0xdb);   /* no match */
  a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);
  g_assert_cmpstr (run.wire->str, ==,
                   "39+ 02 W W W W 51 51 5e M M M 62 39- done ");
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_NO_MATCH);
  a2_run_clear (&run);
}

/* An EP 0x83 transport error ends the flow with that error after the
 * cleanup the sensor needs: 04 + 39 end in the finger wait, 62 + 39 end in
 * the match wait; during the cleanup it changes nothing */
static void
test_a2_flow_transport_error (void)
{
  /* finger wait */
  {
    A2Run run;

    a2_run_init (&run, TRUE);
    a2_expect (&run, VALIDITY_A2_OP_GLOW_START);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
    fpi_validity_a2_flow_transport_error (&run.flow,
                                          g_error_new_literal (G_USB_DEVICE_ERROR,
                                                               G_USB_DEVICE_ERROR_IO,
                                                               "pipe"));
    a2_expect (&run, VALIDITY_A2_OP_CAPTURE_STOP);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_DONE);
    g_assert_cmpstr (run.wire->str, ==, "39+ 02 W 04 39- done ");
    g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_ERROR);
    g_assert_error (run.flow.error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO);
    a2_run_clear (&run);
  }

  /* match wait: no 04 (the image was read), 62 with the handle */
  {
    A2Run run;

    a2_run_init (&run, TRUE);
    a2_run_capture (&run, 0);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
    a2_reply_handle (&run, 0x21);
    a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
    fpi_validity_a2_flow_transport_error (&run.flow,
                                          g_error_new_literal (G_USB_DEVICE_ERROR,
                                                               G_USB_DEVICE_ERROR_IO,
                                                               "pipe"));
    a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
    g_assert_cmpmem (a2_last_cmd (&run)->data, a2_last_cmd (&run)->len,
                     "\x62\x21\x00\x00\x00", 5);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_DONE);
    g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_ERROR);
    g_assert_cmpuint (run.flow.stops, ==, 0);

    /* a later one (or one during the cleanup) keeps the first outcome */
    fpi_validity_a2_flow_transport_error (&run.flow,
                                          g_error_new_literal (G_USB_DEVICE_ERROR,
                                                               G_USB_DEVICE_ERROR_FAILED,
                                                               "again"));
    g_assert_error (run.flow.error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO);
    a2_run_clear (&run);
  }
}

/* A malformed 60 reply, a malformed match event, or no event in time:
 * an error, with 62 and 39 end still sent */
static void
test_a2_flow_match_errors (void)
{
  for (gint variant = 0; variant < 3; variant++)
    {
      A2Run run;

      a2_run_init (&run, TRUE);
      a2_run_capture (&run, 0);
      a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
      a2_reply_handle (&run, 9);
      a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);

      if (variant == 0)
        {
          g_autoptr(GByteArray) bad = a2_match_payload (8, 1, 7, -1, 4);

          a2_event5 (&run, 0x03, 0x00, 0x00, 0x00, 0xdb);
          a2_expect (&run, VALIDITY_A2_OP_GET_RESULT);
          fpi_validity_a2_flow_reply (&run.flow, 0, bad->data, bad->len);
        }
      else if (variant == 1)
        {
          const guint8 one[1] = { 0x03 };

          fpi_validity_a2_flow_event (&run.flow, one, sizeof (one));
        }
      else
        {
          fpi_validity_a2_flow_timeout (&run.flow);
        }

      a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
      a2_ok (&run);
      a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
      a2_ok (&run);
      a2_expect (&run, VALIDITY_A2_OP_DONE);
      g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_ERROR);
      g_assert_error (run.flow.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      g_assert_cmpuint (run.flow.stops, ==, 0);
      a2_run_clear (&run);
    }
}

/* Cancel while waiting for the finger: 04 (capture armed), 39 end */
static void
test_a2_flow_cancel_finger_wait (void)
{
  A2Run run;

  a2_run_init (&run, TRUE);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_START);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (&run, 0x00, 0x00, 0x00, 0x00, 0x00);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  fpi_validity_a2_flow_cancel (&run.flow);

  a2_expect (&run, VALIDITY_A2_OP_CAPTURE_STOP);
  g_assert_cmpmem (a2_last_cmd (&run)->data, a2_last_cmd (&run)->len,
                   "\x04", 1);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);

  g_assert_cmpstr (run.wire->str, ==, "39+ 02 W W 04 39- done ");
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_CANCELLED);
  /* a second cancel during the cleanup changes nothing */
  fpi_validity_a2_flow_cancel (&run.flow);
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_CANCELLED);
  a2_run_clear (&run);
}

/* Cancel in the middle of the readout (between two 51): 04, 39 end */
static void
test_a2_flow_cancel_readout (void)
{
  g_autofree guint8 *frame = NULL;
  gsize frame_len;
  A2Run run;

  frame = a2_make_frame (112, 112, 8, 0, &frame_len);

  a2_run_init (&run, TRUE);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_START);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (&run, 0x03, 0x00, 0x07, 0x00, 0x00);  /* ready as the first event */
  a2_expect (&run, VALIDITY_A2_OP_READ_IMAGE);
  {
    g_autoptr(GByteArray) p = a2_read_payload (frame, 8192);
    fpi_validity_a2_flow_reply (&run.flow, 0, p->data, p->len);
  }
  fpi_validity_a2_flow_cancel (&run.flow);
  g_assert_null (run.flow.readout.buf);   /* pixels dropped */
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE_STOP);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);
  g_assert_cmpstr (run.wire->str, ==, "39+ 02 W 51 04 39- done ");
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_CANCELLED);
  a2_run_clear (&run);
}

/* Cancel while waiting for the match: no 04 (the image was read), 62 */
static void
test_a2_flow_cancel_match_wait (void)
{
  A2Run run;

  a2_run_init (&run, TRUE);
  a2_run_capture (&run, 0);
  a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
  a2_reply_handle (&run, 0x44);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
  fpi_validity_a2_flow_cancel (&run.flow);
  a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
  {
    static const guint8 want[] = { 0x62, 0x44, 0x00, 0x00, 0x00 };
    g_assert_cmpmem (a2_last_cmd (&run)->data, a2_last_cmd (&run)->len,
                     want, sizeof (want));
  }
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);
  g_assert_cmpstr (run.wire->str, ==,
                   "39+ 02 W W W W 51 51 5e M 62 39- done ");
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_CANCELLED);
  g_assert_cmpuint (run.flow.stops, ==, 0);
  a2_run_clear (&run);
}

/* A cancel after the match result skips the final read-only 4a */
static void
test_a2_flow_cancel_after_result (void)
{
  g_autoptr(GByteArray) result = a2_match_payload (8, 1, 7, -1, -1);
  A2Run run;

  a2_run_init (&run, TRUE);
  a2_run_capture (&run, 0);
  a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
  a2_reply_handle (&run, 1);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_MATCH_EVENT);
  a2_event5 (&run, 0x03, 0x00, 0x00, 0x00, 0xdb);
  a2_expect (&run, VALIDITY_A2_OP_GET_RESULT);
  fpi_validity_a2_flow_reply (&run.flow, 0, result->data, result->len);
  a2_expect (&run, VALIDITY_A2_OP_MATCH_CLEANUP);
  a2_ok (&run);
  fpi_validity_a2_flow_cancel (&run.flow);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_CANCELLED);
  a2_run_clear (&run);
}

/* Chip abort (event code 6): 04, then a new 02 after a delay */
static void
test_a2_flow_abort_rearm (void)
{
  A2Run run;
  guint delay = 0;

  a2_run_init (&run, TRUE);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_START);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (&run, 0x03, 0x00, 0x06, 0x00, 0x00);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE_STOP);
  a2_ok (&run);
  g_assert_cmpint (fpi_validity_a2_flow_next (&run.flow, &delay), ==,
                   VALIDITY_A2_OP_DELAY);
  g_assert_cmpuint (delay, ==, VALIDITY_A2_REARM_DELAY_MS);
  g_string_append (run.wire, "D ");

  /* the second capture goes through; the LED stays on */
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (&run, 0x03, 0x42, 0x04, 0x00, 0x40);
  a2_expect (&run, VALIDITY_A2_OP_READ_IMAGE);
  {
    g_autofree guint8 *frame = NULL;
    gsize frame_len;

    frame = a2_make_frame (112, 112, 8, 0, &frame_len);
    {
      g_autoptr(GByteArray) p = a2_read_payload (frame, 8192);
      fpi_validity_a2_flow_reply (&run.flow, 0, p->data, p->len);
    }
    a2_expect (&run, VALIDITY_A2_OP_READ_IMAGE);
    {
      g_autoptr(GByteArray) p = a2_read_payload (frame + 8192, 4364);
      fpi_validity_a2_flow_reply (&run.flow, 0, p->data, p->len);
    }
  }
  a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
  g_assert_cmpstr (run.wire->str, ==,
                   "39+ 02 W 04 D 02 W 51 51 5e ");
  g_assert_cmpuint (run.flow.captures, ==, 2);
  g_assert_cmpuint (run.flow.stops, ==, 1);
  g_assert_cmpuint (run.flow.silent_rearms, ==, 1);
  a2_run_clear (&run);
}

/* Readout status 4 (aborted): 04 and re-arm; status 1: poll again */
static void
test_a2_flow_readout_statuses (void)
{
  g_autofree guint8 *frame = NULL;
  gsize frame_len;
  guint delay = 0;
  A2Run run;

  frame = a2_make_frame (112, 112, 8, 0, &frame_len);

  a2_run_init (&run, TRUE);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_START);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (&run, 0x03, 0x42, 0x04, 0x00, 0x40);
  a2_expect (&run, VALIDITY_A2_OP_READ_IMAGE);
  fpi_validity_a2_flow_reply (&run.flow, 0x0001, NULL, 0);
  g_assert_cmpint (fpi_validity_a2_flow_next (&run.flow, &delay), ==,
                   VALIDITY_A2_OP_DELAY);
  g_assert_cmpuint (delay, ==, VALIDITY_A2_READ_POLL_DELAY_MS);
  a2_expect (&run, VALIDITY_A2_OP_READ_IMAGE);
  fpi_validity_a2_flow_reply (&run.flow, 0x0004, NULL, 0);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE_STOP);
  a2_ok (&run);
  g_assert_cmpint (fpi_validity_a2_flow_next (&run.flow, &delay), ==,
                   VALIDITY_A2_OP_DELAY);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
  g_assert_cmpuint (run.flow.captures, ==, 2);
  g_assert_cmpuint (run.flow.stops, ==, 1);
  a2_run_clear (&run);
}

/* Bad capture code: 04, 39 end, retry -- no silent loop */
static void
test_a2_flow_bad_capture (void)
{
  A2Run run;

  a2_run_init (&run, TRUE);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_START);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (&run, 0x02, 0x00, 0x40, 0x10, 0x00);
  a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
  a2_event5 (&run, 0x03, 0x00, 0x08, 0x00, 0x00);
  a2_expect (&run, VALIDITY_A2_OP_CAPTURE_STOP);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_RETRY);
  g_assert_cmpint (run.flow.retry, ==, FP_DEVICE_RETRY_GENERAL);
  a2_run_clear (&run);
}

/* A readout error stops the capture (04) and fails; so does a rejected
 * capture program; a malformed capture event too */
static void
test_a2_flow_capture_errors (void)
{
  for (gint variant = 0; variant < 3; variant++)
    {
      A2Run run;

      a2_run_init (&run, TRUE);
      a2_expect (&run, VALIDITY_A2_OP_GLOW_START);
      a2_ok (&run);
      a2_expect (&run, VALIDITY_A2_OP_CAPTURE);

      if (variant == 0)
        {
          fpi_validity_a2_flow_reply (&run.flow, 0x04d7, NULL, 0);
        }
      else
        {
          a2_ok (&run);
          a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
          if (variant == 1)
            {
              a2_event5 (&run, 0x03, 0x00, 0x04, 0x00, 0x00);
              a2_expect (&run, VALIDITY_A2_OP_READ_IMAGE);
              fpi_validity_a2_flow_reply (&run.flow, 0x0005, NULL, 0);
            }
          else
            {
              const guint8 short3[3] = { 0x03, 0x00, 0x04 };

              fpi_validity_a2_flow_event (&run.flow, short3, sizeof (short3));
            }
        }

      a2_expect (&run, VALIDITY_A2_OP_CAPTURE_STOP);
      a2_ok (&run);
      a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
      a2_ok (&run);
      a2_expect (&run, VALIDITY_A2_OP_DONE);
      g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_ERROR);
      g_assert_error (run.flow.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      a2_run_clear (&run);
    }
}

/* Empty images (0x0 header) re-arm silently a bounded number of times,
 * each after a 04, then the user is asked to retry */
static void
test_a2_flow_empty_bounded (void)
{
  g_autofree guint8 *frame = NULL;
  gsize frame_len;
  A2Run run;

  frame = a2_make_frame (0, 0, 8, 0x80000001, &frame_len);

  a2_run_init (&run, TRUE);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_START);
  a2_ok (&run);

  for (guint i = 0; i <= VALIDITY_A2_MAX_SILENT_REARMS; i++)
    {
      a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
      a2_ok (&run);
      a2_expect (&run, VALIDITY_A2_OP_WAIT_CAPTURE_EVENT);
      a2_event5 (&run, 0x03, 0x00, 0x04, 0x00, 0x00);
      a2_expect (&run, VALIDITY_A2_OP_READ_IMAGE);
      {
        g_autoptr(GByteArray) p = a2_read_payload (frame, frame_len);
        fpi_validity_a2_flow_reply (&run.flow, 0, p->data, p->len);
      }
      a2_expect (&run, VALIDITY_A2_OP_CAPTURE_STOP);
      a2_ok (&run);
      if (i < VALIDITY_A2_MAX_SILENT_REARMS)
        a2_expect (&run, VALIDITY_A2_OP_DELAY);
    }

  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_RETRY);
  g_assert_cmpuint (run.flow.captures, ==, VALIDITY_A2_MAX_SILENT_REARMS + 1);
  g_assert_cmpuint (run.flow.stops, ==, VALIDITY_A2_MAX_SILENT_REARMS + 1);
  a2_run_clear (&run);
}

/* Header flags after a complete readout: never a 04. Recapture flags
 * re-arm; 0x80000 is used under the vendor rule and rejected (retry)
 * under the strict rule. */
static void
test_a2_flow_image_flags (void)
{
  /* recapture */
  {
    A2Run run;

    a2_run_init (&run, TRUE);
    a2_run_capture (&run, 0x80200000);
    a2_expect (&run, VALIDITY_A2_OP_DELAY);
    a2_expect (&run, VALIDITY_A2_OP_CAPTURE);
    g_assert_cmpuint (run.flow.stops, ==, 0);
    a2_run_clear (&run);
  }

  /* vendor rule: used */
  {
    A2Run run;

    a2_run_init (&run, TRUE);
    a2_run_capture (&run, 0x00080000);
    a2_expect (&run, VALIDITY_A2_OP_MATCH_START);
    g_assert_cmphex (run.flow.header.flags, ==, 0x00080000);
    a2_run_clear (&run);
  }

  /* strict rule: retry, no 04 */
  {
    A2Run run;

    a2_run_init (&run, TRUE);
    run.flow.flags_rule = VALIDITY_A2_FLAGS_RULE_STRICT;
    a2_run_capture (&run, 0x00080000);
    a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
    a2_ok (&run);
    a2_expect (&run, VALIDITY_A2_OP_DONE);
    g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_RETRY);
    g_assert_cmpuint (run.flow.stops, ==, 0);
    a2_run_clear (&run);
  }
}

/* Image capture only: no 5e; the 112x112 pixels are kept for the caller
 * until the flow is cleared, which zeroes them */
static void
test_a2_flow_capture_only (void)
{
  const guint8 *px;
  gsize n = 0;
  A2Run run;

  a2_run_init (&run, FALSE);
  a2_run_capture (&run, 0);
  a2_expect (&run, VALIDITY_A2_OP_GLOW_END);
  a2_ok (&run);
  a2_expect (&run, VALIDITY_A2_OP_DONE);
  g_assert_cmpstr (run.wire->str, ==, "39+ 02 W W W W 51 51 39- done ");
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_IMAGE);
  g_assert_cmpuint (run.flow.header.rows, ==, 112);
  g_assert_cmpuint (run.flow.header.cols, ==, 112);
  g_assert_cmpuint (run.flow.header.resolution, ==, 333);

  px = fpi_validity_a2_readout_pixels (&run.flow.readout, &n);
  g_assert_nonnull (px);
  g_assert_cmpuint (n, ==, 112 * 112);
  for (gsize i = 0; i < n; i++)
    g_assert_cmpuint (px[i], ==, a2_pixel (i));

  /* a cancel that lands in the cleanup turns the result into a cancel */
  fpi_validity_a2_flow_cancel (&run.flow);
  g_assert_cmpint (run.flow.outcome, ==, VALIDITY_A2_OUTCOME_CANCELLED);

  a2_run_clear (&run);
}

/* The bytes of every command the flow sends; 39 is MR's LED pattern */
static void
test_a2_flow_commands (void)
{
  ValidityA2Flow flow;
  const guint8 *glow;
  gsize len = 0, glow_len = 0;
  guint8 *cmd;

  fpi_validity_a2_flow_init (&flow, TRUE, VALIDITY_A2_FLAGS_RULE_WINDOWS);
  flow.match_handle = 0xa1b2c3d4;

  cmd = fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_READ_IMAGE, &len);
  g_assert_cmpmem (cmd, len, "\x51\x00\x20\x00\x00", 5);
  g_free (cmd);

  cmd = fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_CAPTURE_STOP, &len);
  g_assert_cmpmem (cmd, len, "\x04", 1);
  g_free (cmd);

  /* identical to the generic flow's match_finger (bbbhhhhh) */
  {
    gsize mr_len = 0;
    g_autofree guint8 *mr = validity_pack_new (&mr_len, "bbbhhhhh", 0x5e,
                                               0x02, 0xff, 0, 0, 1, 0, 0);

    cmd = fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_MATCH_START, &len);
    g_assert_cmpmem (cmd, len, mr, mr_len);
    g_free (cmd);
  }

  cmd = fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_GET_RESULT, &len);
  g_assert_cmpmem (cmd, len, "\x60\xd4\xc3\xb2\xa1", 5);
  g_free (cmd);

  cmd = fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_MATCH_CLEANUP, &len);
  g_assert_cmpmem (cmd, len, "\x62\xd4\xc3\xb2\xa1", 5);
  g_free (cmd);

  glow = fpi_validity_capture_glow_start_cmd (&glow_len);
  cmd = fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_GLOW_START, &len);
  g_assert_cmpuint (len, ==, 125);
  g_assert_cmpmem (cmd, len, glow, glow_len);
  g_free (cmd);

  glow = fpi_validity_capture_glow_end_cmd (&glow_len);
  cmd = fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_GLOW_END, &len);
  g_assert_cmpmem (cmd, len, glow, glow_len);
  g_free (cmd);

  /* user record ids above 16 bits cannot be read back */
  flow.result.user_dbid = 0x10000;
  g_assert_null (fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_GET_USER,
                                                 &len));
  /* 02 is built by the driver from the calibration */
  g_assert_null (fpi_validity_a2_flow_build_cmd (&flow, VALIDITY_A2_OP_CAPTURE,
                                                 &len));
  g_assert_null (fpi_validity_a2_flow_build_cmd (&flow,
                                                 VALIDITY_A2_OP_WAIT_CAPTURE_EVENT,
                                                 &len));
  fpi_validity_a2_flow_clear (&flow);
}

/* Over every scripted flow above, the set of opcodes is RO/VOL only:
 * 39, 02, 51, 04, 5e, 60, 62, 4a. Check the builder never produces any
 * other first byte for any op. */
static void
test_a2_flow_opcode_inventory (void)
{
  static const guint8 allowed[] = { 0x39, 0x51, 0x04, 0x5e, 0x60, 0x62, 0x4a };
  ValidityA2Flow flow;

  fpi_validity_a2_flow_init (&flow, TRUE, VALIDITY_A2_FLAGS_RULE_WINDOWS);
  flow.result.user_dbid = 3;

  for (gint op = VALIDITY_A2_OP_NONE; op <= VALIDITY_A2_OP_DONE; op++)
    {
      gsize len = 0;
      g_autofree guint8 *cmd = fpi_validity_a2_flow_build_cmd (&flow, op, &len);

      if (!cmd)
        continue;
      g_assert_cmpuint (len, >, 0);
      g_assert_nonnull (memchr (allowed, cmd[0], sizeof (allowed)));
    }
  fpi_validity_a2_flow_clear (&flow);
}

/* --- sensor gate (open) --- */

static void
a2_make_capture_state (ValidityCaptureState *c)
{
  static const guint8 prog[4] = { 0 };

  memset (c, 0, sizeof (*c));
  c->capture_prog = prog;
  c->capture_prog_len = sizeof (prog);
  c->is_type1_device = TRUE;
  c->bytes_per_line = 0x78;
  c->lines_per_frame = 224;
  c->key_calibration_line = 0x38;
  c->calibration_frames = 3;
  c->calibration_iterations = 3;
  c->factory_calibration_values = g_malloc0 (112);
  c->factory_calibration_values_len = 112;
  c->calib_data = g_malloc0 (112 * 0x78);
  c->calib_data_len = 112 * 0x78;
}

static void
test_a2_sensor_gate (void)
{
  ValidityCaptureState c;

  g_autoptr(GError) error = NULL;

  a2_make_capture_state (&c);
  g_assert_cmpint (fpi_validity_a2_check_sensor (0x199, 0x199, &c, TRUE), ==,
                   VALIDITY_A2_SENSOR_OK);
  g_assert_true (fpi_validity_a2_sensor_gate (0x199, 0x199, &c, TRUE, &error));
  g_assert_no_error (error);

  g_assert_cmpint (fpi_validity_a2_check_sensor (0, 0, &c, FALSE), ==,
                   VALIDITY_A2_SENSOR_UNKNOWN);
  /* FM-3380-001 rev 0x5f resolves to type 0xb5 (never run on 00a2) */
  g_assert_cmpint (fpi_validity_a2_check_sensor (0xb5, 0xb5, &c, FALSE), ==,
                   VALIDITY_A2_SENSOR_WRONG_TYPE);
  /* 0x199 profile on 0x969 silicon */
  g_assert_cmpint (fpi_validity_a2_check_sensor (0x199, 0x969, &c, FALSE), ==,
                   VALIDITY_A2_SENSOR_WRONG_TYPE);
  g_assert_cmpint (fpi_validity_a2_check_sensor (0x199, 0x199, NULL, FALSE), ==,
                   VALIDITY_A2_SENSOR_NO_CAPTURE_PROG);

  c.lines_per_frame = 112;
  g_assert_cmpint (fpi_validity_a2_check_sensor (0x199, 0x199, &c, FALSE), ==,
                   VALIDITY_A2_SENSOR_WRONG_GEOMETRY);
  c.lines_per_frame = 224;
  c.key_calibration_line = 0x2a;
  g_assert_cmpint (fpi_validity_a2_check_sensor (0x199, 0x199, &c, FALSE), ==,
                   VALIDITY_A2_SENSOR_WRONG_GEOMETRY);
  c.key_calibration_line = 0x38;

  c.factory_calibration_values_len = 0x38;
  g_assert_cmpint (fpi_validity_a2_check_sensor (0x199, 0x199, &c, FALSE), ==,
                   VALIDITY_A2_SENSOR_NO_FACTORY_CAL);
  c.factory_calibration_values_len = 112;

  g_clear_pointer (&c.calib_data, g_free);
  c.calib_data_len = 0;
  g_assert_cmpint (fpi_validity_a2_check_sensor (0x199, 0x199, &c, FALSE), ==,
                   VALIDITY_A2_SENSOR_OK);
  g_assert_cmpint (fpi_validity_a2_check_sensor (0x199, 0x199, &c, TRUE), ==,
                   VALIDITY_A2_SENSOR_NOT_CALIBRATED);
  g_assert_false (fpi_validity_a2_sensor_gate (0x199, 0x199, &c, TRUE, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);

  c.capture_prog = NULL;
  fpi_validity_capture_state_clear (&c);
}

/* The real (0x190, 0x6a) identity of the E480 sensor resolves to type
 * 0x199, and capture setup for ROM 6.7 gives the geometry the gate wants */
static void
test_a2_sensor_gate_real_setup (void)
{
  const ValidityDeviceInfo *info = fpi_validity_device_info_lookup (0x0190, 0x006a);
  const ValiditySensorTypeInfo *type_info;
  ValidityCaptureState c;

  g_assert_nonnull (info);
  g_assert_cmphex (info->type, ==, 0x0199);
  type_info = fpi_validity_sensor_type_info_lookup (info->type);
  g_assert_nonnull (type_info);

  fpi_validity_capture_state_init (&c);
  g_assert_true (fpi_validity_capture_state_setup (&c, type_info, info->type,
                                                   6, 7, NULL, 0));
  /* no factory bits given here: only that check fails */
  g_assert_cmpint (fpi_validity_a2_check_sensor (info->type, info->type, &c, FALSE),
                   ==, VALIDITY_A2_SENSOR_NO_FACTORY_CAL);
  c.factory_calibration_values = g_malloc0 (112);
  c.factory_calibration_values_len = 112;
  g_assert_cmpint (fpi_validity_a2_check_sensor (info->type, info->type, &c, FALSE),
                   ==, VALIDITY_A2_SENSOR_OK);
  fpi_validity_capture_state_clear (&c);
}

/* Image capture: the vfunc exists only in developer builds */
static void
test_a2_capture_vfunc_dev_only (void)
{
  FpDeviceClass *klass = g_type_class_ref (FPI_TYPE_DEVICE_VALIDITY);

  g_assert_true ((klass->capture != NULL) == fpi_validity_dev_overrides_built ());
  g_assert_true (((klass->features & FP_DEVICE_FEATURE_CAPTURE) != 0) ==
                 fpi_validity_dev_overrides_built ());
  g_type_class_unref (klass);

  g_assert_true (fpi_validity_device_policy (VALIDITY_DEV_A2)->allow_image_capture);
  g_assert_false (fpi_validity_device_policy (VALIDITY_DEV_9A)->allow_image_capture);
}
