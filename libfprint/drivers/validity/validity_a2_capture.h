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

#pragma once

#include <glib.h>
#include "fp-device.h"
#include "validity_db.h"

/* ================================================================
 * EP 0x83 interrupt reports
 *
 * The sensor sends 5-byte reports. During a capture byte 0 is the event
 * type (0 program started, 2 finger down, 3 capture status); a type-3
 * report carries a u16 LE status code in bytes 2..3. During a match the
 * whole report is decoded differently: bytes 0..1 are a u16 LE match code.
 * ================================================================ */

typedef enum {
  VALIDITY_A2_CAPT_EV_MALFORMED = 0, /* empty, or type 3 shorter than 4 B */
  VALIDITY_A2_CAPT_EV_START,         /* type 0: capture program started */
  VALIDITY_A2_CAPT_EV_FINGER_DOWN,   /* type 2 */
  VALIDITY_A2_CAPT_EV_WAIT,          /* type 3, code 1, 2, 3, 5 or 9 */
  VALIDITY_A2_CAPT_EV_READY,         /* type 3, code 4 or 7: image ready */
  VALIDITY_A2_CAPT_EV_ABORT,         /* type 3, code 6: the chip aborted */
  VALIDITY_A2_CAPT_EV_BAD,           /* type 3, code 0, 8 or >= 10 */
  VALIDITY_A2_CAPT_EV_OTHER,         /* any other type: keep waiting */
} ValidityA2CaptureEvent;

/* @out_code (optional): the type-3 code, 0 for other types */
ValidityA2CaptureEvent fpi_validity_a2_classify_capture_event (const guint8 *buf,
                                                               gsize         len,
                                                               guint16      *out_code);

typedef enum {
  VALIDITY_A2_MATCH_EV_MALFORMED = 0, /* shorter than 2 bytes */
  VALIDITY_A2_MATCH_EV_PENDING,       /* code 0, 1, 2: keep waiting */
  VALIDITY_A2_MATCH_EV_MATCH,         /* code 3 */
  VALIDITY_A2_MATCH_EV_NO_MATCH,      /* code 4; byte 2 = templates compared */
  VALIDITY_A2_MATCH_EV_ERROR,         /* code 5; bytes 2..3 = chip status */
  VALIDITY_A2_MATCH_EV_OTHER_DONE,    /* any other code: read the result */
  VALIDITY_A2_MATCH_EV_STALE,         /* 03 xx with xx != 0: a capture-phase
                                       * type-3 report still queued, not a
                                       * match code; keep waiting */
} ValidityA2MatchEvent;

/* @out_code (optional): the u16 code. @out_detail (optional): templates
 * compared (NO_MATCH) or the chip status (ERROR), else 0. */
ValidityA2MatchEvent fpi_validity_a2_classify_match_event (const guint8 *buf,
                                                           gsize         len,
                                                           guint16      *out_code,
                                                           guint16      *out_detail);

/* ================================================================
 * Image readout (51)
 *
 * After "image ready" the host sends 51 <u32 LE max_len> until the image
 * is in. Each reply is status u16 | len u32 LE | len bytes (0 < len <=
 * max_len); a shorter chunk does not end the image.
 * The first chunk starts with a 12-byte header: rows u16, cols u16,
 * resolution u16 (333), bpp u8 (8), pad u8, flags u32. 00a2 sends 112x112
 * 8-bit pixels: 12 + 12544 bytes, i.e. chunks of 8192 + 4364 bytes.
 * ================================================================ */

#define VALIDITY_A2_IMAGE_HEADER_LEN 12
#define VALIDITY_A2_IMAGE_ROWS 112
#define VALIDITY_A2_IMAGE_COLS 112
#define VALIDITY_A2_IMAGE_BPP 8

/* max_len of every 51 request (51 00 20 00 00) */
#define VALIDITY_A2_READ_CHUNK_MAX 0x2000
/* data chunks per image (two were seen; shorter chunks are read on) */
#define VALIDITY_A2_READ_MAX_CHUNKS 9
/* "not ready yet" replies (status 1 or 7) tolerated per image */
#define VALIDITY_A2_READ_MAX_POLLS 10
#define VALIDITY_A2_READ_POLL_DELAY_MS 20
/* the vendor driver's limit for header + image */
#define VALIDITY_A2_READ_MAX_TOTAL (VALIDITY_A2_IMAGE_HEADER_LEN + 0x15000)

/* 51 reply statuses other than 0 */
#define VALIDITY_A2_READ_STATUS_NOT_READY 0x0001
#define VALIDITY_A2_READ_STATUS_ABORTED 0x0004
#define VALIDITY_A2_READ_STATUS_READY 0x0007

#define VALIDITY_A2_IMAGE_FLAG_BIT31 0x80000000u
#define VALIDITY_A2_IMAGE_FLAG_BIT21 0x00200000u

typedef struct
{
  guint16 rows;
  guint16 cols;
  guint16 resolution;   /* 333 on 00a2 (taken as dpi) */
  guint8  bpp;
  guint32 flags;
} ValidityA2ImageHeader;

/* Parse the 12-byte header at the start of @data. FALSE if @len < 12. */
gboolean fpi_validity_a2_parse_image_header (const guint8          *data,
                                             gsize                  len,
                                             ValidityA2ImageHeader *out);

/* How to judge the header's flags word.
 * WINDOWS: what the vendor driver does: bit 31 together with bit 21 means
 *   recapture; bit 31 alone is a capture-quality error; any other value
 *   (no bit 31: 0x80000, 0x8080000, 0x8000000 were seen on 00a2) is
 *   logged and the image is used.
 * STRICT: python-validity PR #261: any non-zero value is an error (bit 31
 *   with bit 21 still means recapture). */
typedef enum {
  VALIDITY_A2_FLAGS_RULE_WINDOWS = 0,
  VALIDITY_A2_FLAGS_RULE_STRICT,
} ValidityA2FlagsRule;

typedef enum {
  VALIDITY_A2_FLAGS_USE = 0,
  VALIDITY_A2_FLAGS_RECAPTURE,
  VALIDITY_A2_FLAGS_REJECT,
} ValidityA2FlagsVerdict;

ValidityA2FlagsVerdict fpi_validity_a2_image_flags_verdict (guint32             flags,
                                                            ValidityA2FlagsRule rule);

typedef enum {
  VALIDITY_A2_READOUT_MORE = 0, /* send the next 51 */
  VALIDITY_A2_READOUT_POLL,     /* not ready yet: send the same 51 again */
  VALIDITY_A2_READOUT_DONE,     /* header and rows*cols pixels are in */
  VALIDITY_A2_READOUT_EMPTY,    /* the header reports no image (0 rows/cols) */
  VALIDITY_A2_READOUT_ABORTED,  /* the chip aborted the capture (status 4) */
  VALIDITY_A2_READOUT_ERROR,    /* malformed or unexpected reply */
} ValidityA2ReadoutStep;

typedef struct
{
  guint8               *buf;          /* header + pixels, zeroed on clear */
  gsize                 len;
  guint                 chunks;       /* status-0 replies */
  guint                 polls;        /* status 1/7 replies */
  gboolean              have_header;
  ValidityA2ImageHeader header;
} ValidityA2Readout;

void fpi_validity_a2_readout_init (ValidityA2Readout *r);
/* Zero and free the pixels; the struct can be fed again after init */
void fpi_validity_a2_readout_clear (ValidityA2Readout *r);

/* Feed one 51 reply: @status and the payload after the status word.
 * ERROR sets @error (FP_DEVICE_ERROR_PROTO). */
ValidityA2ReadoutStep fpi_validity_a2_readout_feed (ValidityA2Readout *r,
                                                    guint16            status,
                                                    const guint8      *payload,
                                                    gsize              payload_len,
                                                    GError           **error);

/* The rows*cols pixels of a DONE readout (row-major), or NULL */
const guint8 *fpi_validity_a2_readout_pixels (const ValidityA2Readout *r,
                                              gsize                   *out_len);

/* ================================================================
 * Match result (60)
 *
 * Reply payload: u16 total_len, then a TLV list tag u16 | len u16 | value.
 * Known tags and their fixed lengths: 1 (4, user record dbid), 2 (4, must
 * be non-zero for a match), 3 (2, finger subtype), 4 (32), 5 (32), 7 (16),
 * 8 (2). Tag 6 and unknown tags are skipped. The vendor driver rejects a
 * wrong length; so does this parser. A result is a match only with tag 1,
 * tag 3 and a non-zero tag 2. @result is overwritten without being freed
 * (clear it first if it holds a result); after a failure it is empty.
 * ================================================================ */
gboolean fpi_validity_a2_parse_match_result (const guint8        *data,
                                             gsize                data_len,
                                             ValidityMatchResult *result,
                                             GError             **error);

/* ================================================================
 * Capture / match flow
 *
 * A pure state machine with no I/O: the caller asks for the next
 * operation, performs it (a command over TLS, an EP 0x83 read, a delay)
 * and feeds the reply, report, cancellation or timeout back. The driver's
 * SSM (fpi_validity_a2_verify.c) and the unit tests both drive it, so the
 * wire sequence is testable without a device.
 *
 * Wire flow (match = TRUE):
 *   39 glow start, 02 IDENTIFY program, EP 0x83 events until "image
 *   ready", 51 00200000 until the image is in (no 04 after a complete
 *   readout), 5e 02 ff 0000 0000 0100 00000000 -> handle h, EP 0x83 match
 *   event, 60 <h> on a match, 62 <h> always once 5e was sent, 39 glow
 *   end, 4a <user> (read-only) if the chip named a user record.
 * With match = FALSE the flow stops after the readout (39 glow end) and
 * keeps the image.
 *
 * 04 (capture stop) is sent only for a capture that was started and not
 * fully read: chip abort, bad capture code, empty image, readout error,
 * cancel. Every command in the flow is volatile or read-only.
 * ================================================================ */

typedef enum {
  VALIDITY_A2_OP_NONE = 0,
  VALIDITY_A2_OP_GLOW_START,          /* 39 <start pattern> */
  VALIDITY_A2_OP_CAPTURE,             /* 02 IDENTIFY program (caller builds it) */
  VALIDITY_A2_OP_WAIT_CAPTURE_EVENT,  /* EP 0x83, no timeout, cancellable */
  VALIDITY_A2_OP_READ_IMAGE,          /* 51 00200000 */
  VALIDITY_A2_OP_CAPTURE_STOP,        /* 04 */
  VALIDITY_A2_OP_MATCH_START,         /* 5e 02 ff 0000 0000 0100 00000000 */
  VALIDITY_A2_OP_WAIT_MATCH_EVENT,    /* EP 0x83, bounded by the caller */
  VALIDITY_A2_OP_GET_RESULT,          /* 60 <h> */
  VALIDITY_A2_OP_MATCH_CLEANUP,       /* 62 <h> */
  VALIDITY_A2_OP_GLOW_END,            /* 39 <end pattern> */
  VALIDITY_A2_OP_GET_USER,            /* 4a <tag 1> 0000 0000 */
  VALIDITY_A2_OP_DELAY,               /* wait, then ask again */
  VALIDITY_A2_OP_DONE,
} ValidityA2Op;

typedef enum {
  VALIDITY_A2_OUTCOME_NONE = 0,
  VALIDITY_A2_OUTCOME_IMAGE,      /* match = FALSE: the image is in */
  VALIDITY_A2_OUTCOME_MATCH,      /* the chip matched; see result + user */
  VALIDITY_A2_OUTCOME_NO_MATCH,
  VALIDITY_A2_OUTCOME_RETRY,      /* ask the user to scan again (retry) */
  VALIDITY_A2_OUTCOME_CANCELLED,
  VALIDITY_A2_OUTCOME_ERROR,      /* see error */
} ValidityA2Outcome;

/* Silent re-arms per action (chip abort, empty image, recapture flags)
 * before the flow asks the user to retry */
#define VALIDITY_A2_MAX_SILENT_REARMS 3
#define VALIDITY_A2_REARM_DELAY_MS 300
/* How long the match event may take (the vendor driver waits 10 s) */
#define VALIDITY_A2_MATCH_TIMEOUT_MS 10000

typedef struct
{
  /* configuration */
  gboolean            match;
  ValidityA2FlagsRule flags_rule;

  /* sequencing */
  ValidityA2Op next_op;      /* op the next fpi_validity_a2_flow_next() issues */
  ValidityA2Op after_delay;  /* op that follows a DELAY */
  ValidityA2Op issued;       /* op in flight, awaiting its reply or report */
  guint        delay_ms;
  gboolean     finishing;    /* cleanup tail: 04, 62, 39 end, 4a, DONE */
  gboolean     rearm_after_stop;

  /* sensor-side state the cleanup depends on */
  gboolean glow_on;
  gboolean capture_armed;    /* 02 sent, its image not fully read */
  gboolean match_open;       /* 5e sent, 62 not yet */
  guint32  match_handle;     /* u32 reply of 5e, passed to 60 and 62 */
  gboolean finger_present;

  /* counters (logging and tests) */
  guint                 captures; /* 02 sent */
  guint                 stops; /* 04 sent */
  guint                 silent_rearms;

  ValidityA2Readout     readout;
  ValidityA2ImageHeader header;   /* of the last complete readout */

  /* result */
  ValidityA2Outcome   outcome;
  FpDeviceRetry       retry;
  GError             *error;
  ValidityMatchResult result;     /* parsed 60 reply */
  ValidityUser        user;       /* 4a reply for result.user_dbid */
  gboolean            user_read;
  gboolean            user_requested;
} ValidityA2Flow;

void fpi_validity_a2_flow_init (ValidityA2Flow     *flow,
                                gboolean            match,
                                ValidityA2FlagsRule flags_rule);

/* Free everything; pixels are zeroed first */
void fpi_validity_a2_flow_clear (ValidityA2Flow *flow);

/* The operation to perform now. Command ops are counted as sent from here
 * on (e.g. CAPTURE arms the capture, CAPTURE_STOP disarms it). For DELAY,
 * @delay_ms (optional) gets the delay; call again once it has passed. */
ValidityA2Op fpi_validity_a2_flow_next (ValidityA2Flow *flow,
                                        guint          *delay_ms);

/* The reply to the command op last returned: status and the payload after
 * the status word */
void fpi_validity_a2_flow_reply (ValidityA2Flow *flow,
                                 guint16         status,
                                 const guint8   *data,
                                 gsize           data_len);

/* An EP 0x83 report for the WAIT_* op last returned */
void fpi_validity_a2_flow_event (ValidityA2Flow *flow,
                                 const guint8   *buf,
                                 gsize           len);

/* The action was cancelled: clean up (04 / 62 / 39 end) and end CANCELLED.
 * Ignored once the flow is cleaning up after another outcome, except that
 * it skips the final read-only 4a. */
void fpi_validity_a2_flow_cancel (ValidityA2Flow *flow);

/* The match event did not arrive in time: clean up and end with an error */
void fpi_validity_a2_flow_timeout (ValidityA2Flow *flow);

/* An EP 0x83 wait failed with a transport error while the device is still
 * there (the interrupt pipe, not the TLS session): clean up (04 / 62 / 39
 * end) and end with @error (taken). Ignored, @error dropped, once the
 * flow is already cleaning up. */
void fpi_validity_a2_flow_transport_error (ValidityA2Flow *flow,
                                           GError         *error);

/* Wire bytes of a command op (every op but CAPTURE, whose program the
 * caller builds from the calibration). NULL for a non-command op. */
guint8 *fpi_validity_a2_flow_build_cmd (const ValidityA2Flow *flow,
                                        ValidityA2Op          op,
                                        gsize                *out_len);

const gchar *fpi_validity_a2_op_name (ValidityA2Op op);

/* ================================================================
 * Driver entry points (fpi_validity_a2_verify.c), used when the device
 * policy has stream_capture_flow
 * ================================================================ */
void fpi_validity_a2_verify (FpDevice *device);
void fpi_validity_a2_identify (FpDevice *device);

/* FpDevice::capture: developer builds and allow_image_capture only */
void fpi_validity_a2_capture (FpDevice *device);

/* Internal enrollment capture. The callback consumes @error; @flow and its
 * pixels are borrowed only for the duration of the callback. Uses the ENROLL
 * capture program and the same event/readout/cleanup flow as diagnostics. */
typedef void (*ValidityA2CaptureDone) (FpDevice       *device,
                                       ValidityA2Flow *flow,
                                       GError         *error,
                                       gpointer        user_data);
void fpi_validity_a2_capture_enroll (FpDevice             *device,
                                     ValidityA2CaptureDone done,
                                     gpointer              user_data);
void fpi_validity_a2_enroll (FpDevice *device);
