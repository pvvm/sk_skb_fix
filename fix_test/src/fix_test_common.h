/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fix_test -- SK_SKB receive path on a stock kernel with the sockmap/strparser
 * fixes applied (see ../apply_fixes.sh). Cut down from q1: SK_SKB only, three
 * access styles, three accessed areas, RO or RW, no work loop, and time inside
 * the BPF programs as the measurement. The client only sends.
 *
 * Shared between the BPF programs (fix_test.bpf.c), the receiver
 * (fix_test_loader.c) and the load generator (fix_test_client.c).
 */
#ifndef _FIX_TEST_COMMON_H
#define _FIX_TEST_COMMON_H

#ifndef __u8
#include <linux/types.h>
#endif

/* ---------------------------------------------------------------------------
 * Wire format -- set by fix_test_client.c, assumed by the parser.
 *
 *   byte 0      message type, opaque ('Q')
 *   bytes 1..4  little-endian u32 "length"; counts ITSELF but not byte 0
 *   bytes 5..8  little-endian u32 sequence number, from 0 on the connection
 *   total       length + 1
 * ------------------------------------------------------------------------ */
#define FT_HEAD_SIZE		5
#define FT_SEQ_OFF		5

/* Largest message the sweep uses, and the size of the copy-out buffer the
 * LOAD and DYNPTR styles own.
 */
#define FT_ACCESS_MAX		16384

/* The verifier will not give a direct-access range to a packet pointer whose
 * variable offset can reach past MAX_PACKET_OFF (0xffff), so the PULL style
 * can only reach a message whose offset in the strparser head satisfies
 * off + access_len + 1 <= 0xffff. Messages past that are skipped and counted
 * (ST_OFF_LIMIT), and the run is marked invalid.
 */
#define FT_PKT_OFF_CEIL		0xfffeU

/* How the program reaches the bytes. */
enum ft_style {
	FT_STYLE_PULL	= 1,	/* bpf_skb_pull_data()                    */
	FT_STYLE_LOAD	= 2,	/* bpf_skb_load_bytes() into a map buffer */
	FT_STYLE_DYNPTR	= 3,	/* bpf_dynptr_slice{,_rdwr}()             */
};

/* How much of the message the program touches. */
enum ft_area {
	FT_AREA_HEADER	= 0,	/* the 5-byte header only */
	FT_AREA_HALF	= 1,	/* 50% of the message     */
	FT_AREA_FULL	= 2,	/* the whole message      */
};

enum ft_mode {
	FT_RO		= 0,
	FT_RW		= 1,	/* also write one byte, observably */
};

/* Byte written in RW mode. The client builds every message out of printable
 * ASCII plus one terminating NUL, so any 0xA5 in a delivered message came from
 * the BPF program, and a missing one means the write-back failed.
 */
#define FT_SENTINEL		0xA5

struct ft_cfg {
	__u32	style;		/* enum ft_style -- loader only */
	__u32	area;		/* enum ft_area  -- reporting   */
	__u32	mode;		/* enum ft_mode  -- loader only */
	__u32	msg_size;	/* wire bytes per message       */

	/* Bytes of each message the program touches. A .rodata constant, so
	 * the verifier folds it -- which is what lets it be the buffer__szk
	 * argument of bpf_dynptr_slice(), which must be constant.
	 */
	__u32	access_len;

	/* Offset within the message of the byte RW mode writes. Derived by
	 * the loader -- see ft_wr_off().
	 */
	__u32	wr_off;

	__u32	sentinel;	/* FT_SENTINEL */
	__u32	pad;
};

/* Bytes of a @msg_size message that area @area covers. */
static inline __u32 ft_access_len(__u32 msg_size, __u32 area)
{
	switch (area) {
	case FT_AREA_HEADER:	return FT_HEAD_SIZE;
	case FT_AREA_HALF:	return msg_size / 2;
	default:		return msg_size;
	}
}

/* Where RW mode writes: the second-to-last byte of the accessed area, except
 * for the 5-byte header area, whose second-to-last byte is inside the length
 * field; there it writes byte 0 (the opaque type byte) instead. Same rule as
 * q1, including its 24-byte floor.
 */
static inline __u32 ft_wr_off(__u32 access_len)
{
	return access_len >= 24 ? access_len - 2 : 0;
}

/* Per-CPU counters, summed by the loader over the measurement window. */
enum ft_stat {
	ST_PARSE_CALLS,		/* parser invocations                         */
	ST_PARSE_FRAMED,	/* parser returned a length                   */
	ST_PARSE_NEEDMORE,	/* parser returned 0, header not yet complete */
	ST_PARSE_ERR,		/* load of the header failed                  */
	ST_PARSE_DESYNC,	/* header at read_offset was not a header     */
	ST_RESYNC_FAIL,		/* verdict could not place the message        */

	ST_RUN_CALLS,		/* verdict invocations                        */
	ST_RUN_MSGS,		/* messages the verdict completed             */
	ST_ACCESS_BYTES,	/* bytes the accessed area asked for          */

	ST_HEADS,		/* verdicts with the message at offset 0      */
	ST_HEAD_LEN,		/* sum of skb->len at those                   */

	ST_WR_OK,		/* sentinel written                           */
	ST_WR_FAIL,		/* write-back helper returned an error        */

	ST_DYN_DIRECT,		/* dynptr: direct pointer, no copy            */
	ST_DYN_COPY,		/* dynptr: copied into our buffer             */
	ST_DYN_NULL,		/* slice returned NULL -- run INVALID         */

	ST_OFF_LIMIT,		/* message past the direct-access ceiling     */
	ST_ERR,			/* pull/load/bounds failure -- run INVALID    */
	ST_MAX
};

#define FT_STAT_NAMES {							\
	"parse_calls", "parse_framed", "parse_needmore", "parse_err",	\
	"parse_desync", "resync_fail",					\
	"run_calls", "run_msgs", "access_bytes",			\
	"heads", "head_len",						\
	"wr_ok", "wr_fail",						\
	"dyn_direct", "dyn_copy", "dyn_null",				\
	"off_limit", "err" }

/* SO_RCVBUF set on the accepted socket before the sockmap attach (the kernel
 * stores twice this, so 1 MB). Fixed, so every run sees the same window.
 */
#define FT_RCVBUF		(512 << 10)

#define FT_PORT			9998

#endif /* _FIX_TEST_COMMON_H */
