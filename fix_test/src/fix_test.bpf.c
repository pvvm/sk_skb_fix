/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fix_test -- the SK_SKB programs from q1, alone. The loader autoloads the
 * parser plus exactly one verdict and folds the cell's configuration into
 * .rodata before load.
 *
 *   SEC("sk_skb/stream_parser")   ft_skskb_parser        framing, identical for
 *                                                        all three styles
 *   SEC("sk_skb/stream_verdict")  ft_verdict_pull_{ro,rw}
 *                                 ft_verdict_load_{ro,rw}
 *                                 ft_verdict_dynptr_{ro,rw}
 *
 * Six separate verdict programs rather than one with a .rodata switch: the
 * verifier adds an unclone prologue (bpf_skb_pull_data(skb, 0)) to any sk_skb
 * program that performs a direct packet write, and on the strparser path the
 * skb is always a clone, so that prologue reallocates the head on every run.
 * It is a property of the PROGRAM, so one program holding all three styles
 * would make LOAD -- which never writes directly -- pay for PULL's.
 *
 * The message offset in the strparser head comes from the bpf_skb_offset()
 * kfunc, as in q1. A kernel without it fails the load with "extern (func
 * ksym) 'bpf_skb_offset': not found".
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

#include "fix_test_common.h"

/* Folded before load by fix_test_loader.c, so every field the programs read
 * is a verifier constant -- access_len must be one, as bpf_dynptr_slice()'s
 * buffer__szk.
 */
const volatile struct ft_cfg cfg = {
	.style		= FT_STYLE_PULL,
	.area		= FT_AREA_FULL,
	.mode		= FT_RO,
	.msg_size	= 128,
	.access_len	= 128,
	.wr_off		= 126,
	.sentinel	= FT_SENTINEL,
};

extern int bpf_skb_offset(struct __sk_buff *ctx) __ksym;

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
			       struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, __u32 offset,
			      void *buffer__opt, __u32 buffer__szk) __ksym;
extern void *bpf_dynptr_slice_rdwr(const struct bpf_dynptr *p, __u32 offset,
				   void *buffer__opt, __u32 buffer__szk) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} sock_map_rx SEC(".maps");

/* All counters in ONE map value, looked up once per program run. */
struct ft_stats {
	__u64 v[ST_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ft_stats);
} stats SEC(".maps");

/* Copy-out destination for LOAD and bounce buffer for DYNPTR. A map rather
 * than the stack because the stack is 512 bytes and the sweep goes to 16 KB.
 */
struct ft_buf {
	__u8 b[FT_ACCESS_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ft_buf);
} buf_map SEC(".maps");

/* SK_SKB framing state: the parser stores the message's offset in the head
 * (from bpf_skb_offset()) for the verdict.
 */
struct ft_msg_state {
	__u32	read_offset;
	__u32	found_seq;	/* sequence number seen at read_offset by the parser */
	__u8	desync;		/* the header at read_offset did not look like one */
	__u8	have_seq;	/* the parser managed to read one for this message  */
	__u8	pad[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ft_msg_state);
} msg_map SEC(".maps");

static __always_inline struct ft_stats *ft_stats_get(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&stats, &zero);
}

#define STAT(S, k, n)	do { if (S) (S)->v[k] += (n); } while (0)

/* ---------------------------------------------------------------------------
 * Parser -- identical for all three access styles. Reads only the header,
 * through bpf_skb_load_bytes(), whatever the verdict goes on to do.
 * ------------------------------------------------------------------------ */
SEC("sk_skb/stream_parser")
int ft_skskb_parser(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct ft_msg_state *m = bpf_map_lookup_elem(&msg_map, &key);
	struct ft_stats *S = ft_stats_get();
	__u32 hdr[2] = {};
	__u32 declared;

	if (!m)
		return 0;

	m->read_offset = bpf_skb_offset(skb);

	STAT(S, ST_PARSE_CALLS, 1);

	if (skb->len < m->read_offset + FT_SEQ_OFF + 4) {
		STAT(S, ST_PARSE_NEEDMORE, 1);
		return 0;
	}

	m->have_seq = 0;
	if (bpf_skb_load_bytes(skb, m->read_offset + 1, hdr, 8)) {
		STAT(S, ST_PARSE_ERR, 1);
		declared = 0;
	} else {
		declared = cfg.msg_size - 1;
		m->found_seq = hdr[1];
		m->have_seq = 1;
	}

	if (declared != cfg.msg_size - 1) {
		m->desync = 1;
		STAT(S, ST_PARSE_DESYNC, 1);
	} else {
		m->desync = 0;
	}

	STAT(S, ST_PARSE_FRAMED, 1);
	return cfg.msg_size;
}

/* ---------------------------------------------------------------------------
 * The three access styles. Each returns 0 on success. @off is the message's
 * offset within the head; all three touch exactly cfg.access_len bytes and,
 * in RW mode, make exactly one byte observable downstream.
 * ------------------------------------------------------------------------ */

/* PULL: linearize [0, off+alen) and read through the packet pointer. */
static __always_inline int ft_access_pull(struct __sk_buff *skb, __u32 off,
					  int rw, struct ft_stats *S)
{
	const __u32 alen = cfg.access_len;
	const __u8 *d, *e;

	/* See FT_PKT_OFF_CEIL. Checked before any pointer arithmetic, because
	 * it is also what gives the verifier the bound that makes the
	 * arithmetic below expressible.
	 */
	if (off > FT_PKT_OFF_CEIL - alen) {
		STAT(S, ST_OFF_LIMIT, 1);
		return -1;
	}

	if (bpf_skb_pull_data(skb, off + alen))
		return -1;

	d = (const __u8 *)(long)skb->data;
	e = (const __u8 *)(long)skb->data_end;

	if (d + off + alen > e)
		return -1;

	if (rw) {
		/* pull_data already made [0, off+alen) writable and wr_off is
		 * inside it, so the store is in place. The pointers must be
		 * re-fetched: the verifier invalidates them across the calls
		 * above.
		 */
		__u8 *w = (__u8 *)(long)skb->data;
		const __u8 *we = (const __u8 *)(long)skb->data_end;
		__u32 widx = off + cfg.wr_off;
		__u8 *wp;

		/* clang proves this compare redundant from the "d + off + alen
		 * > e" check above and deletes it unless the index is hidden,
		 * leaving the verifier a store it never saw range-checked.
		 */
		barrier_var(widx);
		if (widx > FT_PKT_OFF_CEIL) {
			STAT(S, ST_WR_FAIL, 1);
			return -1;
		}
		wp = w + widx;
		if (wp + 1 > we) {
			STAT(S, ST_WR_FAIL, 1);
			return -1;
		}
		*wp = (__u8)cfg.sentinel;
		STAT(S, ST_WR_OK, 1);
	}
	return 0;
}

/* LOAD: copy the area OUT into a private map buffer. In RW mode the one
 * modified byte is written back with bpf_skb_store_bytes(), which makes the
 * skb writable first -- on the strparser path that is always a clone.
 */
static __always_inline int ft_access_load(struct __sk_buff *skb, __u32 off,
					  int rw, struct ft_stats *S)
{
	/* The CONSTANT, not a runtime length: a variable size reaches
	 * bpf_skb_load_bytes() as "R4 invalid zero-sized read".
	 */
	const __u32 alen = cfg.access_len;
	__u32 zero = 0;
	struct ft_buf *b = bpf_map_lookup_elem(&buf_map, &zero);

	if (!b)
		return -1;

	if (bpf_skb_load_bytes(skb, off, b->b, alen))
		return -1;

	if (rw) {
		__u32 w = cfg.wr_off;

		if (w >= FT_ACCESS_MAX)
			return -1;
		b->b[w] = (__u8)cfg.sentinel;

		if (bpf_skb_store_bytes(skb, off + w, &b->b[w], 1, 0))
			STAT(S, ST_WR_FAIL, 1);
		else
			STAT(S, ST_WR_OK, 1);
	}
	return 0;
}

/* DYNPTR: ask for a slice and let the kernel decide -- a direct pointer when
 * the range is contiguous in the head (no copy), otherwise a copy into our
 * buffer, which in RW mode needs bpf_dynptr_write() to become visible.
 */
static __always_inline int ft_access_dynptr(struct __sk_buff *skb, __u32 off,
					    int rw, struct ft_stats *S)
{
	const __u32 alen = cfg.access_len;
	struct bpf_dynptr d;
	__u32 zero = 0;
	struct ft_buf *b = bpf_map_lookup_elem(&buf_map, &zero);
	__u8 *p;

	if (!b)
		return -1;
	if (bpf_dynptr_from_skb(skb, 0, &d))
		return -1;

	p = rw ? bpf_dynptr_slice_rdwr(&d, off, b->b, alen)
	       : bpf_dynptr_slice(&d, off, b->b, alen);
	if (!p) {
		STAT(S, ST_DYN_NULL, 1);
		return -1;
	}

	if (p == b->b)
		STAT(S, ST_DYN_COPY, 1);
	else
		STAT(S, ST_DYN_DIRECT, 1);

	if (rw) {
		__u32 w = cfg.wr_off;
		__u8 sv = (__u8)cfg.sentinel;

		if (w + 1 > cfg.access_len)
			return -1;
		p[w] = sv;

		if (p == b->b) {
			/* The write is in our copy: commit it, which pulls the
			 * skb. Everything derived from @d and @p is invalid
			 * after this. The source is a stack byte, not &p[w]:
			 * a slice pointer with an offset added is a "modified
			 * mem ptr" a helper may not dereference.
			 */
			if (bpf_dynptr_write(&d, off + w, &sv, 1, 0))
				STAT(S, ST_WR_FAIL, 1);
			else
				STAT(S, ST_WR_OK, 1);
		} else {
			/* Written straight into the skb head. */
			STAT(S, ST_WR_OK, 1);
		}
	}
	return 0;
}

/* ---------------------------------------------------------------------------
 * Verdict. One body, instantiated per (style, mode) so each program carries
 * only its own prologue.
 * ------------------------------------------------------------------------ */
static __always_inline int ft_verdict(struct __sk_buff *skb, int style, int rw)
{
	__u32 key = 0;
	struct ft_msg_state *m = bpf_map_lookup_elem(&msg_map, &key);
	struct ft_stats *S = ft_stats_get();
	__u32 off, mlen;
	int err = 0;

	if (!m)
		return SK_DROP;

	STAT(S, ST_RUN_CALLS, 1);

	off  = m->read_offset;
	mlen = cfg.msg_size;

	if (m->desync) {
		m->read_offset = 0;
		m->desync = 0;
		bpf_printk("DROP");
		return SK_DROP;
	}

	if (off == 0) {
		STAT(S, ST_HEADS, 1);
		STAT(S, ST_HEAD_LEN, skb->len);
	}

	if (mlen <= skb->len - off) {
		STAT(S, ST_ACCESS_BYTES, cfg.access_len);

		if (style == FT_STYLE_PULL)
			err = ft_access_pull(skb, off, rw, S);
		else if (style == FT_STYLE_LOAD)
			err = ft_access_load(skb, off, rw, S);
		else
			err = ft_access_dynptr(skb, off, rw, S);

		if (err)
			STAT(S, ST_ERR, 1);
	}

	STAT(S, ST_RUN_MSGS, 1);
	return SK_PASS;
}

SEC("sk_skb/stream_verdict")
int ft_verdict_pull_ro(struct __sk_buff *skb)
{
	return ft_verdict(skb, FT_STYLE_PULL, 0);
}

SEC("sk_skb/stream_verdict")
int ft_verdict_pull_rw(struct __sk_buff *skb)
{
	return ft_verdict(skb, FT_STYLE_PULL, 1);
}

SEC("sk_skb/stream_verdict")
int ft_verdict_load_ro(struct __sk_buff *skb)
{
	return ft_verdict(skb, FT_STYLE_LOAD, 0);
}

SEC("sk_skb/stream_verdict")
int ft_verdict_load_rw(struct __sk_buff *skb)
{
	return ft_verdict(skb, FT_STYLE_LOAD, 1);
}

SEC("sk_skb/stream_verdict")
int ft_verdict_dynptr_ro(struct __sk_buff *skb)
{
	return ft_verdict(skb, FT_STYLE_DYNPTR, 0);
}

SEC("sk_skb/stream_verdict")
int ft_verdict_dynptr_rw(struct __sk_buff *skb)
{
	return ft_verdict(skb, FT_STYLE_DYNPTR, 1);
}

char _license[] SEC("license") = "GPL";
