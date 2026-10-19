#!/usr/bin/env bash
#
# apply_fixes.sh - apply the sockmap/strparser receive-path fixes to a kernel
# source tree:
#
#   net/core/skmsg.c      charge psock ingress skbs by message length instead
#                         of truesize: skb_set_owner_r_special() and its
#                         sock_rfree_len() destructor       [partial, full]
#   net/ipv4/tcp_bpf.c    advance tp->copied_seq incrementally in
#                         tcp_bpf_strp_read_sock()          [partial, full]
#   net/ipv4/tcp_input.c  clamp the tcp_collapse() start in tcp_prune_queue()
#                         to the first skb on sk_receive_queue       [full]
#   net/core/filter.c     add the bpf_skb_offset() kfunc, registered for
#                         BPF_PROG_TYPE_SK_SKB only         [partial, full]
#
# Modes: "partial" applies everything except the tcp_input.c fix; "full"
# applies all four. Neither mode removes a fix that is already in the tree:
# partial mode reports a tcp_input.c fix it finds, but leaves it in place.
#
# Every replaced statement stays in the file, commented out under ORIGINAL
# (pure additions, like the skmsg.c helpers and the kfunc, have none).
# A fix that is already in a file is skipped, so re-running is safe. If any
# file does not look as expected, no file is written.
#
# Usage:
#   ~/sk_skb_fix/apply_fixes.sh partial linux-7.1    # all but tcp_input.c
#   ~/sk_skb_fix/apply_fixes.sh full linux-7.1       # all four changes
#   MODE=full KERNEL=linux-7.1 ~/sk_skb_fix/apply_fixes.sh
#   DRY_RUN=1 ~/sk_skb_fix/apply_fixes.sh full linux-7.1   # print the diff, write nothing
#
# A relative kernel folder is looked up in the current directory, then in $HOME.
#
# Undo in a git tree:
#   git -C <kernel> checkout -- net/core/skmsg.c net/ipv4/tcp_bpf.c \
#       net/ipv4/tcp_input.c net/core/filter.c

set -euo pipefail

usage() {
	echo "usage: $0 <partial|full> <kernel dir>" >&2
	echo "  partial  skmsg.c + tcp_bpf.c fixes + filter.c bpf_skb_offset kfunc" >&2
	echo "  full     partial + tcp_input.c fix" >&2
	echo "MODE and KERNEL can be set in the environment instead." >&2
	exit 1
}

MODE="${1:-${MODE:-}}"
KERNEL="${2:-${KERNEL:-}}"
case "$MODE" in
partial|full) ;;
*) usage ;;
esac
if [[ -z "$KERNEL" ]]; then
	usage
fi
if [[ ! -d "$KERNEL" && -d "$HOME/$KERNEL" ]]; then
	KERNEL="$HOME/$KERNEL"
fi
if [[ ! -d "$KERNEL" ]]; then
	echo "error: kernel folder '$KERNEL' not found" >&2
	exit 1
fi
KERNEL="$(cd "$KERNEL" && pwd)"

for f in net/core/skmsg.c net/ipv4/tcp_bpf.c net/ipv4/tcp_input.c net/core/filter.c; do
	if [[ ! -f "$KERNEL/$f" ]]; then
		echo "error: $KERNEL/$f not found - is this a kernel source tree?" >&2
		exit 1
	fi
done

if ! command -v python3 >/dev/null; then
	echo "error: python3 is required" >&2
	exit 1
fi

echo "Kernel tree: $KERNEL"
echo "Mode:        $MODE"
python3 -I - "$KERNEL" "${DRY_RUN:-0}" "$MODE" <<'PY'
import difflib
import os
import sys

kdir = sys.argv[1]
dry_run = sys.argv[2] not in ("", "0")
mode = sys.argv[3]


class Unexpected(Exception):
    pass


def replace_once(text, old, new, what):
    n = text.count(old)
    if n != 1:
        raise Unexpected(f"expected 1 copy of the original {what}, found {n}")
    return text.replace(old, new)


# ---- net/core/skmsg.c -------------------------------------------------------

SKMSG_DECL = """\
static int sk_psock_skb_ingress_self(struct sk_psock *psock, struct sk_buff *skb,
				     u32 off, u32 len, bool take_ref);
"""

SKMSG_HELPERS = """\
/* Charge a psock ingress skb to @sk by the @len message bytes it carries
 * instead of skb->truesize. sock_rfree_len() releases strp_msg(skb)->full_len,
 * which equals @len for skbs that came through the strparser.
 */
static void sock_rfree_len(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct strp_msg *stm = strp_msg(skb);
	u32 len = stm->full_len;

	atomic_sub(len, &sk->sk_rmem_alloc);
	sk_mem_uncharge(sk, len);
}

static inline void skb_set_owner_r_special(struct sk_buff *skb, struct sock *sk, u32 len)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree_len;
	atomic_add(len, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, len);
}

"""

SKMSG_OWNER_OLD = """\
	skb_set_owner_r(skb, sk);
"""

SKMSG_OWNER_NEW = """\
	/* ORIGINAL
	skb_set_owner_r(skb, sk);
	*/
	skb_set_owner_r_special(skb, sk, len);
"""


def fix_skmsg(text):
    has_helpers = "static void sock_rfree_len(" in text
    n_special = text.count("\tskb_set_owner_r_special(skb, sk, len);")
    if has_helpers and n_special >= 2:
        return None
    if has_helpers or n_special:
        raise Unexpected("skb_set_owner_r_special is only partly applied")

    # One call in sk_psock_skb_ingress(), one in sk_psock_skb_ingress_self().
    n = text.count(SKMSG_OWNER_OLD)
    if n != 2:
        raise Unexpected(f"expected 2 skb_set_owner_r(skb, sk) calls, found {n}")
    text = text.replace(SKMSG_OWNER_OLD, SKMSG_OWNER_NEW)
    return replace_once(text, SKMSG_DECL, SKMSG_HELPERS + SKMSG_DECL,
                        "sk_psock_skb_ingress_self() declaration")


# ---- net/ipv4/tcp_bpf.c -----------------------------------------------------

TCP_BPF_OLD = """\
	tp->copied_seq = psock->copied_seq - psock->ingress_bytes;
"""

TCP_BPF_NEW = """\
	/* ORIGINAL
	tp->copied_seq = psock->copied_seq - psock->ingress_bytes;
	*/
	/* Advance by what was not passed to ingress_msg, so copied_seq stays
	 * behind every SK_PASS byte not yet read, not only this call's.
	 */
	WRITE_ONCE(tp->copied_seq,
		   tp->copied_seq + (copied - psock->ingress_bytes));
"""


def fix_tcp_bpf(text):
    if "tp->copied_seq + (copied - psock->ingress_bytes)" in text:
        return None
    return replace_once(text, TCP_BPF_OLD, TCP_BPF_NEW,
                        "tp->copied_seq assignment in tcp_bpf_strp_read_sock()")


# ---- net/ipv4/tcp_input.c ---------------------------------------------------

TCP_INPUT_OLD = """\
	if (!skb_queue_empty(&sk->sk_receive_queue))
		tcp_collapse(sk, &sk->sk_receive_queue, NULL,
			     skb_peek(&sk->sk_receive_queue),
			     NULL,
			     tp->copied_seq, tp->rcv_nxt);
"""

TCP_INPUT_NEW = """\
	if (!skb_queue_empty(&sk->sk_receive_queue)) {
		/* ORIGINAL
		tcp_collapse(sk, &sk->sk_receive_queue, NULL,
			     skb_peek(&sk->sk_receive_queue),
			     NULL,
			     tp->copied_seq, tp->rcv_nxt);
		*/
		struct sk_buff *head = skb_peek(&sk->sk_receive_queue);
		u32 start = tp->copied_seq;

		/* The queue normally starts at or before copied_seq. A sockmap
		 * strparser socket (tcp_bpf_strp_read_sock) leaves copied_seq
		 * behind bytes it already moved to psock->ingress_msg, so the
		 * queue can start after it. Collapse only what is queued.
		 */
		if (before(start, TCP_SKB_CB(head)->seq))
			start = TCP_SKB_CB(head)->seq;

		tcp_collapse(sk, &sk->sk_receive_queue, NULL, head, NULL,
			     start, tp->rcv_nxt);
	}
"""


def fix_tcp_input(text):
    if "start = TCP_SKB_CB(head)->seq;" in text:
        return None
    return replace_once(text, TCP_INPUT_OLD, TCP_INPUT_NEW,
                        "tcp_collapse() call in tcp_prune_queue()")


# ---- net/core/filter.c ------------------------------------------------------

# The skb kfunc definitions end right before bpf_dynptr_from_skb_rdonly().
FILTER_DEFS_END = """\
__bpf_kfunc_end_defs();

int bpf_dynptr_from_skb_rdonly(struct __sk_buff *skb, u64 flags,
"""

FILTER_KFUNC = """\
/* Offset of the current message within the skb. Only meaningful for skbs
 * that came through the strparser (stream_parser and stream_verdict).
 */
__bpf_kfunc int bpf_skb_offset(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct strp_msg *stm = strp_msg(skb);

	return stm->offset;
}

"""

FILTER_SKB_SET = """\
BTF_KFUNCS_END(bpf_kfunc_check_set_skb)
"""

FILTER_SK_SKB_SET = """\

BTF_KFUNCS_START(bpf_kfunc_check_set_sk_skb)
BTF_ID_FLAGS(func, bpf_skb_offset)
BTF_KFUNCS_END(bpf_kfunc_check_set_sk_skb)
"""

FILTER_SKB_DESC = """\
static const struct btf_kfunc_id_set bpf_kfunc_set_skb = {
	.owner = THIS_MODULE,
	.set = &bpf_kfunc_check_set_skb,
};
"""

FILTER_SK_SKB_DESC = """\

static const struct btf_kfunc_id_set bpf_kfunc_set_sk_skb = {
	.owner = THIS_MODULE,
	.set = &bpf_kfunc_check_set_sk_skb,
};
"""

FILTER_SKB_REG = """\
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SK_SKB, &bpf_kfunc_set_skb);
"""

FILTER_SK_SKB_REG = """\
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SK_SKB, &bpf_kfunc_set_sk_skb);
"""


def fix_filter(text):
    markers = ("__bpf_kfunc int bpf_skb_offset(",
               "BTF_ID_FLAGS(func, bpf_skb_offset)",
               "&bpf_kfunc_set_sk_skb);")
    present = sum(m in text for m in markers)
    if present == len(markers):
        return None
    if present:
        raise Unexpected("bpf_skb_offset kfunc is only partly added")

    # Its own set, so only sk_skb programs see it: bpf_kfunc_set_skb is also
    # registered for tc, cgroup_skb, LWT, ..., where skb->cb is not a strp_msg.
    text = replace_once(text, FILTER_DEFS_END, FILTER_KFUNC + FILTER_DEFS_END,
                        "end of the skb kfunc definitions")
    text = replace_once(text, FILTER_SKB_SET, FILTER_SKB_SET + FILTER_SK_SKB_SET,
                        "bpf_kfunc_check_set_skb set")
    text = replace_once(text, FILTER_SKB_DESC, FILTER_SKB_DESC + FILTER_SK_SKB_DESC,
                        "bpf_kfunc_set_skb descriptor")
    return replace_once(text, FILTER_SKB_REG, FILTER_SKB_REG + FILTER_SK_SKB_REG,
                        "SK_SKB registration in bpf_kfunc_init()")


# ---- driver -----------------------------------------------------------------

# (file, description, fix, applied in partial mode)
FIXES = [
    ("net/core/skmsg.c", "skb_set_owner_r_special + sock_rfree_len", fix_skmsg, True),
    ("net/ipv4/tcp_bpf.c", "incremental tp->copied_seq", fix_tcp_bpf, True),
    ("net/ipv4/tcp_input.c", "tcp_collapse start clamp", fix_tcp_input, False),
    ("net/core/filter.c", "bpf_skb_offset kfunc for sk_skb", fix_filter, True),
]

pending = []
failed = False
for rel, desc, fix, in_partial in FIXES:
    path = os.path.join(kdir, rel)
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
        old = f.read()
    selected = mode == "full" or in_partial
    try:
        new = fix(old)
    except Unexpected as e:
        if selected:
            print(f"  FAIL   {rel}: {e}")
            failed = True
        continue
    if not selected:
        # Not this mode's job, but a tree built in partial mode should not
        # silently carry a full-mode fix.
        if new is None:
            print(f"  note   {rel}: {desc} is already present; partial mode leaves it in place")
        continue
    if new is None:
        print(f"  skip   {rel}: {desc} already present")
        continue
    if not dry_run and not os.access(path, os.W_OK):
        print(f"  FAIL   {rel}: not writable")
        failed = True
        continue
    pending.append((rel, path, old, new))
    print(f"  {'diff ' if dry_run else 'apply'}  {rel}: {desc}")

if failed:
    print("No files were changed.")
    sys.exit(1)

for rel, path, old, new in pending:
    if dry_run:
        sys.stdout.writelines(difflib.unified_diff(
            old.splitlines(True), new.splitlines(True), "a/" + rel, "b/" + rel))
        continue
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(new)

if dry_run:
    print("DRY_RUN: no files were changed.")
elif pending:
    print(f"Done: {len(pending)} file(s) changed.")
else:
    print(f"Nothing to do: all {mode}-mode fixes already present.")
PY
