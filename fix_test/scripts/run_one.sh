#!/bin/bash
# One cell, one rep: start the receiver here, the client on the sender,
# collect two files into $RUNS_DIR.
#
#   <name>.rx    receiver stdout+stderr, including the FTRESULT block
#   <name>.cl    client output, including the FTCLIENT block
#
# Usage: run_one.sh NAME STYLE AREA MODE MSGSIZE SPIN [extra receiver args...]
set -u
. "$(dirname "$0")/fix_test_env.sh"

name=$1 style=$2 area=$3 mode=$4 size=$5 spin=$6
shift 6

mkdir -p "$RUNS_DIR"

# A previous receiver may still hold the port: closing the bpf_enable_stats()
# fd tears down a static key, which takes ~9 s of RCU synchronisation, and a
# receiver wedged in D state holds it forever. Wait, then say which.
for _ in $(seq 1 40); do
	ss -ltn 2>/dev/null | grep -q ":$PORT " || break
	sleep 1
done
if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
	echo "RUNFAIL $name: port $PORT still bound; receiver from a previous run is wedged (reboot)" >&2
	exit 1
fi

rx="$RUNS_DIR/$name.rx"
cl="$RUNS_DIR/$name.cl"

# The client must outlive the receiver's warmup + window; the receiver resets
# the connection when its window ends, which ends the client.
cl_dur=$(( WARMUP + MEASURE + 5 ))

rm -f "$rx" "$cl"

timeout -k 5 "$RUN_TIMEOUT" sudo -n "$FT_LOADER" \
	--obj "$FT_OBJ" --style "$style" --area "$area" --mode "$mode" \
	--msg-size "$size" --warmup "$WARMUP" --measure "$MEASURE" \
	--cpu "$RECV_CPU" --accept-wait 30 --tag "$name" "$@" \
	>"$rx" 2>&1 &
rx_pid=$!

# Wait for the listen, not a fixed sleep.
for _ in $(seq 1 200); do
	grep -q '^listening on' "$rx" 2>/dev/null && break
	kill -0 "$rx_pid" 2>/dev/null || break
	sleep 0.1
done

if ! grep -q '^listening on' "$rx" 2>/dev/null; then
	echo "RUNFAIL $name: receiver never listened" >&2
	wait "$rx_pid" 2>/dev/null
	exit 1
fi

timeout -k 5 "$RUN_TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout=10 "$SEND_HOST" \
	"'$FT_CLIENT' --host '$RECV_IP' --port '$PORT' --msg-size '$size' \
	 --spin '$spin' --duration '$cl_dur' --cpu '$SEND_CPU' --tag '$name'" >"$cl" 2>&1

wait "$rx_pid"
rc=$?

# Host/NIC state stamped INTO the run file, so a setting that silently
# changed (or a reboot that reset it) is visible per run.
{
	printf 'FTRESULT rx_gro=%s\n' \
		"$(ethtool -k "$NET_IFACE" 2>/dev/null | \
		   sed -n 's/^generic-receive-offload: \([a-z]*\).*/\1/p')"
	printf 'FTRESULT rx_mtu=%s\n' "$(cat /sys/class/net/$NET_IFACE/mtu 2>/dev/null)"
	printf 'FTRESULT rx_coalesce=%s\n' \
		"$(sudo -n ethtool -c "$NET_IFACE" 2>/dev/null | \
		   awk '/^Adaptive RX:/{a=$3} /^rx-usecs:/{u=$2} /^rx-frames:/{f=$2} END{print a"/"u"/"f}')"
	printf 'FTRESULT host_smt=%s\n' \
		"$(cat /sys/devices/system/cpu/smt/control 2>/dev/null)"
	printf 'FTRESULT host_c1_disabled=%s\n' \
		"$(cat /sys/devices/system/cpu/cpu$RECV_CPU/cpuidle/state1/disable 2>/dev/null)"
	printf 'FTRESULT host_governor=%s\n' \
		"$(cat /sys/devices/system/cpu/cpu$RECV_CPU/cpufreq/scaling_governor 2>/dev/null)"
} >>"$rx"

# A kernel BUG during this run is a RESULT: record it beside the run.
if sudo -n dmesg 2>/dev/null | tail -400 | grep -q "kernel BUG at"; then
	sudo -n dmesg 2>/dev/null | tail -120 > "$RUNS_DIR/$name.oops"
	echo "OOPS $name: kernel BUG; see $name.oops" >&2
fi

valid=$(grep -m1 '^FTRESULT valid=' "$rx" | cut -d= -f2)
msgs=$(grep -m1 '^FTRESULT msgs=' "$rx" | cut -d= -f2)
printf '%s rc=%s valid=%s msgs=%s\n' "$name" "$rc" "${valid:-?}" "${msgs:-?}"
