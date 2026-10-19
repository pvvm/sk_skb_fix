#!/bin/bash
# The fix_test sweep: time inside the SK_SKB parser + verdict per message, at
# each load point of scripts/spins.env, for every style x mode x area x size.
# Resumable: a run whose .rx already says valid=yes is skipped, so re-running
# after a reboot fills in the gaps.
#
#   scripts/run_experiment.sh                       2 reps, everything
#   scripts/run_experiment.sh --reps 1 --sizes "128 4096" --styles "pull load"
#   scripts/run_experiment.sh --list                print the runs, run nothing
#
# Order: rep, then load point (lowest first), then size, style, mode, area. So
# every lower-load point is banked before any run goes flat out, and an
# interrupted sweep still leaves one complete replicate.
set -u
. "$(dirname "$0")/fix_test_env.sh"
. "$(dirname "$0")/spins.env"

REPS=2
SIZES="128 1024 4096 16384"
STYLES="pull load dynptr"
MODES="ro rw"
AREAS="header half full"
DRYRUN=0

while [ $# -gt 0 ]; do
	case $1 in
	--reps)   REPS=$2; shift 2 ;;
	--sizes)  SIZES=$2; shift 2 ;;
	--styles) STYLES=$2; shift 2 ;;
	--modes)  MODES=$2; shift 2 ;;
	--areas)  AREAS=$2; shift 2 ;;
	--list)   DRYRUN=1; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

for size in $SIZES; do
	eval "list=\${FT_SPINS_$size:-}"
	set -- $list
	if [ $# -ne "$FT_POINTS" ]; then
		echo "FT_SPINS_$size has $# spins, need $FT_POINTS (scripts/spins.env)" >&2
		exit 2
	fi
done
spin_at() {	# $1 = size, $2 = 1-based load point
	local list idx=$2
	eval "list=\${FT_SPINS_$1}"
	set -- $list	# overwrites $1/$2, hence idx
	shift $(( idx - 1 ))
	echo "$1"
}

if [ "$DRYRUN" = 0 ]; then
	# Without the steering rule the flow lands on an unpinned RX queue and
	# the softirq work runs on some other core than the reader's.
	if ! sudo -n ethtool -n "$NET_IFACE" 2>/dev/null | grep -q "Dest port: $PORT"; then
		echo "REFUSING TO RUN: no ethtool steering rule for dst-port $PORT on $NET_IFACE." >&2
		echo "Start setup_exp.sh (NET_IFACE=$NET_IFACE PORT=$PORT GRO=on) first." >&2
		exit 1
	fi
	if [ "$(cat /sys/devices/system/cpu/smt/control 2>/dev/null)" = on ]; then
		echo "REFUSING TO RUN: SMT is on; cpu$RECV_CPU shares its core." >&2
		exit 1
	fi
	# setup_exp.sh's "cpupower idle-set -D 1" also disables C1; put it back.
	if grep -q 1 /sys/devices/system/cpu/cpu*/cpuidle/state1/disable 2>/dev/null; then
		sudo -n cpupower idle-set -e 1 >/dev/null 2>&1
	fi
fi

log="$RUNS_DIR/progress.log"
[ "$DRYRUN" = 1 ] && log=/dev/null || mkdir -p "$RUNS_DIR"
total=$(( REPS * FT_POINTS * $(echo $SIZES | wc -w) * $(echo $STYLES | wc -w) \
	  * $(echo $MODES | wc -w) * $(echo $AREAS | wc -w) ))

# --- stop each curve at its first stall -------------------------------------
#
# A stalled run delivered nothing in its window (or never finished). It gets
# one immediate retry; if that stalls too, the curve's higher load points are
# skipped from then on, recorded in $RUNS_DIR/stall_<style>_<mode>_<area>_<size>
# as "<point> <spin> <run> <reason>". Delete the marker to run the curve again.
is_stall() {	# $1 = .rx path
	local rx=$1 msgs
	[ -f "$rx" ] || return 1
	grep -q '^FTRESULT valid=' "$rx" || return 0
	grep -q '^FTRESULT valid=yes' "$rx" && return 1
	msgs=$(sed -n 's/^FTRESULT msgs=//p' "$rx")
	[ "${msgs:-0}" -eq 0 ] 2>/dev/null
}
stall_reason() {
	if ! grep -q '^FTRESULT valid=' "$1" 2>/dev/null; then
		echo "run never finished (crash?)"
	else
		echo "msgs=$(sed -n 's/^FTRESULT msgs=//p' "$1")"
	fi
}
record_stall() {	# $1 = marker, $2 = point, $3 = spin, $4 = run, $5 = reason
	if [ -f "$1" ] && [ "$(cut -d' ' -f1 "$1")" -le "$2" ]; then
		return
	fi
	echo "$2 $3 $4 $5" > "$1"
	echo "STALL $4: $5 -- load points >= $2 of this curve are skipped from here on" | tee -a "$log"
}

# A WEDGE (receiver in D state, port held forever, reboot needed) and a slow
# release (the ~9 s bpf_enable_stats teardown) look the same for a while; the
# difference is whether a fix_test_loader process is still alive.
after_run() {	# $1 = run name
	for _ in $(seq 1 40); do
		ss -ltn 2>/dev/null | grep -q ":$PORT " || break
		sleep 1
	done
	if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
		# ps -o, NOT ps -eo: -e means "all processes" and silently overrides -C.
		if ps -o pid= -C fix_test_loader >/dev/null 2>&1; then
			echo "ABORT: port $PORT still bound after $1 and a fix_test_loader survives --" \
			     | tee -a "$log"
			echo "       receiver wedged; reboot needed." | tee -a "$log"
			exit 1
		fi
		echo "WARN: port $PORT still bound after $1 but no fix_test_loader is alive;" \
		     "treating as slow teardown and continuing." | tee -a "$log"
	fi
}

n=0 skipped=0 ran=0 stalled=0 t0=$(date +%s)
for rep in $(seq 1 "$REPS"); do
 for pi in $(seq 1 "$FT_POINTS"); do
  for size in $SIZES; do
   spin=$(spin_at "$size" "$pi")
   for style in $STYLES; do
    for mode in $MODES; do
     for area in $AREAS; do
      n=$((n + 1))
      name="ft_${style}_${mode}_${area}_${size}_s${spin}_r${rep}"
      sf="$RUNS_DIR/stall_${style}_${mode}_${area}_${size}"

      if [ -f "$sf" ] && [ "$pi" -ge "$(cut -d' ' -f1 "$sf")" ]; then
         stalled=$((stalled + 1)); continue
      fi
      # A stall from an EARLIER pass is taken as the stall without a retry.
      if [ "$DRYRUN" = 0 ] && is_stall "$RUNS_DIR/$name.rx"; then
         record_stall "$sf" "$pi" "$spin" "$name" \
                      "$(stall_reason "$RUNS_DIR/$name.rx"), earlier pass"
         stalled=$((stalled + 1)); continue
      fi
      # Skip only runs that came out VALID; a failed one is retried next pass.
      if grep -q '^FTRESULT valid=yes' "$RUNS_DIR/$name.rx" 2>/dev/null; then
         skipped=$((skipped + 1)); continue
      fi
      if [ "$DRYRUN" = 1 ]; then echo "$name"; continue; fi

      el=$(( $(date +%s) - t0 ))
      eta="?"
      [ "$ran" -gt 0 ] && eta=$(( el * (total - n) / ran / 60 ))
      printf '[%d/%d ran=%d skip=%d eta=%smin] %s\n' \
             "$n" "$total" "$ran" "$skipped" "$eta" "$name" | tee -a "$log"

      bash "$(dirname "$0")/run_one.sh" "$name" "$style" "$area" "$mode" \
           "$size" "$spin" | tee -a "$log"
      ran=$((ran + 1))
      after_run "$name"

      # One retry before a stall ends the curve; the first attempt is kept
      # as <run>.stall1.*.
      if is_stall "$RUNS_DIR/$name.rx"; then
         for f in rx cl; do
            mv -f "$RUNS_DIR/$name.$f" "$RUNS_DIR/$name.stall1.$f" 2>/dev/null
         done
         echo "STALL? $name ($(stall_reason "$RUNS_DIR/$name.stall1.rx")): retrying once" \
              | tee -a "$log"
         bash "$(dirname "$0")/run_one.sh" "$name" "$style" "$area" "$mode" \
              "$size" "$spin" | tee -a "$log"
         ran=$((ran + 1))
         after_run "$name"
         if is_stall "$RUNS_DIR/$name.rx"; then
            record_stall "$sf" "$pi" "$spin" "$name" \
                         "$(stall_reason "$RUNS_DIR/$name.rx"), confirmed by a retry"
         fi
      fi
     done
    done
   done
  done
 done
done

[ "$DRYRUN" = 1 ] && exit 0
echo "done: $ran run, $skipped skipped, $stalled skipped past a stall, of $total" | tee -a "$log"
