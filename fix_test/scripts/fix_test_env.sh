# Shared settings for the fix_test scripts. Sourced, not executed.
#
# Overriding PORT means also passing the same PORT to setup_exp.sh, or the NIC
# steers the traffic to a queue whose IRQ is not the pinned one.

FT_DIR=${FT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}

: "${NET_IFACE:=ens6f1np1}"
: "${RECV_HOST:=maple03}"
: "${SEND_HOST:=maple01}"
: "${RECV_IP:=192.168.2.30}"
: "${PORT:=9998}"

# CPU 18 is on the NIC's NUMA node and is the core setup_exp.sh pins the
# steered RX queue's IRQ to; the reader runs there too.
: "${RECV_CPU:=18}"
: "${SEND_CPU:=18}"

# Results on LOCAL disk: $HOME is NFS, and a crash reboot wipes /tmp.
: "${RUNS_DIR:=/test_pv/fix_test_runs}"

# Hard ceiling on one run (timeout(1)): a wedged receiver survives SIGKILL.
: "${RUN_TIMEOUT:=120}"

: "${WARMUP:=3}"
: "${MEASURE:=5}"

FT_LOADER=${FT_LOADER:-$FT_DIR/build/fix_test_loader}
FT_OBJ=${FT_OBJ:-$FT_DIR/build/fix_test.bpf.o}
# The client runs on $SEND_HOST, which sees this path over the shared NFS home.
FT_CLIENT=${FT_CLIENT:-$FT_DIR/build/fix_test_client}
