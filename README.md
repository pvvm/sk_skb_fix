## Changing and installing the kernel

### Prerequisites

On Ubuntu/Debian:

```bash
sudo apt install git build-essential bc bison flex libssl-dev libelf-dev \
     libncurses-dev dwarves zstd python3
```

### 1. Clone Linux 7.1

Only clone, build, and change the kernel on the machine you'll use as a server

```bash
cd sk_skb_fix
git clone --depth 1 --branch v7.1 https://github.com/torvalds/linux.git linux-7.1
```

### 2. Apply the fixes

After it, run the script to apply the fixes. The script has two modes:

- `partial`: use this mode first. It contains the first fix (the one I explained a few months ago), plus one that increases the throughput for messages smaller than skb->len. In this setup, the tcp_collapse bug to happen at higher rates for longer messages (e.g. 16348 B-long).

  WORTH TO NOTE: the bug can make the server program be stuck, locking the port 9998 (the one I use), and sometimes even crash the server.
  In case the program gets stuck and locks the port, my only solution is to reboot the server:
  ```bash
  sudo reboot -f
  ```

- `full`: after trying out the partial mode, use this mode. This contains the new fixes. After this fix, I'm expecting the tcp_collapse bug to not happen at higher rates for longer messages (e.g. 16348 B-long). If everything runs well even for this setup, it implies that the error was fixed.

The idea here is for you to apply the fixes for partial first, build the kernel, reboot, try running the with longer messages; if the bug happens, great! :)

Then, you apply the fixes for full mode, rebuild, reboot, and try running it again with longer messages; if the bug doesn't happen anymore, awesome! :)))

```bash
DRY_RUN=1 ./apply_fixes.sh partial linux-7.1   # optional: it will only print the diff
./apply_fixes.sh partial linux-7.1             # or: full
```

### 3. Configure

Start from the config of the kernel the machine runs now (the distro kernel is
fine), then turn on what the fixes and the kfunc need:

```bash
cd linux-7.1
cp /boot/config-$(uname -r) .config
scripts/config --set-str LOCALVERSION -skskb-partial    # -skskb-full for full
scripts/config --set-str SYSTEM_TRUSTED_KEYS "" --set-str SYSTEM_REVOCATION_KEYS ""
scripts/config --enable BPF_SYSCALL --enable BPF_JIT --enable CGROUP_BPF \
               --enable DEBUG_INFO_BTF --enable BPF_STREAM_PARSER
make olddefconfig
```

### 4. Build and install

```bash
make -j$(nproc)
sudo make modules_install
sudo make install
```

### 5. Boot it

```bash
sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux $(make -s kernelrelease)"
sudo reboot -f
```

### Switching modes

From `partial` to `full`: run `./apply_fixes.sh full linux-7.1`, set
`LOCALVERSION` to `-skskb-full`, run `make olddefconfig`, and repeat steps 4–5.
Only the changed files are recompiled. From `full` to `partial`, first restore
`tcp_input.c` with `git -C ~/linux-7.1 checkout -- net/ipv4/tcp_input.c`.

## Build and run experiment

```bash
cd sk_skb_fix/fix_test
make
```

### Run server

On a separate terminal run:
```bash
cd scripts
NET_IFACE=ens6f1np1 ./setup_exp.sh
```
This script is basically yours, but it sets the rules for port 9998, and sets GRO and others to on.

Then, run the experiment on the server side:
```bash
sudo build/fix_test_loader --style load --mode rw --area full --msg-size 16348 \
     --warmup 3 --measure 10 --cpu $CPU_ID --accept-wait 30 --tag manual
```
WORTH TO NOTE: $CPU_ID is the identifier of the CPU core you'll be using for the experiment to send the messages. I use a core from the NUMA node also used by my NIC (18).


### Run client

Finally, run the experiment on the client side. The client can (most probably) have any kernel version, as it doesn't use any eBPF program or anything special:
```bash
cd sk_skb_fix/fix_test/build
./fix_test_client --host $SERVER_IP --port 9998 \
     --msg-size 16348 --spin 0 --duration 13 --cpu $CPU_ID --tag manual
```

WORTH TO NOTE: $SERVER_IP is the IPv4 address of the server machine and $CPU_ID is the identifier of the CPU core you'll be using for the experiment to send the messages. I use a core from the NUMA node also used by my NIC (18).
