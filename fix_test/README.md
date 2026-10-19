### Prerequisites

On Ubuntu/Debian (other distros have the same tools under their own names):

```bash
sudo apt install git build-essential bc bison flex libssl-dev libelf-dev \
     libncurses-dev dwarves zstd python3
```

### 1. Clone Linux 7.1

Only clone, build, and change the kernel on the machine you'll use as a server

```bash
git clone --depth 1 --branch v7.1 https://github.com/torvalds/linux.git ~/linux-7.1
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
apply_fixes.sh partial linux-7.1
apply_fixes.sh full linux-7.1
```

```bash
DRY_RUN=1 ~/sk_skb_fix/apply_fixes.sh full ~/linux-7.1   # optional: print the diff only
~/sk_skb_fix/apply_fixes.sh full ~/linux-7.1             # or: partial
```

### 3. Configure

Start from the config of the kernel the machine runs now (the distro kernel is
fine), then turn on what the fixes and the kfunc need:

```bash
cd ~/linux-7.1
cp /boot/config-$(uname -r) .config
scripts/config --set-str LOCALVERSION -skskb-full    # -skskb-partial for partial
scripts/config --set-str SYSTEM_TRUSTED_KEYS "" --set-str SYSTEM_REVOCATION_KEYS ""
scripts/config --enable BPF_SYSCALL --enable BPF_JIT --enable CGROUP_BPF \
               --enable DEBUG_INFO_BTF --enable BPF_STREAM_PARSER
make olddefconfig
```

- `LOCALVERSION` names the kernel after the mode, so `uname -r` shows which one
  is running (`7.1.0-skskb-full-dirty`; `-dirty` is added because the tree has
  uncommitted changes). It also stops `make install` from overwriting an
  installed kernel that has the same name.
- Ubuntu and Debian configs point the two `*_KEYS` options at distro
  certificate files that aren't in the kernel tree, which breaks the build.
  Clearing them is harmless elsewhere.
- No `/boot/config-$(uname -r)`? Try `zcat /proc/config.gz > .config`. If
  neither exists, start from `make defconfig` and enable the machine's NIC and
  storage drivers in `make menuconfig`, or the kernel may not boot.

`make olddefconfig` silently drops an option whose dependencies aren't met, so
check that nothing is missing (this prints nothing when all is well):

```bash
for o in BPF_SYSCALL BPF_JIT CGROUP_BPF DEBUG_INFO_BTF BPF_STREAM_PARSER STREAM_PARSER; do
    grep -q "^CONFIG_$o=y" .config || echo "missing: CONFIG_$o"
done
```

If `DEBUG_INFO_BTF` is missing, either `pahole` is absent or older than v1.22,
or debug info is off. Fix `pahole` first; then, if `.config` has
`CONFIG_DEBUG_INFO_NONE=y`, turn debug info on and check again:

```bash
scripts/config --enable DEBUG_KERNEL --disable DEBUG_INFO_NONE \
               --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
               --disable DEBUG_INFO_REDUCED --disable DEBUG_INFO_SPLIT \
               --enable DEBUG_INFO_BTF
make olddefconfig
```

### 4. Build and install

```bash
make -j$(nproc)
sudo make INSTALL_MOD_STRIP=1 modules_install
sudo make install
```

- Build as your own user; only the two install steps need root. `sudo make`
  leaves root-owned files in the tree.
- `INSTALL_MOD_STRIP=1` strips debug info from the installed modules (their BTF
  is kept). Without it, a distro-based config gives an initramfs of about
  600 MB, which can fill a small `/boot`.

### 5. Boot it

`make -s kernelrelease` prints the new kernel's name. On Ubuntu with
`GRUB_DEFAULT=saved` in `/etc/default/grub`, boot it once; if it doesn't come
up, a power cycle returns to the previous default:

```bash
sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux $(make -s kernelrelease)"
sudo reboot
```

Once it works, make it the default with `sudo grub-set-default` and the same
string. Without `GRUB_DEFAULT=saved`, pick the kernel under "Advanced options"
in the GRUB menu.

To match maple03, add `ibt=off module.sig_enforce=0` to
`GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub` and run `sudo update-grub`.

### 6. After booting

- `uname -r` should print the name from step 5.
- Ubuntu's `cpupower`, `perf` and `x86_energy_perf_policy` are wrappers that
  run the tool from `/usr/lib/linux-tools/$(uname -r)/`. A self-built kernel
  has no such directory, so the tools fail, and `setup_exp.sh` carries on
  without setting the CPU governor, C-states or EPP. Point it at an installed
  distro kernel's tools (package `linux-tools-<release>`):

  ```bash
  ls /usr/lib/linux-tools/        # pick a distro release, e.g. 6.8.0-147-generic
  sudo ln -sfn /usr/lib/linux-tools/<distro-release> /usr/lib/linux-tools/$(uname -r)
  cpupower frequency-info > /dev/null && echo ok
  ```

- Build the harness and run the dry run under [Build](#build). It loads the
  programs without attaching them, and prints `FTRESULT dry_run=ok` only if
  the running kernel has the kfunc; otherwise the load fails with
  `extern (func ksym) 'bpf_skb_offset': not found`.

### Switching modes

From `partial` to `full`: run `apply_fixes.sh full ~/linux-7.1`, set
`LOCALVERSION` to `-skskb-full`, run `make olddefconfig`, and repeat steps 4–6.
Only the changed files are recompiled. From `full` to `partial`, first restore
`tcp_input.c` with `git -C ~/linux-7.1 checkout -- net/ipv4/tcp_input.c`.

## Build

```bash
cd ~/sk_skb_fix/fix_test
make

## Run

On the server side, with `setup_exp.sh` running (`NET_IFACE=ens6f1np1 PORT=9998 GRO=on`):

One cell by hand:

```bash
# Server
sudo build/fix_test_loader --style load --mode rw --area full --msg-size 16348 \
     --warmup 3 --measure 10 --cpu 18 --accept-wait 30 --tag manual
# Client
~/sk_skb_fix/fix_test/build/fix_test_client --host 192.168.2.30 --port 9998 \
     --msg-size 16348 --spin 0 --duration 13 --cpu 18 --tag manual
```
