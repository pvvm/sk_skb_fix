# SPDX-License-Identifier: GPL-2.0
#
# fix_test -- SK_SKB receive path on a stock kernel with the sockmap fixes.
#
#   make            BPF object, receiver, load generator
#   make KDIR=...   kernel tree whose uapi linux/bpf.h to build against
#                   (default ~/linux-7.1, the tree the fixes are applied to)
#   make clean

KDIR      ?= $(HOME)/linux-7.1

CLANG     ?= clang
CC        ?= gcc

SRC       := src
OBJDIR    := build
UAPI      := include
ARCH_INC  := -I/usr/include/$(shell uname -m)-linux-gnu

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 \
              -Wall -Wno-unused-value -Wno-compare-distinct-pointer-types \
              -I$(UAPI) -I$(SRC) $(ARCH_INC)

CFLAGS    += -O2 -g -Wall -Wextra -Wno-unused-parameter -I$(SRC) -I$(UAPI)
CFLAGS_BPF := $(shell pkg-config --cflags libbpf)
LDLIBS_BPF := $(shell pkg-config --libs libbpf)

BPF_OBJ   := $(OBJDIR)/fix_test.bpf.o
LOADER    := $(OBJDIR)/fix_test_loader
CLIENT    := $(OBJDIR)/fix_test_client

.PHONY: all clean

all: $(BPF_OBJ) $(LOADER) $(CLIENT)

# The kernel's own uapi bpf.h, placed FIRST on the include path so it shadows
# the distro copy and nothing else.
$(UAPI)/linux/bpf.h:
	@mkdir -p $(UAPI)/linux
	@test -f $(KDIR)/include/uapi/linux/bpf.h || \
		{ echo "ERROR: $(KDIR)/include/uapi/linux/bpf.h not found. Set KDIR."; exit 1; }
	ln -sf $(KDIR)/include/uapi/linux/bpf.h $@

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(BPF_OBJ): $(SRC)/fix_test.bpf.c $(SRC)/fix_test_common.h $(UAPI)/linux/bpf.h | $(OBJDIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LOADER): $(SRC)/fix_test_loader.c $(SRC)/fix_test_common.h $(UAPI)/linux/bpf.h | $(OBJDIR)
	$(CC) $(CFLAGS) $(CFLAGS_BPF) $< -o $@ $(LDLIBS_BPF)

$(CLIENT): $(SRC)/fix_test_client.c $(SRC)/fix_test_common.h $(UAPI)/linux/bpf.h | $(OBJDIR)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(BPF_OBJ) $(LOADER) $(CLIENT)
