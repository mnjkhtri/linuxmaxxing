CC ?= x86_64-linux-gnu-gcc
CFLAGS ?= -O2 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -Wall -Wextra
LDFLAGS ?= -static
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BPF_SRC := $(DIR)cfs.bpf.c
BPF_OBJ := $(DIR)cfs.bpf.o
SKEL := $(DIR)cfs.skel.h
LOADER_SRC := $(DIR)cfs.c
LOADER := $(DIR)cfs
VMLINUX := $(DIR)vmlinux.h
KERNEL_BUILD := $(abspath $(DIR)../../build)
CFS_CFLAGS := -g -O2 -Wall -I$(DIR)

.PHONY: all clean workload cfs

all: workload_fork $(LOADER)

workload_fork: workload_fork.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(VMLINUX):
	# vmlinux.h comes from this exact kernel's BTF so CO-RE can name scheduler types.
	$(BPFTOOL) btf dump file $(KERNEL_BUILD)/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(DIR) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	# The generated skeleton gives cfs.c typed access to programs and maps.
	$(BPFTOOL) gen skeleton $< > $@

$(LOADER): $(LOADER_SRC) $(SKEL)
	$(CC) $(CFS_CFLAGS) -o $@ $< $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

clean:
	$(RM) workload_fork $(BPF_OBJ) $(SKEL) $(LOADER)
