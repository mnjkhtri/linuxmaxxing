CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BPF_SRC := $(DIR)cfs_tree.bpf.c
BPF_OBJ := $(DIR)cfs_tree.bpf.o
SKEL := $(DIR)cfs_tree.skel.h
LOADER_SRC := $(DIR)cfs_tree.c
LOADER := $(DIR)cfs_tree
VMLINUX := $(DIR)vmlinux.h

CFLAGS := -g -O2 -Wall -I$(DIR)

.PHONY: all clean

all: $(LOADER)

$(VMLINUX):
	$(BPFTOOL) btf dump file build/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(DIR) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(LOADER): $(LOADER_SRC) $(SKEL)
	$(CC) $(CFLAGS) -o $@ $< $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(LOADER)
