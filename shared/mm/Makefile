CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR := $(DIR)build
BPF_SRC := $(DIR)mm.bpf.c
BPF_OBJ := $(BUILD_DIR)/mm.bpf.o
SKEL := $(BUILD_DIR)/mm.skel.h
LOADER_SRC := $(DIR)mm.c
LOADER := $(BUILD_DIR)/mm
VMLINUX := $(BUILD_DIR)/vmlinux.h
KERNEL_BUILD := $(abspath $(DIR)../../build)

CFLAGS := -g -O2 -Wall -Wextra -I$(BUILD_DIR)

.PHONY: all clean

all: $(LOADER)

$(BUILD_DIR):
	mkdir -p $@

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file $(KERNEL_BUILD)/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(DIR)mm_page_walk.bpf.h $(DIR)mm_xarray_walk.bpf.h $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(BUILD_DIR) -c $< -o $@

$(SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(LOADER): $(LOADER_SRC) $(SKEL) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(LOADER) $(VMLINUX)
	rmdir $(BUILD_DIR) 2>/dev/null || true
