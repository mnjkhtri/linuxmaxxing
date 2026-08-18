CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SHARED_DIR := $(abspath $(DIR)..)
BUILD_DIR := $(DIR)build
BPF_SRC := $(DIR)mm.bpf.c
BPF_OBJ := $(BUILD_DIR)/mm.bpf.o
SKEL := $(BUILD_DIR)/mm.skel.h
LOADER_SRC := $(DIR)mm.c
LOADER := $(BUILD_DIR)/mm
VMLINUX := $(BUILD_DIR)/vmlinux.h
EVENT_HDR := $(DIR)mm_event.h
JSON_WRITER_SRC := $(SHARED_DIR)/json_writer.c
JSON_WRITER_HDR := $(SHARED_DIR)/json_writer.h
KERNEL_BUILD := $(abspath $(DIR)../../build)
WORKLOAD_CFLAGS := -O2 -g -Wall -Wextra

CFLAGS := -g -O2 -Wall -Wextra -I$(BUILD_DIR) -I$(DIR) -I$(SHARED_DIR)

.PHONY: all workload clean

all: $(LOADER) workload

workload: workload_mm

workload_mm: workload_mm.c $(JSON_WRITER_SRC) $(JSON_WRITER_HDR)
	$(CC) $(WORKLOAD_CFLAGS) -I$(SHARED_DIR) -static -o $@ $< $(JSON_WRITER_SRC)

$(BUILD_DIR):
	mkdir -p $@

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file $(KERNEL_BUILD)/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(DIR)mm_page_walk.bpf.h $(DIR)mm_xarray_walk.bpf.h $(EVENT_HDR) $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(BUILD_DIR) -I$(DIR) -c $< -o $@

$(SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(LOADER): $(LOADER_SRC) $(SKEL) $(EVENT_HDR) $(JSON_WRITER_SRC) $(JSON_WRITER_HDR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(JSON_WRITER_SRC) $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(LOADER) $(VMLINUX)
	rm -f workload_mm
	rmdir $(BUILD_DIR) 2>/dev/null || true
