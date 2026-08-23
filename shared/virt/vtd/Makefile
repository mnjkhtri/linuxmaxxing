.DELETE_ON_ERROR:

DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SHARED_DIR := $(abspath $(DIR)../..)

CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

BUILD_DIR := $(DIR)build
BPF_SRC := $(DIR)vtd.bpf.c
BPF_OBJ := $(BUILD_DIR)/vtd.bpf.o
VMLINUX := $(BUILD_DIR)/vmlinux.h
SKEL := $(BUILD_DIR)/vtd.skel.h
OBSERVER := $(BUILD_DIR)/vtd
EVENT_HDR := $(DIR)vtd_event.h
OBSERVER_SRC := $(DIR)observer.c
JSON_WRITER_SRC := $(SHARED_DIR)/json_writer.c
JSON_WRITER_HDR := $(SHARED_DIR)/json_writer.h

OBSERVER_CFLAGS := -O2 -g -Wall -Wextra -I$(BUILD_DIR) -I$(DIR) -I$(SHARED_DIR)
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(BUILD_DIR) -I$(DIR)

.PHONY: all clean

all: $(OBSERVER)

$(BUILD_DIR):
	mkdir -p $@

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(EVENT_HDR) $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(OBSERVER): $(OBSERVER_SRC) $(SKEL) $(EVENT_HDR) $(JSON_WRITER_SRC) $(JSON_WRITER_HDR) | $(BUILD_DIR)
	$(CC) $(OBSERVER_CFLAGS) -o $@ $< $(JSON_WRITER_SRC) $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

clean:
	rm -rf $(BUILD_DIR)
