.DELETE_ON_ERROR:

DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SHARED_DIR := $(abspath $(DIR)../..)

CC ?= gcc
CFLAGS ?= -O0 -g -Wall -Wextra
LD ?= ld
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

BUILD_DIR := $(DIR)build
VMM := $(BUILD_DIR)/vmm
GUEST_OBJ := $(BUILD_DIR)/guest.o
GUEST_BIN := $(BUILD_DIR)/guest.bin
CONTRACT := $(DIR)virtio.h
GUEST_CODE_LIMIT := 0x1000
BPF_SRC := $(DIR)virtio.bpf.c
BPF_OBJ := $(BUILD_DIR)/virtio.bpf.o
SKEL := $(BUILD_DIR)/virtio.skel.h
VMLINUX := $(BUILD_DIR)/vmlinux.h
OBSERVER := $(BUILD_DIR)/virtio
EVENT_HDR := $(DIR)virtio_event.h
JSON_WRITER_SRC := $(SHARED_DIR)/json_writer.c
JSON_WRITER_HDR := $(SHARED_DIR)/json_writer.h

OBSERVER_CFLAGS := -O2 -g -Wall -Wextra -I$(BUILD_DIR) -I$(DIR) -I$(SHARED_DIR)
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(BUILD_DIR) -I$(DIR)

.PHONY: all clean

all: $(VMM) $(GUEST_BIN) $(OBSERVER)

$(BUILD_DIR):
	mkdir -p $@

$(VMM): $(DIR)vmm.c $(CONTRACT) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(DIR) $< -o $@
	@nm -an $@ | grep -Eq ' [tT] handle_mmio$$' || { echo "VMM lacks handle_mmio symbol" >&2; exit 1; }
	@nm -an $@ | grep -Eq ' [tT] process_queue$$' || { echo "VMM lacks process_queue symbol" >&2; exit 1; }

$(GUEST_OBJ): $(DIR)guest.S $(CONTRACT) | $(BUILD_DIR)
	$(CC) -m32 -I$(DIR) -c $< -o $@

$(GUEST_BIN): $(GUEST_OBJ)
	$(LD) -m elf_i386 -Ttext 0x0 --oformat binary $< -o $@
	@test "$$(stat -c %s $@)" -le $$(( $(GUEST_CODE_LIMIT) )) || { echo "guest binary exceeds 0x1000-byte code region" >&2; exit 1; }

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(EVENT_HDR) $(CONTRACT) $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(OBSERVER): $(DIR)virtio.c $(SKEL) $(EVENT_HDR) $(CONTRACT) $(JSON_WRITER_SRC) $(JSON_WRITER_HDR) | $(BUILD_DIR)
	$(CC) $(OBSERVER_CFLAGS) -o $@ $< $(JSON_WRITER_SRC) $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

clean:
	rm -rf $(BUILD_DIR)
