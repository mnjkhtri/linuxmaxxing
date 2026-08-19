.DELETE_ON_ERROR:

DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SHARED_DIR := $(abspath $(DIR)../..)

CC ?= gcc
CFLAGS ?= -O0 -g -Wall -Wextra
AS ?= as
LD ?= ld
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

BUILD_DIR := $(DIR)build
VMM := $(BUILD_DIR)/vmm
GUEST_OBJ := $(BUILD_DIR)/guest.o
GUEST_BIN := $(BUILD_DIR)/guest.bin
BPF_SRC := $(DIR)io.bpf.c
BPF_OBJ := $(BUILD_DIR)/io.bpf.o
SKEL := $(BUILD_DIR)/io.skel.h
KVM_TYPES := $(BUILD_DIR)/kvm_types.h
KVM_COMPAT := $(BUILD_DIR)/kvm_compat.h
VMLINUX := $(BUILD_DIR)/vmlinux.h
IO := $(BUILD_DIR)/io
EVENT_HDR := $(DIR)io_event.h
DEVICE_HDR := $(DIR)device.h
JSON_WRITER_SRC := $(SHARED_DIR)/json_writer.c
JSON_WRITER_HDR := $(SHARED_DIR)/json_writer.h
KVM_BTF_SOURCE := $(shell test -e /sys/kernel/btf/kvm && echo /sys/kernel/btf/kvm || echo /sys/kernel/btf/vmlinux)

IO_CFLAGS := -g -O2 -Wall -Wextra -I$(BUILD_DIR) -I$(SHARED_DIR)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(BUILD_DIR)

.PHONY: all clean clean-io

all: $(VMM) $(GUEST_BIN) $(IO)

$(BUILD_DIR):
	mkdir -p $@

$(VMM): $(DIR)vmm.c $(DEVICE_HDR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -pthread $< -o $@

$(GUEST_OBJ): $(DIR)guest.S | $(BUILD_DIR)
	$(AS) --32 $< -o $@

$(GUEST_BIN): $(GUEST_OBJ)
	$(LD) -m elf_i386 -Ttext 0x0 --oformat binary $< -o $@

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(KVM_TYPES): $(VMLINUX) | $(BUILD_DIR)
	@echo '/* Partial CO-RE KVM structs for kernels that do not expose every needed struct in vmlinux.h. */' > $@; \
	echo '/* Only the fields the observer reads are declared; CO-RE relocates their true offsets. */' >> $@; \
	if ! grep -q "^struct kvm_vcpu {" $(VMLINUX); then \
		echo 'struct kvm;' >> $@; \
		echo 'struct kvm_lapic;' >> $@; \
		echo 'struct kvm_vcpu_arch { struct kvm_lapic *apic; } __attribute__((preserve_access_index));' >> $@; \
		echo 'struct kvm_vcpu { struct kvm *kvm; struct kvm_vcpu_arch arch; } __attribute__((preserve_access_index));' >> $@; \
	fi; \
	if ! grep -q "^struct kvm_lapic {" $(VMLINUX); then \
		echo 'struct kvm_lapic { void *regs; } __attribute__((preserve_access_index));' >> $@; \
	fi; \
	if ! grep -q "^struct kvm_ioapic {" $(VMLINUX); then \
		echo 'struct kvm_ioapic { struct { unsigned long long bits; } redirtbl[16]; } __attribute__((preserve_access_index));' >> $@; \
	fi

$(KVM_COMPAT): | $(BUILD_DIR)
	@if $(BPFTOOL) btf dump file $(KVM_BTF_SOURCE) format c | sed -n '/struct kvm_lapic {/,/^};/p' | grep -q regs; then \
		echo '#define READ_KVM_LAPIC_REGS(apic) ((const __u32 *)BPF_CORE_READ(apic, regs))' > $@; \
		echo '#define READ_KVM_LAPIC_REGS_AVAILABLE 1' >> $@; \
	else \
		echo '#define READ_KVM_LAPIC_REGS(apic) ((const __u32 *)0)' > $@; \
		echo '#define READ_KVM_LAPIC_REGS_AVAILABLE 0' >> $@; \
	fi
	@if $(BPFTOOL) btf dump file $(KVM_BTF_SOURCE) format c | grep -q 'redirtbl'; then \
		echo '#define READ_KVM_IOAPIC_RTE(ioapic, irq) BPF_CORE_READ(ioapic, redirtbl[irq].bits)' >> $@; \
		echo '#define READ_KVM_IOAPIC_RTE_AVAILABLE 1' >> $@; \
	else \
		echo '#define READ_KVM_IOAPIC_RTE(ioapic, irq) 0' >> $@; \
		echo '#define READ_KVM_IOAPIC_RTE_AVAILABLE 0' >> $@; \
	fi

$(BPF_OBJ): $(BPF_SRC) $(EVENT_HDR) $(DEVICE_HDR) $(VMLINUX) $(KVM_TYPES) $(KVM_COMPAT) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(IO): $(DIR)io.c $(SKEL) $(EVENT_HDR) $(DEVICE_HDR) $(KVM_COMPAT) $(JSON_WRITER_SRC) $(JSON_WRITER_HDR) | $(BUILD_DIR)
	$(CC) $(IO_CFLAGS) -o $@ $< $(JSON_WRITER_SRC) $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

clean-io:
	rm -f $(BPF_OBJ) $(SKEL) $(IO) $(VMLINUX) $(KVM_TYPES) $(KVM_COMPAT)

clean:
	rm -rf $(BUILD_DIR)
