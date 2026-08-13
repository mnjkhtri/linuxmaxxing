CC ?= gcc
CFLAGS ?= -O0 -g -Wall -Wextra
AS ?= as
LD ?= ld
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

BUILD_DIR := build
VMM := $(BUILD_DIR)/vmm
GUEST_OBJ := $(BUILD_DIR)/guest.o
GUEST_BIN := $(BUILD_DIR)/guest.bin
BPF_SRC := ept.bpf.c
BPF_OBJ := $(BUILD_DIR)/ept.bpf.o
SKEL := $(BUILD_DIR)/ept.skel.h
KVM_TYPES := $(BUILD_DIR)/kvm_types.h
KVM_COMPAT := $(BUILD_DIR)/kvm_compat.h
VMLINUX := $(BUILD_DIR)/vmlinux.h
EPT := $(BUILD_DIR)/ept
KVM_BTF_SOURCE := $(shell test -e /sys/kernel/btf/kvm && echo /sys/kernel/btf/kvm || echo /sys/kernel/btf/vmlinux)

EPT_CFLAGS := -g -O2 -Wall -Wextra -I$(BUILD_DIR)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(BUILD_DIR)

.PHONY: all clean clean-ept

all: $(VMM) $(GUEST_BIN) $(EPT)

$(BUILD_DIR):
	mkdir -p $@

$(VMM): vmm.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(GUEST_OBJ): guest.S | $(BUILD_DIR)
	$(AS) --32 $< -o $@

$(GUEST_BIN): $(GUEST_OBJ)
	$(LD) -m elf_i386 -Ttext 0x0 --oformat binary $< -o $@

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(KVM_TYPES): $(VMLINUX) | $(BUILD_DIR)
	@if grep -q "^struct kvm_vcpu {" $(VMLINUX); then \
		echo '/* KVM structs are already present in vmlinux.h. */' > $@; \
	else \
		echo '/* Partial CO-RE KVM structs for kernels that expose KVM through module BTF. */' > $@; \
		echo 'struct kvm;' >> $@; \
		echo 'struct kvm_mmu_root_info { __u64 pgd; __u64 hpa; } __attribute__((preserve_access_index));' >> $@; \
		echo 'struct kvm_mmu { struct kvm_mmu_root_info root; __u64 root_hpa; __u64 root_pgd; } __attribute__((preserve_access_index));' >> $@; \
		echo 'struct kvm_vcpu_arch { struct kvm_mmu *mmu; } __attribute__((preserve_access_index));' >> $@; \
		echo 'struct kvm_vcpu { struct kvm *kvm; struct kvm_vcpu_arch arch; } __attribute__((preserve_access_index));' >> $@; \
	fi

$(KVM_COMPAT): | $(BUILD_DIR)
	@if $(BPFTOOL) btf dump file $(KVM_BTF_SOURCE) format c | grep -q "hpa_t root_hpa;"; then \
		echo '#define READ_KVM_MMU_ROOT_HPA(mmu) BPF_CORE_READ(mmu, root_hpa)' > $@; \
		echo '#define READ_KVM_MMU_ROOT_PGD(mmu) BPF_CORE_READ(mmu, root_pgd)' >> $@; \
	else \
		echo '#define READ_KVM_MMU_ROOT_HPA(mmu) BPF_CORE_READ(mmu, root.hpa)' > $@; \
		echo '#define READ_KVM_MMU_ROOT_PGD(mmu) BPF_CORE_READ(mmu, root.pgd)' >> $@; \
	fi

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) $(KVM_TYPES) $(KVM_COMPAT) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(EPT): ept.c $(SKEL) | $(BUILD_DIR)
	$(CC) $(EPT_CFLAGS) -o $@ $< $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

clean-ept:
	rm -f $(BPF_OBJ) $(SKEL) $(EPT) $(VMLINUX) $(KVM_TYPES) $(KVM_COMPAT)

clean:
	rm -rf $(BUILD_DIR) vmm guest.o guest.bin
