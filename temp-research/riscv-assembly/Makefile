RISCV_CC := riscv64-linux-gnu-gcc
X86_CC := gcc
QEMU_RISCV := qemu-riscv64
QEMU_SYSTEM_RISCV := qemu-system-riscv64

BUILD_DIR := build
METAL_SRC := metal-threads/riscv64/tlp-fight.S

.PHONY: all user simd metal-threads run clean

all: user simd metal-threads

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

user: $(BUILD_DIR)/hello-riscv64 $(BUILD_DIR)/bubble-sort-riscv64
	@$(QEMU_RISCV) $(BUILD_DIR)/hello-riscv64
	@$(QEMU_RISCV) $(BUILD_DIR)/bubble-sort-riscv64

$(BUILD_DIR)/hello-riscv64: user/riscv64/hello.s | $(BUILD_DIR)
	$(RISCV_CC) -nostdlib -static $< -o $@

$(BUILD_DIR)/bubble-sort-riscv64: main.c user/riscv64/bubble-sort.s | $(BUILD_DIR)
	$(RISCV_CC) -DUSER -static $^ -o $@

simd: $(BUILD_DIR)/vector-add-avx2-x86-64
	@$(BUILD_DIR)/vector-add-avx2-x86-64

$(BUILD_DIR)/vector-add-avx2-x86-64: main.c simd/x86-64/vector-add-avx2.s | $(BUILD_DIR)
	$(X86_CC) -DSIMD -mavx2 $^ -o $@

$(BUILD_DIR)/tlp-unsafe: $(METAL_SRC) | $(BUILD_DIR)
	$(RISCV_CC) -nostdlib -nostartfiles -static -Ttext=0x80000000 -march=rv64imazicsr -mabi=lp64 $< -o $@

$(BUILD_DIR)/tlp-atomic: $(METAL_SRC) | $(BUILD_DIR)
	$(RISCV_CC) -DUSE_ATOMIC -nostdlib -nostartfiles -static -Ttext=0x80000000 -march=rv64imazicsr -mabi=lp64 $< -o $@

metal-threads: $(BUILD_DIR)/tlp-unsafe $(BUILD_DIR)/tlp-atomic
	@printf '\n== TLP fight unsafe ==\n'
	@$(QEMU_SYSTEM_RISCV) -machine virt -nographic -bios none -smp 4 -kernel $(BUILD_DIR)/tlp-unsafe
	@printf '\n== TLP fight atomic ==\n'
	@$(QEMU_SYSTEM_RISCV) -machine virt -nographic -bios none -smp 4 -kernel $(BUILD_DIR)/tlp-atomic

clean:
	rm -rf $(BUILD_DIR)
