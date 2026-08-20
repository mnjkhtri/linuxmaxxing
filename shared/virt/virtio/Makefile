.DELETE_ON_ERROR:

DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CC ?= gcc
CFLAGS ?= -O0 -g -Wall -Wextra
LD ?= ld

BUILD_DIR := $(DIR)build
VMM := $(BUILD_DIR)/vmm
GUEST_OBJ := $(BUILD_DIR)/guest.o
GUEST_BIN := $(BUILD_DIR)/guest.bin
CONTRACT := $(DIR)virtio.h
GUEST_CODE_LIMIT := 0x1000

.PHONY: all clean

all: $(VMM) $(GUEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(VMM): $(DIR)vmm.c $(CONTRACT) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(DIR) $< -o $@

$(GUEST_OBJ): $(DIR)guest.S $(CONTRACT) | $(BUILD_DIR)
	$(CC) -m32 -I$(DIR) -c $< -o $@

$(GUEST_BIN): $(GUEST_OBJ)
	$(LD) -m elf_i386 -Ttext 0x0 --oformat binary $< -o $@
	@test "$$(stat -c %s $@)" -le $$(( $(GUEST_CODE_LIMIT) )) || { echo "guest binary exceeds 0x1000-byte code region" >&2; exit 1; }

clean:
	rm -rf $(BUILD_DIR)
