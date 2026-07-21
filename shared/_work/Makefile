CC := x86_64-linux-gnu-gcc
CFLAGS ?= -O2 -Wall
LDFLAGS ?= -static
LDLIBS ?= -pthread

BUILD_DIR := build
SOURCES := $(wildcard *.c)
TARGETS := $(patsubst %.c,$(BUILD_DIR)/%,$(SOURCES))

.PHONY: all clean

all: $(TARGETS)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	$(RM) $(TARGETS)
	rmdir $(BUILD_DIR) 2>/dev/null || true
