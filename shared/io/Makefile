KDIR ?= ../../build
CC ?= x86_64-linux-gnu-gcc
WORKLOAD_CFLAGS ?= -O2 -g -Wall -Wextra

SHARED_DIR := ..
JSON_WRITER_SRC := $(SHARED_DIR)/json_writer.c
JSON_WRITER_HDR := $(SHARED_DIR)/json_writer.h

obj-m += qedu_trace.o
obj-m += qedu.o
ccflags-y += -I$(src)
qedu-y := qedu_main.o qedu_chrdev.o qedu_irq.o qedu_dma.o qedu_sysfs.o qedu_debugfs.o

.PHONY: all workload clean

all: workload
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

workload: workload_qedu

workload_qedu: workload_qedu.c $(JSON_WRITER_SRC) $(JSON_WRITER_HDR)
	$(CC) $(WORKLOAD_CFLAGS) -I$(SHARED_DIR) -static -o $@ $< $(JSON_WRITER_SRC)

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	$(RM) workload_qedu
