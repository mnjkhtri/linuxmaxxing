KDIR ?= ../../build
CC ?= x86_64-linux-gnu-gcc
WORKLOAD_CFLAGS ?= -O2 -g -Wall -Wextra

obj-m += qedu.o
qedu-y := qedu_main.o qedu_chrdev.o qedu_irq.o qedu_dma.o qedu_sysfs.o qedu_debugfs.o

.PHONY: all workload clean

all: workload
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

workload: workload_qedu

workload_qedu: workload_qedu.c
	$(CC) $(WORKLOAD_CFLAGS) -static -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	$(RM) workload_qedu
