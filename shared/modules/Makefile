KDIR ?= ../../build

obj-m += core/core_koops.o
obj-m += mm/mm_koops.o

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
