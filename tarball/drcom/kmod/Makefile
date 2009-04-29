#

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m	:= drcom.o

EXTRA_CFLAGS := -I./

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

all: default

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	/sbin/depmod -a $(shell uname -r)


endif

clean:
	@echo "  CLEAN kmod"
	@rm -rf *.o
	@rm -rf *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers
	@rm -rf *.markers *.order

