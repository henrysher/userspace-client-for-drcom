##
## drcom-client
##
##               Makefile
##
## Copyright (c) 2009, drcom-client Team
##
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public
## License as published by the Free Software Foundation; either
## version 2.1 of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
## General Public License for more details.
#
## You should have received a copy of the GNU General Public
## License along with this program; if not, write to the
## Free Software Foundation, Inc., 59 Temple Place - Suite 330,
## Boston, MA 02111-1307, USA.

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m	:= drcom.o

EXTRA_CFLAGS := -I$./include

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
INSTALLDIR ?= /usr/share/drcom/src/kmod
REMOVEDIR ?= /lib/modules/$(shell uname -r)/extra

all: default

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install:
	@mkdir -p $(INSTALLDIR)
	@install -m 755 drcom.c daemon_kernel.h Makefile $(INSTALLDIR)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	/sbin/depmod -a $(shell uname -r)

endif

clean:
	@rm -rf *.o
	@rm -rf *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers
	@rm -rf *.markers *.order

uninstall: clean
	@rm -r $(INSTALLDIR)
	@rm -r $(REMOVEDIR)/drcom.ko
