##
## drcom-client PUM v1.0, Python User Mode
##
##               Makefile
## 
## Copyright (c) 2009, drcom-client Team
## Author:		Henry Huang <henry.s.huang@gmail.com>
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

## FIXME: archlinux not /etc/init.d/ but /etc/rc.d/
INITDIR ?= /etc/init.d/
BINDIR ?= /usr/bin/

all:
	@echo 

install:
	@mkdir -p $(INITDIR)
	@install -m 755 drcom $(INITDIR)
	@mkdir -p $(BINDIR)
	@install -m 755 runlevel drcom mkdrcom $(BINDIR)

uninstall:
	@rm $(BINDIR)/runlevel $(BINDIR)/drcom $(BINDIR)/mkdrcom
	@rm $(INITDIR)/drcom

