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

SUBDIRS = src resource 
DIRS ?= $(DESTDIR)/usr/share/drcom
BINDIR ?= $(DESTDIR)/usr/bin

.PHONY: all clean install uninstall

all:
	@for x in $(SUBDIRS); do (cd $$x && make all) || exit 1; done

clean:
	@for x in $(SUBDIRS); do (cd $$x && make clean) || exit 1; done
	@rm -rf $(DIRS)

install:
	@for x in $(SUBDIRS); do (cd $$x && make install) || exit 1; done
	@drcom start
	@drunlevel add drcom
	@echo
	@echo "Install drcom-client PUM successfully!"
	@echo

uninstall:	clean
	@drunlevel del drcom
	@drcom stop
	@for x in $(SUBDIRS); do (cd $$x && make uninstall) || exit 1; done
	@rm -rf $(BINDIR)/drcom $(BINDIR)/drunlevel $(BINDIR)/mkdrcom
	@echo 
	@echo "Uninstall drcom-client PUM successfully!"
	@echo
