##
## drcom-client PUM v1.0, Python User Mode
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

RESOURCEDIR ?= $(DESTDIR)/usr/share/drcom/resource
MO_DIR ?= $(DESTDIR)/usr/share/drcom/resource/po/zh_CN/LC_MESSAGES
APPDIR ?= $(DESTDIR)/usr/share/applications

.PHONY: all clean install uninstall

all:

clean:
	@rm -rf $(RESOURCEDIR)
	@rm -f $(APPDIR)/drcom.desktop

install:
	@mkdir -p $(RESOURCEDIR)
	@install -m 644 COPYING drcom.png drcom.wav $(RESOURCEDIR)
	@mkdir -p $(MO_DIR)
	@install -m 644 po/zh_CN/LC_MESSAGES/drcom.mo $(MO_DIR)
	@mkdir -p $(APPDIR)
	@install -m 644 drcom.desktop $(APPDIR)

uninstall:	clean
