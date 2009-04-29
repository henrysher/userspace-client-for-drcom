#
# g-DrcomClient , a Novel GUI-based Drcom-Client
#
#       Makefile
#
# Copyright (c) 2008, Henry Huang <henry.s.huang@gmail.com>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

DESUDIR = /usr/bin/
CONFDIR = /usr/share/drcom/
DSKTDIR = /usr/share/applications/

all:
	@echo 

install:
	@mkdir -p $(DESUDIR)
	@cp drcom $(DESUDIR)
	@mkdir -p $(CONFDIR)
	@cp drcom.py $(CONFDIR)
	@cp drcom.png $(CONFDIR)
	@cp drcom.wav $(CONFDIR)
	@cp COPYING $(CONFDIR)
	@cp -r po/ $(CONFDIR)
	@mkdir -p $(DSKTDIR)
	@cp drcom.desktop $(DSKTDIR)
	


clean:
	@echo " CLEAN gdrcom"

