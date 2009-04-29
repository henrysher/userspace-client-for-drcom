TOPSRCDIR = $(shell pwd)
DESTDIR = /usr/local/bin/

export TOPSRCDIR DESTDIR

SUBDIRS = drcom kmod 

.PHONY: all clean install

all:
	@for x in $(SUBDIRS); do (cd $$x && make all) || exit 1; done

clean:
	@for x in $(SUBDIRS); do (cd $$x && make clean) || exit 1; done

install:
	@for x in $(SUBDIRS); do (cd $$x && make install) || exit 1; done
	@echo 
	@echo "Install GUI drcom-client successfully"
	@echo

