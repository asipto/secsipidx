# Makefile to build the app and libs
#

include Makefile.defs

.PHONY: all
all: tool lib

.PHONY: tool
tool:
	GO111MODULE=off ${GO} build -o ${TOOLNAME} .

.PHONY: lib
lib:
	GO111MODULE=off $(MAKE) -C csecsipid/ libso
	GO111MODULE=off $(MAKE) -C csecsipid/ liba

.PHONY: install-tool
install-tool:
	cp ${TOOLNAME} ${DESTDIR}${PREFIX}/bin/

.PHONY: install-lib
install-lib:
	$(MAKE) -C csecsipid/ install-libso
	$(MAKE) -C csecsipid/ install-liba

.PHONY: install-dev
install-dev:
	$(MAKE) -C csecsipid/ install-dev

.PHONY: install-lib-all
install-lib-all: install-lib install-dev

.PHONY: install-dirs
install-dirs:
	mkdir -p ${DESTDIR}${PREFIX}
	mkdir -p ${DESTDIR}${PREFIX}/bin
	mkdir -p ${DESTDIR}${PREFIX}/lib
	mkdir -p ${DESTDIR}${PREFIX}/lib/pkgconfig
	mkdir -p ${DESTDIR}${PREFIX}/include

.PHONY: install
install: install-dirs install-tool install-lib install-dev

.PHONY: clean
clean:
	rm -rf ${TOOLNAME}
	$(MAKE) -C csecsipid/ clean

