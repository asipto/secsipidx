# Makefile to build libraries
#

include ../Makefile.defs

SOBASENAME=libsecsipid.so
SOLIBNAME=${SOBASENAME}.${LIBVERMAJ}
SOREALNAME=${SOBASENAME}.${LIBVERSION}

ifneq ($(OS), darwin)
LD_FLAGS += -extldflags=-Wl,-soname,${SOLIBNAME}
LD_OPTS = -ldflags="${LD_FLAGS}"
else
LD_OPTS =
endif

ABASENAME=libsecsipid.a

.PHONY: all
all: libso

.PHONY: libso
libso:
	rm -rf ${SOLIBNAME}
	rm -rf ${SOBASENAME}
	rm -rf ${SOREALNAME}
	GO111MODULE=${GO111MODVAL} go build ${LD_OPTS} -o ${SOBASENAME} -buildmode=c-shared csecsipid.go
	mv ${SOBASENAME} ${SOREALNAME}
	ln -s ${SOREALNAME} ${SOLIBNAME}
	ln -s ${SOREALNAME} ${SOBASENAME}

.PHONY: liba
liba:
	GO111MODULE=${GO111MODVAL} go build -o ${ABASENAME} -buildmode=c-archive csecsipid.go


.PHONY: install-libso
install-libso:
	cp ${SOREALNAME} ${DESTDIR}${PREFIX}/lib/
	ln -fs ${SOREALNAME} ${DESTDIR}${PREFIX}/lib/${SOBASENAME}
	ln -fs ${SOREALNAME} ${DESTDIR}${PREFIX}/lib/${SOLIBNAME}

.PHONY: install-liba
install-liba:
	cp ${ABASENAME} ${DESTDIR}${PREFIX}/lib/

.PHONY: install-dev
install-dev:
	cp secsipid-1.pc ${DESTDIR}${PREFIX}/lib/pkgconfig/
	cp libsecsipid.h ${DESTDIR}${PREFIX}/include/
	cp secsipid.h ${DESTDIR}${PREFIX}/include/

.PHONY: install
install: install-libso install-liba install-dev

.PHONY: clean
clean:
	rm -f ${SOBASENAME} ${SOREALNAME} ${SOLIBNAME}
	rm -f ${ABASENAME}
