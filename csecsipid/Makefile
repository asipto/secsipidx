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
	cp ${SOREALNAME} ${DESTDIR}${LIBDIR}/
	ln -fs ${SOREALNAME} ${DESTDIR}${LIBDIR}/${SOBASENAME}
	ln -fs ${SOREALNAME} ${DESTDIR}${LIBDIR}/${SOLIBNAME}

.PHONY: install-liba
install-liba:
	cp ${ABASENAME} ${DESTDIR}${LIBDIR}/

secsipid-$(LIBVERMAJ).pc: secsipid.pc.in
	sed -e 's|@prefix@|${PREFIX}|g' \
	    -e 's|@libdir@|${LIBDIR}|g' \
			-e 's|@version@|${LIBVERSION}|g' \
	    secsipid.pc.in > secsipid-${LIBVERMAJ}.pc

.PHONY: install-dev
install-dev: secsipid-$(LIBVERMAJ).pc
	cp secsipid-${LIBVERMAJ}.pc ${DESTDIR}${LIBDIR}/pkgconfig/
	cp libsecsipid.h ${DESTDIR}${PREFIX}/include/
	cp secsipid.h ${DESTDIR}${PREFIX}/include/

.PHONY: install
install: install-libso install-liba install-dev

.PHONY: clean
clean:
	rm -f ${SOBASENAME} ${SOREALNAME} ${SOLIBNAME}
	rm -f ${ABASENAME}
