# Makefile to build libraries
#

include ../Makefile.defs

SOBASENAME=libsecsipid.so
SOLIBNAME=${SOBASENAME}.1
SOREALNAME=${SOBASENAME}.1.0.0

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
	go build ${LD_OPTS} -o ${SOBASENAME} -buildmode=c-shared csecsipid.go
	mv ${SOBASENAME} ${SOREALNAME}
	ln -s ${SOREALNAME} ${SOLIBNAME}
	ln -s ${SOREALNAME} ${SOBASENAME}

.PHONY: liba
liba:
	go build -o ${ABASENAME} -buildmode=c-archive csecsipid.go


.PHONY: install-libso
install-libso:
	cp ${SOREALNAME} ${PREFIX}/lib/
	rm -rf ${PREFIX}/lib/${SOBASENAME}
	rm -rf ${PREFIX}/lib/${SOLIBNAME}
	ln -s ${PREFIX}/lib/${SOREALNAME} ${PREFIX}/lib/${SOBASENAME}
	ln -s ${PREFIX}/lib/${SOREALNAME} ${PREFIX}/lib/${SOLIBNAME}

.PHONY: install-liba
install-liba:
	cp ${ABASENAME} ${PREFIX}/lib/

.PHONY: install-dev
install-dev:
	cp libsecsipid.h ${PREFIX}/include/
	cp secsipid.h ${PREFIX}/include/

.PHONY: install
install: install-libso install-liba install-dev

.PHONY: clean
clean:
	rm -f ${SOBASENAME} ${SOREALNAME} ${SOLIBNAME}
	rm -f ${ABASENAME}
