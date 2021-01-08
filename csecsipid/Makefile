# Makefile to build libraries
#

SONAME=libsecsipid.so.1
NAME=libsecsipid.so
REAL_NAME=libsecsipid.so.1.0.0
LD_FLAGS += -extldflags=-Wl,-soname,${SONAME}

all: libso

libso:
	go build -ldflags="${LD_FLAGS}" -o ${NAME} -buildmode=c-shared csecsipid.go
	mv ${NAME} ${REAL_NAME}
	ln -s ${REAL_NAME} ${SONAME}
	ln -s ${REAL_NAME} ${NAME}
liba:
	go build -o libsecsipid.a -buildmode=c-archive csecsipid.go

clean:
	rm -f ${NAME} ${REAL_NAME} ${SONAME}
	rm -f libsecsipid.a
