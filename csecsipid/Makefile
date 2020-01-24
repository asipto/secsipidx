# Makefile to build libraries
#

all: libso

libso:
	go build -o libsecsipid.so -buildmode=c-shared csecsipid.go

liba:
	go build -o libsecsipid.a -buildmode=c-archive csecsipid.go

clean:
	rm -f libsecsipid.so
	rm -f linsecsipid.a