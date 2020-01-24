# Makefile to build libraries
#

all: libso

libso:
	go build -o secsipid.so -buildmode=c-shared csecsipid.go

liba:
	go build -o secsipid.a -buildmode=c-archive csecsipid.go

clean:
	rm -f secsipid.so
	rm -f secsipid.a