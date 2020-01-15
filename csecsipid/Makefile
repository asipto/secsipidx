# Makefile to build libraries
#

all: libso

libso:
	go build -o secsipid.so -buildmode=c-shared csecsipid.go

clean:
	rm -f secsipid.so