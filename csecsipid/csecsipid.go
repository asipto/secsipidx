package main

import "C"

import (
	"github.com/asipto/secsipidx/secsipid"
)

// SecSIPIDSign --
//export SecSIPIDSign
func SecSIPIDSign(headerJSON *C.char, payloadJSON *C.char, prvkeyPath *C.char, outPtr **C.char) int32 {
	signature := secsipid.SJWTEncodeText(C.GoString(headerJSON), C.GoString(payloadJSON), C.GoString(prvkeyPath))
	*outPtr = C.CString(signature)
	return int32(len(signature))
}

func main() {}
