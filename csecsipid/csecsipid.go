package main

import "C"

import (
	"github.com/asipto/secsipidx/secsipid"
)

// SecSIPIDSignJSONHP --
//export SecSIPIDSignJSONHP
func SecSIPIDSignJSONHP(headerJSON *C.char, payloadJSON *C.char, prvkeyPath *C.char, outPtr **C.char) C.int {
	signature, _ := secsipid.SJWTEncodeText(C.GoString(headerJSON), C.GoString(payloadJSON), C.GoString(prvkeyPath))
	*outPtr = C.CString(signature)
	return C.int(len(signature))
}

// SecSIPIDGetIdentity --
//export SecSIPIDGetIdentity
func SecSIPIDGetIdentity(origTN *C.char, destTN *C.char, attestVal *C.char, origID *C.char, x5uVal *C.char, prvkeyPath *C.char, outPtr **C.char) C.int {
	signature, _ := secsipid.SJWTGetIdentity(C.GoString(origTN), C.GoString(destTN), C.GoString(attestVal), C.GoString(origID), C.GoString(x5uVal), C.GoString(prvkeyPath))
	*outPtr = C.CString(signature)
	return C.int(len(signature))
}

// SecSIPIDCheck --
//export SecSIPIDCheck
func SecSIPIDCheck(identityVal *C.char, identityLen C.int, expireVal C.int, pubkeyPath *C.char, timeoutVal C.int) C.int {
	var sIdentity string
	if identityLen == 0 {
		sIdentity = C.GoString(identityVal)
	} else {
		sIdentity = C.GoStringN(identityVal, identityLen)
	}
	ret, _ := secsipid.SJWTCheckIdentity(sIdentity, int(expireVal), C.GoString(pubkeyPath), int(timeoutVal))
	return C.int(ret)
}

// SecSIPIDCheckFull --
//export SecSIPIDCheckFull
func SecSIPIDCheckFull(identityVal *C.char, identityLen C.int, expireVal C.int, pubkeyPath *C.char, timeoutVal C.int) C.int {
	var sIdentity string
	if identityLen == 0 {
		sIdentity = C.GoString(identityVal)
	} else {
		sIdentity = C.GoStringN(identityVal, identityLen)
	}
	ret, _ := secsipid.SJWTCheckFullIdentity(sIdentity, int(expireVal), C.GoString(pubkeyPath), int(timeoutVal))
	return C.int(ret)
}

//
func main() {}
