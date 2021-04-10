package main

import "C"

import (
	"github.com/asipto/secsipidx/secsipid"
)

// SecSIPIDSignJSONHP --
// * sign the JSON header and payload with provided private key
// * headerJSON -  header part in JSON forman (0-terminated string)
// * payloadJSON -  payload part in JSON forman (0-terminated string)
// * prvkeyPath - path to private key to be used to generate the signature
// * outPtr - to be set to the pointer containing the output (it is a
//   0-terminated string); the `*outPtr` must be freed after use
// * return: the length of `*outPtr`
//export SecSIPIDSignJSONHP
func SecSIPIDSignJSONHP(headerJSON *C.char, payloadJSON *C.char, prvkeyPath *C.char, outPtr **C.char) C.int {
	signature, _ := secsipid.SJWTEncodeText(C.GoString(headerJSON), C.GoString(payloadJSON), C.GoString(prvkeyPath))
	*outPtr = C.CString(signature)
	return C.int(len(signature))
}

// SecSIPIDGetIdentity --
// Generate the Identity header content using the input attributes
// * origTN - calling number
// * destTN - called number
// * attestVal - attestation level
// * origID - unique ID for tracking purposes, if empty string a UUID is generated
// * x5uVal - location of public certificate
// * prvkeyPath - path to private key to be used to generate the signature
// * outPtr - to be set to the pointer containing the output (it is a
//   0-terminated string); the `*outPtr` must be freed after use
// * return: the length of `*outPtr`
//export SecSIPIDGetIdentity
func SecSIPIDGetIdentity(origTN *C.char, destTN *C.char, attestVal *C.char, origID *C.char, x5uVal *C.char, prvkeyPath *C.char, outPtr **C.char) C.int {
	signature, _ := secsipid.SJWTGetIdentity(C.GoString(origTN), C.GoString(destTN), C.GoString(attestVal), C.GoString(origID), C.GoString(x5uVal), C.GoString(prvkeyPath))
	*outPtr = C.CString(signature)
	return C.int(len(signature))
}

// SecSIPIDGetIdentityPrvKey --
// Generate the Identity header content using the input attributes
// * origTN - calling number
// * destTN - called number
// * attestVal - attestation level
// * origID - unique ID for tracking purposes, if empty string a UUID is generated
// * x5uVal - location of public certificate
// * prvkeyData - content of private key to be used to generate the signature
// * outPtr - to be set to the pointer containing the output (it is a
//   0-terminated string); the `*outPtr` must be freed after use
// * return: the length of `*outPtr`
//export SecSIPIDGetIdentityPrvKey
func SecSIPIDGetIdentityPrvKey(origTN *C.char, destTN *C.char, attestVal *C.char, origID *C.char, x5uVal *C.char, prvkeyData *C.char, outPtr **C.char) C.int {
	signature, _ := secsipid.SJWTGetIdentityPrvKey(C.GoString(origTN), C.GoString(destTN), C.GoString(attestVal), C.GoString(origID), C.GoString(x5uVal), []byte(C.GoString(prvkeyData)))
	*outPtr = C.CString(signature)
	return C.int(len(signature))
}

// SecSIPIDCheck --
// check the Identity header value
// * identityVal - identity header value
// * identityLen - length of identityVal, if is 0, identityVal is expected
//   to be 0-terminated
// * expireVal - number of seconds until the validity is considered expired
// * pubkeyPath - file path or URL to public key
// * timeoutVal - timeout in seconds to try to fetch the public key via HTTP
// * return: 0 - if validity is ok; <0 - on error or validity is not ok
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
// check the Identity header value
// * identityVal - identity header value with header parameters
// * identityLen - length of identityVal, if it is 0, identityVal is expected
//   to be 0-terminated
// * expireVal - number of seconds until the validity is considered expired
// * pubkeyPath - file path or URL to public key
// * timeoutVal - timeout in seconds to try to fetch the public key via HTTP
// * return: 0 - if validity is ok; <0 - on error or validity is not ok
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

// SecSIPIDCheckFullPubKey --
// check the Identity header value
// * identityVal - identity header value with header parameters
// * identityLen - length of identityVal, if it is 0, identityVal is expected
//   to be 0-terminated
// * expireVal - number of seconds until the validity is considered expired
// * pubkeyVal - the value of the public key
// * pubkeyLen - the length of the public key, if it is 0, then the pubkeyVal
//   is expected to be 0-terminated
// * return: 0 - if validity is ok; <0 - on error or validity is not ok
//export SecSIPIDCheckFullPubKey
func SecSIPIDCheckFullPubKey(identityVal *C.char, identityLen C.int, expireVal C.int, pubkeyVal *C.char, pubkeyLen C.int) C.int {
	var sIdentity string
	var sPubKeyVal string
	if identityLen == 0 {
		sIdentity = C.GoString(identityVal)
	} else {
		sIdentity = C.GoStringN(identityVal, identityLen)
	}
	if pubkeyLen == 0 {
		sPubKeyVal = C.GoString(pubkeyVal)
	} else {
		sPubKeyVal = C.GoStringN(pubkeyVal, pubkeyLen)
	}
	ret, _ := secsipid.SJWTCheckFullIdentityPubKey(sIdentity, int(expireVal), sPubKeyVal)
	return C.int(ret)

}

// SecSIPIDSetFileCacheOptions --
// set the options for local file caching of public keys
// * dirPath - path to local directory where to store the files
// * expireVal - number of the seconds after which to invalidate the cached file
// * return: 0
//export SecSIPIDSetFileCacheOptions
func SecSIPIDSetFileCacheOptions(dirPath *C.char, expireVal C.int) C.int {
	secsipid.SetURLFileCacheOptions(C.GoString(dirPath), int(expireVal))
	return C.int(0)
}

// SecSIPIDGetURLContent --
// get the content of an URL
// * urlVal - the HTTP or HTTPS URL
// * timeoutVal - timeout in seconds to try to get the content of the HTTP URL
// * outPtr - to be set to the pointer containing the output (it is a
//   0-terminated string); the `*outPtr` must be freed after use
// * outLen: to be set to the length of `*outPtr`
// * return: 0 - on success; -1 - on failure
//export SecSIPIDGetURLContent
func SecSIPIDGetURLContent(urlVal *C.char, timeoutVal C.int, outPtr **C.char, outLen *C.int) C.int {
	content, _ := secsipid.SJWTGetURLContent(C.GoString(urlVal), int(timeoutVal))
	if content != nil {
		*outPtr = C.CString(string(content))
		*outLen = C.int(len(string(content)))
		return C.int(0)
	}
	return C.int(-1)
}

// SecSIPIDOptSetS --
// set a string option for the library
// * optName - name of the option
// * optVal - value of the option
// * return: 0 if option was set, -1 otherwise
//export SecSIPIDOptSetS
func SecSIPIDOptSetS(optName *C.char, optVal *C.char) C.int {
	ret := secsipid.SJWTLibOptSetS(C.GoString(optName), C.GoString(optVal))
	return C.int(ret)
}

// SecSIPIDOptSetN --
// set a number (integer) option for the library
// * optName - name of the option
// * optVal - value of the option
// * 0 if option was set, -1 otherwise
//export SecSIPIDOptSetN
func SecSIPIDOptSetN(optName *C.char, optVal C.int) C.int {
	ret := secsipid.SJWTLibOptSetN(C.GoString(optName), int(optVal))
	return C.int(ret)
}

// SecSIPIDOptSetV --
// set an option for the library
// * optNameVal - string with name=value of the option
// * 0 if option was set, -1 otherwise
//export SecSIPIDOptSetV
func SecSIPIDOptSetV(optNameVal *C.char) C.int {
	ret := secsipid.SJWTLibOptSetV(C.GoString(optNameVal))
	return C.int(ret)
}

//
func main() {}
