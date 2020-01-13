package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/asipto/secsipidx/secsipid"
)

const secsipidxVersion = "1.0"

// CLIOptions - structure for command line options
type CLIOptions struct {
	fprvkey   string
	fpubkey   string
	header    string
	fheader   string
	payload   string
	fpayload  string
	identity  string
	fidentity string
	alg       string
	ppt       string
	typ       string
	x5u       string
	attest    string
	desttn    string
	origtn    string
	iat       int
	origid    string
	check     bool
	sign      bool
	jsonparse bool
	ltest     bool
	version   bool
}

var cliops = CLIOptions{
	fprvkey:   "",
	fpubkey:   "",
	header:    "",
	fheader:   "",
	payload:   "",
	fpayload:  "",
	identity:  "",
	fidentity: "",
	alg:       "ES256",
	ppt:       "shaken",
	typ:       "passport",
	x5u:       "",
	attest:    "C",
	desttn:    "",
	origtn:    "",
	iat:       0,
	origid:    "",
	check:     false,
	sign:      true,
	jsonparse: false,
	ltest:     false,
	version:   false,
}

// initialize application components
func init() {
	// command line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s (v%s):\n", filepath.Base(os.Args[0]), secsipidxVersion)
		fmt.Fprintf(os.Stderr, "    (eacsome options have short and long version)\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.StringVar(&cliops.fprvkey, "fprvkey", cliops.fprvkey, "path to private key")
	flag.StringVar(&cliops.fprvkey, "k", cliops.fprvkey, "path to private key")
	flag.StringVar(&cliops.fpubkey, "fpubkey", cliops.fpubkey, "path to private key")
	flag.StringVar(&cliops.fpubkey, "p", cliops.fpubkey, "path to private key")
	flag.StringVar(&cliops.fheader, "fheader", cliops.fheader, "path to file with header value in JSON format")
	flag.StringVar(&cliops.header, "header", cliops.header, "header value in JSON format")
	flag.StringVar(&cliops.fpayload, "fpayload", cliops.fpayload, "path to file with payload value in JSON format")
	flag.StringVar(&cliops.payload, "payload", cliops.payload, "payload value in JSON format")
	flag.StringVar(&cliops.fidentity, "fidentity", cliops.fidentity, "path to file with identity value")
	flag.StringVar(&cliops.identity, "identity", cliops.identity, "identity value")
	flag.StringVar(&cliops.alg, "alg", cliops.alg, "encryption algorithm (default: ES256)")
	flag.StringVar(&cliops.ppt, "ppt", cliops.ppt, "used extension (default: shaken)")
	flag.StringVar(&cliops.typ, "typ", cliops.typ, "token type (default: passport)")
	flag.StringVar(&cliops.x5u, "x5u", cliops.x5u, "value of the field with the location of the certificate used to sign the token (default: '')")
	flag.StringVar(&cliops.attest, "attest", cliops.attest, "attestation level (default: 'C')")
	flag.StringVar(&cliops.attest, "a", cliops.attest, "attestation level (default: 'C')")
	flag.StringVar(&cliops.desttn, "dest-tn", cliops.desttn, "destination (called) number (default: '')")
	flag.StringVar(&cliops.desttn, "d", cliops.desttn, "destination (called) number (default: '')")
	flag.StringVar(&cliops.origtn, "orig-tn", cliops.origtn, "origination (calling) number (default: '')")
	flag.StringVar(&cliops.origtn, "o", cliops.origtn, "origination (calling) number (default: '')")
	flag.IntVar(&cliops.iat, "iat", cliops.iat, "timestamp when the token was created")
	flag.StringVar(&cliops.origid, "orig-id", cliops.origid, "origination identifier (default: '')")
	flag.BoolVar(&cliops.check, "check", cliops.check, "check validity of the signature")
	flag.BoolVar(&cliops.check, "c", cliops.check, "check validity of the signature")
	flag.BoolVar(&cliops.sign, "sign", cliops.sign, "sign the header and payload")
	flag.BoolVar(&cliops.sign, "s", cliops.sign, "sign the header and payload")
	flag.BoolVar(&cliops.jsonparse, "json-parse", cliops.jsonparse, "parse and re-serialize JSON header and payaload values")
	flag.BoolVar(&cliops.ltest, "ltest", cliops.ltest, "run local basic test")
	flag.BoolVar(&cliops.ltest, "l", cliops.ltest, "run local basic test")
	flag.BoolVar(&cliops.version, "version", cliops.version, "print version")
}

func localTest() {
	var err error

	header := secsipid.SJWTHeader{
		Alg: "ES256",
		Ppt: "shaken",
		Typ: "passport",
		X5u: "https://certs.kamailio.org/stir-shaken/cert01.crt",
	}

	payload := secsipid.SJWTPayload{
		ATTest: "A",
		Dest: secsipid.SJWTDest{
			TN: []string{"493044444444"},
		},
		IAT: time.Now().Unix(),
		Orig: secsipid.SJWTOrig{
			TN: "493055555555",
		},
		OrigID: "32c7e392-33fc-11ea-840b-784f435c76a8",
	}
	prvkey, _ := ioutil.ReadFile("../test/certs/ec256-private.pem")

	var ecdsaPrvKey *ecdsa.PrivateKey
	if ecdsaPrvKey, err = secsipid.SJWTParseECPrivateKeyFromPEM(prvkey); err != nil {
		fmt.Printf("Unable to parse ECDSA private key: %v\n", err)
		return
	}

	pubkey, _ := ioutil.ReadFile("../test/certs/ec256-public.pem")

	var ecdsaPubKey *ecdsa.PublicKey
	if ecdsaPubKey, err = secsipid.SJWTParseECPublicKeyFromPEM(pubkey); err != nil {
		fmt.Printf("Unable to parse ECDSA public key: %v\n", err)
		return
	}

	token := secsipid.SJWTEncode(header, payload, ecdsaPrvKey)
	fmt.Printf("Result: %s\n", token)
	payloadOut, _ := secsipid.SJWTDecodeWithPubKey(token, ecdsaPubKey)
	jsonPayload, _ := json.Marshal(payloadOut)
	fmt.Printf("Payload: %s\n", jsonPayload)

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	signatureText := secsipid.SJWTEncodeText(string(headerJSON), string(payloadJSON), "certs/ec256-private.pem")
	fmt.Printf("Signature: %s\n", signatureText)
}

func secsipidxCLISign() int {
	var err error
	var useStruct bool
	var sHeader string
	var sPayload string
	var token string

	if len(cliops.fprvkey) <= 0 {
		fmt.Printf("path to private key not provided\n")
		return -1
	}

	useStruct = false

	header := secsipid.SJWTHeader{}
	if len(cliops.fheader) > 0 {
		vHeader, _ := ioutil.ReadFile(cliops.fheader)
		if cliops.jsonparse {
			err = json.Unmarshal(vHeader, &header)
			if err != nil {
				fmt.Printf("Failed to parse header json\n")
				fmt.Println(err)
				return -1
			}
			useStruct = true
		} else {
			sHeader = string(vHeader)
		}
	} else if len(cliops.header) > 0 {
		if cliops.jsonparse {
			err = json.Unmarshal([]byte(cliops.header), &header)
			if err != nil {
				fmt.Printf("Failed to parse header json\n")
				fmt.Println(err)
				return -1
			}
			useStruct = true
		} else {
			sHeader = cliops.header
		}
	} else {
		header = secsipid.SJWTHeader{
			Alg: cliops.alg,
			Ppt: cliops.ppt,
			Typ: cliops.typ,
			X5u: cliops.x5u,
		}
		if len(header.X5u) <= 0 {
			header.X5u = "https://127.0.0.1/cert.pem"
		}
		useStruct = true
	}
	payload := secsipid.SJWTPayload{}
	if len(cliops.fpayload) > 0 {
		vPayload, _ := ioutil.ReadFile(cliops.fpayload)
		if cliops.jsonparse {
			err = json.Unmarshal(vPayload, &payload)
			if err != nil {
				fmt.Printf("Failed to parse payload json\n")
				fmt.Println(err)
				return -1
			}
			useStruct = true
		} else {
			sPayload = string(vPayload)
		}
	} else if len(cliops.payload) > 0 {
		if cliops.jsonparse {
			err = json.Unmarshal([]byte(cliops.payload), &payload)
			if err != nil {
				fmt.Printf("Failed to parse payload json\n")
				fmt.Println(err)
				return -1
			}
			useStruct = true
		} else {
			sPayload = cliops.payload
		}
	} else {
		payload = secsipid.SJWTPayload{
			ATTest: cliops.attest,
			Dest: secsipid.SJWTDest{
				TN: []string{cliops.desttn},
			},
			IAT: int64(cliops.iat),
			Orig: secsipid.SJWTOrig{
				TN: cliops.origtn,
			},
			OrigID: cliops.origid,
		}
		if payload.IAT == 0 {
			payload.IAT = time.Now().Unix()
		}
		useStruct = true
	}

	if useStruct {
		prvkey, _ := ioutil.ReadFile(cliops.fprvkey)
		var ecdsaPrvKey *ecdsa.PrivateKey

		if ecdsaPrvKey, err = secsipid.SJWTParseECPrivateKeyFromPEM(prvkey); err != nil {
			fmt.Printf("Unable to parse ECDSA private key: %v\n", err)
			return -1
		}
		token = secsipid.SJWTEncode(header, payload, ecdsaPrvKey)
	} else {
		token = secsipid.SJWTEncodeText(sHeader, sPayload, cliops.fprvkey)
	}
	fmt.Printf("Result: %s\n", token)

	return 0
}

func secsipidxCLICheck() int {
	return -1
}

func main() {
	flag.Parse()

	fmt.Printf("\n")

	if cliops.version {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), secsipidxVersion)
		os.Exit(1)
	}

	if cliops.ltest {
		localTest()
		os.Exit(1)
	}

	if cliops.sign {
		secsipidxCLISign()
	} else if cliops.check {
		secsipidxCLICheck()
	} else {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), secsipidxVersion)
		fmt.Printf("run '%s --help' to see the options\n", filepath.Base(os.Args[0]))
	}

}
