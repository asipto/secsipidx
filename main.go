package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asipto/secsipidx/secsipid"
)

const secsipidxVersion = "1.3.2"

const (
	maxHTTPRequestBodyBytes = 1 << 20
	httpReadHeaderTimeout   = 5 * time.Second
	httpReadTimeout         = 10 * time.Second
	httpWriteTimeout        = 10 * time.Second
	httpIdleTimeout         = 30 * time.Second
)

// CLIOptions - structure for command line options
type CLIOptions struct {
	httpsrv            string
	httpssrv           string
	httpspubkey        string
	httpsprvkey        string
	httpdir            string
	fprvkey            string
	fpubkey            string
	header             string
	fheader            string
	payload            string
	fpayload           string
	identity           string
	fidentity          string
	alg                string
	ppt                string
	typ                string
	x5u                string
	attest             string
	desttn             string
	origtn             string
	iat                int
	origid             string
	check              bool
	sign               bool
	signfull           bool
	jsonparse          bool
	expire             int
	timeout            int
	ltest              bool
	version            bool
	cachedir           string
	cacheexpire        int
	cachefilemode      string
	denyprivateX5U     bool
	maxURLContentBytes int
	cafile             string
	cainter            string
	crlfile            string
	certverify         int
	verbosity          int
}

var cliops = CLIOptions{
	httpsrv:            "",
	httpssrv:           "",
	httpspubkey:        "",
	httpsprvkey:        "",
	httpdir:            "",
	fprvkey:            "",
	fpubkey:            "",
	header:             "",
	fheader:            "",
	payload:            "",
	fpayload:           "",
	identity:           "",
	fidentity:          "",
	alg:                "ES256",
	ppt:                "shaken",
	typ:                "passport",
	x5u:                "",
	attest:             "C",
	desttn:             "",
	origtn:             "",
	iat:                0,
	origid:             "",
	check:              false,
	sign:               false,
	signfull:           false,
	jsonparse:          false,
	expire:             0,
	timeout:            3,
	ltest:              false,
	version:            false,
	cachedir:           "",
	cacheexpire:        3600,
	cachefilemode:      "plain",
	denyprivateX5U:     false,
	maxURLContentBytes: 1 << 20,
	cafile:             "",
	cainter:            "",
	crlfile:            "",
	certverify:         0,
	verbosity:          0,
}

func registerFlags(fs *flag.FlagSet, opts *CLIOptions) {
	fs.StringVar(&opts.httpsrv, "http-srv", opts.httpsrv, "http server bind address")
	fs.StringVar(&opts.httpsrv, "H", opts.httpsrv, "http server bind address")
	fs.StringVar(&opts.httpssrv, "https-srv", opts.httpssrv, "https server bind address")
	fs.StringVar(&opts.httpspubkey, "https-pubkey", opts.httpspubkey, "https server public key")
	fs.StringVar(&opts.httpsprvkey, "https-prvkey", opts.httpsprvkey, "https server private key")
	fs.StringVar(&opts.httpdir, "http-dir", opts.httpdir, "directory to serve over http")
	fs.StringVar(&opts.fprvkey, "fprvkey", opts.fprvkey, "path to private key")
	fs.StringVar(&opts.fprvkey, "k", opts.fprvkey, "path to private key")
	fs.StringVar(&opts.fpubkey, "fpubkey", opts.fpubkey, "path to public key")
	fs.StringVar(&opts.fpubkey, "p", opts.fpubkey, "path to public key")
	fs.StringVar(&opts.fheader, "fheader", opts.fheader, "path to file with header value in JSON format")
	fs.StringVar(&opts.header, "header", opts.header, "header value in JSON format")
	fs.StringVar(&opts.fpayload, "fpayload", opts.fpayload, "path to file with payload value in JSON format")
	fs.StringVar(&opts.payload, "payload", opts.payload, "payload value in JSON format")
	fs.StringVar(&opts.fidentity, "fidentity", opts.fidentity, "path to file with identity value")
	fs.StringVar(&opts.identity, "identity", opts.identity, "identity value")
	fs.StringVar(&opts.alg, "alg", opts.alg, "encryption algorithm")
	fs.StringVar(&opts.ppt, "ppt", opts.ppt, "used extension")
	fs.StringVar(&opts.typ, "typ", opts.typ, "token type")
	fs.StringVar(&opts.x5u, "x5u", opts.x5u, "value of the field with the location of the certificate used to sign the token (default: '')")
	fs.StringVar(&opts.attest, "attest", opts.attest, "attestation level")
	fs.StringVar(&opts.attest, "a", opts.attest, "attestation level")
	fs.StringVar(&opts.desttn, "dest-tn", opts.desttn, "destination (called) number (default: '')")
	fs.StringVar(&opts.desttn, "d", opts.desttn, "destination (called) number (default: '')")
	fs.StringVar(&opts.origtn, "orig-tn", opts.origtn, "origination (calling) number (default: '')")
	fs.StringVar(&opts.origtn, "o", opts.origtn, "origination (calling) number (default: '')")
	fs.IntVar(&opts.iat, "iat", opts.iat, "timestamp when the token was created")
	fs.StringVar(&opts.origid, "orig-id", opts.origid, "origination identifier (default: '')")
	fs.BoolVar(&opts.check, "check", opts.check, "check validity of the signature")
	fs.BoolVar(&opts.check, "c", opts.check, "check validity of the signature")
	fs.BoolVar(&opts.sign, "sign", opts.sign, "sign the header and payload given as full JSON documents")
	fs.BoolVar(&opts.sign, "s", opts.sign, "sign the header and payload given as full JSON documents")
	fs.BoolVar(&opts.signfull, "sign-full", opts.signfull, "sign the header and payload build from the individual parameter values")
	fs.BoolVar(&opts.signfull, "S", opts.signfull, "sign the header and payload, with parameters")
	fs.BoolVar(&opts.jsonparse, "json-parse", opts.jsonparse, "parse and re-serialize JSON header and payload values")
	fs.IntVar(&opts.expire, "expire", opts.expire, "duration of token validity (in seconds)")
	fs.IntVar(&opts.timeout, "timeout", opts.timeout, "http get timeout (in seconds)")
	fs.BoolVar(&opts.ltest, "ltest", opts.ltest, "run local basic test")
	fs.BoolVar(&opts.ltest, "l", opts.ltest, "run local basic test")
	fs.BoolVar(&opts.version, "version", opts.version, "print version")
	fs.StringVar(&opts.cachedir, "cache-dir", opts.cachedir, "path to the directory with cached certificates (default: '')")
	fs.IntVar(&opts.cacheexpire, "cache-expire", opts.cacheexpire, "duration of cached certificates (in seconds)")
	fs.StringVar(&opts.cachefilemode, "cache-file-mode", opts.cachefilemode, "cache filename mode: plain or sha256")
	fs.BoolVar(&opts.denyprivateX5U, "deny-private-x5u", opts.denyprivateX5U, "deny certificate URLs resolving to private or local addresses")
	fs.IntVar(&opts.maxURLContentBytes, "max-url-content-bytes", opts.maxURLContentBytes, "maximum downloaded certificate size in bytes")
	fs.StringVar(&opts.cafile, "ca-file", opts.cafile, "file with root CA certificates in pem format")
	fs.StringVar(&opts.cainter, "ca-inter", opts.cainter, "file with intermediate CA certificates in pem format")
	fs.StringVar(&opts.crlfile, "crl-file", opts.crlfile, "file with CRL in pem format")
	fs.IntVar(&opts.certverify, "cert-verify", opts.certverify, "certificate verification mode (default 0)")
	fs.IntVar(&opts.verbosity, "verbosity", opts.verbosity, "verbosity level (default 0)")
	fs.IntVar(&opts.verbosity, "vl", opts.verbosity, "verbosity level (default 0)")
}

// initialize application components
func init() {
	// command line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s (v%s):\n", filepath.Base(os.Args[0]), secsipidxVersion)
		fmt.Fprintf(os.Stderr, "    (some options have short and long version)\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	registerFlags(flag.CommandLine, &cliops)
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
	prvkey, err := os.ReadFile("../test/certs/ec256-private.pem")
	if err != nil {
		fmt.Printf("Unable to read ECDSA private key: %v\n", err)
		return
	}

	var ecdsaPrvKey *ecdsa.PrivateKey
	if ecdsaPrvKey, _, err = secsipid.SJWTParseECPrivateKeyFromPEM(prvkey); err != nil {
		fmt.Printf("Unable to parse ECDSA private key: %v\n", err)
		return
	}

	pubkey, err := os.ReadFile("../test/certs/ec256-public.pem")
	if err != nil {
		fmt.Printf("Unable to read ECDSA public key: %v\n", err)
		return
	}

	var ecdsaPubKey *ecdsa.PublicKey
	if ecdsaPubKey, _, err = secsipid.SJWTParseECPublicKeyFromPEM(pubkey); err != nil {
		fmt.Printf("Unable to parse ECDSA public key: %v\n", err)
		return
	}

	token := secsipid.SJWTEncode(header, payload, ecdsaPrvKey)
	fmt.Printf("Result: %s\n", token)
	payloadOut, _ := secsipid.SJWTDecodeWithPubKey(token, cliops.expire, ecdsaPubKey)
	jsonPayload, _ := json.Marshal(payloadOut)
	fmt.Printf("Payload: %s\n", jsonPayload)

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	signatureText, _, _ := secsipid.SJWTEncodeText(string(headerJSON), string(payloadJSON), "certs/ec256-private.pem")
	fmt.Printf("Signature: %s\n", signatureText)
}

func secsipidxCLISignFull() int {

	token, _, err := secsipid.SJWTGetIdentity(cliops.origtn, cliops.desttn, cliops.attest, cliops.origid, cliops.x5u, cliops.fprvkey)

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return -1
	}
	fmt.Printf("%s\n", token)
	return 0
}

func readCLIFile(path string, label string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s file %q: %w", label, path, err)
	}
	return data, nil
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
		vHeader, err := readCLIFile(cliops.fheader, "header")
		if err != nil {
			fmt.Printf("%v\n", err)
			return -1
		}
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
		vPayload, err := readCLIFile(cliops.fpayload, "payload")
		if err != nil {
			fmt.Printf("%v\n", err)
			return -1
		}
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
		if cliops.verbosity > 0 {
			fmt.Printf("Signing using the structures build from parameter values\n")
		}
		prvkey, err := readCLIFile(cliops.fprvkey, "private key")
		if err != nil {
			fmt.Printf("%v\n", err)
			return -1
		}
		var ecdsaPrvKey *ecdsa.PrivateKey

		if ecdsaPrvKey, _, err = secsipid.SJWTParseECPrivateKeyFromPEM(prvkey); err != nil {
			fmt.Printf("Unable to parse ECDSA private key: %v\n", err)
			return -1
		}
		token = secsipid.SJWTEncode(header, payload, ecdsaPrvKey)
	} else {
		if cliops.verbosity > 0 {
			fmt.Printf("Signing using the JSON documents from parameters\n")
		}
		token, _, _ = secsipid.SJWTEncodeText(sHeader, sPayload, cliops.fprvkey)
	}
	fmt.Printf("%s\n", token)

	return 0
}

func secsipidxCLICheck() int {
	var sIdentity string
	var ret int
	var err error

	if len(cliops.fidentity) > 0 {
		vIdentity, err := readCLIFile(cliops.fidentity, "identity")
		if err != nil {
			fmt.Printf("%v\n", err)
			return -1
		}
		sIdentity = string(vIdentity)
	} else if len(cliops.identity) > 0 {
		sIdentity = cliops.identity
	} else {
		fmt.Printf("Identity value not provided\n")
		return -1
	}

	ret, err = secsipid.SJWTCheckFullIdentity(sIdentity, cliops.expire, cliops.fpubkey, cliops.timeout)

	if err != nil {
		fmt.Printf("error message: %v\n", err)
	}
	return ret
}

func readHTTPRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHTTPRequestBodyBytes)
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return nil, false
	}

	return body, true
}

func httpHandleV1Check(w http.ResponseWriter, r *http.Request) {
	var ret int

	fmt.Printf("incoming request for identity check ...\n")
	body, ok := readHTTPRequestBody(w, r)
	if !ok {
		return
	}

	var err error
	ret, err = secsipid.SJWTCheckFullIdentity(string(body), cliops.expire, cliops.fpubkey, cliops.timeout)

	if err != nil {
		fmt.Printf("failed checking identity: %v\n", err)
		http.Error(w, "FAILED\n", http.StatusInternalServerError)
		return
	}
	fmt.Printf("valid identity - return code: %d\n", ret)
	fmt.Fprintf(w, "OK\n")
}

func httpHandleV1SignCSV(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("incoming request for building identity ...\n")
	body, ok := readHTTPRequestBody(w, r)
	if !ok {
		return
	}

	var err error
	token := strings.Split(strings.TrimSpace(string(body)), ",")
	if len(token) < 5 {
		fmt.Printf("too few tokens in input body: %d\n", len(token))
		http.Error(w, "too few tokens", http.StatusBadRequest)
		return
	}

	var hdr string
	hdr, _, err = secsipid.SJWTGetIdentity(token[0], token[1], token[2], token[3], token[4], cliops.fprvkey)
	if err != nil {
		fmt.Printf("error reading body: %v", err)
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "%s\n", hdr)

}

func buildHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/check", httpHandleV1Check)
	mux.HandleFunc("/v1/sign-csv", httpHandleV1SignCSV)
	if len(cliops.httpdir) > 0 {
		fmt.Printf("serving files over http from directory: %s\n", cliops.httpdir)
		mux.Handle("/v1/pub/", http.StripPrefix("/v1/pub/", http.FileServer(http.Dir(cliops.httpdir))))
	}
	return mux
}

func startHTTPServices(handler http.Handler) chan error {

	errchan := make(chan error)

	// starting HTTP server
	if len(cliops.httpsrv) > 0 {
		go func() {
			log.Printf("starting HTTP service on: %s ...", cliops.httpsrv)

			server := &http.Server{
				Addr:              cliops.httpsrv,
				Handler:           handler,
				ReadHeaderTimeout: httpReadHeaderTimeout,
				ReadTimeout:       httpReadTimeout,
				WriteTimeout:      httpWriteTimeout,
				IdleTimeout:       httpIdleTimeout,
			}
			if err := server.ListenAndServe(); err != nil {
				errchan <- err
			}

		}()
	}

	// starting HTTPS server
	if len(cliops.httpssrv) > 0 && len(cliops.httpspubkey) > 0 && len(cliops.httpsprvkey) > 0 {
		go func() {
			log.Printf("Starting HTTPS service on: %s ...", cliops.httpssrv)
			server := &http.Server{
				Addr:              cliops.httpssrv,
				Handler:           handler,
				ReadHeaderTimeout: httpReadHeaderTimeout,
				ReadTimeout:       httpReadTimeout,
				WriteTimeout:      httpWriteTimeout,
				IdleTimeout:       httpIdleTimeout,
			}
			if err := server.ListenAndServeTLS(cliops.httpspubkey, cliops.httpsprvkey); err != nil {
				errchan <- err
			}
		}()
	}

	return errchan
}

func httpServiceExitCode(err error) int {
	if err == nil || err == http.ErrServerClosed {
		return 0
	}
	return 1
}

func main() {
	var ret int

	flag.Parse()

	if cliops.version {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), secsipidxVersion)
		os.Exit(0)
	}

	if cliops.ltest {
		localTest()
		os.Exit(0)
	}

	if len(cliops.cachedir) > 0 {
		secsipid.SetURLFileCacheOptions(cliops.cachedir, cliops.cacheexpire)
	}
	if len(cliops.cachefilemode) > 0 {
		if secsipid.SJWTLibOptSetS("CacheNameMode", cliops.cachefilemode) != secsipid.SJWTRetOK {
			fmt.Printf("invalid cache file mode: %s\n", cliops.cachefilemode)
			os.Exit(1)
		}
	}
	if cliops.denyprivateX5U {
		secsipid.SJWTLibOptSetN("DenyPrivateX5U", 1)
	}
	if secsipid.SJWTLibOptSetN("MaxURLContentBytes", cliops.maxURLContentBytes) != secsipid.SJWTRetOK {
		fmt.Printf("invalid maximum URL content size: %d\n", cliops.maxURLContentBytes)
		os.Exit(1)
	}

	if len(cliops.cafile) > 0 {
		secsipid.SJWTLibOptSetS("CertCAFile", cliops.cafile)
	}
	if len(cliops.cainter) > 0 {
		secsipid.SJWTLibOptSetS("CertCAInter", cliops.cainter)
	}
	if len(cliops.crlfile) > 0 {
		secsipid.SJWTLibOptSetS("CertCRLFile", cliops.crlfile)
	}
	if cliops.certverify > 0 {
		secsipid.SJWTLibOptSetN("CertVerify", cliops.certverify)
	}
	if len(cliops.x5u) > 0 {
		secsipid.SJWTLibOptSetS("x5u", cliops.x5u)
	}

	if (len(cliops.httpsrv) > 0) || (len(cliops.httpssrv) > 0 && len(cliops.httpspubkey) > 0 && len(cliops.httpsprvkey) > 0) {
		fmt.Printf("starting http services ...\n")

		errchan := startHTTPServices(buildHTTPHandler())
		select {
		case err := <-errchan:
			log.Printf("unable to start http services due to (error: %v)", err)
			os.Exit(httpServiceExitCode(err))
		}
	}

	ret = 0
	if cliops.check {
		if cliops.verbosity > 0 {
			fmt.Printf("Running with check command\n")
		}
		ret = secsipidxCLICheck()
		if ret == 0 {
			fmt.Printf("ok\n")
		} else {
			fmt.Printf("not-ok\n")
		}
		os.Exit(ret)
	} else if cliops.signfull {
		if cliops.verbosity > 0 {
			fmt.Printf("Running with sign-full command\n")
		}
		ret = secsipidxCLISignFull()
		os.Exit(ret)
	} else if cliops.sign {
		if cliops.verbosity > 0 {
			fmt.Printf("Running with sign command\n")
		}
		ret = secsipidxCLISign()
		os.Exit(ret)
	} else {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), secsipidxVersion)
		fmt.Printf("run '%s --help' to see the options\n", filepath.Base(os.Args[0]))
	}
	os.Exit(ret)
}
