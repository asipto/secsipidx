package secsipid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// return and error code values
const (
	SJWTRetOK = 0
	// generic errors
	SJWTRetErr = -1
	// public certificate and private key errors: -100..-199
	SJWTRetErrCertInvalid         = -101
	SJWTRetErrCertInvalidFormat   = -102
	SJWTRetErrCertExpired         = -103
	SJWTRetErrCertBeforeValidity  = -104
	SJWTRetErrCertProcessing      = -105
	SJWTRetErrCertNoCAFile        = -106
	SJWTRetErrCertReadCAFile      = -107
	SJWTRetErrCertNoCAInter       = -108
	SJWTRetErrCertReadCAInter     = -109
	SJWTRetErrCertNoCRLFile       = -110
	SJWTRetErrCertReadCRLFile     = -111
	SJWTRetErrCertRevoked         = -112
	SJWTRetErrCertInvalidEC       = -114
	SJWTRetErrPrvKeyInvalid       = -151
	SJWTRetErrPrvKeyInvalidFormat = -152
	SJWTRetErrPrvKeyInvalidEC     = -152
	// identity JSON header, payload and signature errors: -200..-299
	SJWTRetErrJSONHdrParse          = -201
	SJWTRetErrJSONHdrAlg            = -202
	SJWTRetErrJSONHdrPpt            = -203
	SJWTRetErrJSONHdrTyp            = -204
	SJWTRetErrJSONHdrX5u            = -205
	SJWTRetErrJSONPayloadParse      = -231
	SJWTRetErrJSONPayloadIATExpired = -232
	SJWTRetErrJSONSignatureInvalid  = -251
	SJWTRetErrJSONSignatureHashing  = -252
	SJWTRetErrJSONSignatureSize     = -253
	SJWTRetErrJSONSignatureFailure  = -254
	// identity SIP header errors: -300..-399
	SJWTRetErrSIPHdrParse = -301
	SJWTRetErrSIPHdrAlg   = -302
	SJWTRetErrSIPHdrPpt   = -303
	SJWTRetErrSIPHdrInfo  = -303
	SJWTRetErrSIPHdrEmpty = -304
	// http and file operations errors: -400..-499
	SJWTRetErrHTTPInvalidURL = -401
	SJWTRetErrHTTPGet        = -402
	SJWTRetErrHTTPStatusCode = -403
	SJWTRetErrHTTPReadBody   = -404
	SJWTRetErrFileRead       = -451
)

// SJWTHeader - header for JWT
type SJWTHeader struct {
	Alg string `json:"alg"`
	Ppt string `json:"ppt"`
	Typ string `json:"typ"`
	X5u string `json:"x5u"`
}

// SJWTDest --
type SJWTDest struct {
	TN []string `json:"tn"`
}

// SJWTOrig --
type SJWTOrig struct {
	TN string `json:"tn"`
}

// SJWTPayload - JWT payload
type SJWTPayload struct {
	ATTest string   `json:"attest"`
	Dest   SJWTDest `json:"dest"`
	IAT    int64    `json:"iat"`
	Orig   SJWTOrig `json:"orig"`
	OrigID string   `json:"origid"`
}

type SJWTLibOptions struct {
	cacheDirPath string
	cacheExpire  int
	certCAFile   string
	certCAInter  string
	certCRLFile  string
	certVerify   int
	x5u          string
}

var globalLibOptions = SJWTLibOptions{
	cacheDirPath: "",
	cacheExpire:  3600,
	certCAFile:   "",
	certCAInter:  "",
	certCRLFile:  "",
	certVerify:   0,
	x5u:          "https://127.0.0.1/cert.pem",
}

var (
	sES256KeyBits = 256
	sES256KeySize = 32
)

// SetFileCacheOptions --
func SetURLFileCacheOptions(path string, expire int) {
	globalLibOptions.cacheDirPath = path
	globalLibOptions.cacheExpire = expire
}

// SJWTLibOptSetS --
func SJWTLibOptSetS(optname string, optval string) int {
	switch optname {
	case "CacheDirPath":
		globalLibOptions.cacheDirPath = optval
		return SJWTRetOK
	case "CertCAFile":
		globalLibOptions.certCAFile = optval
		return SJWTRetOK
	case "CertCRLFile":
		globalLibOptions.certCRLFile = optval
		return SJWTRetOK
	case "CertCAInter":
		globalLibOptions.certCAInter = optval
		return SJWTRetOK
	case "x5u":
		globalLibOptions.x5u = optval
		return SJWTRetOK
	}
	return SJWTRetErr
}

// SJWTLibOptSetN --
func SJWTLibOptSetN(optname string, optval int) int {
	switch optname {
	case "CacheExpires":
		globalLibOptions.cacheExpire = optval
		return SJWTRetOK
	case "CertVerify":
		globalLibOptions.certVerify = optval
		return SJWTRetOK
	}
	return SJWTRetErr
}

// SJWTLibOptSetV --
func SJWTLibOptSetV(optnameval string) int {
	optArray := strings.SplitN(optnameval, "=", 2)
	optName := optArray[0]
	optVal := optArray[1]
	switch optName {
	case "CacheExpires", "CertVerify":
		intVal, _ := strconv.Atoi(optVal)
		return SJWTLibOptSetN(optName, intVal)
	case "CacheDirPath", "CertCAFile", "CertCAInter", "CertCRLFile":
		return SJWTLibOptSetS(optName, optVal)
	}
	return SJWTRetErr
}

// SJWTRemoveWhiteSpaces --
func SJWTRemoveWhiteSpaces(s string) string {
	rout := make([]rune, 0, len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			rout = append(rout, r)
		}
	}
	return string(rout)
}

// SJWTRemoveWhiteSpaces --
func SJWTGetURLCacheFilePath(urlVal string) string {
	filePath := strings.Replace(urlVal, "://", "_", -1)
	filePath = strings.Replace(filePath, "/", "_", -1)
	if len(globalLibOptions.cacheDirPath) > 0 {
		filePath = globalLibOptions.cacheDirPath + "/" + filePath
	}
	return filePath
}

// SJWTPubKeyVerify -
func SJWTPubKeyVerify(pubKey []byte) (int, error) {
	if globalLibOptions.certVerify == 0 {
		return SJWTRetOK, nil
	}

	var certVal *x509.Certificate
	var certInter []*x509.Certificate
	var rootCAs *x509.CertPool
	var interCAs *x509.CertPool
	var err error

	// The public key may contain multiple intermediate certificates, we must
	// parse those out and include them when doing the actual validation.
	var toDecode = pubKey
	var block *pem.Block
	for true {
		// Decode the next block in the public key. If there are no more blocks then
		// this will return nil.
		block, toDecode = pem.Decode(toDecode)
		if block == nil {
			break
		}

		// Parse the block as an x509 certificate.
		blockCert, err := x509.ParseCertificate(block.Bytes)
		if blockCert == nil {
			return SJWTRetErrCertInvalidFormat, err
		}

		// If this was the first block then it represents the public certificate,
		// otherwise it is an intermediate certificate.
		if certVal == nil {
			certVal = blockCert
		} else {
			certInter = append(certInter, blockCert)
		}
	}

	if certVal == nil {
		return SJWTRetErrCertInvalidFormat, errors.New("failed to parse certificate PEM")
	}

	if (globalLibOptions.certVerify & (1 << 0)) != 0 {
		if !time.Now().Before(certVal.NotAfter) {
			return SJWTRetErrCertExpired, errors.New("certificate expired")
		} else if !time.Now().After(certVal.NotBefore) {
			return SJWTRetErrCertBeforeValidity, errors.New("certificate not valid yet")
		}
	}

	rootCAs = nil
	interCAs = nil
	if (globalLibOptions.certVerify & (1 << 1)) != 0 {
		// Get the SystemCertPool
		rootCAs, err = SystemCertPool()
		if rootCAs == nil {
			return SJWTRetErrCertProcessing, err
		}
	}
	if (globalLibOptions.certVerify & (1 << 2)) != 0 {
		if len(globalLibOptions.certCAFile) <= 0 {
			return SJWTRetErrCertNoCAFile, errors.New("no CA file")
		}

		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
			if rootCAs == nil {
				return SJWTRetErrCertProcessing, errors.New("no new ca cert pool")
			}
		}
		var certsCA []byte
		// Read in the cert file
		certsCA, err = ioutil.ReadFile(globalLibOptions.certCAFile)
		if err != nil {
			return SJWTRetErrCertReadCAFile, errors.New("failed to read CA file")
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(certsCA); !ok {
			return SJWTRetErrCertProcessing, errors.New("failed to append CA file")
		}
	}
	if (globalLibOptions.certVerify & (1 << 3)) != 0 {
		if len(globalLibOptions.certCAInter) <= 0 {
			return SJWTRetErrCertNoCAInter, errors.New("no intermediate CA file")
		}
		interCAs = x509.NewCertPool()
		if interCAs == nil {
			return SJWTRetErrCertProcessing, errors.New("no new ca intermediate cert pool")
		}
		var certsCA []byte
		// Read in the cert file
		certsCA, err = ioutil.ReadFile(globalLibOptions.certCAInter)
		if err != nil {
			return SJWTRetErrCertReadCAInter, errors.New("failed to read intermediate CA file")
		}

		// Append our cert to the system pool
		if ok := interCAs.AppendCertsFromPEM(certsCA); !ok {
			return SJWTRetErrCertProcessing, errors.New("failed to append intermediate CA file")
		}
	}

	// Append any intermediate certificates included in pubKey.
	if len(certInter) > 0 {
		if interCAs == nil {
			interCAs = x509.NewCertPool()
		}
		if interCAs == nil {
			return SJWTRetErrCertProcessing, errors.New("no new ca intermediate cert pool")
		}
		// Append our certs
		for _, iCert := range certInter {
			interCAs.AddCert(iCert)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: interCAs,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err = certVal.Verify(opts); err != nil {
		return SJWTRetErrCertInvalid, err
	}

	if (globalLibOptions.certVerify & (1 << 4)) != 0 {
		if len(globalLibOptions.certCRLFile) <= 0 {
			return SJWTRetErrCertNoCRLFile, errors.New("no CRL file")
		}
		var rootCRL *pkix.CertificateList
		rootCRL = nil
		var certsCRLData []byte
		// Read in the cert file
		certsCRLData, err = ioutil.ReadFile(globalLibOptions.certCRLFile)
		if err != nil {
			return SJWTRetErrCertReadCRLFile, errors.New("failed to read CRL file")
		}
		rootCRL, err = x509.ParseCRL(certsCRLData)
		for _, revoked := range rootCRL.TBSCertList.RevokedCertificates {
			if certVal.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				return SJWTRetErrCertRevoked, errors.New("serial number match - certificate is revoked")
			}
		}
	}

	return SJWTRetOK, nil
}

// SJWTParseECPrivateKeyFromPEM Parse PEM encoded Elliptic Curve Private Key Structure
func SJWTParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, int, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, SJWTRetErrPrvKeyInvalidFormat, errors.New("key must be PEM encoded")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, SJWTRetErrPrvKeyInvalid, err
		}
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, SJWTRetErrPrvKeyInvalidEC, errors.New("not EC private key")
	}

	return pkey, SJWTRetOK, nil
}

// SJWTParseECPublicKeyFromPEM Parse PEM encoded PKCS1 or PKCS8 public key
func SJWTParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, int, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, SJWTRetErrCertInvalidFormat, errors.New("key must be PEM encoded")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, SJWTRetErrCertInvalid, err
		}
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, SJWTRetErrCertInvalidEC, errors.New("not EC public key")
	}

	return pkey, SJWTRetOK, nil
}

// SJWTBase64EncodeString encode string to base64 with padding stripped
func SJWTBase64EncodeString(src string) string {
	return strings.
		TrimRight(base64.URLEncoding.
			EncodeToString([]byte(src)), "=")
}

// SJWTBase64DecodeString takes in a base 64 encoded string and returns the
// actual string or an error of it fails to decode the string
func SJWTBase64DecodeString(src string) (string, error) {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		return "", fmt.Errorf("decoding error %s", err)
	}
	return string(decoded), nil
}

// SJWTBase64EncodeBytes encode bytes array to base64 with padding stripped
func SJWTBase64EncodeBytes(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// SJWTBase64DecodeBytes takes in a base 64 encoded string and returns the
// actual bytes array or an error of it fails to decode the string
func SJWTBase64DecodeBytes(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

// SJWTGetURLCachedContent --
func SJWTGetURLCachedContent(urlVal string) ([]byte, error) {
	filePath := SJWTGetURLCacheFilePath(urlVal)

	fileStat, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	tnow := time.Now()
	if int(tnow.Sub(fileStat.ModTime()).Seconds()) > globalLibOptions.cacheExpire {
		os.Remove(filePath)
		return nil, nil
	}
	return ioutil.ReadFile(filePath)
}

// SJWTSetURLCachedContent --
func SJWTSetURLCachedContent(urlVal string, data []byte) error {
	filePath := SJWTGetURLCacheFilePath(urlVal)

	return ioutil.WriteFile(filePath, data, 0640)
}

// SJWTGetURLContent --
func SJWTGetURLContent(urlVal string, timeoutVal int) ([]byte, int, error) {
	if len(urlVal) == 0 {
		return nil, SJWTRetErrHTTPInvalidURL, errors.New("no URL value")
	}

	if !(strings.HasPrefix(urlVal, "http://") || strings.HasPrefix(urlVal, "https://")) {
		return nil, SJWTRetErrHTTPInvalidURL, errors.New("invalid URL value")
	}

	if len(globalLibOptions.cacheDirPath) > 0 {
		cdata, cerr := SJWTGetURLCachedContent(urlVal)
		if cdata != nil {
			return cdata, SJWTRetOK, cerr
		}
	}
	httpClient := http.Client{
		Timeout: time.Duration(timeoutVal) * time.Second,
	}
	resp, err := httpClient.Get(urlVal)
	if err != nil {
		return nil, SJWTRetErrHTTPGet, fmt.Errorf("http get failure: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, SJWTRetErrHTTPStatusCode, fmt.Errorf("http status error: %v", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, SJWTRetErrHTTPReadBody, fmt.Errorf("read http body failure: %v", err)
	}

	if len(globalLibOptions.cacheDirPath) > 0 {
		SJWTSetURLCachedContent(urlVal, data)
	}

	return data, SJWTRetOK, nil
}

// SJWTGetValidPayload --
func SJWTGetValidPayload(base64Payload string, expireVal int) (*SJWTPayload, int, error) {
	if len(base64Payload) == 0 {
		return nil, SJWTRetErrJSONPayloadParse, errors.New("empty payload")
	}
	decodedPayload, payloadErr := SJWTBase64DecodeString(base64Payload)
	if payloadErr != nil {
		return nil, SJWTRetErrJSONPayloadParse, fmt.Errorf("invalid payload: %s", payloadErr.Error())
	}
	payload := SJWTPayload{}

	err := json.Unmarshal([]byte(decodedPayload), &payload)
	if err != nil {
		return nil, SJWTRetErrJSONPayloadParse, fmt.Errorf("invalid payload: %s", err.Error())
	}

	if payload.IAT == 0 || time.Now().Unix() > payload.IAT+int64(expireVal) {
		return nil, SJWTRetErrJSONPayloadIATExpired, errors.New("expired token")
	}

	return &payload, SJWTRetOK, nil
}

// SJWTVerifyWithPubKey - implements the verify
// For this verify method, key must be an ecdsa.PublicKey struct
func SJWTVerifyWithPubKey(signingString string, signature string, key interface{}) (int, error) {
	var err error

	var sig []byte
	if sig, err = SJWTBase64DecodeBytes(signature); err != nil {
		return -1, err
	}

	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	default:
		return SJWTRetErrCertInvalidFormat, errors.New("invalid key type")
	}

	if len(sig) != 2*sES256KeySize {
		return SJWTRetErrJSONSignatureSize, errors.New("ECDSA signature size verification failed")
	}

	r := big.NewInt(0).SetBytes(sig[:sES256KeySize])
	s := big.NewInt(0).SetBytes(sig[sES256KeySize:])

	if !crypto.SHA256.Available() {
		return SJWTRetErrJSONSignatureHashing, errors.New("hashing function unavailable")
	}
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signingString))

	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus == true {
		return SJWTRetOK, nil
	}
	return SJWTRetErrJSONSignatureInvalid, errors.New("ECDSA verification failed")
}

// SJWTSignWithPrvKey - implements the signing
// For this signing method, key must be an ecdsa.PrivateKey struct
func SJWTSignWithPrvKey(signingString string, key interface{}) (string, int, error) {
	var ecdsaKey *ecdsa.PrivateKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		ecdsaKey = k
	default:
		return "", SJWTRetErrPrvKeyInvalidEC, errors.New("invalid key type")
	}

	if !crypto.SHA256.Available() {
		return "", SJWTRetErrJSONSignatureHashing, errors.New("hashing function not available")
	}

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signingString))

	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil))
	if err == nil {
		curveBits := ecdsaKey.Curve.Params().BitSize

		if sES256KeyBits != curveBits {
			return "", SJWTRetErrJSONSignatureSize, errors.New("invalid key size")
		}

		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes++
		}

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		out := append(rBytesPadded, sBytesPadded...)

		return SJWTBase64EncodeBytes(out), SJWTRetOK, nil
	}
	return "", SJWTRetErrJSONSignatureFailure, err
}

// SJWTEncode - encode payload to JWT
func SJWTEncode(header SJWTHeader, payload SJWTPayload, prvkey interface{}) string {
	str, _ := json.Marshal(header)
	jwthdr := SJWTBase64EncodeString(string(str))
	encodedPayload, _ := json.Marshal(payload)
	signingValue := jwthdr + "." +
		SJWTBase64EncodeString(string(encodedPayload))
	signatureValue, _, _ := SJWTSignWithPrvKey(signingValue, prvkey)
	return signingValue + "." + signatureValue
}

// SJWTDecodeWithPubKey - decode JWT string
func SJWTDecodeWithPubKey(jwt string, expireVal int, pubkey interface{}) (*SJWTPayload, error) {
	var ret int
	var err error
	var payload *SJWTPayload

	token := strings.Split(strings.TrimSpace(jwt), ".")

	if len(token) != 3 {
		splitErr := errors.New("invalid token - must contain header, payload and signature")
		return nil, splitErr
	}

	payload, ret, err = SJWTGetValidPayload(token[1], expireVal)
	if err != nil {
		return nil, fmt.Errorf("getting payload failed: (%d) %v", ret, err)
	}

	signatureValue := token[0] + "." + token[1]

	ret, err = SJWTVerifyWithPubKey(signatureValue, token[2], pubkey)
	if err != nil {
		return nil, fmt.Errorf("verify failed: (%d) %v", ret, err)
	}
	return payload, nil
}

// SJWTEncodeText - encode header and payload to JWT
func SJWTEncodeText(headerJSON string, payloadJSON string, prvkeyPath string) (string, int, error) {
	var ret int
	var err error
	var signatureValue string
	var ecdsaPrvKey *ecdsa.PrivateKey

	prvkey, _ := ioutil.ReadFile(prvkeyPath)

	if ecdsaPrvKey, ret, err = SJWTParseECPrivateKeyFromPEM(prvkey); err != nil {
		return "", ret, err
	}

	signingValue := SJWTBase64EncodeString(strings.TrimSpace(headerJSON)) +
		"." + SJWTBase64EncodeString(strings.TrimSpace(payloadJSON))
	signatureValue, ret, err = SJWTSignWithPrvKey(signingValue, ecdsaPrvKey)
	if err != nil {
		return "", ret, fmt.Errorf("failed to build signature: %v", err)
	}
	return signingValue + "." + signatureValue, SJWTRetOK, nil
}

// SJWTCheckAttributes - implements the verify of attributes
func SJWTCheckAttributes(bToken string, paramInfo string) (int, error) {
	vHeader, err := SJWTBase64DecodeString(bToken)

	header := SJWTHeader{}
	err = json.Unmarshal([]byte(vHeader), &header)
	if err != nil {
		return SJWTRetErrJSONHdrParse, err
	}
	if len(header.Alg) > 0 && header.Alg != "ES256" {
		return SJWTRetErrJSONHdrAlg, fmt.Errorf("invalid value for alg in json header")
	}
	if len(header.Ppt) > 0 && header.Ppt != "shaken" {
		return SJWTRetErrJSONHdrPpt, fmt.Errorf("invalid value for ppt in json header")
	}
	if len(header.Typ) > 0 && header.Typ != "passport" {
		return SJWTRetErrJSONHdrTyp, fmt.Errorf("invalid value for typ in json header")
	}
	if len(header.X5u) > 0 && header.X5u != paramInfo {
		return SJWTRetErrJSONHdrX5u, fmt.Errorf("mismatching value for x5u and info attributes")
	}
	return SJWTRetOK, nil
}

// SJWTCheckIdentityPKMode - implements the verify of identity
func SJWTCheckIdentityPKMode(identityVal string, expireVal int, pubkeyVal string, pubkeyMode int, timeoutVal int) (int, error) {
	var err error
	var ret int
	var ecdsaPubKey *ecdsa.PublicKey
	var pubkey []byte
	var payload *SJWTPayload

	token := strings.Split(strings.TrimSpace(identityVal), ".")

	if len(token) != 3 {
		return SJWTRetErrSIPHdrParse, fmt.Errorf("invalid token - must contain header, payload and signature")
	}

	payload, ret, err = SJWTGetValidPayload(token[1], expireVal)
	if err != nil {
		return ret, err
	}

	if pubkeyMode == 1 {
		pubkey = []byte(pubkeyVal)
	} else {
		if strings.HasPrefix(pubkeyVal, "http://") || strings.HasPrefix(pubkeyVal, "https://") {
			pubkey, ret, err = SJWTGetURLContent(pubkeyVal, timeoutVal)
		} else if strings.HasPrefix(pubkeyVal, "file://") {
			fileUrl, _ := url.Parse(pubkeyVal)
			pubkey, err = ioutil.ReadFile(fileUrl.Path)
			ret = SJWTRetErrFileRead
		} else {
			pubkey, err = ioutil.ReadFile(pubkeyVal)
			ret = SJWTRetErrFileRead
		}
		if err != nil {
			return ret, err
		}
	}

	ret, err = SJWTPubKeyVerify(pubkey)
	if ret != SJWTRetOK {
		return ret, err
	}

	if ecdsaPubKey, ret, err = SJWTParseECPublicKeyFromPEM(pubkey); err != nil {
		return ret, err
	}
	ret, err = SJWTVerifyWithPubKey(token[0]+"."+token[1], token[2], ecdsaPubKey)
	if err == nil {
		return SJWTRetOK, nil
	}

	return ret, fmt.Errorf("failed to verify - origid (%s) (%d) %v", payload.OrigID, ret, err)
}

// SJWTCheckIdentity - implements the verify of identity
func SJWTCheckIdentity(identityVal string, expireVal int, pubkeyPath string, timeoutVal int) (int, error) {
	return SJWTCheckIdentityPKMode(identityVal, expireVal, pubkeyPath, 0, timeoutVal)
}

// SJWTGetValidInfoAttr - return info param value of alg and ppt are valid
func SJWTGetValidInfoAttr(hdrtoken []string) (string, int, error) {
	paramInfo := ""
	for i := 1; i < len(hdrtoken); i++ {
		ptoken := strings.Split(hdrtoken[i], "=")
		if len(ptoken) == 2 {
			if ptoken[0] == "alg" {
				if ptoken[1] != "ES256" {
					return "", SJWTRetErrSIPHdrAlg, fmt.Errorf("invalid value for alg header parameter")
				}
			} else if ptoken[0] == "ppt" {
				if ptoken[1] != "shaken" && ptoken[1] != `"shaken"` {
					return "", SJWTRetErrSIPHdrPpt, fmt.Errorf("invalid value for ppt header parameter")
				}
			} else if ptoken[0] == "info" {
				paramInfo = ptoken[1]
			}
		}
	}
	if len(paramInfo) <= 2 {
		return "", SJWTRetErrSIPHdrInfo, fmt.Errorf("invalid value info header parameter")
	}
	if paramInfo[0] == '<' && paramInfo[len(paramInfo)-1] == '>' {
		paramInfo = paramInfo[1 : len(paramInfo)-1]
	}

	return paramInfo, SJWTRetOK, nil
}

// SJWTCheckFullIdentity - implements the verify of identity
func SJWTCheckFullIdentity(identityVal string, expireVal int, pubkeyPath string, timeoutVal int) (int, error) {
	if len(pubkeyPath) == 0 {
		return SJWTCheckFullIdentityURL(identityVal, expireVal, timeoutVal)
	}

	hdrtoken := strings.Split(SJWTRemoveWhiteSpaces(identityVal), ";")

	ret, err := SJWTCheckIdentity(hdrtoken[0], expireVal, pubkeyPath, timeoutVal)
	if ret != 0 {
		return ret, err
	}

	if len(hdrtoken) == 1 {
		return SJWTRetErrSIPHdrParse, nil
	}

	paramInfo := ""
	paramInfo, ret, err = SJWTGetValidInfoAttr(hdrtoken)
	if err != nil {
		return ret, err
	}

	btoken := strings.Split(strings.TrimSpace(hdrtoken[0]), ".")

	if len(btoken[0]) == 0 {
		return SJWTRetErrJSONHdrParse, nil
	}
	return SJWTCheckAttributes(btoken[0], paramInfo)
}

// SJWTCheckFullIdentityURL - implements the verify of identity using URL
func SJWTCheckFullIdentityURL(identityVal string, expireVal int, timeoutVal int) (int, error) {
	var ecdsaPubKey *ecdsa.PublicKey
	var ret int
	var err error
	var pubkey []byte

	hdrtoken := strings.Split(SJWTRemoveWhiteSpaces(identityVal), ";")

	if len(hdrtoken) <= 1 {
		return SJWTRetErrSIPHdrParse, fmt.Errorf("missing parts of the message header")
	}

	paramInfo := ""
	paramInfo, ret, err = SJWTGetValidInfoAttr(hdrtoken)
	if err != nil {
		return ret, err
	}

	pubkey, ret, err = SJWTGetURLContent(paramInfo, timeoutVal)

	if pubkey == nil {
		return ret, err
	}

	ret, err = SJWTPubKeyVerify(pubkey)
	if ret != SJWTRetOK {
		return ret, err
	}

	if ecdsaPubKey, ret, err = SJWTParseECPublicKeyFromPEM(pubkey); err != nil {
		return ret, err
	}

	btoken := strings.Split(strings.TrimSpace(hdrtoken[0]), ".")

	if len(btoken) != 3 {
		return SJWTRetErrSIPHdrParse, fmt.Errorf("invalid token - must contain header, payload and signature")
	}

	if len(btoken[0]) == 0 {
		return SJWTRetErrSIPHdrParse, fmt.Errorf("no json header part")
	}

	var payload *SJWTPayload
	payload, ret, err = SJWTGetValidPayload(btoken[1], expireVal)
	if payload == nil || err != nil {
		return ret, err
	}

	ret, err = SJWTVerifyWithPubKey(btoken[0]+"."+btoken[1], btoken[2], ecdsaPubKey)
	if err != nil {
		return ret, err
	}

	return SJWTCheckAttributes(btoken[0], paramInfo)
}

// SJWTCheckFullIdentityPubKey - implements the verify of identity using public key
func SJWTCheckFullIdentityPubKey(identityVal string, expireVal int, pubkeyVal string) (int, error) {
	hdrtoken := strings.Split(SJWTRemoveWhiteSpaces(identityVal), ";")

	ret, err := SJWTCheckIdentityPKMode(hdrtoken[0], expireVal, pubkeyVal, 1, 5)
	if ret != 0 {
		return ret, err
	}

	if len(hdrtoken) == 1 {
		return SJWTRetOK, nil
	}

	paramInfo := ""
	paramInfo, ret, err = SJWTGetValidInfoAttr(hdrtoken)
	if err != nil {
		return ret, err
	}

	btoken := strings.Split(strings.TrimSpace(hdrtoken[0]), ".")

	if len(btoken[0]) == 0 {
		return SJWTRetOK, nil
	}
	return SJWTCheckAttributes(btoken[0], paramInfo)
}

// SJWTGetIdentityPrvKey --
func SJWTGetIdentityPrvKey(origTN string, destTN string, attestVal string, origID string, x5uVal string, prvkeyData []byte) (string, int, error) {
	var ret int
	var err error
	var vOrigID string

	header := SJWTHeader{
		Alg: "ES256",
		Ppt: "shaken",
		Typ: "passport",
		X5u: globalLibOptions.x5u,
	}
	if len(x5uVal) > 0 {
		header.X5u = x5uVal
	}
	if len(origID) > 0 {
		vOrigID = origID
	} else {
		vuuid := uuid.New()
		vOrigID = vuuid.String()
	}

	payload := SJWTPayload{
		ATTest: attestVal,
		Dest: SJWTDest{
			TN: []string{destTN},
		},
		IAT: time.Now().Unix(),
		Orig: SJWTOrig{
			TN: origTN,
		},
		OrigID: vOrigID,
	}

	var ecdsaPrvKey *ecdsa.PrivateKey
	if ecdsaPrvKey, ret, err = SJWTParseECPrivateKeyFromPEM(prvkeyData); err != nil {
		return "", ret, fmt.Errorf("Unable to parse ECDSA private key: %v", err)
	}
	token := SJWTEncode(header, payload, ecdsaPrvKey)

	if len(token) > 0 {
		return token + ";info=<" + header.X5u + ">;alg=ES256;ppt=shaken", SJWTRetOK, nil
	}
	return "", SJWTRetErrSIPHdrEmpty, errors.New("empty result")
}

// SJWTGetIdentity --
func SJWTGetIdentity(origTN string, destTN string, attestVal string, origID string, x5uVal string, prvkeyPath string) (string, int, error) {
	var prvkey []byte
	var err error

	prvkey, err = ioutil.ReadFile(prvkeyPath)
	if err != nil {
		return "", SJWTRetErrFileRead, fmt.Errorf("Unable to read private key file: %v", err)
	}
	return SJWTGetIdentityPrvKey(origTN, destTN, attestVal, origID, x5uVal, prvkey)
}
