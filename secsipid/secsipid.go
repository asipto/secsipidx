package secsipid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
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
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
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

type SJWTFileCacheMeta struct {
	dirPath string
	expire  int
}

var urlFileCacheOptions = SJWTFileCacheMeta{
	dirPath: "",
	expire:  3600,
}

var (
	sES256KeyBits = 256
	sES256KeySize = 32
)

// SetFileCacheOptions --
func SetURLFileCacheOptions(path string, expire int) {
	urlFileCacheOptions.dirPath = path
	urlFileCacheOptions.expire = expire
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
	if len(urlFileCacheOptions.dirPath) > 0 {
		filePath = urlFileCacheOptions.dirPath + "/" + filePath
	}
	return filePath
}

// SJWTParseECPrivateKeyFromPEM Parse PEM encoded Elliptic Curve Private Key Structure
func SJWTParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("key must be PEM encoded")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, errors.New("not EC private key")
	}

	return pkey, nil
}

// SJWTParseECPublicKeyFromPEM Parse PEM encoded PKCS1 or PKCS8 public key
func SJWTParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("key must be PEM encoded")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, errors.New("not EC public key")
	}

	return pkey, nil
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
	if int(tnow.Sub(fileStat.ModTime()).Seconds()) > urlFileCacheOptions.expire {
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
func SJWTGetURLContent(urlVal string, timeoutVal int) ([]byte, error) {
	if len(urlFileCacheOptions.dirPath) > 0 {
		cdata, cerr := SJWTGetURLCachedContent(urlVal)
		if cdata != nil {
			return cdata, cerr
		}
	}
	httpClient := http.Client{
		Timeout: time.Duration(timeoutVal) * time.Second,
	}
	resp, err := httpClient.Get(urlVal)
	if err != nil {
		return nil, fmt.Errorf("http get failure: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status error: %v", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read http body failure: %v", err)
	}

	if len(urlFileCacheOptions.dirPath) > 0 {
		SJWTSetURLCachedContent(urlVal, data)
	}

	return data, nil
}

// SJWTGetValidPayload --
func SJWTGetValidPayload(base64Payload string, expireVal int) (*SJWTPayload, error) {
	decodedPayload, payloadErr := SJWTBase64DecodeString(base64Payload)
	if payloadErr != nil {
		return nil, fmt.Errorf("invalid payload: %s", payloadErr.Error())
	}
	payload := SJWTPayload{}

	err := json.Unmarshal([]byte(decodedPayload), &payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload: %s", err.Error())
	}

	if payload.IAT != 0 && time.Now().Unix() > payload.IAT+int64(expireVal) {
		return nil, errors.New("expired token")
	}

	return &payload, nil
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
		return -1, errors.New("invalid key type")
	}

	if len(sig) != 2*sES256KeySize {
		return -1, errors.New("ECDSA signature size verification failed")
	}

	r := big.NewInt(0).SetBytes(sig[:sES256KeySize])
	s := big.NewInt(0).SetBytes(sig[sES256KeySize:])

	if !crypto.SHA256.Available() {
		return -1, errors.New("hashing function unavailable")
	}
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signingString))

	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus == true {
		return 0, nil
	}
	return -1, errors.New("ECDSA verification failed")
}

// SJWTSignWithPrvKey - implements the signing
// For this signing method, key must be an ecdsa.PrivateKey struct
func SJWTSignWithPrvKey(signingString string, key interface{}) (string, error) {
	var ecdsaKey *ecdsa.PrivateKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		ecdsaKey = k
	default:
		return "", errors.New("invalid key type")
	}

	if !crypto.SHA256.Available() {
		return "", errors.New("hashing function not available")
	}

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signingString))

	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil))
	if err == nil {
		curveBits := ecdsaKey.Curve.Params().BitSize

		if sES256KeyBits != curveBits {
			return "", errors.New("invalid key size")
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

		return SJWTBase64EncodeBytes(out), nil
	}
	return "", err
}

// SJWTEncode - encode payload to JWT
func SJWTEncode(header SJWTHeader, payload SJWTPayload, prvkey interface{}) string {
	str, _ := json.Marshal(header)
	jwthdr := SJWTBase64EncodeString(string(str))
	encodedPayload, _ := json.Marshal(payload)
	signingValue := jwthdr + "." +
		SJWTBase64EncodeString(string(encodedPayload))
	signatureValue, _ := SJWTSignWithPrvKey(signingValue, prvkey)
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

	payload, err = SJWTGetValidPayload(token[1], expireVal)
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
func SJWTEncodeText(headerJSON string, payloadJSON string, prvkeyPath string) (string, error) {
	var err error
	var signatureValue string
	var ecdsaPrvKey *ecdsa.PrivateKey

	prvkey, _ := ioutil.ReadFile(prvkeyPath)

	if ecdsaPrvKey, err = SJWTParseECPrivateKeyFromPEM(prvkey); err != nil {
		return "", err
	}

	signingValue := SJWTBase64EncodeString(strings.TrimSpace(headerJSON)) +
		"." + SJWTBase64EncodeString(strings.TrimSpace(payloadJSON))
	signatureValue, err = SJWTSignWithPrvKey(signingValue, ecdsaPrvKey)
	if err != nil {
		return "", fmt.Errorf("failed to build signature: %v", err)
	}
	return signingValue + "." + signatureValue, nil
}

// SJWTCheckAttributes - implements the verify of attributes
func SJWTCheckAttributes(bToken string, paramInfo string) (int, error) {
	vHeader, err := SJWTBase64DecodeString(bToken)

	header := SJWTHeader{}
	err = json.Unmarshal([]byte(vHeader), &header)
	if err != nil {
		return -3, err
	}
	if len(header.Alg) > 0 && header.Alg != "ES256" {
		return -2, fmt.Errorf("invalid value for alg in json header")
	}
	if len(header.Ppt) > 0 && header.Ppt != "shaken" {
		return -2, fmt.Errorf("invalid value for ppt in json header")
	}
	if len(header.Typ) > 0 && header.Typ != "passport" {
		return -2, fmt.Errorf("invalid value for typ in json header")
	}
	if len(header.X5u) > 0 && header.X5u != paramInfo {
		return -2, fmt.Errorf("mismatching value for x5u and info attributes")
	}
	return 0, nil
}

// SJWTCheckIdentity - implements the verify of identity
func SJWTCheckIdentity(identityVal string, expireVal int, pubkeyPath string, timeoutVal int) (int, error) {
	var err error
	var ret int
	var ecdsaPubKey *ecdsa.PublicKey
	var pubkey []byte
	var payload *SJWTPayload

	token := strings.Split(strings.TrimSpace(identityVal), ".")

	if len(token) != 3 {
		return -1, fmt.Errorf("invalid token - must contain header, payload and signature")
	}

	payload, err = SJWTGetValidPayload(token[1], expireVal)
	if err != nil {
		return -1, err
	}

	if strings.HasPrefix(pubkeyPath, "http://") || strings.HasPrefix(pubkeyPath, "https://") {
		pubkey, err = SJWTGetURLContent(pubkeyPath, timeoutVal)
	} else if strings.HasPrefix(pubkeyPath, "file://") {
		fileUrl, _ := url.Parse(pubkeyPath)
		pubkey, err = ioutil.ReadFile(fileUrl.Path)
	} else {
		pubkey, err = ioutil.ReadFile(pubkeyPath)
	}
	if err != nil {
		return -1, err
	}

	if ecdsaPubKey, err = SJWTParseECPublicKeyFromPEM(pubkey); err != nil {
		return -1, err
	}
	ret, err = SJWTVerifyWithPubKey(token[0]+"."+token[1], token[2], ecdsaPubKey)
	if err == nil {
		return 0, nil
	}

	return 1, fmt.Errorf("failed to verify - origid (%s) (%d) %v", payload.OrigID, ret, err)
}

// SJWTGetValidInfoAttr - return info param value of alg and ppt are valid
func SJWTGetValidInfoAttr(hdrtoken []string) (string, error) {
	paramInfo := ""
	for i := 1; i < len(hdrtoken); i++ {
		ptoken := strings.Split(hdrtoken[i], "=")
		if len(ptoken) == 2 {
			if ptoken[0] == "alg" {
				if ptoken[1] != "ES256" {
					return "", fmt.Errorf("invalid value for alg header parameter")
				}
			} else if ptoken[0] == "ppt" {
				if ptoken[1] != "shaken" && ptoken[1] != `"shaken"` {
					return "", fmt.Errorf("invalid value for ppt header parameter")
				}
			} else if ptoken[0] == "info" {
				paramInfo = ptoken[1]
			}
		}
	}
	if len(paramInfo) <= 2 {
		return "", fmt.Errorf("invalid value info header parameter")
	}
	if paramInfo[0] == '<' && paramInfo[len(paramInfo)-1] == '>' {
		paramInfo = paramInfo[1 : len(paramInfo)-1]
	}

	return paramInfo, nil
}

// SJWTCheckFullIdentity - implements the verify of identity
func SJWTCheckFullIdentity(identityVal string, expireVal int, pubkeyPath string, timeoutVal int) (int, error) {
	hdrtoken := strings.Split(SJWTRemoveWhiteSpaces(identityVal), ";")

	ret, err := SJWTCheckIdentity(hdrtoken[0], expireVal, pubkeyPath, timeoutVal)
	if ret != 0 {
		return ret, err
	}

	if len(hdrtoken) == 1 {
		return 0, nil
	}

	paramInfo := ""
	paramInfo, err = SJWTGetValidInfoAttr(hdrtoken)
	if err != nil {
		return -1, err
	}

	btoken := strings.Split(strings.TrimSpace(hdrtoken[0]), ".")

	if len(btoken[0]) == 0 {
		return 0, nil
	}
	return SJWTCheckAttributes(btoken[0], paramInfo)
}

// SJWTCheckFullIdentityURL - implements the verify of identity using URL
func SJWTCheckFullIdentityURL(identityVal string, expireVal int, timeoutVal int) (int, error) {
	var ecdsaPubKey *ecdsa.PublicKey
	var ret int

	hdrtoken := strings.Split(SJWTRemoveWhiteSpaces(identityVal), ";")

	if len(hdrtoken) == 1 {
		return -1, fmt.Errorf("missing parts of the message header")
	}

	paramInfo, err1 := SJWTGetValidInfoAttr(hdrtoken)
	if err1 != nil {
		return -1, err1
	}

	pubkey, err := SJWTGetURLContent(paramInfo, timeoutVal)

	if ecdsaPubKey, err = SJWTParseECPublicKeyFromPEM(pubkey); err != nil {
		return -1, err
	}

	btoken := strings.Split(strings.TrimSpace(hdrtoken[0]), ".")

	if len(btoken[0]) == 0 {
		return -1, fmt.Errorf("ino json header part")
	}

	ret, err = SJWTVerifyWithPubKey(btoken[0]+"."+btoken[1], btoken[2], ecdsaPubKey)
	if err != nil {
		return ret, err
	}

	return SJWTCheckAttributes(btoken[0], paramInfo)
}

// SJWTGetIdentity --
func SJWTGetIdentity(origTN string, destTN string, attestVal string, origID string, x5uVal string, prvkeyPath string) (string, error) {
	var err error
	var vOrigID string

	header := SJWTHeader{
		Alg: "ES256",
		Ppt: "shaken",
		Typ: "passport",
		X5u: "https://127.0.0.1/cert.pem",
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

	prvkey, _ := ioutil.ReadFile(prvkeyPath)
	var ecdsaPrvKey *ecdsa.PrivateKey

	if ecdsaPrvKey, err = SJWTParseECPrivateKeyFromPEM(prvkey); err != nil {
		return "", fmt.Errorf("Unable to parse ECDSA private key: %v", err)
	}
	token := SJWTEncode(header, payload, ecdsaPrvKey)

	if len(token) > 0 {
		return token + ";info=<" + header.X5u + ">;>alg=ES256;ppt=shaken", nil
	}
	return "", nil
}
