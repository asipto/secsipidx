package secsipid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"time"
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

var (
	sJWTExpireInterval = 300
	sES256KeyBits      = 256
	sES256KeySize      = 32
)

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

// SJWTBase64Encode takes in a string and returns a base 64 encoded string
func SJWTBase64Encode(src string) string {
	return strings.
		TrimRight(base64.URLEncoding.
			EncodeToString([]byte(src)), "=")
}

// SJWTBase64Decode takes in a base 64 encoded string and returns the
// actual string or an error of it fails to decode the string
func SJWTBase64Decode(src string) (string, error) {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		errMsg := fmt.Errorf("decoding error %s", err)
		return "", errMsg
	}
	return string(decoded), nil
}

// SJWTHash generates a Hmac256 hash of a string using a secret
func SJWTHash(src string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(src))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// SJWTEncodeSegment Encode JWT specific base64url encoding with padding stripped
func SJWTEncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// SJWTDecodeSegment - Decode JWT specific base64url encoding with padding stripped
func SJWTDecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

// SJWTVerify - implements the verify
// For this verify method, key must be an ecdsa.PublicKey struct
func SJWTVerify(signingString string, signature string, key interface{}) error {
	var err error

	var sig []byte
	if sig, err = SJWTDecodeSegment(signature); err != nil {
		return err
	}

	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	default:
		return errors.New("invalid key type")
	}

	if len(sig) != 2*sES256KeySize {
		return errors.New("ECDSA signature size verification failed")
	}

	r := big.NewInt(0).SetBytes(sig[:sES256KeySize])
	s := big.NewInt(0).SetBytes(sig[sES256KeySize:])

	if !crypto.SHA256.Available() {
		return errors.New("hashing function unavailable")
	}
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signingString))

	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus == true {
		return nil
	}
	return errors.New("ECDSA verification failed")
}

// SJWTSign - implements the signing
// For this signing method, key must be an ecdsa.PrivateKey struct
func SJWTSign(signingString string, key interface{}) (string, error) {
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

		return SJWTEncodeSegment(out), nil
	}
	return "", err
}

// SJWTIsValidHash validates a hash againt a value
func SJWTIsValidHash(value string, hash string, secret string) bool {
	return hash == SJWTHash(value, secret)
}

// SJWTEncode - encode payload to JWT
func SJWTEncode(header SJWTHeader, payload SJWTPayload, prvkey interface{}) string {
	str, _ := json.Marshal(header)
	jwthdr := SJWTBase64Encode(string(str))
	encodedPayload, _ := json.Marshal(payload)
	signingValue := jwthdr + "." +
		SJWTBase64Encode(string(encodedPayload))
	signatureValue, _ := SJWTSign(signingValue, prvkey)
	return signingValue + "." + signatureValue
}

// SJWTDecode - decode JWT string
func SJWTDecode(jwt string, pubkey interface{}) (*SJWTPayload, error) {
	token := strings.Split(jwt, ".")

	if len(token) != 3 {
		splitErr := errors.New("invalid token - must contain header, payload and signature")
		return nil, splitErr
	}

	decodedPayload, payloadErr := SJWTBase64Decode(token[1])
	if payloadErr != nil {
		return nil, fmt.Errorf("invalid payload: %s", payloadErr.Error())
	}
	payload := SJWTPayload{}

	err := json.Unmarshal([]byte(decodedPayload), &payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload: %s", err.Error())
	}

	if payload.IAT != 0 && time.Now().Unix() > payload.IAT+int64(sJWTExpireInterval) {
		return nil, errors.New("expired token")
	}
	signatureValue := token[0] + "." + token[1]

	err = SJWTVerify(signatureValue, token[2], pubkey)
	if err != nil {
		return nil, err
	}
	return &payload, nil
}

// SJWTEncodeText - encode header and payload to JWT
func SJWTEncodeText(headerJSON string, payloadJSON string, prvkeyPath string) string {
	prvkey, _ := ioutil.ReadFile(prvkeyPath)

	signingValue := SJWTBase64Encode(headerJSON) + "." + SJWTBase64Encode(payloadJSON)
	signatureValue, _ := SJWTSign(signingValue, prvkey)
	return signingValue + "." + signatureValue
}
