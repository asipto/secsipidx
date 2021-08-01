package secsipid_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/asipto/secsipidx/secsipid"
	"github.com/gomagedon/expectate"
)

type ParseECPrivateKeyTest struct {
	inputPem []byte

	expectedKey     *ecdsa.PrivateKey
	expectedErrCode int
	expectedErrMsg  string
}

func TestParseECPrivateKeyFromPEM(t *testing.T) {
	runTest := func(t *testing.T, testCase ParseECPrivateKeyTest) {
		expect := expectate.Expect(t)

		key, errCode, err := secsipid.SJWTParseECPrivateKeyFromPEM(testCase.inputPem)

		if testCase.expectedKey == nil {
			expect(key).ToBe((*ecdsa.PrivateKey)(nil))
		} else {
			expect(key).ToEqual(testCase.expectedKey)
		}
		expect(errCode).ToBe(testCase.expectedErrCode)
		expect(getMsgFromErr(err)).ToBe(testCase.expectedErrMsg)
	}

	t.Run("ErrPrvKeyInvalidFormat with bad key format", func(t *testing.T) {
		runTest(t, ParseECPrivateKeyTest{
			inputPem: []byte("bad key format"),

			expectedErrCode: secsipid.SJWTRetErrPrvKeyInvalidFormat,
			expectedErrMsg:  "key must be PEM encoded",
		})
	})

	t.Run("ErrPrvKeyInvalid with invalid key", func(t *testing.T) {
		invalidKey, _ := pemEncode(&pem.Block{
			Type:  "INVALID KEY",
			Bytes: []byte("invalid key body"),
		})

		runTest(t, ParseECPrivateKeyTest{
			inputPem: invalidKey,

			expectedErrCode: secsipid.SJWTRetErrPrvKeyInvalid,
			expectedErrMsg:  `asn1: structure error: tags don't match (16 vs {class:1 tag:9 length:110 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} pkcs8 @2`,
		})
	})

	t.Run("ErrPrvKeyInvalidEC with non-EC PKCS8 key", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 512)
		rsaPKCS8Key, _ := x509.MarshalPKCS8PrivateKey(privateKey)
		rsaKeyPEM, _ := pemEncode(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: rsaPKCS8Key,
		})

		runTest(t, ParseECPrivateKeyTest{
			inputPem: rsaKeyPEM,

			expectedErrCode: secsipid.SJWTRetErrPrvKeyInvalidEC,
			expectedErrMsg:  "not EC private key",
		})
	})

	t.Run("Works with EC private key", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		privateKeyBytes, _ := x509.MarshalECPrivateKey(privateKey)
		ecPrivateKeyPEM, _ := pemEncode(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		runTest(t, ParseECPrivateKeyTest{
			inputPem: ecPrivateKeyPEM,

			expectedErrCode: secsipid.SJWTRetOK,
			expectedKey:     privateKey,
		})
	})

	t.Run("Works with PKCS8 encoded EC private key", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
		ecPrivateKeyPEM, _ := pemEncode(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: pkcs8Bytes,
		})

		runTest(t, ParseECPrivateKeyTest{
			inputPem: ecPrivateKeyPEM,

			expectedErrCode: secsipid.SJWTRetOK,
			expectedKey:     privateKey,
		})
	})
}

func pemEncode(block *pem.Block) ([]byte, error) {
	pemBytes := bytes.NewBufferString("")
	err := pem.Encode(pemBytes, block)
	if err != nil {
		return nil, err
	}
	return pemBytes.Bytes(), nil
}
