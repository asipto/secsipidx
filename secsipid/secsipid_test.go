package secsipid_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asipto/secsipidx/secsipid"
	"github.com/gomagedon/expectate"
)

type PubKeyVerifyTest struct {
	certVerify int
	inputKey   []byte

	expectedErrCode int
	expectedErrMsg  string
}

func TestPubKeyVerify(t *testing.T) {
	runTest := func(t *testing.T, testCase PubKeyVerifyTest) {
		expect := expectate.Expect(t) // testing utility

		secsipid.SJWTLibOptSetN("CertVerify", testCase.certVerify)

		errCode, err := secsipid.SJWTPubKeyVerify(testCase.inputKey)
		errMsg := getMsgFromErr(err)

		expect(errCode).ToBe(testCase.expectedErrCode)
		if len(testCase.expectedErrMsg) > 0 {
			expect(errMsg).ToBe(testCase.expectedErrMsg)
		}
	}

	os.Remove("dummyCA.pem")
	os.Remove("dummyInterCA.pem")
	os.Remove("dummyCRLFile.crl")

	// Test
	t.Run("OK when certVerify is 0", func(t *testing.T) {
		runTest(t, PubKeyVerifyTest{
			certVerify: 0,
			inputKey:   []byte("foo"),

			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})
	})

	// Test (for every non-zero value of certVerify)
	for certVerify := 1; certVerify <= 32; certVerify += 1 {
		t.Run("ErrCertInvalidFormat when key is invalid format", func(t *testing.T) {
			runTest(t, PubKeyVerifyTest{
				certVerify: certVerify,
				inputKey:   []byte("this is an invalid cert"),

				expectedErrCode: secsipid.SJWTRetErrCertInvalidFormat,
				expectedErrMsg:  "failed to parse certificate PEM",
			})
		})
	}

	certGenerator := NewDummyCA()

	t.Run("ErrCertExpired", func(t *testing.T) {
		cert := certGenerator.generateExpiredCert()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00001,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertExpired,
			expectedErrMsg:  "certificate expired",
		})
	})

	t.Run("ErrCertBeforeValidity", func(t *testing.T) {
		cert := certGenerator.generateCertBeforeValidity()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00001,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertBeforeValidity,
			expectedErrMsg:  "certificate not valid yet",
		})
	})

	t.Run("ErrCertInvalid with no root CAs", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00001, // haven't enabled system CA or custom CA
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertInvalid,
			expectedErrMsg:  "",
		})
	})

	t.Run("ErrCertInvalid with default system CAs", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00010,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertInvalid,
			expectedErrMsg:  "x509: certificate signed by unknown authority",
		})
	})

	t.Run("Cert is valid with dummy system CAs", func(t *testing.T) {
		oldSSLCertDir := os.Getenv("SSL_CERT_DIR")
		oldSSLCertFile := os.Getenv("SSL_CERT_FILE")

		workDir, _ := os.Getwd()

		os.Setenv("SSL_CERT_DIR", workDir)
		defer os.Setenv("SSL_CERT_DIR", oldSSLCertDir)
		os.Setenv("SSL_CERT_FILE", path.Join(workDir, "dummyCA.pem"))
		defer os.Setenv("SSL_CERT_FILE", oldSSLCertFile)

		println(os.Getenv("SSL_CERT_DIR"))

		cert := certGenerator.generateValidCert()
		os.WriteFile("dummyCA.pem", certGenerator.caPEMBytes, 0777)

		secsipid.ResetSystemCertPool()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00010,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		os.Remove("dummyCA.pem")
	})

	t.Run("ErrCertNoCAFile with no CA file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertNoCAFile,
			expectedErrMsg:  "no custom CA file",
		})
	})

	t.Run("ErrCertReadCAFile with non-existant CA file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		secsipid.SJWTLibOptSetS("CertCAFile", "nonexistant.pem")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertReadCAFile,
			expectedErrMsg:  "failed to read CA file",
		})
	})

	t.Run("ErrCertProcessing with invalid CA file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		secsipid.SJWTLibOptSetS("CertCAFile", "dummyCA.pem")
		os.WriteFile("dummyCA.pem", []byte("invalid cert"), 0777)

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertProcessing,
			expectedErrMsg:  "failed to append CA file",
		})

		os.Remove("dummyCA.pem")
	})

	t.Run("OK with correct custom CA file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()
		os.WriteFile("dummyCA.pem", certGenerator.caPEMBytes, 0777)

		secsipid.SJWTLibOptSetS("CertCAFile", "dummyCA.pem")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b00100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		os.Remove("dummyCA.pem")
	})

	t.Run("ErrCertNoCAInter with no intermediate CA file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b01000,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertNoCAInter,
			expectedErrMsg:  "no intermediate CA file",
		})
	})

	t.Run("ErrCertReadCAInter with non-existant intermediate CA file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		secsipid.SJWTLibOptSetS("CertCAInter", "nonexistant.pem")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b01000,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertReadCAInter,
			expectedErrMsg:  "failed to read intermediate CA file",
		})
	})

	t.Run("ErrCertProcessing with invalid intermediate CA file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		os.WriteFile("dummyInterCA.pem", []byte("invalid cert"), 0777)
		secsipid.SJWTLibOptSetS("CertCAInter", "dummyInterCA.pem")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b01000,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertProcessing,
			expectedErrMsg:  "failed to append intermediate CA file",
		})

		os.Remove("dummyInterCA.pem")
	})

	t.Run("OK with correct intermediate and root CA files", func(t *testing.T) {
		interCertGenerator := NewIntermediateCA(certGenerator)
		cert := interCertGenerator.generateValidCert()

		os.WriteFile("dummyCA.pem", certGenerator.caPEMBytes, 0777)
		os.WriteFile("dummyInterCA.pem", interCertGenerator.caPEMBytes, 0777)
		secsipid.SJWTLibOptSetS("CertCAFile", "dummyCA.pem")
		secsipid.SJWTLibOptSetS("CertCAInter", "dummyInterCA.pem")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b01100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		os.Remove("dummyCA.pem")
		os.Remove("dummyInterCA.pem")
	})

	t.Run("ErrCertNoCRLFile with no CRL file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		os.WriteFile("dummyCA.pem", certGenerator.caPEMBytes, 0777)
		secsipid.SJWTLibOptSetS("CertCAFile", "dummyCA.pem")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b10100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertNoCRLFile,
			expectedErrMsg:  "no CRL file",
		})

		os.Remove("dummyCA.pem")
	})

	t.Run("ErrCertReadCRLFile with non-existant CRL file", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		os.WriteFile("dummyCA.pem", certGenerator.caPEMBytes, 0777)
		secsipid.SJWTLibOptSetS("CertCAFile", "dummyCA.pem")

		secsipid.SJWTLibOptSetS("CertCRLFile", "dummyCRLFile.crl")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b10100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertReadCRLFile,
			expectedErrMsg:  "failed to read CRL file",
		})

		os.Remove("dummyCA.pem")
		os.Remove("dummyCRLFile.crl")
	})

	t.Run("OK if CRL does not contain cert", func(t *testing.T) {
		cert := certGenerator.generateValidCert()

		os.WriteFile("dummyCA.pem", certGenerator.caPEMBytes, 0777)
		secsipid.SJWTLibOptSetS("CertCAFile", "dummyCA.pem")

		crl := &x509.RevocationList{
			Number: big.NewInt(1),
			RevokedCertificates: []pkix.RevokedCertificate{
				{
					SerialNumber:   big.NewInt(0),
					RevocationTime: time.Now(),
				},
			},
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().AddDate(1, 0, 0),
		}
		crlBytes, _ := x509.CreateRevocationList(
			rand.Reader, crl, certGenerator.ca, certGenerator.caPrivKey)

		os.WriteFile("dummyCRLFile.crl", crlBytes, 0777)
		secsipid.SJWTLibOptSetS("CertCRLFile", "dummyCRLFile.crl")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b10100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		os.Remove("dummyCA.pem")
	})

	t.Run("ErrCertRevoked when CRL contains cert", func(t *testing.T) {
		cert, serialNum := certGenerator.generateCertWithTimes(
			time.Now(), time.Now().AddDate(1, 0, 0))

		os.WriteFile("dummyCA.pem", certGenerator.caPEMBytes, 0777)
		secsipid.SJWTLibOptSetS("CertCAFile", "dummyCA.pem")

		crl := &x509.RevocationList{
			Number: big.NewInt(1),
			RevokedCertificates: []pkix.RevokedCertificate{
				{
					SerialNumber:   serialNum,
					RevocationTime: time.Now(),
				},
			},
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().AddDate(1, 0, 0),
		}
		crlBytes, _ := x509.CreateRevocationList(
			rand.Reader, crl, certGenerator.ca, certGenerator.caPrivKey)

		os.WriteFile("dummyCRLFile.crl", crlBytes, 0777)
		secsipid.SJWTLibOptSetS("CertCRLFile", "dummyCRLFile.crl")

		runTest(t, PubKeyVerifyTest{
			certVerify: 0b10100,
			inputKey:   cert,

			expectedErrCode: secsipid.SJWTRetErrCertRevoked,
			expectedErrMsg:  "serial number match - certificate is revoked",
		})

		os.Remove("dummyCA.pem")
		os.Remove("dummyCRLFile.crl")
	})
}

func getMsgFromErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type DummyCertGenerator struct {
	ca         *x509.Certificate
	caPEMBytes []byte
	caPrivKey  *rsa.PrivateKey
}

func NewDummyCA() DummyCertGenerator {
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 512)

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		SubjectKeyId: x509.MarshalPKCS1PublicKey(&caPrivKey.PublicKey),
		Subject: pkix.Name{
			Organization:  []string{"Foo, Inc."},
			Country:       []string{"Fantasyland"},
			Province:      []string{""},
			Locality:      []string{"Metropolis"},
			StreetAddress: []string{"111 Main St."},
			PostalCode:    []string{"11111"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, _ := x509.CreateCertificate(
		rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return DummyCertGenerator{
		ca:         ca,
		caPrivKey:  caPrivKey,
		caPEMBytes: caPEM.Bytes(),
	}
}

func NewIntermediateCA(certGenerator DummyCertGenerator) DummyCertGenerator {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization:  []string{"FooBar, Inc."},
			Country:       []string{"Fantasyland"},
			Province:      []string{""},
			Locality:      []string{"Metropolis"},
			StreetAddress: []string{"333 Main St."},
			PostalCode:    []string{"33333"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 512)

	caBytes, _ := x509.CreateCertificate(
		rand.Reader, ca, certGenerator.ca,
		&caPrivKey.PublicKey, certGenerator.caPrivKey)

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return DummyCertGenerator{
		ca:         ca,
		caPrivKey:  caPrivKey,
		caPEMBytes: caPEM.Bytes(),
	}
}

func (gen DummyCertGenerator) generateExpiredCert() []byte {
	cert, _ := gen.generateCertWithTimes(
		time.Now().AddDate(-1, 0, 0), // 1 year ago
		time.Now().AddDate(0, 0, -1), // 1 day ago
	)
	return cert
}

func (gen DummyCertGenerator) generateCertBeforeValidity() []byte {
	cert, _ := gen.generateCertWithTimes(
		time.Now().AddDate(1, 0, 0), // 1 year from now
		time.Now().AddDate(2, 0, 0), // 2 years from now
	)
	return cert
}

func (gen DummyCertGenerator) generateValidCert() []byte {
	cert, _ := gen.generateCertWithTimes(
		time.Now(),
		time.Now().AddDate(1, 0, 0), // 1 year from now
	)
	return cert
}

func (gen DummyCertGenerator) generateCertWithTimes(notBefore time.Time, notAfter time.Time) ([]byte, *big.Int) {
	serialNum, _ := rand.Int(rand.Reader, big.NewInt(10000))
	cert := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			Organization:  []string{"Bar, Inc."},
			Country:       []string{"Fantasyland"},
			Province:      []string{""},
			Locality:      []string{"Metropolis"},
			StreetAddress: []string{"222 Main St."},
			PostalCode:    []string{"11111"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 512)
	certBytes, _ := x509.CreateCertificate(
		rand.Reader, cert, gen.ca, &certPrivKey.PublicKey, gen.caPrivKey)

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return certPEM.Bytes(), serialNum
}

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
		if len(testCase.expectedErrMsg) > 0 {
			expect(getMsgFromErr(err)).ToBe(testCase.expectedErrMsg)
		}
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

type ParseECPublicKeyTest struct {
	inputPem []byte

	expectedKey     *ecdsa.PublicKey
	expectedErrCode int
	expectedErrMsg  string
}

func TestParseECPublicKeyFromPEM(t *testing.T) {
	runTest := func(t *testing.T, testCase ParseECPublicKeyTest) {
		expect := expectate.Expect(t)

		key, errCode, err := secsipid.SJWTParseECPublicKeyFromPEM(testCase.inputPem)

		if testCase.expectedKey == nil {
			expect(key).ToBe((*ecdsa.PublicKey)(nil))
		} else {
			expect(key).ToEqual(testCase.expectedKey)
		}
		expect(errCode).ToBe(testCase.expectedErrCode)
		if len(testCase.expectedErrMsg) > 0 {
			expect(getMsgFromErr(err)).ToBe(testCase.expectedErrMsg)
		}
	}

	t.Run("ErrCertInvalidFormat with bad key format", func(t *testing.T) {
		runTest(t, ParseECPublicKeyTest{
			inputPem: []byte("bad key format"),

			expectedErrCode: secsipid.SJWTRetErrCertInvalidFormat,
			expectedErrMsg:  "key must be PEM encoded",
		})
	})

	t.Run("ErrCertInvalid with invalid certificate", func(t *testing.T) {
		invalidCert, _ := pemEncode(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid certificate"),
		})

		runTest(t, ParseECPublicKeyTest{
			inputPem: invalidCert,

			expectedErrCode: secsipid.SJWTRetErrCertInvalid,
			expectedErrMsg:  "",
		})
	})

	t.Run("ErrCertInvalidEC with non-EC public key", func(t *testing.T) {
		privKey, _ := rsa.GenerateKey(rand.Reader, 512)
		pubKey := &privKey.PublicKey
		pubKeyBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
		rsaPublicKey, _ := pemEncode(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: pubKeyBytes,
		})

		runTest(t, ParseECPublicKeyTest{
			inputPem: rsaPublicKey,

			expectedErrCode: secsipid.SJWTRetErrCertInvalidEC,
			expectedErrMsg:  "not EC public key",
		})
	})

	t.Run("OK with EC public key", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubKey := &privKey.PublicKey
		pubKeyBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
		ecPublicKey, _ := pemEncode(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: pubKeyBytes,
		})

		runTest(t, ParseECPublicKeyTest{
			inputPem: ecPublicKey,

			expectedKey: pubKey,
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

func TestSJWTLibOptSetV(t *testing.T) {
	t.Run("rejects malformed input without panicking", func(t *testing.T) {
		expect := expectate.Expect(t)

		testCases := []string{
			"",
			"CacheExpires",
			"=",
			"=123",
		}

		for _, input := range testCases {
			expect(secsipid.SJWTLibOptSetV(input)).ToBe(secsipid.SJWTRetErr)
		}
	})

	t.Run("sets numeric options from valid key value input", func(t *testing.T) {
		expect := expectate.Expect(t)
		defer secsipid.SJWTLibOptSetN("MaxURLContentBytes", testMaxURLContentBytes)

		expect(secsipid.SJWTLibOptSetV("CacheExpires=42")).ToBe(secsipid.SJWTRetOK)
		expect(secsipid.SJWTLibOptGetN("CacheExpires")).ToBe(42)
		expect(secsipid.SJWTLibOptSetV("DenyPrivateX5U=1")).ToBe(secsipid.SJWTRetOK)
		expect(secsipid.SJWTLibOptGetN("DenyPrivateX5U")).ToBe(1)
		expect(secsipid.SJWTLibOptSetN("DenyPrivateX5U", 0)).ToBe(secsipid.SJWTRetOK)
		expect(secsipid.SJWTLibOptSetV("MaxURLContentBytes=2048")).ToBe(secsipid.SJWTRetOK)
		expect(secsipid.SJWTLibOptGetN("MaxURLContentBytes")).ToBe(2048)
		expect(secsipid.SJWTLibOptSetN("MaxURLContentBytes", 0)).ToBe(secsipid.SJWTRetErr)
	})

	t.Run("sets string options from valid key value input", func(t *testing.T) {
		expect := expectate.Expect(t)

		expect(secsipid.SJWTLibOptSetV("CertCAFile=dummy-ca.pem")).ToBe(secsipid.SJWTRetOK)
		expect(secsipid.SJWTLibOptSetS("CertCAFile", "")).ToBe(secsipid.SJWTRetOK)
	})
}

func TestSignerAndVerifierUseInstanceLocalOptions(t *testing.T) {
	expect := expectate.Expect(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privateKeyPEM, err := pemEncode(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		t.Fatalf("encode private key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	signerA := secsipid.NewSJWTSigner(secsipid.SJWTOptions{
		CacheExpire: 3600,
		X5U:         "https://signer-a.example/cert.pem",
	})
	signerB := secsipid.NewSJWTSigner(secsipid.SJWTOptions{
		CacheExpire: 3600,
		X5U:         "https://signer-b.example/cert.pem",
	})

	identityA, ret, err := signerA.GetIdentityPrvKey("12025550100", "12025550101", "A", "", "", privateKeyPEM)
	expect(ret).ToBe(secsipid.SJWTRetOK)
	if err != nil {
		t.Fatalf("sign identity A: %v", err)
	}
	expect(strings.Contains(identityA, "https://signer-a.example/cert.pem")).ToBe(true)
	expect(strings.Contains(identityA, "https://signer-b.example/cert.pem")).ToBe(false)

	identityB, ret, err := signerB.GetIdentityPrvKey("12025550100", "12025550101", "A", "", "", privateKeyPEM)
	expect(ret).ToBe(secsipid.SJWTRetOK)
	if err != nil {
		t.Fatalf("sign identity B: %v", err)
	}
	expect(strings.Contains(identityB, "https://signer-b.example/cert.pem")).ToBe(true)
	expect(strings.Contains(identityB, "https://signer-a.example/cert.pem")).ToBe(false)

	strictVerifier := secsipid.NewSJWTVerifier(secsipid.SJWTOptions{
		CacheExpire: 3600,
		CertVerify:  0,
		AttrsVerify: 1,
	})
	relaxedVerifier := secsipid.NewSJWTVerifier(secsipid.SJWTOptions{
		CacheExpire: 3600,
		CertVerify:  0,
		AttrsVerify: 0,
	})

	tamperedIdentity := strings.Replace(identityA,
		";info=<https://signer-a.example/cert.pem>",
		";info=<https://tampered.example/cert.pem>",
		1)

	ret, err = strictVerifier.CheckFullIdentityPubKey(tamperedIdentity, 3600, string(publicKeyPEM))
	expect(ret).ToBe(secsipid.SJWTRetErrJSONHdrX5u)
	expect(getMsgFromErr(err)).ToBe("mismatching value for x5u and info attributes")

	ret, err = relaxedVerifier.CheckFullIdentityPubKey(tamperedIdentity, 3600, string(publicKeyPEM))
	expect(ret).ToBe(secsipid.SJWTRetOK)
	expect(err).ToBe(error(nil))
}

type GetURLValueTest struct {
	urlVal     string
	timeoutVal int

	expectedContent []byte
	expectedErrCode int
	expectedErrMsg  string
}

const testMaxURLContentBytes = 1 << 20

func TestGetURLContent(t *testing.T) {
	os.Remove("http_example.com_foo")
	os.Remove("http_localhost:5555_foo")
	secsipid.SJWTLibOptSetS("CacheNameMode", "plain")
	secsipid.SJWTLibOptSetN("MaxURLContentBytes", testMaxURLContentBytes)
	defer secsipid.SJWTLibOptSetN("MaxURLContentBytes", testMaxURLContentBytes)

	tcpDialErrMsg := getTcpDialErrMsg()

	runTest := func(t *testing.T, testCase GetURLValueTest) {
		expect := expectate.Expect(t)

		content, errCode, err := secsipid.SJWTGetURLContent(
			testCase.urlVal, testCase.timeoutVal)

		expect(content).ToEqual(testCase.expectedContent)
		expect(errCode).ToBe(testCase.expectedErrCode)
		if len(testCase.expectedErrMsg) > 0 {
			expect(getMsgFromErr(err)).ToBe(testCase.expectedErrMsg)
		}
	}

	t.Run("ErrHTTPInvalidURL with empty urlVal", func(t *testing.T) {
		runTest(t, GetURLValueTest{
			urlVal:     "",
			timeoutVal: 10,

			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPInvalidURL,
			expectedErrMsg:  "no URL value",
		})
	})

	t.Run("ErrHTTPInvalidURL with non-http scheme", func(t *testing.T) {
		badSchemes := []string{"sip", "ftp", "file", "foo", "bar", "invalid"}

		for _, scheme := range badSchemes {
			t.Run(scheme, func(t *testing.T) {
				runTest(t, GetURLValueTest{
					urlVal:     fmt.Sprintf("%s://example.com/somepath", scheme),
					timeoutVal: 10,

					expectedContent: nil,
					expectedErrCode: secsipid.SJWTRetErrHTTPInvalidURL,
					expectedErrMsg:  "invalid URL value",
				})
			})
		}
	})

	t.Run("OK with cached value", func(t *testing.T) {
		workDir, _ := os.Getwd()
		secsipid.SetURLFileCacheOptions(workDir, 3600)
		os.WriteFile("http_example.com_foo", []byte("Hello, world"), 0777)

		runTest(t, GetURLValueTest{
			urlVal:     "http://example.com/foo",
			timeoutVal: 10,

			expectedContent: []byte("Hello, world"),
			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		os.Remove("http_example.com_foo")
	})

	t.Run("ErrHTTPGet with no cache file and no running server", func(t *testing.T) {
		workDir, _ := os.Getwd()
		secsipid.SetURLFileCacheOptions(workDir, 3600)
		defer secsipid.SetURLFileCacheOptions("", 0)

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPGet,
			expectedErrMsg:  tcpDialErrMsg,
		})
	})

	t.Run("ErrHTTPGet when timeout expires", func(t *testing.T) {
		if os.Getenv("GO_TEST_ALL") != "on" {
			t.Skip("This test takes a long time. $GO_TEST_ALL must be set to 'on'")
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
		})
		stopTestServer := startTestServer(handler)
		defer stopTestServer()

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 1,

			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPGet,
			expectedErrMsg:  `http get failure: Get "http://localhost:5555/foo": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`,
		})
	})

	t.Run("ErrHTTPStatusCode when not 200 OK status code", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
		})
		stopTestServer := startTestServer(handler)
		defer stopTestServer()

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPStatusCode,
			expectedErrMsg:  "http status error: 400",
		})
	})

	t.Run("ErrHTTPReadBody with bad response body", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1")
		})
		stopTestServer := startTestServer(handler)
		defer stopTestServer()

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPReadBody,
			expectedErrMsg:  "read http body failure: unexpected EOF",
		})
	})

	t.Run("OK when response body is at the size limit", func(t *testing.T) {
		responseBody := strings.Repeat("a", testMaxURLContentBytes)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(responseBody))
		})
		stopTestServer := startTestServer(handler)
		defer stopTestServer()

		runTest(t, GetURLValueTest{
			urlVal:          "http://localhost:5555/foo",
			timeoutVal:      10,
			expectedContent: []byte(responseBody),
			expectedErrCode: secsipid.SJWTRetOK,
		})
	})

	t.Run("ErrHTTPReadBody when response body exceeds the size limit", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(strings.Repeat("a", testMaxURLContentBytes+1)))
		})
		stopTestServer := startTestServer(handler)
		defer stopTestServer()

		runTest(t, GetURLValueTest{
			urlVal:          "http://localhost:5555/foo",
			timeoutVal:      10,
			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPReadBody,
			expectedErrMsg:  "read http body failure: content exceeds 1048576 byte limit",
		})
	})

	t.Run("ErrHTTPReadBody uses configured response body size limit", func(t *testing.T) {
		const configuredLimit = 16
		secsipid.SJWTLibOptSetN("MaxURLContentBytes", configuredLimit)
		defer secsipid.SJWTLibOptSetN("MaxURLContentBytes", testMaxURLContentBytes)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(strings.Repeat("a", configuredLimit+1)))
		})
		stopTestServer := startTestServer(handler)
		defer stopTestServer()

		runTest(t, GetURLValueTest{
			urlVal:          "http://localhost:5555/foo",
			timeoutVal:      10,
			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPReadBody,
			expectedErrMsg:  "read http body failure: content exceeds 16 byte limit",
		})
	})

	t.Run("OK but does not cache if cacheDirPath is unset", func(t *testing.T) {
		secsipid.SetURLFileCacheOptions("", 0)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello from the server!"))
		})
		stopTestServer := startTestServer(handler)

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: []byte("Hello from the server!"),
			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		stopTestServer()

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPGet,
			expectedErrMsg:  tcpDialErrMsg,
		})
	})

	t.Run("OK and caches if cacheDirPath is set", func(t *testing.T) {
		workDir, _ := os.Getwd()
		secsipid.SetURLFileCacheOptions(workDir, 3600)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello from the server!"))
		})
		stopTestServer := startTestServer(handler)

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: []byte("Hello from the server!"),
			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		stopTestServer()

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: []byte("Hello from the server!"),
			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		os.Remove("http_localhost:5555_foo")
	})

	t.Run("Not OK if cache expires", func(t *testing.T) {
		if os.Getenv("GO_TEST_ALL") != "on" {
			t.Skip("This test takes a long time. $GO_TEST_ALL must be set to 'on'")
		}

		workDir, _ := os.Getwd()
		secsipid.SetURLFileCacheOptions(workDir, 1)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello from the server!"))
		})
		stopTestServer := startTestServer(handler)

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: []byte("Hello from the server!"),
			expectedErrCode: secsipid.SJWTRetOK,
			expectedErrMsg:  "",
		})

		stopTestServer()
		time.Sleep(time.Second * 2)

		runTest(t, GetURLValueTest{
			urlVal:     "http://localhost:5555/foo",
			timeoutVal: 10,

			expectedContent: nil,
			expectedErrCode: secsipid.SJWTRetErrHTTPGet,
			expectedErrMsg:  tcpDialErrMsg,
		})

		os.Remove("http_localhost:5555_foo")
	})
}

func TestURLCacheFilePathModes(t *testing.T) {
	expect := expectate.Expect(t)
	workDir := t.TempDir()
	urlVal := "http://example.com/foo"

	secsipid.SetURLFileCacheOptions(workDir, 3600)
	defer secsipid.SetURLFileCacheOptions("", 0)
	defer secsipid.SJWTLibOptSetS("CacheNameMode", "plain")

	secsipid.SJWTLibOptSetS("CacheNameMode", "plain")
	expect(secsipid.SJWTGetURLCacheFilePath(urlVal)).ToBe(filepath.Join(workDir, "http_example.com_foo"))

	secsipid.SJWTLibOptSetS("CacheNameMode", "sha256")
	hashVal := sha256.Sum256([]byte(urlVal))
	expect(secsipid.SJWTGetURLCacheFilePath(urlVal)).ToBe(filepath.Join(workDir, "url_"+hex.EncodeToString(hashVal[:])))
}

func TestGetURLContentCreatesCacheDirectoryAndWritesHashedFile(t *testing.T) {
	expect := expectate.Expect(t)
	cacheDir := filepath.Join(t.TempDir(), "nested", "cache")

	secsipid.SetURLFileCacheOptions(cacheDir, 3600)
	secsipid.SJWTLibOptSetS("CacheNameMode", "sha256")
	defer secsipid.SetURLFileCacheOptions("", 0)
	defer secsipid.SJWTLibOptSetS("CacheNameMode", "plain")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from the server!"))
	})
	stopTestServer := startTestServer(handler)
	defer stopTestServer()

	content, errCode, err := secsipid.SJWTGetURLContent("http://localhost:5555/foo", 10)
	expect(content).ToEqual([]byte("Hello from the server!"))
	expect(errCode).ToBe(secsipid.SJWTRetOK)
	expect(err).ToBe(error(nil))

	cacheFilePath := secsipid.SJWTGetURLCacheFilePath("http://localhost:5555/foo")
	_, statErr := os.Stat(cacheFilePath)
	expect(statErr).ToBe(error(nil))
}

func TestGetURLContentBlocksPrivateAddressesWhenEnabled(t *testing.T) {
	secsipid.SetURLFileCacheOptions("", 0)
	secsipid.SJWTLibOptSetN("DenyPrivateX5U", 1)
	defer secsipid.SJWTLibOptSetN("DenyPrivateX5U", 0)

	urls := []string{
		"http://127.0.0.1:1/cert.pem",
		"http://10.0.0.1/cert.pem",
		"http://172.16.0.1/cert.pem",
		"http://192.168.0.1/cert.pem",
		"http://100.64.0.1/cert.pem",
		"http://169.254.1.1/cert.pem",
		"http://224.0.0.1/cert.pem",
		"http://0.0.0.0/cert.pem",
		"http://[::1]/cert.pem",
		"http://[fc00::1]/cert.pem",
		"http://[fe80::1]/cert.pem",
	}

	for _, urlVal := range urls {
		t.Run(urlVal, func(t *testing.T) {
			content, errCode, err := secsipid.SJWTGetURLContent(urlVal, 10)
			if content != nil {
				t.Fatalf("expected no content, got %q", content)
			}
			if errCode != secsipid.SJWTRetErrHTTPGet {
				t.Fatalf("expected HTTP get error code, got %d", errCode)
			}
			if err == nil || !strings.Contains(err.Error(), "blocked non-public address") {
				t.Fatalf("expected blocked private address error, got %v", err)
			}
		})
	}
}

func startTestServer(handler http.Handler) (shutdown func()) {
	server := http.Server{
		Addr:    "127.0.0.1:5555",
		Handler: handler,
	}

	listener, _ := net.Listen("tcp", "localhost:5555")
	go server.Serve(listener)

	return func() {
		server.Shutdown(context.Background())
		listener.Close()
	}
}

func getTcpDialErrMsg() string {
	_, tcpDialErr := http.Get("http://localhost:5555/foo")
	return "http get failure: " + tcpDialErr.Error()
}
