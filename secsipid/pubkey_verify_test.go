package secsipid_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path"
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
		expect(errMsg).ToBe(testCase.expectedErrMsg)
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
			expectedErrMsg:  "x509: certificate signed by unknown authority",
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
			expectedErrMsg:  "no CA file",
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
