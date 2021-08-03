package secsipid_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/asipto/secsipidx/secsipid"
	"github.com/gomagedon/expectate"
)

type GetURLValueTest struct {
	urlVal     string
	timeoutVal int

	expectedContent []byte
	expectedErrCode int
	expectedErrMsg  string
}

func TestGetURLContent(t *testing.T) {
	os.Remove("http_example.com_foo")
	os.Remove("http_localhost:5555_foo")

	tcpDialErrMsg := getTcpDialErrMsg()

	runTest := func(t *testing.T, testCase GetURLValueTest) {
		expect := expectate.Expect(t) // testing utility

		content, errCode, err := secsipid.SJWTGetURLContent(
			testCase.urlVal, testCase.timeoutVal)

		expect(content).ToEqual(testCase.expectedContent)
		expect(errCode).ToBe(testCase.expectedErrCode)
		expect(getMsgFromErr(err)).ToBe(testCase.expectedErrMsg)
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
		secsipid.SetURLFileCacheOptions(workDir, int(time.Hour))
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
		secsipid.SetURLFileCacheOptions(workDir, int(time.Hour))
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
			time.Sleep(time.Second * 2) // time out
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
			// This will cause the response body to be invalid and return an error when read
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
		secsipid.SetURLFileCacheOptions(workDir, int(time.Hour))

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
	// Can't hardcode this error message because localhost resolves differently
	// on different machines (like a GitHub actions container)
	_, tcpDialErr := http.Get("http://localhost:5555/foo")
	return "http get failure: " + tcpDialErr.Error()
}
