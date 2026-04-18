package main

import (
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPServiceExitCode(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil error is success", err: nil, want: 0},
		{name: "server closed is success", err: http.ErrServerClosed, want: 0},
		{name: "other error is failure", err: errors.New("bind failed"), want: 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpServiceExitCode(tc.err); got != tc.want {
				t.Fatalf("expected exit code %d, got %d", tc.want, got)
			}
		})
	}
}

func TestRegisterFlagsParsesSignFullFlagsIndependently(t *testing.T) {
	t.Run("long flag sets signfull", func(t *testing.T) {
		opts := cliops
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		registerFlags(fs, &opts)

		if err := fs.Parse([]string{"-sign-full"}); err != nil {
			t.Fatalf("parse flags: %v", err)
		}
		if !opts.signfull {
			t.Fatalf("expected signfull to be true")
		}
		if opts.sign {
			t.Fatalf("expected sign to remain false")
		}
	})

	t.Run("short flag sets signfull", func(t *testing.T) {
		opts := cliops
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		registerFlags(fs, &opts)

		if err := fs.Parse([]string{"-S"}); err != nil {
			t.Fatalf("parse flags: %v", err)
		}
		if !opts.signfull {
			t.Fatalf("expected signfull to be true")
		}
		if opts.sign {
			t.Fatalf("expected sign to remain false")
		}
	})
}

func TestCLICommandsFailOnMissingInputFiles(t *testing.T) {
	t.Run("sign fails when header file is missing", func(t *testing.T) {
		prev := cliops
		defer func() {
			cliops = prev
		}()

		cliops = CLIOptions{
			fprvkey: "/does/not/matter.pem",
			fheader: "/definitely/missing-header.json",
		}

		if ret := secsipidxCLISign(); ret == 0 {
			t.Fatalf("expected sign command to fail for missing header file")
		}
	})

	t.Run("check fails when identity file is missing", func(t *testing.T) {
		prev := cliops
		defer func() {
			cliops = prev
		}()

		cliops = CLIOptions{
			fidentity: "/definitely/missing-identity.txt",
		}

		if ret := secsipidxCLICheck(); ret == 0 {
			t.Fatalf("expected check command to fail for missing identity file")
		}
	})
}

func TestReadHTTPRequestBodyRejectsLargePayloads(t *testing.T) {
	oversizedBody := strings.Repeat("a", maxHTTPRequestBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(oversizedBody))
	rec := httptest.NewRecorder()

	body, ok := readHTTPRequestBody(rec, req)
	if ok {
		t.Fatalf("expected oversized body to be rejected")
	}
	if body != nil {
		t.Fatalf("expected no body to be returned for oversized payload")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, rec.Code)
	}
}

func TestReadHTTPRequestBodyAllowsSmallPayloads(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader("ok"))
	rec := httptest.NewRecorder()

	body, ok := readHTTPRequestBody(rec, req)
	if !ok {
		t.Fatalf("expected small body to be accepted, got status %d", rec.Code)
	}
	if string(body) != "ok" {
		t.Fatalf("expected body %q, got %q", "ok", string(body))
	}
}
