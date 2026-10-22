package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asipto/secsipidx/secsipid"
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

func TestRegisterFlagsDeniesPrivateCertificateURLsExplicitly(t *testing.T) {
	opts := cliops
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fs, &opts)

	if err := fs.Parse([]string{"-deny-private-x5u"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if !opts.denyprivateX5U {
		t.Fatalf("expected deny-private-x5u to be true")
	}
}

func TestRegisterFlagsSetsMaximumURLContentSize(t *testing.T) {
	opts := cliops
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fs, &opts)

	if err := fs.Parse([]string{"-max-url-content-bytes", "2048"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if opts.maxURLContentBytes != 2048 {
		t.Fatalf("expected max URL content size 2048, got %d", opts.maxURLContentBytes)
	}
}

func TestRegisterFlagsSetsRedisCacheOptions(t *testing.T) {
	opts := cliops
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fs, &opts)

	err := fs.Parse([]string{
		"-cache-backend", "redis",
		"-cache-expire", "900",
		"-redis-url", "rediss://user:password@example.com:6380/2",
		"-redis-key-prefix", "tenant-a:cert:",
		"-redis-timeout", "5",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if opts.cachebackend != "redis" || opts.cacheexpire != 900 ||
		opts.redisurl != "rediss://user:password@example.com:6380/2" ||
		opts.rediskeyprefix != "tenant-a:cert:" || opts.redistimeout != 5 {
		t.Fatalf("unexpected Redis CLI options: %+v", opts)
	}
}

func restoreMainCacheOptions(options secsipid.SJWTOptions) {
	secsipid.SJWTLibOptSetS("CacheBackend", "none")
	secsipid.SJWTLibOptSetS("CacheDirPath", options.CacheDirPath)
	secsipid.SJWTLibOptSetN("CacheExpires", options.CacheExpire)
	secsipid.SJWTLibOptSetS("CacheNameMode", options.CacheNameMode)
	secsipid.SJWTLibOptSetS("RedisURL", options.RedisURL)
	secsipid.SJWTLibOptSetS("RedisKeyPrefix", options.RedisKeyPrefix)
	secsipid.SJWTLibOptSetN("RedisTimeout", options.RedisTimeout)
	secsipid.SJWTLibOptSetS("CacheBackend", options.CacheBackend)
}

func TestConfigureCache(t *testing.T) {
	t.Run("configures Redis", func(t *testing.T) {
		original := secsipid.DefaultSJWTOptions()
		defer restoreMainCacheOptions(original)

		opts := cliops
		opts.cachebackend = "redis"
		opts.cacheexpire = 900
		opts.redisurl = "redis://localhost:6379/2"
		opts.rediskeyprefix = "tenant-a:cert:"
		opts.redistimeout = 5
		if err := configureCache(opts); err != nil {
			t.Fatalf("configure Redis cache: %v", err)
		}

		configured := secsipid.DefaultSJWTOptions()
		if configured.CacheBackend != "redis" || configured.CacheExpire != 900 ||
			configured.RedisURL != opts.redisurl || configured.RedisKeyPrefix != opts.rediskeyprefix ||
			configured.RedisTimeout != 5 {
			t.Fatalf("unexpected configured Redis options: %+v", configured)
		}
	})

	t.Run("preserves legacy file activation", func(t *testing.T) {
		original := secsipid.DefaultSJWTOptions()
		defer restoreMainCacheOptions(original)

		opts := cliops
		opts.cachebackend = ""
		opts.cachedir = t.TempDir()
		opts.cachefilemode = "sha256"
		if err := configureCache(opts); err != nil {
			t.Fatalf("configure file cache: %v", err)
		}

		configured := secsipid.DefaultSJWTOptions()
		if configured.CacheBackend != "" || configured.CacheDirPath != opts.cachedir ||
			configured.CacheNameMode != "sha256" {
			t.Fatalf("unexpected configured file options: %+v", configured)
		}
	})

	testCases := []struct {
		name        string
		configure   func(*CLIOptions)
		errorSubstr string
	}{
		{
			name: "invalid backend",
			configure: func(opts *CLIOptions) {
				opts.cachebackend = "invalid"
			},
			errorSubstr: "invalid cache backend",
		},
		{
			name: "missing Redis URL",
			configure: func(opts *CLIOptions) {
				opts.cachebackend = "redis"
				opts.redisurl = ""
			},
			errorSubstr: "Redis URL is required",
		},
		{
			name: "Redis and file conflict",
			configure: func(opts *CLIOptions) {
				opts.cachebackend = "redis"
				opts.redisurl = "redis://localhost:6379"
				opts.cachedir = t.TempDir()
			},
			errorSubstr: "cache directory cannot be used",
		},
		{
			name: "malformed Redis URL",
			configure: func(opts *CLIOptions) {
				opts.cachebackend = "redis"
				opts.redisurl = "://invalid"
			},
			errorSubstr: "invalid Redis URL",
		},
		{
			name: "invalid Redis timeout",
			configure: func(opts *CLIOptions) {
				opts.redistimeout = 0
			},
			errorSubstr: "invalid Redis timeout",
		},
		{
			name: "non-Redis backend with Redis URL",
			configure: func(opts *CLIOptions) {
				opts.cachebackend = "file"
				opts.redisurl = "redis://localhost:6379"
			},
			errorSubstr: "Redis URL requires",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			original := secsipid.DefaultSJWTOptions()
			defer restoreMainCacheOptions(original)

			opts := cliops
			testCase.configure(&opts)
			err := configureCache(opts)
			if err == nil || !strings.Contains(err.Error(), testCase.errorSubstr) {
				t.Fatalf("expected error containing %q, got %v", testCase.errorSubstr, err)
			}
		})
	}
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

func TestHTTPHandleV1CheckRejectsNonzeroResultWithoutError(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicKeyPath := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(publicKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER}), 0600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	identity, ret, err := secsipid.SJWTGetIdentityPrvKey(
		"12025550100", "12025550101", "A", "", "https://example.com/cert.pem", privateKeyPEM)
	if err != nil || ret != secsipid.SJWTRetOK {
		t.Fatalf("build identity: ret=%d err=%v", ret, err)
	}
	identityToken := strings.SplitN(identity, ";", 2)[0]

	previousOptions := cliops
	defer func() { cliops = previousOptions }()
	cliops.fpubkey = publicKeyPath
	cliops.expire = 3600

	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(identityToken))
	rec := httptest.NewRecorder()
	httpHandleV1Check(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "FAILED" {
		t.Fatalf("expected failed response, got %q", rec.Body.String())
	}
}
