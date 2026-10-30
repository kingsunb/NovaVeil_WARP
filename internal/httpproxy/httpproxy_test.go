package httpproxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testProxyError struct {
	status int
	retry  time.Duration
}

func (e testProxyError) Error() string { return "test proxy error" }

func (e testProxyError) ProxyStatus() (int, time.Duration) {
	return e.status, e.retry
}

func TestProxyUsername(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"basic", "Basic " + base64.StdEncoding.EncodeToString([]byte("warp-3:secret")), "warp-3"},
		{"lowercase", "basic " + base64.StdEncoding.EncodeToString([]byte("warp-0:")), "warp-0"},
		{"no password", "Basic " + base64.StdEncoding.EncodeToString([]byte("warp-1")), "warp-1"},
		{"missing", "", ""},
		{"not basic", "Bearer token", ""},
		{"bad base64", "Basic !!!", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
			if tc.header != "" {
				req.Header.Set("Proxy-Authorization", tc.header)
			}
			if got := proxyUsername(req); got != tc.want {
				t.Fatalf("proxyUsername = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteDialErrorAuth(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDialError(rec, testProxyError{status: http.StatusProxyAuthRequired})
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", rec.Code)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); got != `Basic realm="warp-slots"` {
		t.Fatalf("Proxy-Authenticate = %q", got)
	}
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Fatalf("Retry-After = %q, want empty", got)
	}
}

func TestWriteDialErrorUnavailable(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDialError(rec, testProxyError{status: http.StatusServiceUnavailable, retry: 1500 * time.Millisecond})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
}

func TestProxyUsernameContext(t *testing.T) {
	ctx := withProxyUsername(context.Background(), "warp-4")
	if got := proxyUsernameFromContext(ctx); got != "warp-4" {
		t.Fatalf("context username = %q", got)
	}
	if got := proxyUsernameFromContext(context.Background()); got != "" {
		t.Fatalf("empty context username = %q", got)
	}
}
