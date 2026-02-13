package gitealimit

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type fakeTransport struct {
	verify func(*http.Request) int
	calls  int32
}

func (t *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls++
	status := t.verify(r)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString("")),
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

func newTestLimiter(tr *fakeTransport) *GiteaIPLimit {
	trustAuth := true
	cooldown := caddy.Duration(10 * time.Second)

	m := &GiteaIPLimit{
		GiteaURL:           "http://gitea.local",
		VerifyPath:         "/api/v1/user",
		CookieName:         "i_like_gitea",
		TrustAuthorization: &trustAuth,
		VerifyCooldown:     &cooldown,
		Limit:              100,
		Window:             caddy.Duration(5 * time.Minute),
		TrustedFor:         caddy.Duration(6 * time.Hour),
		Timeout:            caddy.Duration(2 * time.Second),
		client:             &http.Client{Timeout: 2 * time.Second, Transport: tr},
		logger:             zap.NewNop(),
		anonymousIPs:       make(map[string]*anonWindow),
		trustedIPs:         make(map[string]time.Time),
		nextVerifyAt:       make(map[string]time.Time),
		lastCleanup:        time.Now(),
	}
	return m
}

func okNext(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
	return nil
}

func TestCookieCanTrustIP(t *testing.T) {
	ft := &fakeTransport{
		verify: func(r *http.Request) int {
			if r.URL.Path != "/api/v1/user" {
				return http.StatusNotFound
			}
			c, err := r.Cookie("i_like_gitea")
			if err == nil && c.Value == "good" {
				return http.StatusOK
			}
			return http.StatusUnauthorized
		},
	}
	m := newTestLimiter(ft)

	// First request provides the cookie and should become trusted.
	r1 := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	r1.RemoteAddr = "1.2.3.4:1234"
	r1.AddCookie(&http.Cookie{Name: "i_like_gitea", Value: "good"})
	w1 := httptest.NewRecorder()
	if err := m.ServeHTTP(w1, r1, caddyhttp.HandlerFunc(okNext)); err != nil {
		t.Fatalf("ServeHTTP err: %v", err)
	}
	if w1.Result().StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want %d", w1.Result().StatusCode, http.StatusOK)
	}

	// Second request has no cookie, but should still be trusted.
	r2 := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	r2.RemoteAddr = "1.2.3.4:5678"
	w2 := httptest.NewRecorder()
	if err := m.ServeHTTP(w2, r2, caddyhttp.HandlerFunc(okNext)); err != nil {
		t.Fatalf("ServeHTTP err: %v", err)
	}
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want %d", w2.Result().StatusCode, http.StatusOK)
	}
}

func TestAuthorizationCanTrustIP(t *testing.T) {
	ft := &fakeTransport{
		verify: func(r *http.Request) int {
			if r.URL.Path != "/api/v1/user" {
				return http.StatusNotFound
			}
			if r.Header.Get("Authorization") == "Basic good" {
				return http.StatusOK
			}
			return http.StatusUnauthorized
		},
	}
	m := newTestLimiter(ft)

	// First request provides Authorization and should become trusted.
	r1 := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	r1.RemoteAddr = "1.2.3.5:1234"
	r1.Header.Set("Authorization", "Basic good")
	w1 := httptest.NewRecorder()
	if err := m.ServeHTTP(w1, r1, caddyhttp.HandlerFunc(okNext)); err != nil {
		t.Fatalf("ServeHTTP err: %v", err)
	}
	if w1.Result().StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want %d", w1.Result().StatusCode, http.StatusOK)
	}

	// Second request has no auth, but should still be trusted.
	r2 := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	r2.RemoteAddr = "1.2.3.5:5678"
	w2 := httptest.NewRecorder()
	if err := m.ServeHTTP(w2, r2, caddyhttp.HandlerFunc(okNext)); err != nil {
		t.Fatalf("ServeHTTP err: %v", err)
	}
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want %d", w2.Result().StatusCode, http.StatusOK)
	}
}

func TestVerifyCooldownThrottlesRepeatedFailures(t *testing.T) {
	ft := &fakeTransport{
		verify: func(r *http.Request) int {
			if r.URL.Path == "/api/v1/user" {
				return http.StatusUnauthorized
			}
			return http.StatusNotFound
		},
	}
	m := newTestLimiter(ft)

	r1 := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	r1.RemoteAddr = "1.2.3.6:1234"
	r1.Header.Set("Authorization", "Basic bad")
	w1 := httptest.NewRecorder()
	if err := m.ServeHTTP(w1, r1, caddyhttp.HandlerFunc(okNext)); err != nil {
		t.Fatalf("ServeHTTP err: %v", err)
	}

	r2 := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	r2.RemoteAddr = "1.2.3.6:5678"
	r2.Header.Set("Authorization", "Basic bad")
	w2 := httptest.NewRecorder()
	if err := m.ServeHTTP(w2, r2, caddyhttp.HandlerFunc(okNext)); err != nil {
		t.Fatalf("ServeHTTP err: %v", err)
	}

	if got := ft.calls; got != 1 {
		t.Fatalf("verifyCalls=%d, want 1 (second request should be throttled by cooldown)", got)
	}
}
