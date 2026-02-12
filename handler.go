package gitealimit

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func (m *GiteaIPLimit) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	now := time.Now()
	ip := remoteIP(r)
	if ip == "" {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("unable to determine client IP"))
	}

	m.mu.Lock()
	m.cleanupLocked(now)
	if expireAt, ok := m.trustedIPs[ip]; ok && now.Before(expireAt) {
		m.mu.Unlock()
		return next.ServeHTTP(w, r)
	}
	m.mu.Unlock()

	cookie, err := r.Cookie(m.CookieName)
	if err == nil && strings.TrimSpace(cookie.Value) != "" {
		valid, verifyErr := m.verifyGiteaCookie(r.Context(), cookie)
		if verifyErr != nil {
			m.logger.Warn("gitea cookie verification failed", zap.String("ip", ip), zap.Error(verifyErr))
		}
		if valid {
			m.mu.Lock()
			m.trustedIPs[ip] = now.Add(time.Duration(m.TrustedFor))
			delete(m.anonymousIPs, ip)
			m.mu.Unlock()
			return next.ServeHTTP(w, r)
		}
	}

	allowed, retryAfter := m.allowAnonymous(ip, now)
	if !allowed {
		if retryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "rate limit exceeded for anonymous IP\n")
		return nil
	}

	return next.ServeHTTP(w, r)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	if ip := net.ParseIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}
	return ""
}
