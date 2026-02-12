package gitealimit

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func (*GiteaIPLimit) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gitea_ip_limit",
		New: func() caddy.Module { return new(GiteaIPLimit) },
	}
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m GiteaIPLimit
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

func (m *GiteaIPLimit) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.setDefaults()

	m.client = &http.Client{
		Timeout: time.Duration(m.Timeout),
	}
	m.anonymousIPs = make(map[string]*anonWindow)
	m.trustedIPs = make(map[string]time.Time)
	m.lastCleanup = time.Now()

	return nil
}

func (m *GiteaIPLimit) Validate() error {
	if m.GiteaURL == "" {
		return fmt.Errorf("gitea_url is required")
	}
	if _, err := url.ParseRequestURI(m.GiteaURL); err != nil {
		return fmt.Errorf("invalid gitea_url: %w", err)
	}
	if m.Limit <= 0 {
		return fmt.Errorf("limit must be > 0")
	}
	if time.Duration(m.Window) <= 0 {
		return fmt.Errorf("window must be > 0")
	}
	if time.Duration(m.TrustedFor) <= 0 {
		return fmt.Errorf("trusted_for must be > 0")
	}
	if time.Duration(m.Timeout) <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	return nil
}

func (m *GiteaIPLimit) setDefaults() {
	if m.VerifyPath == "" {
		m.VerifyPath = "/api/v1/user"
	}
	if m.CookieName == "" {
		m.CookieName = "i_like_gitea"
	}
	if m.Limit == 0 {
		m.Limit = 100
	}
	if m.Window == 0 {
		m.Window = caddy.Duration(5 * time.Minute)
	}
	if m.TrustedFor == 0 {
		m.TrustedFor = caddy.Duration(6 * time.Hour)
	}
	if m.Timeout == 0 {
		m.Timeout = caddy.Duration(3 * time.Second)
	}
}
