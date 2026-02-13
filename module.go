package gitealimit

import (
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&GiteaIPLimit{})
	httpcaddyfile.RegisterHandlerDirective("gitea_ip_limit", parseCaddyfile)
}

// GiteaIPLimit limits anonymous requests by IP and lifts limits for trusted IPs
// that present a valid Gitea session cookie (and optionally a valid Authorization header).
type GiteaIPLimit struct {
	GiteaURL   string `json:"gitea_url,omitempty"`
	VerifyPath string `json:"verify_path,omitempty"`
	CookieName string `json:"cookie_name,omitempty"`
	// TrustAuthorization controls whether a valid Authorization header
	// (e.g. Git over HTTPS Basic auth / token) can also lift the rate limit.
	//
	// When enabled, the handler verifies the header by calling Gitea's
	// configured VerifyPath and checking for a 200 response.
	TrustAuthorization *bool `json:"trust_authorization,omitempty"`
	// VerifyCooldown reduces load on Gitea by throttling repeated failed
	// verification attempts per IP.
	VerifyCooldown *caddy.Duration `json:"verify_cooldown,omitempty"`
	Limit          int             `json:"limit,omitempty"`
	Window         caddy.Duration  `json:"window,omitempty"`
	TrustedFor     caddy.Duration  `json:"trusted_for,omitempty"`
	Timeout        caddy.Duration  `json:"timeout,omitempty"`

	client *http.Client
	logger *zap.Logger

	mu           sync.Mutex
	anonymousIPs map[string]*anonWindow
	trustedIPs   map[string]time.Time
	nextVerifyAt map[string]time.Time
	lastCleanup  time.Time
}

type anonWindow struct {
	windowStart time.Time
	count       int
}

var (
	_ caddy.Provisioner           = (*GiteaIPLimit)(nil)
	_ caddy.Validator             = (*GiteaIPLimit)(nil)
	_ caddyfile.Unmarshaler       = (*GiteaIPLimit)(nil)
	_ caddyhttp.MiddlewareHandler = (*GiteaIPLimit)(nil)
)
