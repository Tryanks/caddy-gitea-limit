package gitealimit

import (
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func (m *GiteaIPLimit) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "gitea_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.GiteaURL = d.Val()
			case "verify_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.VerifyPath = d.Val()
			case "cookie_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.CookieName = d.Val()
			case "limit":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid limit: %v", err)
				}
				m.Limit = n
			case "window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid window duration: %v", err)
				}
				m.Window = caddy.Duration(dur)
			case "trusted_for":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid trusted_for duration: %v", err)
				}
				m.TrustedFor = caddy.Duration(dur)
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid timeout duration: %v", err)
				}
				m.Timeout = caddy.Duration(dur)
			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	m.setDefaults()
	return nil
}
