# caddy-gitea-limit

Caddy HTTP middleware plugin:

- Anonymous IP: limited to `100` requests per `5m` (configurable)
- Logged-in IP:
  - Must have cookie `i_like_gitea` (configurable)
  - Cookie is verified against configured Gitea API
  - If valid, this IP is trusted for `6h` (configurable) with no rate limit

## Build

```bash
# Build from remote module path
xcaddy build \
  --with github.com/Tryanks/caddy-gitea-limit
```

```bash
# Local development build (inside this repository)
xcaddy build \
  --with github.com/Tryanks/caddy-gitea-limit=.
```

## Caddyfile

```caddyfile
:80 {
  route {
    gitea_ip_limit {
      gitea_url http://127.0.0.1:3000
      verify_path /api/v1/user
      cookie_name i_like_gitea
      limit 100
      window 5m
      trusted_for 6h
      timeout 3s
    }

    reverse_proxy 127.0.0.1:8080
  }
}
```

## Notes

- The plugin identifies client IP from `RemoteAddr`.
- Cookie verification sends request to `GET {gitea_url}{verify_path}` with the same cookie.
- API response `200` is treated as valid session.
- If Gitea API is unavailable, request falls back to anonymous rate limit path.
