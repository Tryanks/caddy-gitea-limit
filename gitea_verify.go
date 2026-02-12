package gitealimit

import (
	"context"
	"io"
	"net/http"
	"strings"
)

func (m *GiteaIPLimit) verifyGiteaCookie(ctx context.Context, cookie *http.Cookie) (bool, error) {
	base := strings.TrimRight(m.GiteaURL, "/")
	path := m.VerifyPath
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return false, err
	}
	req.AddCookie(&http.Cookie{
		Name:  m.CookieName,
		Value: cookie.Value,
	})

	resp, err := m.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode == http.StatusOK, nil
}
