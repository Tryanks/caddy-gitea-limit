package gitealimit

import (
	"context"
	"io"
	"net/http"
	"strings"
)

func (m *GiteaIPLimit) verifyGiteaAuthorization(ctx context.Context, authorization string) (bool, error) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return false, nil
	}

	req, err := m.newVerifyRequest(ctx)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", authorization)

	return m.doVerify(req)
}

func (m *GiteaIPLimit) verifyGiteaCookie(ctx context.Context, cookie *http.Cookie) (bool, error) {
	req, err := m.newVerifyRequest(ctx)
	if err != nil {
		return false, err
	}
	req.AddCookie(&http.Cookie{
		Name:  m.CookieName,
		Value: cookie.Value,
	})

	return m.doVerify(req)
}

func (m *GiteaIPLimit) newVerifyRequest(ctx context.Context) (*http.Request, error) {
	base := strings.TrimRight(m.GiteaURL, "/")
	path := m.VerifyPath
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
}

func (m *GiteaIPLimit) doVerify(req *http.Request) (bool, error) {
	resp, err := m.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode == http.StatusOK, nil
}
