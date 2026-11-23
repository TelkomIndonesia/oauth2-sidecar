// Package validator authenticates each caller with a dedicated GitLab OAuth application.
package validator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const Header = "X-Sidecar-Authorization"

// New constructs a forwarder for one backend. Application Authorization headers pass through.
func New(issuer, clientID, upstream string, allowed []string, log *slog.Logger) (http.Handler, error) {
	idp, err := url.Parse(issuer)
	if err != nil || idp.Scheme != "https" || idp.Hostname() == "" || idp.User != nil || idp.RawQuery != "" || idp.Fragment != "" {
		return nil, errors.New("a GitLab HTTPS issuer URL is required")
	}
	target, err := url.Parse(upstream)
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Hostname() == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, errors.New("an absolute HTTP(S) upstream URL is required")
	}
	if clientID == "" || len(allowed) == 0 {
		return nil, errors.New("a dedicated GitLab client ID and allowed user IDs are required")
	}
	users := make(map[string]bool, len(allowed))
	for _, sub := range allowed {
		id, err := strconv.ParseInt(sub, 10, 64)
		if err != nil || id <= 0 || sub != strconv.FormatInt(id, 10) {
			return nil, fmt.Errorf("invalid GitLab user ID %q", sub)
		}
		users[sub] = true
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	proxy := &httputil.ReverseProxy{Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(target)
		p.SetXForwarded()
		p.Out.Header.Del(Header)
		p.Out.Trailer.Del(Header)
	}}
	infoURL := idp.JoinPath("oauth/token/info")
	userURL := idp.JoinPath("oauth/userinfo")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := requestToken(r)
		if bearer == "" {
			http.Error(w, "personal OAuth access token required", http.StatusUnauthorized)
			return
		}
		var info struct {
			UserID      int64    `json:"resource_owner_id"`
			Scope       []string `json:"scope"`
			ExpiresIn   *int64   `json:"expires_in"`
			Application struct {
				UID string `json:"uid"`
			} `json:"application"`
		}
		status := lookup(r.Context(), client, infoURL, bearer, &info)
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}
		if info.UserID <= 0 || (info.ExpiresIn != nil && *info.ExpiresIn <= 0) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		sub := strconv.FormatInt(info.UserID, 10)
		if info.Application.UID != clientID || !slices.Contains(info.Scope, "openid") || !users[sub] {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		var user struct {
			Subject  string `json:"sub"`
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		status = lookup(r.Context(), client, userURL, bearer, &user)
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}
		if user.Subject != sub {
			http.Error(w, "inconsistent token identity", http.StatusUnauthorized)
			return
		}
		attrs := []slog.Attr{slog.String("oidc_issuer", issuer), slog.String("oidc_sub", sub), slog.String("method", r.Method)}
		if user.Verified && user.Email != "" {
			attrs = append(attrs, slog.String("gitlab_email", user.Email))
		}
		log.LogAttrs(r.Context(), slog.LevelInfo, "authorized request", attrs...)
		proxy.ServeHTTP(w, r)
	}), nil
}

func requestToken(r *http.Request) string {
	values := r.Header.Values(Header)
	if len(values) != 1 {
		return ""
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.ContainsAny(token, " ,\t\r\n") {
		return ""
	}
	return token
}

func lookup(ctx context.Context, client *http.Client, endpoint *url.URL, bearer string, dest any) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return http.StatusBadGateway
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return http.StatusBadGateway
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return resp.StatusCode
	case http.StatusOK:
		const limit = 1 << 20
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err == nil && len(body) <= limit && json.Unmarshal(body, dest) == nil {
			return http.StatusOK
		}
	}
	return http.StatusBadGateway
}
