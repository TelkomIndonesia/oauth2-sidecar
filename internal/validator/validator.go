// Package validator authenticates each caller with a dedicated GitLab OAuth application.
package validator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Header = "X-Sidecar-Authorization"

const (
	validationTTL   = 30 * time.Second
	maxCachedTokens = 1024
)

type identity struct {
	sub, email string
	validUntil time.Time
}

type auditContextKey struct{}
type auditIdentity struct{ sub, requestID string }

type handler struct {
	trustedProxies   []netip.Prefix
	issuer, clientID string
	users            map[string]bool
	infoURL, userURL *url.URL
	client           *http.Client
	proxy            http.Handler
	log              *slog.Logger
	now              func() time.Time

	lookups lookupBudget
	mu      sync.Mutex
	cache   map[[sha256.Size]byte]identity
}

// New constructs a forwarder for one backend. Application Authorization headers pass through.
func New(issuer, clientID, upstream string, allowed []string, log *slog.Logger, trustedProxies ...netip.Prefix) (http.Handler, error) {
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
	proxy := &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			p.SetXForwarded()
			p.Out.Header.Del(Header)
			p.Out.Trailer.Del(Header)
			audit := p.In.Context().Value(auditContextKey{}).(auditIdentity)
			p.Out.Header.Set("X-Forwarded-User", audit.sub)
			p.Out.Header.Set("X-Request-ID", audit.requestID)
			p.Out.Trailer.Del("X-Forwarded-User")
			p.Out.Trailer.Del("X-Request-ID")
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request == nil {
				return nil
			}
			requestID := resp.Request.Header.Get("X-Request-ID")
			if backendID := resp.Header.Get("X-Request-ID"); backendID != "" && backendID != requestID {
				log.InfoContext(resp.Request.Context(), "backend request ID", "request_id", requestID, "backend_request_id", backendID)
			}
			return nil
		},
	}
	return &handler{
		issuer: issuer, clientID: clientID, users: users, trustedProxies: trustedProxies,
		infoURL: idp.JoinPath("oauth/token/info"), userURL: idp.JoinPath("oauth/userinfo"),
		client: client, proxy: proxy, log: log, now: time.Now,
		cache: make(map[[sha256.Size]byte]identity),
	}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bearer := requestToken(r)
	if bearer == "" {
		http.Error(w, "personal OAuth access token required", http.StatusUnauthorized)
		return
	}
	key := sha256.Sum256([]byte(bearer))
	started := h.now()
	h.mu.Lock()
	id, ok := h.cache[key]
	h.mu.Unlock()
	if !ok || !started.Before(id.validUntil) {
		refund, retry := h.lookups.reserve(lookupPeer(r, h.trustedProxies), started)
		if refund == nil {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			http.Error(w, "too many validation attempts", http.StatusTooManyRequests)
			return
		}
		id, ok = h.verify(w, r, bearer, started)
		if !ok {
			return
		}
		refund()
		if !id.validUntil.IsZero() {
			h.remember(key, id)
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		http.Error(w, "could not assign request ID", http.StatusInternalServerError)
		return
	}
	audit := auditIdentity{sub: id.sub, requestID: hex.EncodeToString(nonce[:])}
	r = r.WithContext(context.WithValue(r.Context(), auditContextKey{}, audit))
	attrs := []slog.Attr{
		slog.String("request_id", audit.requestID),
		slog.String("oidc_issuer", h.issuer),
		slog.String("oidc_sub", id.sub),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	if id.email != "" {
		attrs = append(attrs, slog.String("gitlab_email", id.email))
	}
	h.log.LogAttrs(r.Context(), slog.LevelInfo, "authorized request", attrs...)
	h.proxy.ServeHTTP(w, r)
}

func (h *handler) verify(w http.ResponseWriter, r *http.Request, bearer string, started time.Time) (identity, bool) {
	var info struct {
		UserID      int64    `json:"resource_owner_id"`
		Scope       []string `json:"scope"`
		ExpiresIn   *int64   `json:"expires_in"`
		Application struct {
			UID string `json:"uid"`
		} `json:"application"`
	}
	status := lookup(r.Context(), h.client, h.infoURL, bearer, &info)
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return identity{}, false
	}
	if info.UserID <= 0 || (info.ExpiresIn != nil && *info.ExpiresIn <= 0) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return identity{}, false
	}
	sub := strconv.FormatInt(info.UserID, 10)
	if info.Application.UID != h.clientID || !slices.Contains(info.Scope, "openid") || !h.users[sub] {
		http.Error(w, "access denied", http.StatusForbidden)
		return identity{}, false
	}
	var user struct {
		Subject  string `json:"sub"`
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	status = lookup(r.Context(), h.client, h.userURL, bearer, &user)
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return identity{}, false
	}
	if user.Subject != sub {
		http.Error(w, "inconsistent token identity", http.StatusUnauthorized)
		return identity{}, false
	}
	id := identity{sub: sub}
	if user.Verified {
		id.email = user.Email
	}
	if info.ExpiresIn != nil {
		// Start the lifetime before introspection so network time counts against it.
		remaining := *info.ExpiresIn
		if int64(h.now().Sub(started)/time.Second) >= remaining {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return identity{}, false
		}
		seconds := min(remaining, int64(validationTTL/time.Second))
		id.validUntil = started.Add(time.Duration(seconds) * time.Second)
	}
	return id, true
}

func (h *handler) remember(key [sha256.Size]byte, id identity) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, present := h.cache[key]; !present && len(h.cache) >= maxCachedTokens {
		// Any entry can be evicted safely. Its next request will revalidate with GitLab.
		for evict := range h.cache {
			delete(h.cache, evict)
			break
		}
	}
	h.cache[key] = id
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
