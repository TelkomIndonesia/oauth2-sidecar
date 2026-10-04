package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type testToken string

func (t testToken) AccessToken(context.Context) (string, error) { return string(t), nil }
func TestProxyReplacesAuthorizationAndForwardsPath(t *testing.T) {
	got := make(chan *http.Request, 1)
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer u.Close()
	p, e := New(u.URL, testToken("new"), slog.Default(), map[string]string{"service.local": "api.internal"}, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo?q=1", nil)
	r.Host = "service.local"
	r.Header.Set("Authorization", "Bearer old")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	x := <-got
	if x.URL.Path != "/v1/foo" || x.URL.RawQuery != "q=1" || x.Header.Get("Authorization") != "Bearer new" || x.Host != "api.internal" {
		t.Fatalf("bad upstream request: %s %s %q host=%q", x.URL.Path, x.URL.RawQuery, x.Header.Get("Authorization"), x.Host)
	}
}
func TestProxyHostRouteTargetsMappedOrigin(t *testing.T) {
	defaultHit := make(chan *http.Request, 1)
	def := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defaultHit <- r.Clone(r.Context()); w.WriteHeader(200) }))
	defer def.Close()
	got := make(chan *http.Request, 1)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer other.Close()
	target, e := url.Parse(other.URL + "/base")
	if e != nil {
		t.Fatal(e)
	}
	p, e := New(def.URL, testToken("new"), slog.Default(), nil, map[string]*url.URL{"app.local": target}, false)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo?q=1", nil)
	r.Host = "app.local"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	x := <-got
	if x.URL.Path != "/base/v1/foo" || x.URL.RawQuery != "q=1" || x.Host != target.Host {
		t.Fatalf("bad routed request: path=%s q=%s host=%q", x.URL.Path, x.URL.RawQuery, x.Host)
	}
	select {
	case <-defaultHit:
		t.Fatal("default upstream should not receive routed request")
	default:
	}
}

func TestProxyRouteOnlyWithoutUpstream(t *testing.T) {
	got := make(chan *http.Request, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer up.Close()
	target, e := url.Parse(up.URL + "/base")
	if e != nil {
		t.Fatal(e)
	}
	p, e := New("", testToken("new"), slog.Default(), nil, map[string]*url.URL{"app.local": target}, false)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "app.local"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	x := <-got
	if x.URL.Path != "/base/v1/foo" || x.Host != target.Host {
		t.Fatalf("bad routed request: path=%s host=%q", x.URL.Path, x.Host)
	}
}

func TestProxyMappingOnlyWithoutUpstream(t *testing.T) {
	got := make(chan *http.Request, 1)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer up.Close()
	dest := strings.TrimPrefix(up.URL, "https://")
	p, e := New("", testToken("new"), slog.Default(), map[string]string{"app.local": dest}, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "app.local"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	x := <-got
	if x.URL.Path != "/v1/foo" || x.Host != dest || x.Header.Get("Authorization") != "Bearer new" {
		t.Fatalf("bad mapped request: path=%s host=%q auth=%q", x.URL.Path, x.Host, x.Header.Get("Authorization"))
	}
}

func TestProxyMappingWildcardWithoutUpstream(t *testing.T) {
	got := make(chan *http.Request, 1)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer up.Close()
	dest := strings.TrimPrefix(up.URL, "https://")
	p, e := New("", testToken("new"), slog.Default(), map[string]string{"*": dest}, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "unmapped.local"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	x := <-got
	if x.Host != dest {
		t.Fatalf("bad wildcard host %q", x.Host)
	}
}

func TestProxyHostPortStrippedForMatching(t *testing.T) {
	got := make(chan *http.Request, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer up.Close()
	target, e := url.Parse(up.URL + "/base")
	if e != nil {
		t.Fatal(e)
	}
	p, e := New("", testToken("new"), slog.Default(), nil, map[string]*url.URL{"oss.localhost": target}, false)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "oss.localhost:18080"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("route with port status %d", w.Code)
	}
	if x := <-got; x.URL.Path != "/base/v1/foo" || x.Host != target.Host {
		t.Fatalf("bad routed request: path=%s host=%q", x.URL.Path, x.Host)
	}

	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer tls.Close()
	dest := strings.TrimPrefix(tls.URL, "https://")
	mp, e := New("", testToken("new"), slog.Default(), map[string]string{"oss.localhost": dest}, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	r = httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "oss.localhost:18080"
	w = httptest.NewRecorder()
	mp.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("mapping with port status %d", w.Code)
	}
	if x := <-got; x.Host != dest {
		t.Fatalf("bad mapped host %q", x.Host)
	}
}

func TestProxyUnmatchedHostRejected(t *testing.T) {
	p, e := New("", testToken("new"), slog.Default(), map[string]string{"app.local": "api.internal"}, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "other.local"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d", w.Code)
	}
}

func TestProxyRoutingRejectsInvalidUpstream(t *testing.T) {
	for _, raw := range []string{"not-a-url", "https://", "://bad", "relative/path"} {
		if _, e := New(raw, testToken("new"), slog.Default(), nil, nil, false); e == nil {
			t.Fatalf("expected invalid upstream error for %q", raw)
		}
	}
}

func TestProxyMixedRouteAndMappingFallback(t *testing.T) {
	routed := make(chan *http.Request, 1)
	routeUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { routed <- r.Clone(r.Context()); w.WriteHeader(201) }))
	defer routeUp.Close()
	mapped := make(chan *http.Request, 1)
	mapUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mapped <- r.Clone(r.Context()); w.WriteHeader(202) }))
	defer mapUp.Close()

	route, e := url.Parse(routeUp.URL + "/base")
	if e != nil {
		t.Fatal(e)
	}
	dest := strings.TrimPrefix(mapUp.URL, "https://")
	p, e := New("", testToken("new"), slog.Default(), map[string]string{"fallback.local": dest}, map[string]*url.URL{"app.local": route}, true)
	if e != nil {
		t.Fatal(e)
	}

	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "app.local"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("route status %d", w.Code)
	}
	if x := <-routed; x.URL.Path != "/base/v1/foo" {
		t.Fatalf("bad routed path %q", x.URL.Path)
	}
	select {
	case <-mapped:
		t.Fatal("mapping upstream should not receive routed request")
	default:
	}

	r = httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "fallback.local"
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 202 {
		t.Fatalf("mapping fallback status %d", w.Code)
	}
	if x := <-mapped; x.URL.Path != "/v1/foo" || x.Host != dest {
		t.Fatalf("bad mapping fallback: path=%q host=%q", x.URL.Path, x.Host)
	}
}

func TestProxyInsecurePreservesClonedTLSConfig(t *testing.T) {
	original := http.DefaultTransport
	clone := original.(*http.Transport).Clone()
	clone.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	http.DefaultTransport = clone
	t.Cleanup(func() { http.DefaultTransport = original; clone.CloseIdleConnections() })

	p, e := New("", testToken("new"), slog.Default(), nil, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	got := p.rp.Transport.(transport).base.(*http.Transport).TLSClientConfig
	if got == nil || !got.InsecureSkipVerify || got.MinVersion != tls.VersionTLS12 {
		t.Fatalf("cloned TLS config not preserved: %+v", got)
	}
	if clone.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("global default transport was mutated")
	}
}

func TestProxyTLSVerification(t *testing.T) {
	got := make(chan struct{}, 1)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- struct{}{}; w.WriteHeader(204) }))
	defer up.Close()
	dest := strings.TrimPrefix(up.URL, "https://")
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "app.local"

	strict, e := New("", testToken("new"), slog.Default(), map[string]string{"app.local": dest}, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	strict.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected TLS verification failure, got status %d", w.Code)
	}

	relaxed, e := New("", testToken("new"), slog.Default(), map[string]string{"app.local": dest}, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	w = httptest.NewRecorder()
	relaxed.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("expected opted-in success, got status %d", w.Code)
	}
	select {
	case <-got:
	default:
		t.Fatal("upstream did not receive requested after skipping verification")
	}
}
