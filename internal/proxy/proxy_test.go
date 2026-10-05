package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/TelkomIndonesia/oauth2-sidecar/internal/config"
)

type testToken string

func (t testToken) AccessToken(context.Context) (string, error) { return string(t), nil }

func route(t *testing.T, raw, ip string) map[string]config.HostRoute {
	t.Helper()
	target, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	return map[string]config.HostRoute{"app.local": {Target: target, IP: ip}}
}

func TestProxyReplacesAuthorizationAndForwardsPath(t *testing.T) {
	got := make(chan *http.Request, 1)
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer u.Close()
	p, e := New(u.URL, testToken("new"), slog.Default(), nil, false)
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
	if x.URL.Path != "/v1/foo" || x.URL.RawQuery != "q=1" || x.Header.Get("Authorization") != "Bearer new" || x.Host != u.URL[len("http://"):] {
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
	routes := route(t, other.URL+"/base", "")
	p, e := New(def.URL, testToken("new"), slog.Default(), routes, false)
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
	if x.URL.Path != "/base/v1/foo" || x.URL.RawQuery != "q=1" || x.Host != routes["app.local"].Target.Host {
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
	routes := route(t, up.URL+"/base", "")
	p, e := New("", testToken("new"), slog.Default(), routes, false)
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
	if x.URL.Path != "/base/v1/foo" || x.Host != routes["app.local"].Target.Host {
		t.Fatalf("bad routed request: path=%s host=%q", x.URL.Path, x.Host)
	}
}

func TestProxyHostPortStrippedForMatching(t *testing.T) {
	got := make(chan *http.Request, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer up.Close()
	routes := map[string]config.HostRoute{}
	target, e := url.Parse(up.URL + "/base")
	if e != nil {
		t.Fatal(e)
	}
	routes["oss.localhost"] = config.HostRoute{Target: target}
	p, e := New("", testToken("new"), slog.Default(), routes, false)
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
}

func TestProxyUnmatchedHostRejected(t *testing.T) {
	p, e := New("", testToken("new"), slog.Default(), route(t, "https://api.internal", ""), false)
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
		if _, e := New(raw, testToken("new"), slog.Default(), nil, false); e == nil {
			t.Fatalf("expected invalid upstream error for %q", raw)
		}
	}
}

func TestProxyRouteIPOverrideDialsAddress(t *testing.T) {
	got := make(chan *http.Request, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer up.Close()
	_, port, e := net.SplitHostPort(up.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	routes := route(t, "http://upstream.example:"+port, "127.0.0.1")
	p, e := New("", testToken("new"), slog.Default(), routes, false)
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
	if x := <-got; x.Host != "upstream.example:"+port {
		t.Fatalf("bad override host %q", x.Host)
	}
}

func TestProxyRouteIPOverridePreservesTLSVerification(t *testing.T) {
	got := make(chan *http.Request, 1)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer up.Close()
	_, port, e := net.SplitHostPort(up.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	routes := route(t, "https://example.com:"+port, "127.0.0.1")
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "app.local"

	strict, e := New("", testToken("new"), slog.Default(), routes, false)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	strict.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected verification to stay active over IP override, got status %d", w.Code)
	}

	relaxed, e := New("", testToken("new"), slog.Default(), routes, true)
	if e != nil {
		t.Fatal(e)
	}
	w = httptest.NewRecorder()
	relaxed.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("expected opted-in success, got status %d", w.Code)
	}
	x := <-got
	if x.Host != "example.com:"+port || x.TLS == nil || x.TLS.ServerName != "example.com" {
		t.Fatalf("hostname not preserved over IP override: host=%q sni=%v", x.Host, x.TLS)
	}
}

func TestProxyInsecurePreservesClonedTLSConfig(t *testing.T) {
	original := http.DefaultTransport
	clone := original.(*http.Transport).Clone()
	clone.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	http.DefaultTransport = clone
	t.Cleanup(func() { http.DefaultTransport = original; clone.CloseIdleConnections() })

	p, e := New("", testToken("new"), slog.Default(), nil, true)
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
	routes := route(t, up.URL, "")
	r := httptest.NewRequest(http.MethodGet, "http://local/v1/foo", nil)
	r.Host = "app.local"

	strict, e := New("", testToken("new"), slog.Default(), routes, false)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	strict.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected TLS verification failure, got status %d", w.Code)
	}

	relaxed, e := New("", testToken("new"), slog.Default(), routes, true)
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
