package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type testToken string

func (t testToken) AccessToken(context.Context) (string, error) { return string(t), nil }
func TestProxyReplacesAuthorizationAndForwardsPath(t *testing.T) {
	got := make(chan *http.Request, 1)
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer u.Close()
	p, e := New(u.URL, testToken("new"), slog.Default(), map[string]string{"service.local": "api.internal"}, nil)
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
	p, e := New(def.URL, testToken("new"), slog.Default(), nil, map[string]*url.URL{"app.local": target})
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
