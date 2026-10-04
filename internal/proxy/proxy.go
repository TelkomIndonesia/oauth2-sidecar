package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type TokenSource interface {
	AccessToken(context.Context) (string, error)
}
type Proxy struct{ rp *httputil.ReverseProxy }

func New(raw string, src TokenSource, log *slog.Logger, mappings map[string]string, routes map[string]*url.URL) (*Proxy, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid upstream URL")
	}
	rp := &httputil.ReverseProxy{Transport: transport{src: src, base: http.DefaultTransport, log: log}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, e error) {
		log.Error("proxy request", "error", e)
		http.Error(w, "upstream request failed", 502)
	}}
	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		host := strings.ToLower(pr.In.Host)
		target := u
		source := "upstream"
		if ru, ok := routes[host]; ok {
			target = ru
			source = "host-route"
		}
		pr.SetURL(target)
		pr.SetXForwarded()
		mapping := ""
		if h, ok := mappings[host]; ok {
			pr.Out.Host = h
			mapping = host
		} else if h, ok := mappings["*"]; ok {
			pr.Out.Host = h
			mapping = "*"
		}
		log.Debug("proxy request",
			"method", pr.In.Method,
			"host", host,
			"target", pr.Out.URL.String(),
			"source", source,
			"host-mapping", mapping,
		)
	}
	return &Proxy{rp: rp}, nil
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.rp.ServeHTTP(w, r) }

type transport struct {
	src  TokenSource
	base http.RoundTripper
	log  *slog.Logger
}

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	a, e := t.src.AccessToken(r.Context())
	if e != nil {
		return nil, fmt.Errorf("get access token: %w", e)
	}
	t.log.Debug("injecting access token", "method", r.Method, "url", r.URL.String(), "bytes", len(a))
	q := r.Clone(r.Context())
	q.Header = r.Header.Clone()
	q.Header.Set("Authorization", "Bearer "+a)
	return t.base.RoundTrip(q)
}
