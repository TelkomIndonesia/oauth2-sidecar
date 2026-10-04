package proxy

import (
	"context"
	"crypto/tls"
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
type Proxy struct {
	rp  *httputil.ReverseProxy
	r   *resolver
	log *slog.Logger
}

type resolver struct {
	upstream    *url.URL
	upstreamSet bool
	mappings    map[string]string
	routes      map[string]*url.URL
}

func newResolver(upstream *url.URL, mappings map[string]string, routes map[string]*url.URL) *resolver {
	return &resolver{upstream: upstream, upstreamSet: upstream != nil, mappings: mappings, routes: routes}
}

func (r *resolver) resolve(host string) (*url.URL, string, bool) {
	if u, ok := r.routes[host]; ok {
		return u, "host-route", true
	}
	if r.upstreamSet {
		return r.upstream, "upstream", true
	}
	if v, ok := r.mapping(host); ok {
		return &url.URL{Scheme: "https", Host: v}, "host-mapping", true
	}
	return nil, "", false
}

func (r *resolver) mapping(host string) (string, bool) {
	if v, ok := r.mappings[host]; ok {
		return v, true
	}
	if v, ok := r.mappings["*"]; ok {
		return v, true
	}
	return "", false
}

func (r *resolver) mappingSource(host string) string {
	if _, ok := r.mappings[host]; ok {
		return host
	}
	if _, ok := r.mappings["*"]; ok {
		return "*"
	}
	return ""
}

func New(raw string, src TokenSource, log *slog.Logger, mappings map[string]string, routes map[string]*url.URL, insecure bool) (*Proxy, error) {
	var upstream *url.URL
	if raw != "" {
		u, e := url.Parse(raw)
		if e != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid upstream URL")
		}
		upstream = u
	}
	base := http.DefaultTransport
	if insecure {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
		base = transport
	}
	r := newResolver(upstream, mappings, routes)
	rp := &httputil.ReverseProxy{Transport: transport{src: src, base: base, log: log}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, e error) {
		log.Error("proxy request", "error", e)
		http.Error(w, "upstream request failed", 502)
	}}
	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		host := normalizeHost(pr.In.Host)
		target, source, _ := r.resolve(host)
		pr.SetURL(target)
		pr.SetXForwarded()
		if h, ok := r.mapping(host); ok {
			pr.Out.Host = h
		}
		log.Debug("proxy request",
			"method", pr.In.Method,
			"host", host,
			"target", pr.Out.URL.String(),
			"source", source,
			"host-mapping", r.mappingSource(host),
		)
	}
	return &Proxy{rp: rp, r: r, log: log}, nil
}

func normalizeHost(h string) string {
	h = strings.ToLower(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.LastIndex(h, "]:"); i != -1 {
			return h[:i+1]
		}
		return h
	}
	if i := strings.LastIndex(h, ":"); i != -1 {
		return h[:i]
	}
	return h
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := normalizeHost(req.Host)
	if _, _, ok := p.r.resolve(host); !ok {
		p.log.Error("no target for host", "host", host)
		http.Error(w, "no upstream destination for host", http.StatusBadGateway)
		return
	}
	p.rp.ServeHTTP(w, req)
}

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
