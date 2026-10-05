package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/TelkomIndonesia/oauth2-sidecar/internal/config"
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
	routes      map[string]config.HostRoute
}

func newResolver(upstream *url.URL, routes map[string]config.HostRoute) *resolver {
	return &resolver{upstream: upstream, upstreamSet: upstream != nil, routes: routes}
}

func (r *resolver) resolve(host string) (*url.URL, string, bool) {
	if rt, ok := r.routes[host]; ok {
		return rt.Target, "host-route", true
	}
	if r.upstreamSet {
		return r.upstream, "upstream", true
	}
	return nil, "", false
}

func New(raw string, src TokenSource, log *slog.Logger, routes map[string]config.HostRoute, insecure bool) (*Proxy, error) {
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
	if overrides := dialOverrides(routes); len(overrides) > 0 {
		transport := base.(*http.Transport).Clone()
		applyDialOverrides(transport, overrides)
		base = transport
	}
	r := newResolver(upstream, routes)
	rp := &httputil.ReverseProxy{Transport: transport{src: src, base: base, log: log}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, e error) {
		log.Error("proxy request", "error", e)
		http.Error(w, "upstream request failed", 502)
	}}
	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		host := normalizeHost(pr.In.Host)
		target, source, _ := r.resolve(host)
		pr.SetURL(target)
		pr.SetXForwarded()
		log.Debug("proxy request",
			"method", pr.In.Method,
			"host", host,
			"target", pr.Out.URL.String(),
			"source", source,
		)
	}
	return &Proxy{rp: rp, r: r, log: log}, nil
}

func dialOverrides(routes map[string]config.HostRoute) map[string]string {
	out := map[string]string{}
	for _, rt := range routes {
		if rt.IP != "" && rt.Target != nil && rt.Target.Hostname() != "" {
			out[strings.ToLower(rt.Target.Hostname())] = rt.IP
		}
	}
	return out
}

func applyDialOverrides(t *http.Transport, overrides map[string]string) {
	dial := t.DialContext
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		if ip, ok := overrides[strings.ToLower(host)]; ok {
			address = net.JoinHostPort(ip, port)
		}
		return dial(ctx, network, address)
	}
	proxy := t.Proxy
	t.Proxy = func(r *http.Request) (*url.URL, error) {
		if _, ok := overrides[strings.ToLower(r.URL.Hostname())]; ok || proxy == nil {
			return nil, nil
		}
		return proxy(r)
	}
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
