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
	rp     *httputil.ReverseProxy
	routes map[string]*httputil.ReverseProxy
	log    *slog.Logger
}

func New(raw string, src TokenSource, log *slog.Logger, routes map[string]config.HostRoute, insecure bool, header string) (*Proxy, error) {
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
	makeProxy := func(target *url.URL, base http.RoundTripper, source string) *httputil.ReverseProxy {
		return &httputil.ReverseProxy{
			Transport: transport{src: src, base: base, log: log, header: header},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, e error) {
				log.Error("proxy request", "error", e)
				http.Error(w, "upstream request failed", http.StatusBadGateway)
			},
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.SetXForwarded()
				log.Debug("proxy request", "method", pr.In.Method, "host", normalizeHost(pr.In.Host), "target", pr.Out.URL.String(), "source", source)
			},
		}
	}
	p := &Proxy{routes: make(map[string]*httputil.ReverseProxy), log: log}
	if upstream != nil {
		p.rp = makeProxy(upstream, base, "upstream")
	}
	for host, route := range routes {
		rt := base
		if route.IP != "" {
			rt = pinnedTransport(base.(*http.Transport), route.IP)
		}
		p.routes[host] = makeProxy(route.Target, rt, "host-route")
	}
	return p, nil
}

func pinnedTransport(base *http.Transport, ip string) *http.Transport {
	t := base.Clone()
	t.Proxy = nil
	dial := t.DialContext
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		return dial(ctx, network, net.JoinHostPort(ip, port))
	}
	return t
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

// HandlerForListener restricts a loopback proxy to local CLI hosts and explicit host routes.
func (p *Proxy) HandlerForListener(addr *net.TCPAddr) http.Handler {
	if !addr.IP.IsLoopback() {
		return p
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeHost(r.Host)
		if host != "localhost" && !addr.IP.Equal(net.ParseIP(strings.Trim(host, "[]"))) && p.routes[host] == nil {
			http.Error(w, "unexpected local proxy host", http.StatusForbidden)
			return
		}
		for key := range r.Header {
			if strings.EqualFold(key, "Origin") || strings.HasPrefix(strings.ToLower(key), "sec-fetch-") {
				http.Error(w, "local command-line requests only", http.StatusForbidden)
				return
			}
		}
		p.ServeHTTP(w, r)
	})
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := normalizeHost(req.Host)
	rp := p.routes[host]
	if rp == nil {
		rp = p.rp
	}
	if rp == nil {
		p.log.Error("no target for host", "host", host)
		http.Error(w, "no upstream destination for host", http.StatusBadGateway)
		return
	}
	rp.ServeHTTP(w, req)
}

type transport struct {
	src    TokenSource
	base   http.RoundTripper
	log    *slog.Logger
	header string
}

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	a, e := t.src.AccessToken(r.Context())
	if e != nil {
		return nil, fmt.Errorf("get access token: %w", e)
	}
	t.log.Debug("injecting access token", "method", r.Method, "url", r.URL.String(), "bytes", len(a))
	q := r.Clone(r.Context())
	q.Header = r.Header.Clone()
	q.Header.Set(t.header, "Bearer "+a)
	return t.base.RoundTrip(q)
}
