package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/browser"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Provider struct {
	OIDC     *oidc.Provider
	Endpoint oauth2.Endpoint
	client   *http.Client
}

func issuerClient(issuer, ip string) (*http.Client, error) {
	if net.ParseIP(ip) == nil {
		return nil, errors.New("issuer IP must be an IPv4 or IPv6 address")
	}
	u, e := url.Parse(issuer)
	if e != nil || u.Hostname() == "" {
		return nil, errors.New("invalid issuer URL")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		if strings.EqualFold(host, u.Hostname()) {
			address = net.JoinHostPort(ip, port)
		}
		return dial(ctx, network, address)
	}
	proxy := transport.Proxy
	transport.Proxy = func(r *http.Request) (*url.URL, error) {
		if strings.EqualFold(r.URL.Hostname(), u.Hostname()) || proxy == nil {
			return nil, nil
		}
		return proxy(r)
	}
	return &http.Client{Transport: transport}, nil
}

func NewProvider(ctx context.Context, issuer, ip string) (*Provider, error) {
	var client *http.Client
	if ip != "" {
		var e error
		client, e = issuerClient(issuer, ip)
		if e != nil {
			return nil, e
		}
		ctx = oidc.ClientContext(ctx, client)
	}
	p, e := oidc.NewProvider(ctx, issuer)
	if e != nil {
		return nil, e
	}
	return &Provider{OIDC: p, Endpoint: p.Endpoint(), client: client}, nil
}

type Authenticator struct {
	p    *Provider
	c    config.Config
	open func(string) error
}

func NewAuthenticator(p *Provider, c config.Config) *Authenticator {
	return &Authenticator{p: p, c: c, open: openBrowser}
}
func (a *Authenticator) Refresh(ctx context.Context, t *oauth2.Token) (*oauth2.Token, error) {
	if a.p.client != nil {
		ctx = oidc.ClientContext(ctx, a.p.client)
	}
	return (&oauth2.Config{ClientID: a.c.ClientID, Endpoint: a.p.Endpoint, Scopes: strings.Fields(a.c.Scope)}).TokenSource(ctx, t).Token()
}
func (a *Authenticator) Login(ctx context.Context) (*oauth2.Token, error) {
	state, e := random(32)
	if e != nil {
		return nil, e
	}
	ver, e := random(32)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256([]byte(ver))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	addr := "127.0.0.1:0"
	if a.c.RedirectPort != "" {
		addr = "127.0.0.1:" + a.c.RedirectPort
	}
	ln, e := net.Listen("tcp", addr)
	if e != nil {
		return nil, e
	}
	defer ln.Close()
	redirect := "http://" + ln.Addr().String() + "/callback"
	result := make(chan callback, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("state") != state {
			result <- callback{e: errors.New("OAuth state mismatch")}
			http.Error(w, "authentication failed", 400)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			result <- callback{e: fmt.Errorf("authorization failed: %s", r.URL.Query().Get("error"))}
			http.Error(w, "authentication failed", 400)
			return
		}
		fmt.Fprintln(w, "Authentication complete. You can close this window.")
		result <- callback{code: code}
	})}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())
	cfg := &oauth2.Config{ClientID: a.c.ClientID, Endpoint: a.p.Endpoint, RedirectURL: redirect, Scopes: strings.Fields(a.c.Scope)}
	if e = a.open(cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("code_challenge", challenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))); e != nil {
		return nil, e
	}
	var cb callback
	select {
	case cb = <-result:
	case <-time.After(10 * time.Minute):
		return nil, errors.New("authentication timed out")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if cb.e != nil {
		return nil, cb.e
	}
	if a.p.client != nil {
		ctx = oidc.ClientContext(ctx, a.p.client)
	}
	t, e := cfg.Exchange(ctx, cb.code, oauth2.SetAuthURLParam("code_verifier", ver))
	if e != nil {
		return nil, e
	}
	if raw, ok := t.Extra("id_token").(string); ok && raw != "" {
		if _, e = a.p.OIDC.VerifierContext(ctx, &oidc.Config{ClientID: a.c.ClientID}).Verify(ctx, raw); e != nil {
			return nil, fmt.Errorf("verify ID token: %w", e)
		}
	}
	return t, nil
}

type callback struct {
	code string
	e    error
}

func random(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func openBrowser(raw string) error {
	u, e := url.Parse(raw)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		return errors.New("refusing non-HTTPS authorization URL")
	}
	return browser.OpenURL(raw)
}
