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
}

func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	p, e := oidc.NewProvider(ctx, issuer)
	if e != nil {
		return nil, e
	}
	return &Provider{p, p.Endpoint()}, nil
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
	t, e := cfg.Exchange(ctx, cb.code, oauth2.SetAuthURLParam("code_verifier", ver))
	if e != nil {
		return nil, e
	}
	if raw, ok := t.Extra("id_token").(string); ok && raw != "" {
		if _, e = a.p.OIDC.Verifier(&oidc.Config{ClientID: a.c.ClientID}).Verify(ctx, raw); e != nil {
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
