package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TelkomIndonesia/oauth2-sidecar/internal/auth"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/config"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/proxy"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/token"
)

var version = "dev"

func cacheListenerAddress(configured string, ln net.Listener) string {
	_, port, _ := net.SplitHostPort(configured)
	if strings.Trim(port, "0") == "" {
		return ln.Addr().String()
	}
	return configured
}

func main() {
	c, action, e := config.Parse(os.Args[1:])
	if errors.Is(e, config.ErrHelp) {
		return
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	if action == config.ActionVersion {
		fmt.Println(version)
		return
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if c.Verbose {
		opts.Level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(log)
	var ln net.Listener
	cacheListen := c.Listen
	if action != config.ActionLogout {
		ln, e = net.Listen("tcp", c.Listen)
		if e != nil {
			panic(e)
		}
		defer ln.Close()
		cacheListen = cacheListenerAddress(c.Listen, ln)
	}
	if c.TokenStore == "" {
		c.TokenStore, e = token.DefaultPath(c.Issuer, c.ClientID, c.Scope, cacheListen)
		if e != nil {
			panic(e)
		}
	}
	s := token.NewFileStore(c.TokenStore, c.Issuer, c.ClientID, c.Scope)
	if action == config.ActionLogout {
		e = s.Delete(context.Background())
		if e != nil && !errors.Is(e, token.ErrNotFound) {
			panic(e)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	log.Info("connecting to issuer", "issuer", c.Issuer)
	p, e := auth.NewProvider(ctx, c.Issuer, c.IssuerIP)
	if e != nil {
		panic(e)
	}
	a := auth.NewAuthenticator(p, c, log)
	m := token.NewManager(s, a)
	log.Info("acquiring token", "store", c.TokenStore)
	if _, e = m.Acquire(context.Background(), c.Login); e != nil {
		panic(e)
	}
	pr, e := proxy.New(c.Upstream, m, log, c.HostRoutes, c.InsecureSkipVerify, c.TokenHeader)
	if e != nil {
		panic(e)
	}
	log.Info("listening", "address", ln.Addr().String(), "upstream", c.Upstream)
	if host, _, _ := net.SplitHostPort(ln.Addr().String()); host != "127.0.0.1" && host != "::1" {
		log.Warn("non-loopback listen address", "address", ln.Addr().String())
	}
	srv := &http.Server{Handler: pr, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, srv, ln); err != nil {
		panic(err)
	}
}

func serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(drain)
	}
}
