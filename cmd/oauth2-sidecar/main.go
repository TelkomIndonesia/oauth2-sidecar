package main

import (
	"context"
	"errors"
	"flag"
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
	if len(os.Args) > 1 && (os.Args[1] == "device" || os.Args[1] == "validate") {
		var err error
		if os.Args[1] == "device" {
			err = device(os.Args[2:])
		} else {
			err = validate(os.Args[2:])
		}
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	c, action, e := config.Parse(os.Args[1:])
	if errors.Is(e, config.ErrHelp) {
		fmt.Println("Personal access: oauth2-sidecar device --help | oauth2-sidecar validate --help")
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
	runProxy(c, action, false)
}

func runProxy(c config.Config, action config.Action, local bool) {
	var e error
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
	var handler http.Handler = pr
	if local {
		handler = deviceHandler(pr)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		q, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(q)
	}()
	if e = srv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
		panic(e)
	}
}
