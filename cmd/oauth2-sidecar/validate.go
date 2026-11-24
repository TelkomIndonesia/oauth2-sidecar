package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TelkomIndonesia/oauth2-sidecar/internal/validator"
)

func validate(args []string) error {
	flags := flag.NewFlagSet("oauth2-sidecar validate", flag.ContinueOnError)
	issuer := flags.String("issuer", "", "GitLab HTTPS issuer URL")
	id := flags.String("client-id", "", "dedicated GitLab OAuth application ID")
	upstream := flags.String("upstream", "", "fixed backend URL")
	users := flags.String("allow-users", "", "comma-separated GitLab user IDs authorized to access this backend")
	listen := flags.String("listen", ":8080", "listen address behind the HTTPS route")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected validator argument")
	}
	handler, err := validator.New(*issuer, *id, *upstream, strings.Split(*users, ","), slog.Default())
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	slog.Info("validator listening", "address", ln.Addr().String())
	return serve(ctx, srv, ln)
}
