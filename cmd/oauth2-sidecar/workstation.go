package main

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/TelkomIndonesia/oauth2-sidecar/internal/config"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/token"
)

// A personal token is scoped to one HTTPS validator and one local OS user.
func configureWorkstation(c *config.Config) error {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("the personal token header requires a loopback IP listen address")
	}
	if c.InsecureSkipVerify || len(c.HostRoutes) != 0 {
		return errors.New("the personal token header requires a single TLS-verified upstream")
	}
	for _, raw := range []string{c.Issuer, c.Upstream} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("issuer and validator must be absolute HTTPS URLs without credentials, query or fragment")
		}
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("the personal token header requires a GitLab client ID")
	}
	if c.TokenStore == "" {
		c.TokenStore, err = token.DefaultPath(c.Issuer, c.ClientID, c.Scope, c.Upstream)
	}
	return err
}
