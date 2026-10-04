package config

import (
	"errors"
	"testing"
)

func TestParseHostRoute(t *testing.T) {
	c, action, e := Parse([]string{"--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example", "--host-route", "app.local=https://other.example:8443/base"})
	if e != nil {
		t.Fatal(e)
	}
	if action != ActionRun {
		t.Fatalf("action %d", action)
	}
	u := c.HostRoutes["app.local"]
	if u == nil || u.Scheme != "https" || u.Host != "other.example:8443" || u.Path != "/base" {
		t.Fatalf("bad route: %v", c.HostRoutes)
	}
}

func TestParseHostRouteFromEnv(t *testing.T) {
	t.Setenv("OAUTH2_SIDECAR_HOST_ROUTE", "a.local=http://a.internal,b.local=https://b.internal/b")
	c, _, e := Parse([]string{"--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example"})
	if e != nil {
		t.Fatal(e)
	}
	if c.HostRoutes["a.local"].Host != "a.internal" || c.HostRoutes["b.local"].Path != "/b" {
		t.Fatalf("bad routes: %v", c.HostRoutes)
	}
}

func TestParseHostRouteRejectsInvalidTarget(t *testing.T) {
	base := []string{"--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example"}
	for _, v := range []string{"app.local=other.internal", "app.local=ftp://other.internal", "=https://other.internal", "app.local="} {
		if _, _, e := Parse(append(append([]string{}, base...), "--host-route", v)); e == nil {
			t.Fatalf("expected error for %q", v)
		}
	}
}

func TestParseIssuerIP(t *testing.T) {
	base := []string{"--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example"}
	c, _, e := Parse(append(append([]string{}, base...), "--issuer-ip", "2001:db8::1"))
	if e != nil || c.IssuerIP != "2001:db8::1" {
		t.Fatalf("issuer IP %q: %v", c.IssuerIP, e)
	}
	t.Setenv("OAUTH2_SIDECAR_ISSUER_IP", "192.0.2.1")
	c, _, e = Parse(base)
	if e != nil || c.IssuerIP != "192.0.2.1" {
		t.Fatalf("issuer IP from environment %q: %v", c.IssuerIP, e)
	}
	c, _, e = Parse(append(append([]string{}, base...), "--issuer-ip", "192.0.2.2"))
	if e != nil || c.IssuerIP != "192.0.2.2" {
		t.Fatalf("issuer IP flag precedence %q: %v", c.IssuerIP, e)
	}
	for _, ip := range []string{"issuer.example", "192.0.2.1:443", "[2001:db8::1]", "not-an-ip"} {
		if _, _, e := Parse(append(append([]string{}, base...), "--issuer-ip", ip)); e == nil {
			t.Fatalf("expected invalid issuer IP error for %q", ip)
		}
	}
}

func TestParseHelp(t *testing.T) {
	if _, _, e := Parse([]string{"--help"}); !errors.Is(e, ErrHelp) {
		t.Fatalf("expected ErrHelp, got %v", e)
	}
}
