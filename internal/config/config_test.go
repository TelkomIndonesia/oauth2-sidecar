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
	rt := c.HostRoutes["app.local"]
	if rt.Target == nil || rt.Target.Scheme != "https" || rt.Target.Host != "other.example:8443" || rt.Target.Path != "/base" || rt.IP != "" {
		t.Fatalf("bad route: %v", c.HostRoutes)
	}
}

func TestParseHostRouteFromEnv(t *testing.T) {
	t.Setenv("OAUTH2_SIDECAR_HOST_ROUTE", "a.local=http://a.internal,b.local=https://b.internal/b")
	c, _, e := Parse([]string{"--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example"})
	if e != nil {
		t.Fatal(e)
	}
	if c.HostRoutes["a.local"].Target.Host != "a.internal" || c.HostRoutes["b.local"].Target.Path != "/b" {
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

func TestParseHostRouteIPOverride(t *testing.T) {
	base := []string{"--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example"}
	c, _, e := Parse(append(append([]string{}, base...), "--host-route", "app.local=https://other.example:8443/base=10.0.0.5"))
	if e != nil {
		t.Fatal(e)
	}
	rt := c.HostRoutes["app.local"]
	if rt.Target == nil || rt.Target.Host != "other.example:8443" || rt.Target.Path != "/base" || rt.IP != "10.0.0.5" {
		t.Fatalf("bad route with ip: %+v", rt)
	}
	c, _, e = Parse(append(append([]string{}, base...), "--host-route", "app.local=https://other.example=2001:db8::1"))
	if e != nil {
		t.Fatal(e)
	}
	if rt := c.HostRoutes["app.local"]; rt.Target.Host != "other.example" || rt.IP != "2001:db8::1" {
		t.Fatalf("bad ipv6 override: %+v", rt)
	}
	for _, v := range []string{"app.local=https://other.example=not-an-ip", "app.local=https://other.example=", "app.local=https://other.example=192.0.2.1:443"} {
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

func TestParseRequiresDestination(t *testing.T) {
	if _, _, e := Parse([]string{"--issuer", "https://issuer.example", "--client-id", "c"}); e == nil {
		t.Fatal("expected error when no upstream or host-route is given")
	}
}

func TestParseRouteOnly(t *testing.T) {
	c, action, e := Parse([]string{"--issuer", "https://issuer.example", "--client-id", "c", "--host-route", "app.local=https://other.example:8443/base"})
	if e != nil {
		t.Fatal(e)
	}
	if action != ActionRun || c.Upstream != "" || c.HostRoutes["app.local"].Target.Host != "other.example:8443" {
		t.Fatalf("bad route-only config: %+v", c)
	}
}

func TestParseInsecureSkipVerify(t *testing.T) {
	base := []string{"--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example"}
	if c, _, e := Parse(base); e != nil || c.InsecureSkipVerify {
		t.Fatalf("default insecure skip verify: %v %v", c.InsecureSkipVerify, e)
	}
	if c, _, e := Parse(append(append([]string{}, base...), "--insecure-skip-verify")); e != nil || !c.InsecureSkipVerify {
		t.Fatalf("flag insecure skip verify: %v %v", c.InsecureSkipVerify, e)
	}
	t.Setenv("OAUTH2_SIDECAR_INSECURE_SKIP_VERIFY", "true")
	if c, _, e := Parse(base); e != nil || !c.InsecureSkipVerify {
		t.Fatalf("env insecure skip verify: %v %v", c.InsecureSkipVerify, e)
	}
}
