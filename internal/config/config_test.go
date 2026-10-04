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

func TestParseRequiresDestination(t *testing.T) {
	if _, _, e := Parse([]string{"--issuer", "https://issuer.example", "--client-id", "c"}); e == nil {
		t.Fatal("expected error when no upstream, host-route, or host-mapping is given")
	}
}

func TestParseMappingOnly(t *testing.T) {
	c, action, e := Parse([]string{"--issuer", "https://issuer.example", "--client-id", "c", "--host-mapping", "app.local=api.internal:8443"})
	if e != nil {
		t.Fatal(e)
	}
	if action != ActionRun || c.Upstream != "" || c.HostMappings["app.local"] != "api.internal:8443" {
		t.Fatalf("bad mapping-only config: %+v", c)
	}
}

func TestParseRouteOnly(t *testing.T) {
	c, action, e := Parse([]string{"--issuer", "https://issuer.example", "--client-id", "c", "--host-route", "app.local=https://other.example:8443/base"})
	if e != nil {
		t.Fatal(e)
	}
	if action != ActionRun || c.Upstream != "" || c.HostRoutes["app.local"].Host != "other.example:8443" {
		t.Fatalf("bad route-only config: %+v", c)
	}
}

func TestParseMappingDestinationValidation(t *testing.T) {
	base := []string{"--issuer", "https://issuer.example", "--client-id", "c"}
	for _, v := range []string{"app.local=https://other.internal", "app.local=other.internal/path", "app.local=user@other.internal", "app.local=bad host", "app.local=:8443"} {
		if _, _, e := Parse(append(append([]string{}, base...), "--host-mapping", v)); e == nil {
			t.Fatalf("expected error for mapping-only destination %q", v)
		}
	}
	for _, v := range []string{"app.local=api.internal", "app.local=api.internal:8443", "app.local=[2001:db8::1]:8443"} {
		if _, _, e := Parse(append(append([]string{}, base...), "--host-mapping", v)); e != nil {
			t.Fatalf("unexpected error for mapping-only destination %q: %v", v, e)
		}
	}
	withUpstream := append(append([]string{}, base...), "--upstream", "https://upstream.example", "--host-mapping", "app.local=https://other.internal")
	if _, _, e := Parse(withUpstream); e != nil {
		t.Fatalf("mapping destination with upstream should not be validated: %v", e)
	}
}

func TestParseMixedRouteMappingValidatesDestinations(t *testing.T) {
	base := []string{"--issuer", "https://issuer.example", "--client-id", "c"}
	bad := append(append([]string{}, base...), "--host-route", "app.local=https://other.example", "--host-mapping", "fallback.local=https://bad.internal")
	if _, _, e := Parse(bad); e == nil {
		t.Fatal("expected mapping destination validation to apply with routes and no upstream")
	}
	good := append(append([]string{}, base...), "--host-route", "app.local=https://other.example", "--host-mapping", "fallback.local=bad.internal:8443")
	if _, _, e := Parse(good); e != nil {
		t.Fatalf("valid mixed route/mapping: %v", e)
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
