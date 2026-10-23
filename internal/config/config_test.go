package config

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestParseTokenHeader(t *testing.T) {
	base := []string{"--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example"}
	if c, _, e := Parse(base); e != nil || c.TokenHeader != "Authorization" {
		t.Fatalf("default token header: %q %v", c.TokenHeader, e)
	}
	if c, _, e := Parse(append(append([]string{}, base...), "--token-header", "X-Dex-Token")); e != nil || c.TokenHeader != "X-Dex-Token" {
		t.Fatalf("flag token header: %q %v", c.TokenHeader, e)
	}
	for _, h := range []string{"", "X Dex", "X-Dex:", "X-Dé"} {
		if _, _, e := Parse(append(append([]string{}, base...), "--token-header", h)); e == nil || !strings.Contains(e.Error(), "--token-header") {
			t.Fatalf("%q: want --token-header error, got %v", h, e)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if e := os.WriteFile(p, []byte(body), 0o600); e != nil {
		t.Fatal(e)
	}
	return p
}

func TestParseConfigFile(t *testing.T) {
	p := writeConfig(t, "issuer: https://issuer.example\nclient-id: c\nlisten: 127.0.0.1:9000\nredirect-port: 8250\nhost-route:\n  a.localhost: http://a.internal=10.0.0.5\n")
	c, _, e := Parse([]string{"--config", p})
	if e != nil {
		t.Fatal(e)
	}
	if c.Listen != "127.0.0.1:9000" || c.RedirectPort != "8250" || c.HostRoutes["a.localhost"].IP != "10.0.0.5" {
		t.Fatalf("config not applied: %+v", c)
	}
	if c, _, e = Parse([]string{"--config", p, "--listen", "127.0.0.1:7000"}); e != nil || c.Listen != "127.0.0.1:7000" {
		t.Fatalf("flag must beat config: %q %v", c.Listen, e)
	}
	empty := []string{"--config", writeConfig(t, ""), "--issuer", "https://issuer.example", "--client-id", "c", "--upstream", "https://upstream.example"}
	if _, _, e = Parse(empty); e != nil {
		t.Fatalf("empty config: %v", e)
	}
	t.Setenv("OAUTH2_SIDECAR_LISTEN", "127.0.0.1:6000")
	if c, _, e = Parse([]string{"--config", p}); e != nil || c.Listen != "127.0.0.1:6000" {
		t.Fatalf("environment must beat config: %q %v", c.Listen, e)
	}
}

func TestParseConfigStdinJSON(t *testing.T) {
	defer func(r io.Reader) { stdin = r }(stdin)
	stdin = strings.NewReader(`{"issuer": "https://issuer.example", "client-id": "c", "upstream": "https://upstream.example"}`)
	if c, _, e := Parse([]string{"--config", "-"}); e != nil || c.Upstream != "https://upstream.example" {
		t.Fatalf("stdin config: %+v %v", c, e)
	}
}

func TestParseConfigURL(t *testing.T) {
	config := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "issuer: https://issuer.example\nclient-id: c\nupstream: https://upstream.example\n")
	})
	plain := httptest.NewServer(config)
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/c.yaml":
			config(w, r)
		case "/redirect":
			http.Redirect(w, r, plain.URL+"/c.yaml", http.StatusFound)
		case "/truncated":
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "issuer: https://issuer.example\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	defer func(c *http.Client) { configClient = c }(configClient)
	configClient = srv.Client()
	for _, src := range []string{srv.URL + "/c.yaml", plain.URL + "/c.yaml", "HTTP" + plain.URL[4:] + "/c.yaml"} {
		if c, _, e := Parse([]string{"--config", src}); e != nil || c.ClientID != "c" {
			t.Fatalf("%s: %+v %v", src, c, e)
		}
	}
	for src, want := range map[string]string{
		srv.URL + "/missing":   "404 Not Found",
		srv.URL + "/redirect":  "redirected to http",
		srv.URL + "/truncated": "unexpected EOF",
	} {
		if _, _, e := Parse([]string{"--config", src}); e == nil || !strings.Contains(e.Error(), want) {
			t.Fatalf("%s: want %q, got %v", src, want, e)
		}
	}
}

func TestParseConfigRejectsBadFiles(t *testing.T) {
	for body, want := range map[string]string{
		"lisen: 127.0.0.1:9000":    `unsupported key "lisen"`,
		"logout: true":             `unsupported key "logout"`,
		"config: other.yaml":       `unsupported key "config"`,
		"scope: [":                 "yaml:",
		"host-route: [a=http://a]": "invalid map value",
		"---\nlisten: :9000":       "want one YAML document",
	} {
		p := writeConfig(t, "issuer: https://issuer.example\nclient-id: c\nupstream: https://upstream.example\n"+body+"\n")
		if _, _, e := Parse([]string{"--config", p}); e == nil || !strings.Contains(e.Error(), want) {
			t.Fatalf("%q: want %q, got %v", body, want, e)
		}
	}
}
