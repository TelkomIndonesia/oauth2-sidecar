package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
)

type Action int

const (
	ActionRun Action = iota
	ActionLogin
	ActionLogout
	ActionVersion
)

// ErrHelp is returned by Parse when the user asked for --help. The help text
// has already been written to stdout by then.
var ErrHelp = errors.New("help requested")

type Config struct {
	Issuer, IssuerIP, ClientID, Scope, Upstream, Listen, RedirectPort, TokenStore string
	Login                                                                         bool
	Verbose                                                                       bool
	InsecureSkipVerify                                                            bool
	HostRoutes                                                                    map[string]HostRoute
}

type HostRoute struct {
	Target *url.URL
	IP     string
}

type cli struct {
	Issuer       string            `name:"issuer" help:"OIDC issuer URL." placeholder:"URL"`
	IssuerIP     string            `name:"issuer-ip" help:"Connect to this IPv4 or IPv6 address for the issuer hostname (sidecar only; preserves TLS verification)." placeholder:"IP"`
	ClientID     string            `name:"client-id" help:"OAuth client ID registered with the issuer." placeholder:"ID"`
	Scope        string            `name:"scope" default:"openid profile offline_access" help:"Space separated OAuth scopes."`
	Upstream     string            `name:"upstream" help:"Upstream base URL to proxy authenticated requests to (optional if --host-route defines a destination)." placeholder:"URL"`
	Listen       string            `name:"listen" default:"127.0.0.1:8080" help:"Address to listen on." placeholder:"HOST:PORT"`
	RedirectPort string            `name:"redirect-port" help:"Fixed local port for the OAuth2 loopback redirect." placeholder:"PORT"`
	TokenStore   string            `name:"token-store" help:"Path to the token cache file." placeholder:"PATH"`
	HostRoutes   map[string]string `name:"host-route" mapsep:"," help:"Route an incoming Host to scheme://remote-host[/path][=remote-ip] (repeatable); remote-ip dials that address while preserving TLS verification for the URL hostname." placeholder:"LOCAL=URL[=IP]"`
	Login        bool              `name:"login" env:"-" help:"Force authentication, then serve."`
	SkipVerify   bool              `name:"insecure-skip-verify" help:"Skip TLS certificate verification for proxied upstream requests only; issuer verification is unchanged."`
	Logout       bool              `name:"logout" env:"-" help:"Delete the stored token, then exit."`
	Version      bool              `name:"version" env:"-" help:"Print the build version, then exit."`
	Verbose      bool              `name:"verbose" short:"v" help:"Enable verbose debug logging."`
}

var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

func Parse(args []string) (c Config, action Action, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok && errors.Is(e, ErrHelp) {
				err = ErrHelp
				return
			}
			panic(r)
		}
	}()
	var cl cli
	k, e := kong.New(&cl,
		kong.Name("oauth2-sidecar"),
		kong.Description("Local OAuth2/OIDC-authenticated reverse proxy."),
		kong.DefaultEnvars("OAUTH2_SIDECAR"),
		kong.Writers(stdout, stderr),
		kong.Exit(func(int) { panic(ErrHelp) }),
	)
	if e != nil {
		return Config{}, ActionRun, e
	}
	if _, e = k.Parse(args); e != nil {
		return Config{}, ActionRun, e
	}
	c = Config{
		Issuer:             cl.Issuer,
		IssuerIP:           cl.IssuerIP,
		ClientID:           cl.ClientID,
		Scope:              cl.Scope,
		Upstream:           cl.Upstream,
		Listen:             cl.Listen,
		RedirectPort:       cl.RedirectPort,
		TokenStore:         cl.TokenStore,
		Login:              cl.Login,
		Verbose:            cl.Verbose,
		InsecureSkipVerify: cl.SkipVerify,
	}
	if c.HostRoutes, e = normalizeRoutes(cl.HostRoutes); e != nil {
		return Config{}, ActionRun, e
	}
	if cl.Version {
		return c, ActionVersion, nil
	}
	if cl.Login && cl.Logout {
		return c, ActionRun, errors.New("--login and --logout cannot be combined")
	}
	if cl.Logout {
		return c, ActionLogout, nil
	}
	if c.Issuer == "" || c.ClientID == "" {
		return c, ActionRun, errors.New("--issuer and --client-id are required")
	}
	if c.Upstream == "" && len(c.HostRoutes) == 0 {
		return c, ActionRun, errors.New("--upstream is required unless --host-route defines a destination")
	}
	u, e := url.Parse(c.Issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" {
		return c, ActionRun, errors.New("--issuer must be an absolute HTTPS URL")
	}
	if c.Upstream != "" {
		u, e := url.Parse(c.Upstream)
		if e != nil || u.Scheme != "https" || u.Host == "" {
			return c, ActionRun, errors.New("--upstream must be an absolute HTTPS URL")
		}
	}
	if c.IssuerIP != "" {
		if net.ParseIP(c.IssuerIP) == nil {
			return c, ActionRun, errors.New("--issuer-ip must be an IPv4 or IPv6 address")
		}
	}
	if _, _, e := net.SplitHostPort(c.Listen); e != nil {
		return c, ActionRun, fmt.Errorf("--listen must be host:port: %w", e)
	}
	if c.RedirectPort != "" {
		if _, e := strconv.Atoi(c.RedirectPort); e != nil {
			return c, ActionRun, errors.New("--redirect-port must be numeric")
		}
	}
	if c.TokenStore == "" {
		d, e := os.UserConfigDir()
		if e != nil {
			return c, ActionRun, e
		}
		c.TokenStore = filepath.Join(d, "oauth2-sidecar", "token.json")
	}
	if strings.TrimSpace(c.Scope) == "" {
		return c, ActionRun, errors.New("--scope cannot be empty")
	}
	return c, ActionRun, nil
}

func normalizeRoutes(m map[string]string) (map[string]HostRoute, error) {
	out := make(map[string]HostRoute, len(m))
	for k, v := range m {
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			return nil, errors.New("host route must use local-host=scheme://remote-host[/path][=remote-ip]")
		}
		target, ip, e := parseRouteValue(v)
		if e != nil {
			return nil, e
		}
		out[k] = HostRoute{Target: target, IP: ip}
	}
	return out, nil
}

func parseRouteValue(v string) (*url.URL, string, error) {
	raw, ip := v, ""
	if i := strings.LastIndex(v, "="); i != -1 {
		suffix := strings.TrimSpace(v[i+1:])
		if net.ParseIP(suffix) == nil {
			return nil, "", fmt.Errorf("host route remote-ip %q must be an IPv4 or IPv6 address", suffix)
		}
		raw, ip = strings.TrimSpace(v[:i]), suffix
	}
	u, e := url.Parse(raw)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, "", errors.New("host route target must be an absolute http or https URL")
	}
	return u, ip, nil
}
