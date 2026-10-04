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
	Issuer, ClientID, Scope, Upstream, Listen, RedirectPort, TokenStore string
	Login                                                               bool
	Verbose                                                             bool
	HostMappings                                                        map[string]string
	HostRoutes                                                          map[string]*url.URL
}

type cli struct {
	Issuer       string              `name:"issuer" help:"OIDC issuer URL." placeholder:"URL"`
	ClientID     string              `name:"client-id" help:"OAuth client ID registered with the issuer." placeholder:"ID"`
	Scope        string              `name:"scope" default:"openid profile offline_access" help:"Space separated OAuth scopes."`
	Upstream     string              `name:"upstream" help:"Upstream base URL to proxy authenticated requests to." placeholder:"URL"`
	Listen       string              `name:"listen" default:"127.0.0.1:8080" help:"Address to listen on." placeholder:"HOST:PORT"`
	RedirectPort string              `name:"redirect-port" help:"Fixed local port for the OAuth2 loopback redirect." placeholder:"PORT"`
	TokenStore   string              `name:"token-store" help:"Path to the token cache file." placeholder:"PATH"`
	HostMappings map[string]string   `name:"host-mapping" mapsep:"," help:"Map an incoming Host to an upstream Host header (repeatable)." placeholder:"LOCAL=UPSTREAM"`
	HostRoutes   map[string]*url.URL `name:"host-route" mapsep:"," help:"Route an incoming Host to scheme://remote-host[/path] (repeatable)." placeholder:"LOCAL=URL"`
	Login        bool                `name:"login" env:"-" help:"Force authentication, then serve."`
	Logout       bool                `name:"logout" env:"-" help:"Delete the stored token, then exit."`
	Version      bool                `name:"version" env:"-" help:"Print the build version, then exit."`
	Verbose      bool                `name:"verbose" short:"v" help:"Enable verbose debug logging."`
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
		Issuer:       cl.Issuer,
		ClientID:     cl.ClientID,
		Scope:        cl.Scope,
		Upstream:     cl.Upstream,
		Listen:       cl.Listen,
		RedirectPort: cl.RedirectPort,
		TokenStore:   cl.TokenStore,
		Login:        cl.Login,
		Verbose:      cl.Verbose,
	}
	if c.HostMappings, e = normalizeMappings(cl.HostMappings); e != nil {
		return Config{}, ActionRun, e
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
	if c.Issuer == "" || c.ClientID == "" || c.Upstream == "" {
		return c, ActionRun, errors.New("--issuer, --client-id, and --upstream are required")
	}
	for n, s := range map[string]string{"issuer": c.Issuer, "upstream": c.Upstream} {
		u, e := url.Parse(s)
		if e != nil || u.Scheme != "https" || u.Host == "" {
			return c, ActionRun, fmt.Errorf("--%s must be an absolute HTTPS URL", n)
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

func normalizeMappings(m map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(m))
	for k, v := range m {
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			return nil, errors.New("host mapping must use source-host=upstream-host")
		}
		out[k] = v
	}
	return out, nil
}

func normalizeRoutes(m map[string]*url.URL) (map[string]*url.URL, error) {
	out := make(map[string]*url.URL, len(m))
	for k, u := range m {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			return nil, errors.New("host route must use local-host=scheme://remote-host[/path]")
		}
		if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, errors.New("host route target must be an absolute http or https URL")
		}
		out[k] = u
	}
	return out, nil
}
