package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/TelkomIndonesia/oauth2-sidecar/internal/config"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/token"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/validator"
)

const deviceListen = "127.0.0.1:18080"

type deviceProfile struct {
	Issuer    string `json:"issuer"`
	ClientID  string `json:"client-id"`
	Validator string `json:"validator"`
}

func (p deviceProfile) config() (config.Config, error) {
	for _, raw := range []string{p.Issuer, p.Validator} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return config.Config{}, errors.New("issuer and validator must be absolute HTTPS URLs without credentials, query or fragment")
		}
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return config.Config{}, errors.New("OAuth application ID is required")
	}
	c := config.Config{Issuer: p.Issuer, ClientID: p.ClientID, Upstream: p.Validator, Scope: "openid email", Listen: deviceListen, RedirectPort: "8250", TokenHeader: validator.Header}
	path, err := token.DefaultPath(c.Issuer, c.ClientID, c.Scope, p.Validator)
	c.TokenStore = path
	return c, err
}

func setupDevice(path string, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	var p deviceProfile
	for _, item := range []struct {
		label string
		value *string
	}{{"GitLab issuer URL", &p.Issuer}, {"OAuth application ID", &p.ClientID}, {"HTTPS validator URL", &p.Validator}} {
		fmt.Fprintf(out, "%s: ", item.label)
		if !scanner.Scan() {
			return errors.New("setup needs an issuer, application ID and validator URL")
		}
		*item.value = strings.TrimSpace(scanner.Text())
	}
	if _, err := p.config(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".device-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(p)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	fmt.Fprintln(out, "Profile saved. Run oauth2-sidecar device to sign in and start the local forwarder.")
	return nil
}

func device(args []string) error {
	if len(args) > 1 {
		return errors.New("usage: oauth2-sidecar device [setup|login|logout]")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "oauth2-sidecar", "device.json")
	action := config.ActionRun
	force := false
	if len(args) == 1 {
		switch args[0] {
		case "setup":
			return setupDevice(path, os.Stdin, os.Stderr)
		case "logout":
			action = config.ActionLogout
		case "login":
			force = true
		case "--help", "-h":
			fmt.Println("Usage: oauth2-sidecar device [setup|login|logout]")
			return nil
		default:
			return fmt.Errorf("unknown device command %q", args[0])
		}
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("run oauth2-sidecar device setup first")
	}
	if err != nil {
		return err
	}
	var p deviceProfile
	if err = json.Unmarshal(b, &p); err != nil {
		return err
	}
	c, err := p.config()
	if err != nil {
		return err
	}
	c.Login = force
	runProxy(c, action, true)
	return nil
}

func deviceHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != deviceListen || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Sec-Fetch-Mode")) != 0 {
			http.Error(w, "local command-line requests only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
