package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TelkomIndonesia/oauth2-sidecar/internal/config"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

func TestIssuerIPAuthentication(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if e != nil {
		t.Fatal(e)
	}
	var issuer, rawToken string
	requests := make(chan string, 10)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		u, _ := url.Parse(issuer)
		if r.Host != u.Host || r.TLS.ServerName != u.Hostname() {
			t.Errorf("host=%q SNI=%q", r.Host, r.TLS.ServerName)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realm/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer,
				"authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token",
				"jwks_uri": issuer + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/realm/token":
			if e := r.ParseForm(); e != nil {
				t.Error(e)
			}
			if grant := r.Form.Get("grant_type"); grant != "authorization_code" && grant != "refresh_token" {
				t.Errorf("unexpected grant type %q", grant)
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 3600, "id_token": rawToken})
		case "/realm/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	_, port, e := net.SplitHostPort(server.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	issuer = "https://issuer.example.com:" + port + "/realm"
	claims, e := json.Marshal(map[string]any{"iss": issuer, "sub": "user", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
	if e != nil {
		t.Fatal(e)
	}
	signed, e := signer.Sign(claims)
	if e != nil {
		t.Fatal(e)
	}
	rawToken, e = signed.CompactSerialize()
	if e != nil {
		t.Fatal(e)
	}
	original := http.DefaultTransport
	base := original.(*http.Transport).Clone()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	base.TLSClientConfig = &tls.Config{RootCAs: roots}
	proxyURL, _ := url.Parse("http://127.0.0.1:1")
	base.Proxy = http.ProxyURL(proxyURL)
	http.DefaultTransport = base
	t.Cleanup(func() { http.DefaultTransport = original; base.CloseIdleConnections() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, e := NewProvider(ctx, issuer, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	defer p.client.CloseIdleConnections()
	a := NewAuthenticator(p, config.Config{ClientID: "client", Scope: "openid"})
	a.open = func(raw string) error {
		u, e := url.Parse(raw)
		if e != nil {
			return e
		}
		if !strings.HasPrefix(raw, issuer+"/authorize?") {
			t.Errorf("authorization URL changed: %s", raw)
		}
		q := u.Query()
		callback, e := url.Parse(q.Get("redirect_uri"))
		if e != nil {
			return e
		}
		callback.RawQuery = url.Values{"code": {"code"}, "state": {q.Get("state")}}.Encode()
		client := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
		defer client.CloseIdleConnections()
		resp, e := client.Get(callback.String())
		if e != nil {
			return e
		}
		return resp.Body.Close()
	}
	if token, e := a.Login(ctx); e != nil || token.AccessToken != "access" {
		t.Fatalf("login failed: %v", e)
	}
	if token, e := a.Refresh(ctx, &oauth2.Token{RefreshToken: "refresh"}); e != nil || token.AccessToken != "access" {
		t.Fatalf("refresh failed: %v", e)
	}
	for _, want := range []string{"/realm/.well-known/openid-configuration", "/realm/token", "/realm/keys", "/realm/token"} {
		select {
		case got := <-requests:
			if got != want {
				t.Fatalf("request path %q, want %q", got, want)
			}
		default:
			t.Fatalf("missing request to %s", want)
		}
	}
	transport := p.client.Transport.(*http.Transport)
	request, _ := http.NewRequest(http.MethodGet, "https://unrelated.example", nil)
	if got, e := transport.Proxy(request); e != nil || got.String() != proxyURL.String() {
		t.Fatalf("unrelated host proxy changed: %v, %v", got, e)
	}
	client, e := issuerClient("https://wrong.invalid:"+port, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	if resp, e := client.Get("https://wrong.invalid:" + port); e == nil {
		resp.Body.Close()
		t.Fatal("expected TLS hostname verification failure")
	}
	if base.TLSClientConfig.InsecureSkipVerify || base.Proxy == nil || http.DefaultTransport != base {
		t.Fatal("default transport was modified")
	}
}

func TestNewProviderDefaultAndIssuerValidation(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"issuer": issuer})
	}))
	defer server.Close()
	issuer = server.URL
	p, e := NewProvider(context.Background(), issuer, "")
	if e != nil || p.client != nil {
		t.Fatalf("default provider: %v", e)
	}
	issuer = "https://different.example"
	if _, e := NewProvider(context.Background(), server.URL, "127.0.0.1"); e == nil || !strings.Contains(e.Error(), "issuer did not match") {
		t.Fatalf("expected issuer mismatch, got %v", e)
	}
	if _, e := NewProvider(context.Background(), server.URL, "not-an-ip"); e == nil {
		t.Fatal("expected invalid IP error")
	}
}
