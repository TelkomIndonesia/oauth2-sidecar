package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TelkomIndonesia/oauth2-sidecar/internal/proxy"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/token"
	"github.com/TelkomIndonesia/oauth2-sidecar/internal/validator"
	"golang.org/x/oauth2"
)

func TestDeviceSetup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user", "device.json")
	if err := setupDevice(path, strings.NewReader("https://gitlab.example\napp\nhttps://forwarder.example\n"), io.Discard); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p deviceProfile
	if err = json.Unmarshal(saved, &p); err != nil {
		t.Fatal(err)
	}
	c, err := p.config()
	if err != nil || c.TokenHeader != validator.Header || c.Upstream != "https://forwarder.example" || c.Listen != deviceListen || c.TokenStore == "" {
		t.Fatal("invalid saved profile", err)
	}
	if err := setupDevice(path, strings.NewReader("https://gitlab.example\napp\nhttp://other.example\n"), io.Discard); err == nil {
		t.Fatal("accepted plaintext validator")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, saved) {
		t.Fatal("failed setup damaged the previous profile")
	}
}

func TestPersonalDeviceThroughValidator(t *testing.T) {
	// The token manager, proxy, validator and application use their real HTTP entry points.
	var lookups atomic.Int32
	gitlab := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sub := 17
		if key == "device-b" {
			sub = 24
		}
		switch key {
		case "revoked":
			w.WriteHeader(401)
			return
		case "unavailable":
			w.WriteHeader(503)
			return
		case "other-user":
			sub = 80
		case "redirect":
			http.Redirect(w, r, "/unexpected", 302)
			return
		}
		switch r.URL.Path {
		case "/oauth/token/info":
			clientID := "app"
			if key == "wrong-app" {
				clientID = "different"
			}
			remaining := 3600
			if key == "expired" {
				remaining = 0
			}
			fmt.Fprintf(w, `{"resource_owner_id":%d,"scope":["openid","email"],"application":{"uid":%q},"expires_in":%d}`, sub, clientID, remaining)
		case "/oauth/userinfo":
			if key == "mismatch" {
				sub = 400
			}
			fmt.Fprintf(w, `{"sub":"%d","email":"user%d@example.test","email_verified":%t}`, sub, sub, key != "device-b")
		default:
			t.Error("unexpected identity lookup")
			http.NotFound(w, r)
		}
	}))
	defer gitlab.Close()
	original := http.DefaultTransport
	http.DefaultTransport = gitlab.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(validator.Header) != "" || r.Header.Get("Authorization") != "Bearer app-credential" || r.URL.RequestURI() != "/base/rpc?q=1" || r.Method != "POST" {
			t.Error("unexpected upstream request")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "payload" {
			t.Error("request body changed")
		}
		w.Header().Set("X-Request-ID", "backend-id")
		w.WriteHeader(201)
	}))
	defer app.Close()
	var records bytes.Buffer
	gateway, err := validator.New(gitlab.URL, "app", app.URL+"/base", []string{"17", "24"}, slog.New(slog.NewJSONHandler(&records, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(gateway)
	defer server.Close()
	for _, tc := range []struct {
		token       string
		status      int
		sub, email  string
		wantLookups int32
	}{
		{"device-a", 201, "17", "user17@example.test", 2}, {"device-b", 201, "24", "", 2},
		{"device-a", 201, "17", "user17@example.test", 0},
		{"revoked", 401, "", "", 1}, {"expired", 401, "", "", 1}, {"wrong-app", 403, "", "", 1}, {"other-user", 403, "", "", 1},
		{"unavailable", 502, "", "", 1}, {"redirect", 502, "", "", 1}, {"mismatch", 401, "", "", 2},
	} {
		t.Run(tc.token, func(t *testing.T) {
			records.Reset()
			before := lookups.Load()
			profile := deviceProfile{Issuer: gitlab.URL, ClientID: "app", Validator: server.URL}
			c, err := profile.config()
			if err != nil {
				t.Fatal(err)
			}
			store := token.NewFileStore(filepath.Join(t.TempDir(), "token.json"), c.Issuer, c.ClientID, c.Scope)
			if err := store.Save(context.Background(), &oauth2.Token{AccessToken: tc.token}); err != nil {
				t.Fatal(err)
			}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			local, err := proxy.New(c.Upstream, token.NewManager(store, nil), logger, nil, false, c.TokenHeader)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "http://"+deviceListen+"/rpc?q=1", strings.NewReader("payload"))
			r.Header.Set("Authorization", "Bearer app-credential")
			w := httptest.NewRecorder()
			deviceHandler(local).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			if calls := lookups.Load() - before; calls != tc.wantLookups {
				t.Errorf("GitLab calls for this request = %d, want %d", calls, tc.wantLookups)
			}
			if tc.status != 201 {
				if records.Len() != 0 {
					t.Fatal("rejected request logged as authorized")
				}
				return
			}
			var record map[string]any
			if err := json.Unmarshal(records.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["oidc_sub"] != tc.sub || record["oidc_issuer"] != gitlab.URL || w.Header().Get("X-Request-ID") != "backend-id" {
				t.Fatal("wrong identity or response headers")
			}
			if record["method"] != "POST" || record["path"] != "/rpc" || strings.Contains(records.String(), "q=1") {
				t.Error("audit event must include the incoming method and path and omit the query")
			}
			email, _ := record["gitlab_email"].(string)
			if email != tc.email || strings.Contains(records.String(), tc.token) {
				t.Fatal("unexpected email or credential in logs")
			}
		})
	}
	for _, headers := range [][]string{nil, {"Bearer device-a", "Bearer device-b"}} {
		r := httptest.NewRequest("GET", "/rpc", nil)
		for _, h := range headers {
			r.Header.Add(validator.Header, h)
		}
		w := httptest.NewRecorder()
		gateway.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("ambiguous or missing credential: %d", w.Code)
		}
	}
}

func TestDeviceAcceptsLocalCLIOnly(t *testing.T) {
	h := deviceHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected forward") }))
	for _, r := range []*http.Request{httptest.NewRequest("GET", "http://other.example/", nil), httptest.NewRequest("GET", "http://"+deviceListen+"/", nil)} {
		if r.Host == deviceListen {
			r.Header.Set("Origin", "https://example.test")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}
