package validator

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidationCacheLifetime(t *testing.T) {
	for _, tc := range []struct {
		name, expiresIn string
		lifetime        time.Duration
	}{
		{"cache limit", "3600", 30 * time.Second},
		{"token expires first", "2", 2 * time.Second},
		{"unknown expiry", "null", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var issuerStatus atomic.Int32
			issuerStatus.Store(http.StatusOK)
			issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status := int(issuerStatus.Load()); status != http.StatusOK {
					w.WriteHeader(status)
					return
				}
				switch r.URL.Path {
				case "/oauth/token/info":
					fmt.Fprintf(w, `{"resource_owner_id":17,"scope":["openid"],"application":{"uid":"app"},"expires_in":%s}`, tc.expiresIn)
				case "/oauth/userinfo":
					io.WriteString(w, `{"sub":"17"}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer issuer.Close()
			gateway, err := New(issuer.URL, "app", "http://backend.test", []string{"17"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			h := gateway.(*handler)
			h.client.Transport = issuer.Client().Transport
			h.proxy = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			start := time.Now()
			now := start
			h.now = func() time.Time { return now }
			check := func(want int) {
				t.Helper()
				r := httptest.NewRequest("GET", "/rpc", nil)
				r.Header.Set(Header, "Bearer personal")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != want {
					t.Fatalf("at offset %v got status %d, want %d", now.Sub(start), w.Code, want)
				}
			}
			check(http.StatusNoContent)
			issuerStatus.Store(http.StatusUnauthorized)
			if tc.lifetime > 0 {
				now = start.Add(tc.lifetime - time.Nanosecond)
				check(http.StatusNoContent)
			}
			now = start.Add(tc.lifetime)
			check(http.StatusUnauthorized)
			issuerStatus.Store(http.StatusServiceUnavailable)
			check(http.StatusBadGateway)
			issuerStatus.Store(http.StatusOK)
			check(http.StatusNoContent)
		})
	}
}
