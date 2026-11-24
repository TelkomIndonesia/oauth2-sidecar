package validator

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

func TestPeerLookupBudget(t *testing.T) {
	var calls atomic.Int32
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer issuer.Close()
	gateway, err := New(issuer.URL, "app", "http://backend.test", []string{"17"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := gateway.(*handler)
	h.client.Transport = issuer.Client().Transport
	now := time.Now()
	h.now = func() time.Time { return now }
	h.proxy = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cached := "cached-fixture"
	h.remember(sha256.Sum256([]byte(cached)), identity{sub: "17", validUntil: now.Add(validationTTL)})
	// Leave one real lookup available to the first TCP peer.
	peer := netip.MustParseAddr("192.0.2.10")
	h.lookups = lookupBudget{until: now.Add(time.Minute), used: map[netip.Addr]int{peer: lookupsPerMinute - 1}}
	check := func(remote, bearer string, want int, wantCalls int32) {
		t.Helper()
		r := httptest.NewRequest("GET", "/rpc", nil)
		r.RemoteAddr = remote
		r.Header.Set(Header, "Bearer "+bearer)
		r.Header.Set("X-Forwarded-For", "198.51.100.8")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want || calls.Load() != wantCalls {
			t.Fatalf("status=%d calls=%d, want %d/%d", w.Code, calls.Load(), want, wantCalls)
		}
		if want == 429 && w.Header().Get("Retry-After") != "60" {
			t.Fatal("missing retry window")
		}
	}
	check("192.0.2.10:3001", "invalid", 401, 1)
	check("192.0.2.10:3002", "other", 429, 1)
	check("192.0.2.10:3002", cached, 204, 1)
	check("192.0.2.20:3001", "invalid", 401, 2)
	now = now.Add(time.Minute)
	check("192.0.2.10:3001", "invalid", 401, 3)
}

func TestLookupBudgetReservations(t *testing.T) {
	var budget lookupBudget
	now := time.Now()
	remote := netip.MustParseAddr("192.0.2.1")
	var pending []func()
	for i := 0; i < lookupsPerMinute; i++ {
		refund, _ := budget.reserve(remote, now)
		if refund == nil {
			t.Fatal("early rejection")
		}
		pending = append(pending, refund)
	}
	if refund, _ := budget.reserve(remote, now); refund != nil {
		t.Fatal("parallel reservations exceeded limit")
	}
	pending[0]()
	if refund, _ := budget.reserve(remote, now); refund == nil {
		t.Fatal("successful lookup did not free its slot")
	}
	later := now.Add(time.Minute)
	next, _ := budget.reserve(remote, later)
	pending[1]()
	if budget.used[netip.MustParseAddr("192.0.2.1")] != 1 {
		t.Fatal("old completion changed the next window")
	}
	next()
}

func TestLookupPeer(t *testing.T) {
	networks := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	for _, tc := range []struct {
		remote string
		chain  []string
		want   string
	}{
		{"198.51.100.7:1000", []string{"203.0.113.9"}, "198.51.100.7"},
		{"192.0.2.1:1000", []string{"203.0.113.9, 198.51.100.7", "192.0.2.2"}, "198.51.100.7"},
		{"192.0.2.1:1000", []string{"203.0.113.9, broken"}, "192.0.2.1"},
		{"192.0.2.1:1000", nil, "192.0.2.1"},
		{"192.0.2.1:1000", []string{"2001:db8::123"}, "2001:db8::123"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		for _, line := range tc.chain {
			r.Header.Add("X-Forwarded-For", line)
		}
		if got := lookupPeer(r, networks).String(); got != tc.want {
			t.Errorf("peer %v, chain %v: got %s, want %s", tc.remote, tc.chain, got, tc.want)
		}
	}
}
