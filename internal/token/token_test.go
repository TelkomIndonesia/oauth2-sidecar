package token

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestFileStoreProfile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cache")
	store := NewFileStore(path, "issuer", "client", "openid profile")
	if err := os.WriteFile(path, []byte(`{"access_token":"legacy"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("legacy cache: %v", err)
	}
	if err := store.Save(ctx, &oauth2.Token{AccessToken: "example"}); err != nil {
		t.Fatal(err)
	}
	for _, other := range []Store{
		NewFileStore(path, "other", "client", "openid profile"),
		NewFileStore(path, "issuer", "other", "openid profile"),
		NewFileStore(path, "issuer", "client", "openid"),
	} {
		if _, err := other.Load(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatalf("different profile: %v", err)
		}
	}
	same := NewFileStore(path, "issuer", "client", "profile openid")
	tok, err := same.Load(ctx)
	if err != nil || tok.AccessToken != "example" {
		t.Fatal("same profile did not reuse token", err)
	}
}

type loginStub struct {
	Authenticator
	calls int
	err   error
}

func (a *loginStub) Login(context.Context) (*oauth2.Token, error) {
	a.calls++
	return &oauth2.Token{AccessToken: "fresh"}, a.err
}

func TestForcedLogin(t *testing.T) {
	ctx := context.Background()
	store := NewFileStore(filepath.Join(t.TempDir(), "cache"), "issuer", "client", "openid")
	if err := store.Save(ctx, &oauth2.Token{AccessToken: "cached"}); err != nil {
		t.Fatal(err)
	}
	auth := &loginStub{}
	manager := NewManager(store, auth)
	tok, err := manager.Acquire(ctx, false)
	if err != nil || tok.AccessToken != "cached" || auth.calls != 0 {
		t.Fatal("normal startup did not reuse cache", err)
	}
	auth.err = errors.New("login failed")
	if _, err := manager.Acquire(ctx, true); !errors.Is(err, auth.err) {
		t.Fatal("missing login failure", err)
	}
	tok, err = store.Load(ctx)
	if err != nil || tok.AccessToken != "cached" {
		t.Fatal("failed login replaced cache", err)
	}
	auth.err = nil
	tok, err = manager.Acquire(ctx, true)
	if err != nil || tok.AccessToken != "fresh" || auth.calls != 2 {
		t.Fatal("forced login did not authenticate", err)
	}
	tok, err = store.Load(ctx)
	if err != nil || tok.AccessToken != "fresh" {
		t.Fatal("fresh token missing from cache", err)
	}
}

func TestIndependentSessionUpdates(t *testing.T) {
	ctx := context.Background()
	path := func(client, scope, listen string) string {
		t.Helper()
		p, err := DefaultPath("issuer", client, scope, listen)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Base(p)
	}
	dir := t.TempDir()
	open := func(port string) Store {
		return NewFileStore(filepath.Join(dir, path("client", "openid profile", port)), "issuer", "client", "openid profile")
	}
	a, b := open("localhost:8001"), open("localhost:8002")
	save := func(s Store, v string) {
		t.Helper()
		if err := s.Save(ctx, &oauth2.Token{AccessToken: v}); err != nil {
			t.Fatal(err)
		}
	}
	save(a, "first")
	save(b, "second")
	save(a, "updated")
	for port, want := range map[string]string{"localhost:8001": "updated", "localhost:8002": "second"} {
		tok, err := open(port).Load(ctx)
		if err != nil || tok.AccessToken != want {
			t.Fatalf("session %s lost its update: %v", port, err)
		}
	}
	first := path("client", "openid profile", "localhost:8001")
	if first == path("other", "openid profile", "localhost:8001") || first != path("client", "profile openid", "localhost:8001") {
		t.Fatal("unstable profile key")
	}
}

type testAuth struct {
	refreshErr               error
	loginCount, refreshCount int
}

func (a *testAuth) Login(context.Context) (*oauth2.Token, error) {
	a.loginCount++
	return &oauth2.Token{AccessToken: "login"}, nil
}
func (a *testAuth) Refresh(context.Context, *oauth2.Token) (*oauth2.Token, error) {
	a.refreshCount++
	return &oauth2.Token{AccessToken: "refreshed"}, a.refreshErr
}

func TestAcquire(t *testing.T) {
	t.Run("cache read error", func(t *testing.T) {
		store := NewFileStore(t.TempDir(), "issuer", "client", "openid")
		auth := &testAuth{}
		_, err := NewManager(store, auth).Acquire(context.Background(), false)
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) || auth.loginCount != 0 || auth.refreshCount != 0 {
			t.Fatalf("expected cache I/O error before authentication, got %v (logins %d, refreshes %d)", err, auth.loginCount, auth.refreshCount)
		}
	})
	transient := errors.New("issuer unavailable")
	for _, tc := range []struct {
		name, cache       string
		force             bool
		refreshErr        error
		want              string
		logins, refreshes int
	}{
		{"cached", "valid", false, nil, "saved", 0, 0},
		{"force", "valid", true, nil, "login", 1, 0},
		{"corrupt", "corrupt", false, nil, "login", 1, 0},
		{"expired", "expired", false, nil, "refreshed", 0, 1},
		{"temporary failure", "expired", false, transient, "", 0, 1},
		{"invalid client", "expired", false, &oauth2.RetrieveError{ErrorCode: "invalid_client"}, "", 0, 1},
		{"non-JSON rejection", "expired", false, &oauth2.RetrieveError{Response: &http.Response{StatusCode: 403, Status: "403 Forbidden"}, Body: []byte("Forbidden")}, "", 0, 1},
		{"revoked", "expired", false, &oauth2.RetrieveError{ErrorCode: "invalid_grant"}, "login", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "token.json")
			s := NewFileStore(path, "issuer", "client", "openid")
			if tc.cache == "corrupt" {
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				old := &oauth2.Token{AccessToken: "saved", RefreshToken: "refresh"}
				if tc.cache == "expired" {
					old.Expiry = time.Now().Add(-time.Hour)
				}
				if err := s.Save(ctx, old); err != nil {
					t.Fatal(err)
				}
			}
			a := &testAuth{refreshErr: tc.refreshErr}
			got, err := NewManager(s, a).Acquire(ctx, tc.force)
			if tc.want == "" {
				if !errors.Is(err, tc.refreshErr) {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.Contains(err.Error(), "--login") {
					t.Fatalf("refresh error missing recovery hint: %v", err)
				}
			} else if err != nil || got.AccessToken != tc.want {
				t.Fatalf("token %v, error %v", got, err)
			}
			saved, err := s.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && saved.AccessToken != tc.want || tc.want == "" && saved.AccessToken != "saved" {
				t.Fatalf("unexpected persisted access token %q", saved.AccessToken)
			}
			if tc.want == "refreshed" && saved.RefreshToken != "refresh" {
				t.Fatal("refresh token lost")
			}
			if a.loginCount != tc.logins || a.refreshCount != tc.refreshes {
				t.Fatalf("logins %d, refreshes %d", a.loginCount, a.refreshCount)
			}
		})
	}
}
