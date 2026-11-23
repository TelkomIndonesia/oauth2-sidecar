package token

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

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
