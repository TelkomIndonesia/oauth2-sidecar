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
