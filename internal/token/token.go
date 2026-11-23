package token

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var ErrNotFound = errors.New("token not found")

type Store interface {
	Load(context.Context) (*oauth2.Token, error)
	Save(context.Context, *oauth2.Token) error
	Delete(context.Context) error
}
type profile struct {
	Issuer   string
	ClientID string
	Scope    string
}

type cacheEntry struct {
	Profile profile
	Token   *oauth2.Token
}

type fileStore struct {
	path    string
	profile profile
}

func (s fileStore) Load(_ context.Context) (*oauth2.Token, error) {
	b, e := os.ReadFile(s.path)
	if errors.Is(e, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	var entry cacheEntry
	if e := json.Unmarshal(b, &entry); e != nil {
		return nil, e
	}
	if entry.Profile != s.profile || entry.Token == nil {
		return nil, ErrNotFound
	}
	return entry.Token, nil
}
func (s fileStore) Save(_ context.Context, t *oauth2.Token) error {
	if e := os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	b, e := json.Marshal(cacheEntry{Profile: s.profile, Token: t})
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".token-")
	if e != nil {
		return e
	}
	n := f.Name()
	defer os.Remove(n)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(n, s.path)
}
func (s fileStore) Delete(_ context.Context) error {
	e := os.Remove(s.path)
	if errors.Is(e, os.ErrNotExist) {
		return ErrNotFound
	}
	return e
}
func NewFileStore(path, issuer, clientID, scope string) Store {
	return fileStore{path: path, profile: newProfile(issuer, clientID, scope)}
}

func newProfile(issuer, clientID, scope string) profile {
	scopes := strings.Fields(scope)
	sort.Strings(scopes)
	return profile{Issuer: issuer, ClientID: clientID, Scope: strings.Join(scopes, " ")}
}

func DefaultPath(issuer, clientID, scope, listen string) (string, error) {
	if issuer == "" || clientID == "" {
		return "", errors.New("default token cache requires --issuer and --client-id")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	p := newProfile(issuer, clientID, scope)
	key, err := json.Marshal([4]string{p.Issuer, p.ClientID, p.Scope, listen})
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "oauth2-sidecar", fmt.Sprintf("token-%x.json", sha256.Sum256(key))), nil
}

type Authenticator interface {
	Login(context.Context) (*oauth2.Token, error)
	Refresh(context.Context, *oauth2.Token) (*oauth2.Token, error)
}
type Manager struct {
	store    Store
	auth     Authenticator
	mu       sync.Mutex
	t        *oauth2.Token
	inflight *call
}
type call struct {
	done chan struct{}
	t    *oauth2.Token
	e    error
}

func NewManager(s Store, a Authenticator) *Manager { return &Manager{store: s, auth: a} }

// Acquire selects the initial token before the proxy starts serving.
func (m *Manager) Acquire(ctx context.Context, forceLogin bool) (*oauth2.Token, error) {
	if forceLogin {
		return m.login(ctx)
	}
	return m.Token(ctx)
}

func (m *Manager) Token(ctx context.Context) (*oauth2.Token, error) {
	m.mu.Lock()
	if m.t != nil && m.t.Valid() {
		t := m.t
		m.mu.Unlock()
		return t, nil
	}
	if m.t == nil {
		if t, e := m.store.Load(ctx); e == nil {
			m.t = t
			if t.Valid() {
				m.mu.Unlock()
				return t, nil
			}
		}
	}
	old := m.t
	m.mu.Unlock()
	if old != nil && old.RefreshToken != "" {
		if t, e := m.refresh(ctx, old); e == nil {
			return t, nil
		}
	}
	return m.login(ctx)
}
func (m *Manager) AccessToken(ctx context.Context) (string, error) {
	t, e := m.Token(ctx)
	if e != nil {
		return "", e
	}
	return t.AccessToken, nil
}
func (m *Manager) refresh(ctx context.Context, old *oauth2.Token) (*oauth2.Token, error) {
	return m.single(ctx, func(c context.Context) (*oauth2.Token, error) {
		t, e := m.auth.Refresh(c, old)
		if e == nil {
			if t.RefreshToken == "" {
				t.RefreshToken = old.RefreshToken
			}
			e = m.store.Save(c, t)
		}
		return t, e
	})
}
func (m *Manager) login(ctx context.Context) (*oauth2.Token, error) {
	return m.single(ctx, func(c context.Context) (*oauth2.Token, error) {
		t, e := m.auth.Login(c)
		if e == nil {
			e = m.store.Save(c, t)
		}
		return t, e
	})
}
func (m *Manager) single(ctx context.Context, fn func(context.Context) (*oauth2.Token, error)) (*oauth2.Token, error) {
	m.mu.Lock()
	if m.inflight != nil {
		c := m.inflight
		m.mu.Unlock()
		select {
		case <-c.done:
			return c.t, c.e
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	m.inflight = c
	m.mu.Unlock()
	t, e := fn(ctx)
	m.mu.Lock()
	if e == nil {
		m.t = t
	}
	c.t, c.e = t, e
	close(c.done)
	m.inflight = nil
	m.mu.Unlock()
	return t, e
}
