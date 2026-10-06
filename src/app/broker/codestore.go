package broker

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

type Grant struct {
	ClientID     string
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	Scope        string
}

type CodeStore struct {
	mu    sync.Mutex
	items map[string]codeEntry
	ttl   time.Duration
	stop  chan struct{}
	done  chan struct{}
}

type codeEntry struct {
	grant  Grant
	expiry time.Time
}

func NewCodeStore(ttl time.Duration) *CodeStore {
	s := &CodeStore{
		items: make(map[string]codeEntry),
		ttl:   ttl,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

func (s *CodeStore) Mint(grant Grant) (string, error) {
	if grant.ClientID == "" {
		return "", fmt.Errorf("mint: client id is empty")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint: generate code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[code] = codeEntry{
		grant:  grant,
		expiry: time.Now().Add(s.ttl),
	}
	return code, nil
}

func (s *CodeStore) Exchange(code, clientID string) (Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.items[code]
	if !ok {
		return Grant{}, false
	}

	if time.Now().After(entry.expiry) {
		delete(s.items, code)
		return Grant{}, false
	}

	if entry.grant.ClientID != clientID {
		return Grant{}, false
	}

	delete(s.items, code)
	return entry.grant, true
}

func (s *CodeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapExpiredLocked()
	return len(s.items)
}

func (s *CodeStore) Close() {
	select {
	case <-s.stop:
		return
	default:
	}
	close(s.stop)
	<-s.done
}

func (s *CodeStore) cleanupLoop() {
	defer close(s.done)
	interval := s.ttl / 2
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			s.reapExpiredLocked()
			s.mu.Unlock()
		}
	}
}

func (s *CodeStore) reapExpiredLocked() {
	now := time.Now()
	for code, entry := range s.items {
		if now.After(entry.expiry) {
			delete(s.items, code)
		}
	}
}
