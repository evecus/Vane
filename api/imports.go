package api

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// ─── Session store (mutex-protected) ─────────────────────────────────────────

type sessionStore struct {
	mu   sync.Mutex
	data map[string]time.Time
}

var sessions = &sessionStore{data: make(map[string]time.Time)}

func (s *sessionStore) set(token string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[token] = exp
}

func (s *sessionStore) get(token string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.data[token]
	return exp, ok
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
}

// purgeExpired removes sessions whose expiry has passed.
func (s *sessionStore) purgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for tok, exp := range s.data {
		if now.After(exp) {
			delete(s.data, tok)
		}
	}
}

func init() {
	// Background goroutine to clean up expired sessions every hour
	go func() {
		t := time.NewTicker(time.Hour)
		for range t.C {
			sessions.purgeExpired()
		}
	}()
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
