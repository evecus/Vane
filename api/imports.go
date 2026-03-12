package api

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"
)

// ─── Session store (SQLite-backed, memory-cached) ─────────────────────────────
//
// Sessions are persisted to the database so they survive process restarts
// (e.g. the automatic restart that happens when the admin port is changed).
// An in-memory cache is kept for fast lookups; DB is the source of truth.

type sessionStore struct {
	mu   sync.Mutex
	data map[string]time.Time // in-memory cache
	db   *sql.DB              // nil until initDB is called
}

var sessions = &sessionStore{data: make(map[string]time.Time)}

// initDB must be called once at startup with the application's DB handle.
// It loads all non-expired sessions into the in-memory cache.
func (s *sessionStore) initDB(db *sql.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = db

	rows, err := db.Query(`SELECT token, expires_at FROM sessions WHERE expires_at > ?`, time.Now().Unix())
	if err != nil {
		log.Printf("[sessions] load failed: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var token string
		var expUnix int64
		if err := rows.Scan(&token, &expUnix); err == nil {
			s.data[token] = time.Unix(expUnix, 0)
		}
	}
}

func (s *sessionStore) set(token string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[token] = exp
	if s.db != nil {
		_, err := s.db.Exec(
			`INSERT INTO sessions(token, expires_at) VALUES(?,?)
			 ON CONFLICT(token) DO UPDATE SET expires_at=excluded.expires_at`,
			token, exp.Unix(),
		)
		if err != nil {
			log.Printf("[sessions] persist set error: %v", err)
		}
	}
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
	if s.db != nil {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	}
}

// clearAll removes all active sessions (forces re-login for all clients).
func (s *sessionStore) clearAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]time.Time)
	if s.db != nil {
		_, _ = s.db.Exec(`DELETE FROM sessions`)
	}
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
	if s.db != nil {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now.Unix())
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

// InitSessions wires the session store to the application database.
// Must be called once after the DB is ready, before any request is served.
func InitSessions(db *sql.DB) {
	sessions.initDB(db)
}
