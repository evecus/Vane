// Package store provides an encrypted SQLite-backed key-value store.
// All values are encrypted with AES-256-GCM before being written to disk.
// The encryption key is derived from a machine-specific secret using PBKDF2-SHA256.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2Iter = 200_000
	keyLen     = 32 // AES-256
)

// Store is a thread-safe, encrypted SQLite key-value store organised into buckets.
type Store struct {
	mu  sync.RWMutex
	db  *sql.DB
	gcm cipher.AEAD
}

// Open opens (or creates) the encrypted database at path.
// secret is used to derive the AES key; it should come from a secure source.
func Open(path, secret string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store open: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer

	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS kv (
			bucket TEXT NOT NULL,
			key    TEXT NOT NULL,
			value  BLOB NOT NULL,
			PRIMARY KEY (bucket, key)
		);
	`); err != nil {
		return nil, fmt.Errorf("store init schema: %w", err)
	}

	salt := deriveSalt(path)
	rawKey := pbkdf2.Key([]byte(secret), salt, pbkdf2Iter, keyLen, sha256.New)
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Store{db: db, gcm: gcm}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Set encrypts value and stores it under bucket/key.
func (s *Store) Set(bucket, key, value string) error {
	enc, err := s.encrypt([]byte(value))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(
		`INSERT INTO kv (bucket,key,value) VALUES(?,?,?) ON CONFLICT(bucket,key) DO UPDATE SET value=excluded.value`,
		bucket, key, enc,
	)
	return err
}

// Get retrieves and decrypts the value at bucket/key.
// Returns ("", false, nil) when not found.
func (s *Store) Get(bucket, key string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var enc []byte
	err := s.db.QueryRow(`SELECT value FROM kv WHERE bucket=? AND key=?`, bucket, key).Scan(&enc)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := s.decrypt(enc)
	if err != nil {
		return "", false, err
	}
	return string(plain), true, nil
}

// Delete removes bucket/key. No error if not found.
func (s *Store) Delete(bucket, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM kv WHERE bucket=? AND key=?`, bucket, key)
	return err
}

// Keys returns all keys in a bucket.
func (s *Store) Keys(bucket string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT key FROM kv WHERE bucket=? ORDER BY key`, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// DeleteBucket removes all rows in a bucket.
func (s *Store) DeleteBucket(bucket string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM kv WHERE bucket=?`, bucket)
	return err
}

// ── encryption helpers ────────────────────────────────────────────────────────

func (s *Store) encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.gcm.Seal(nonce, nonce, plain, nil), nil
}

func (s *Store) decrypt(data []byte) ([]byte, error) {
	ns := s.gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return s.gcm.Open(nil, data[:ns], data[ns:], nil)
}

// deriveSalt creates a deterministic but path-specific salt.
func deriveSalt(path string) []byte {
	h := sha256.Sum256([]byte("vane-store-v1:" + path))
	return h[:]
}

// MachineSecret returns a stable per-host secret based on hostname + a fixed salt.
// Falls back to a fixed string if hostname is unavailable.
func MachineSecret() string {
	host, err := os.Hostname()
	if err != nil {
		host = "vane-fallback-host"
	}
	h := sha256.Sum256([]byte("vane-machine-secret-2024:" + host))
	return hex.EncodeToString(h[:])
}
