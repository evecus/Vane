package api

import (
	"crypto/rand"
	"fmt"
)

func generateToken() string {
	b := make([]byte, 32) // 256-bit token
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
