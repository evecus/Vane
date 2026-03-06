package api

import (
	"crypto/rand"
	"fmt"
)

func generateToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
