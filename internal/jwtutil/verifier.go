package jwtutil

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("jwtutil: invalid token")

type Verifier struct {
	issuer   string
	audience string

	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

func NewVerifier(issuer, audience string) *Verifier {
	return &Verifier{issuer: issuer, audience: audience, keys: map[string]ed25519.PublicKey{}}
}

func (v *Verifier) SetKeys(keys map[string]ed25519.PublicKey) {
	cp := make(map[string]ed25519.PublicKey, len(keys))
	for k, pk := range keys {
		cp[k] = pk
	}
	v.mu.Lock()
	v.keys = cp
	v.mu.Unlock()
}

func (v *Verifier) Verify(raw string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, v.keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return claims, nil
}

func (v *Verifier) keyFunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("missing kid")
	}
	v.mu.RLock()
	key, ok := v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, errors.New("unknown kid")
	}
	return key, nil
}