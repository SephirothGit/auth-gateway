package jwtutil

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

type Signer struct {
	priv     ed25519.PrivateKey
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
}

func NewSigner(priv ed25519.PrivateKey, issuer, audience string, ttl time.Duration) *Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{priv: priv, kid: KeyID(pub), issuer: issuer, audience: audience, ttl: ttl}
}

func (s *Signer) KeyID() string { return s.kid }

func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// выпуск acess токена
func (s *Signer) Sign(userID, role string, now time.Time) (string, time.Time, error) {
	exp := now.Add(s.ttl)
	claims := Claims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{s.audience},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = s.kid

	signed, err := tok.SignedString(s.priv)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwtutil: sign: %w", err)
	}
	return signed, exp, nil
}