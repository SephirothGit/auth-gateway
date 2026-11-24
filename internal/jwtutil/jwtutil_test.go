package jwtutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func newPair(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSigner(priv, "iss", "aud", time.Minute)
	v := NewVerifier("iss", "aud")
	v.SetKeys(map[string]ed25519.PublicKey{s.KeyID(): s.PublicKey()})
	return s, v
}

func TestRoundTrip(t *testing.T) {
	s, v := newPair(t)
	tok, _, err := s.Sign("user-1", "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user-1" || c.Role != "admin" {
		t.Fatalf("unexpected claims: %+v", c)
	}
}

func TestExpired(t *testing.T) {
	s, v := newPair(t)
	tok, _, _ := s.Sign("u", "user", time.Now().Add(-time.Hour))
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestForeignKey(t *testing.T) {
	s, _ := newPair(t)
	_, other := newPair(t)
	tok, _, _ := s.Sign("u", "user", time.Now())
	if _, err := other.Verify(tok); err == nil {
		t.Fatal("expected error for token signed by unknown key")
	}
}