package tokensvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SephirothGit/auth-gateway/internal/jwtutil"
)

var (
	ErrInvalidRefresh  = errors.New("tokensvc: invalid refresh token")
	ErrInvalidArgument = errors.New("tokensvc: invalid argument")
)

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

type Service struct {
	pool       *pgxpool.Pool
	store      Store
	signer     *jwtutil.Signer
	refreshTTL time.Duration
	now        func() time.Time
}

func NewService(pool *pgxpool.Pool, signer *jwtutil.Signer, refreshTTL time.Duration) *Service {
	return &Service{pool: pool, signer: signer, refreshTTL: refreshTTL, now: time.Now}
}

func (s *Service) Issue(ctx context.Context, userID uuid.UUID, role string) (*TokenPair, error) {
	if role != "admin" && role != "user" {
		return nil, fmt.Errorf("%w: unknown role %q", ErrInvalidArgument, role)

	}
	now := s.now()
	return s.issue(ctx, s.pool, userID, role, uuid.New(), now, now.Add(s.refreshTTL))
}

func (s *Service) Refresh(ctx context.Context, raw string) (*TokenPair, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	now := s.now()

	rt, err := s.store.Get(ctx, tx, hashToken(raw), true)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidRefresh
	}
	if err != nil {
		return nil, err
	}

	if rt.RevokedAt != nil || !now.Before(rt.ExpiresAt) {
		return nil, ErrInvalidRefresh
	}

	if rt.UsedAt != nil {
		if err := s.store.RevokeFamily(ctx, tx, rt.FamilyID, now); err != nil {
			return nil, err
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrInvalidRefresh
	}

	if err := s.store.MarkUsed(ctx, tx, rt.ID, now); err != nil {
		return nil, err
	}
	pair, err := s.issue(ctx, tx, rt.UserID, rt.Role, rt.FamilyID, now, rt.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

func (s *Service) RevokeToken(ctx context.Context, raw string) error {
	rt, err := s.store.Get(ctx, s.pool, hashToken(raw), false)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.store.RevokeFamily(ctx, s.pool, rt.FamilyID, s.now())
}

func (s *Service) RevokeUser(ctx context.Context, userID uuid.UUID) error {
	return s.store.RevokeUser(ctx, s.pool, userID, s.now())
}

func (s *Service) issue(ctx context.Context, q querier, userID uuid.UUID, role string, familyID uuid.UUID, now, refreshExp time.Time) (*TokenPair, error) {
	access, accessExp, err := s.signer.Sign(userID.String(), role, now)
	if err != nil {
		return nil, err
	}
	raw, hash, err := newRefreshToken()
	if err != nil {
		return nil, err
	}

	err = s.store.Insert(ctx, q, RefreshToken{
		ID:        uuid.New(),
		FamilyID:  familyID,
		UserID:    userID,
		Role:      role,
		ExpiresAt: refreshExp,
	}, hash)
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:      access,
		RefreshToken:     raw,
		AccessExpiresAt:  accessExp,
		RefreshExpiresAt: refreshExp,
	}, nil
}

func newRefreshToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
