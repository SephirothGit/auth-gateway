package tokensvc

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type RefreshToken struct {
	ID        uuid.UUID
	FamilyID  uuid.UUID
	UserID    uuid.UUID
	Role      string
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

type Store struct{}

func (Store) Insert(ctx context.Context, q querier, t RefreshToken, hash []byte) error {
	_, err := q.Exec(ctx, `
		INSERT INTO refresh_tokens (id, family_id, user_id, role, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		t.ID, t.FamilyID, t.UserID, t.Role, hash, t.ExpiresAt)
	return err
}

func (Store) Get(ctx context.Context, q querier, hash []byte, lock bool) (*RefreshToken, error) {
	query := `SELECT id, family_id, user_id, role, expires_at, used_at, revoked_at
		FROM refresh_tokens WHERE token_hash = $1`
	if lock {
		query += " FOR UPDATE"
	}
	var t RefreshToken
	err := q.QueryRow(ctx, query, hash).Scan(
		&t.ID, &t.FamilyID, &t.UserID, &t.Role, &t.ExpiresAt, &t.UsedAt, &t.RevokedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (Store) MarkUsed(ctx context.Context, q querier, id uuid.UUID, at time.Time) error {
	_, err := q.Exec(ctx, `UPDATE refresh_tokens SET used_at = $2 WHERE id = $1`, id, at)
	return err
}

func (Store) RevokeFamily(ctx context.Context, q querier, familyID uuid.UUID, at time.Time) error {
	_, err := q.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = $2
		WHERE family_id = $1 AND revoked_at IS NULL`, familyID, at)
	return err
}

func (Store) RevokeUser(ctx context.Context, q querier, userID uuid.UUID, at time.Time) error {
	_, err := q.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL`, userID, at)
	return err
}
