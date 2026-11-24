-- +goose Up
ALTER TABLE refresh_tokens ADD COLUMN role TEXT NOT NULL DEFAULT 'user';

-- +goose Down
ALTER TABLE refresh_tokens DROP COLUMN role;