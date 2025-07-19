-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (gen_random_UUID(), NOW(), NOW(), $1)
RETURNING id, created_at, updated_at, email;