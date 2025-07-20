-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (gen_random_UUID(), NOW(), NOW(), $1)
RETURNING id AS id, created_at, updated_at, email;

-- name: DeleteUsers :exec
DELETE FROM users;