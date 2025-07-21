-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (gen_random_UUID(), NOW(), NOW(), $1, $2)
RETURNING id , created_at, updated_at, email;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: GetUserInfo :one
SELECT id, created_at, updated_at, email, hashed_password FROM users
WHERE email = $1;