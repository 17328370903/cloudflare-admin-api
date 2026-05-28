DROP TABLE IF EXISTS users;

CREATE TABLE users
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    password        TEXT NOT NULL,
    last_login_time TEXT,
    last_login_ip   TEXT,
    created_at      TEXT,
    updated_at      TEXT
);

INSERT INTO users (name, password, last_login_time, last_login_ip, created_at, updated_at)
VALUES ('admin', 'e10adc3949ba59abbe56e057f20f883e', '2026-01-01 00:00:00', '127.0.0.1', '2026-01-01 00:00:00', '2026-01-01 00:00:00');