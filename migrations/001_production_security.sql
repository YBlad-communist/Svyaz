-- Svyaz database migration
-- This file runs automatically on first container startup via docker-entrypoint-initdb.d.
-- Column additions for E2EE + 2FA

ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(32);
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_public_key TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_backup_key TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 1;

CREATE TABLE IF NOT EXISTS prekeys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    key_id INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_prekeys_user_id ON prekeys(user_id);

CREATE TABLE IF NOT EXISTS encrypted_messages (
    id SERIAL PRIMARY KEY,
    chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
    sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    ephemeral_key TEXT NOT NULL,
    salt VARCHAR(64) NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    read_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_enc_msg_chat_created ON encrypted_messages(chat_id, created_at);

CREATE TABLE IF NOT EXISTS signal_sessions (
    id SERIAL PRIMARY KEY,
    chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    their_identity_key TEXT NOT NULL,
    our_ephemeral_key TEXT NOT NULL,
    session_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(chat_id, user_id)
);

ALTER TABLE chats ADD COLUMN IF NOT EXISTS is_e2ee BOOLEAN DEFAULT FALSE;
