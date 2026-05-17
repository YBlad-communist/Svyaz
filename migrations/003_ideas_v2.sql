-- Migration: Ideas v2 (likes + join requests)
-- Run: psql -U svyaz -d svyaz -f migrations/003_ideas_v2.sql

-- 1. Drop old idea_votes table
DROP TABLE IF EXISTS idea_votes CASCADE;

-- 2. Idea likes (simple like, no up/down)
CREATE TABLE IF NOT EXISTS idea_likes (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    idea_id INTEGER REFERENCES ideas(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (user_id, idea_id)
);
CREATE INDEX IF NOT EXISTS idx_idea_likes_idea ON idea_likes(idea_id);

-- 3. Idea join requests
CREATE TABLE IF NOT EXISTS idea_join_requests (
    id SERIAL PRIMARY KEY,
    idea_id INTEGER REFERENCES ideas(id) ON DELETE CASCADE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_idea_join_request_unique ON idea_join_requests(idea_id, user_id);
CREATE INDEX IF NOT EXISTS idx_idea_join_requests_idea ON idea_join_requests(idea_id);
CREATE INDEX IF NOT EXISTS idx_idea_join_requests_user ON idea_join_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_idea_join_requests_status ON idea_join_requests(status);
