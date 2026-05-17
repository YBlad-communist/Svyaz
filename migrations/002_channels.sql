-- Migration: IT Social Network v2 (без премиума, с каналами)
-- Run: psql -U svyaz -d svyaz -f migrations/002_channels.sql

-- 1. Soft delete fields for User
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_users_is_deleted ON users(is_deleted);

-- 2. GitHub & developer role fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_username VARCHAR(39);
ALTER TABLE users ADD COLUMN IF NOT EXISTS developer_role VARCHAR(20);

-- 3. Remove premium columns if they exist
ALTER TABLE users DROP COLUMN IF EXISTS premium_expires_at;
ALTER TABLE users DROP COLUMN IF EXISTS premium_badge;
ALTER TABLE users DROP COLUMN IF EXISTS profile_accent_color;

-- 4. Technology table
CREATE TABLE IF NOT EXISTS technologies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    category VARCHAR(30),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies(name);

-- 5. Role table (developer roles for ideas)
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(30) UNIQUE NOT NULL,
    label VARCHAR(50) NOT NULL,
    icon VARCHAR(20)
);

-- 6. User-Technology ManyToMany
CREATE TABLE IF NOT EXISTS user_technologies (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    technology_id INTEGER REFERENCES technologies(id) ON DELETE CASCADE,
    skill_level VARCHAR(20) DEFAULT 'intermediate',
    PRIMARY KEY (user_id, technology_id)
);

-- 7. Idea table
CREATE TABLE IF NOT EXISTS ideas (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    problem TEXT,
    solution TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    author_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    chat_id INTEGER REFERENCES chats(id) ON DELETE SET NULL,
    is_active BOOLEAN DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_ideas_author ON ideas(author_id);
CREATE INDEX IF NOT EXISTS idx_ideas_active ON ideas(is_active);

-- 8. IdeaVote table
CREATE TABLE IF NOT EXISTS idea_votes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    idea_id INTEGER REFERENCES ideas(id) ON DELETE CASCADE NOT NULL,
    vote_type VARCHAR(4) NOT NULL CHECK (vote_type IN ('up', 'down')),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_idea_votes_unique ON idea_votes(user_id, idea_id);

-- 9. Idea-Technology ManyToMany
CREATE TABLE IF NOT EXISTS idea_technologies (
    idea_id INTEGER REFERENCES ideas(id) ON DELETE CASCADE,
    technology_id INTEGER REFERENCES technologies(id) ON DELETE CASCADE,
    PRIMARY KEY (idea_id, technology_id)
);

-- 10. Idea-Role ManyToMany
CREATE TABLE IF NOT EXISTS idea_roles (
    idea_id INTEGER REFERENCES ideas(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (idea_id, role_id)
);

-- 11. Chat idea_id link
ALTER TABLE chats ADD COLUMN IF NOT EXISTS idea_id INTEGER REFERENCES ideas(id) ON DELETE SET NULL;

-- ============================================================
-- CHANNELS
-- ============================================================

-- 12. Channel table
CREATE TABLE IF NOT EXISTS channels (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(100) NOT NULL,
    description TEXT DEFAULT '',
    type VARCHAR(20) DEFAULT 'public',
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    avatar_url VARCHAR(500),
    cover_url VARCHAR(500),
    is_verified BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_channels_name ON channels(name);
CREATE INDEX IF NOT EXISTS idx_channels_owner ON channels(owner_id);

-- 13. Channel members (via channel_members table)
CREATE TABLE IF NOT EXISTS channel_members (
    id SERIAL PRIMARY KEY,
    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    role VARCHAR(20) DEFAULT 'member',
    status VARCHAR(20) DEFAULT 'active',
    joined_at TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_channel_member_unique ON channel_members(channel_id, user_id);
CREATE INDEX IF NOT EXISTS idx_channel_members_channel ON channel_members(channel_id);
CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members(user_id);

-- 14. Channel posts
CREATE TABLE IF NOT EXISTS channel_posts (
    id SERIAL PRIMARY KEY,
    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE NOT NULL,
    author_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    content TEXT NOT NULL,
    media_url VARCHAR(500),
    media_type VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    likes_count INTEGER DEFAULT 0,
    comments_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_channel_posts_channel ON channel_posts(channel_id);
CREATE INDEX IF NOT EXISTS idx_channel_posts_author ON channel_posts(author_id);

-- 15. Channel post likes
CREATE TABLE IF NOT EXISTS channel_post_likes (
    id SERIAL PRIMARY KEY,
    post_id INTEGER REFERENCES channel_posts(id) ON DELETE CASCADE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_channel_post_like_unique ON channel_post_likes(post_id, user_id);

-- 16. Channel post comments
CREATE TABLE IF NOT EXISTS channel_post_comments (
    id SERIAL PRIMARY KEY,
    post_id INTEGER REFERENCES channel_posts(id) ON DELETE CASCADE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_channel_post_comments_post ON channel_post_comments(post_id);

-- 17. Channel invites
CREATE TABLE IF NOT EXISTS channel_invites (
    id SERIAL PRIMARY KEY,
    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE NOT NULL,
    inviter_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    invitee_user_id INTEGER REFERENCES users(id),
    invitee_email VARCHAR(120),
    token VARCHAR(64) UNIQUE NOT NULL,
    expires_at TIMESTAMP,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_channel_invites_token ON channel_invites(token);
CREATE INDEX IF NOT EXISTS idx_channel_invites_channel ON channel_invites(channel_id);

-- ============================================================
-- DROP OLD PREMIUM TABLES
-- ============================================================
DROP TABLE IF EXISTS user_customizations CASCADE;
DROP TABLE IF EXISTS user_frames CASCADE;
DROP TABLE IF EXISTS avatar_frames CASCADE;

-- ============================================================
-- SEED DATA
-- ============================================================
INSERT INTO technologies (name, category) VALUES
    ('Python', 'backend'), ('JavaScript', 'frontend'), ('TypeScript', 'frontend'),
    ('React', 'frontend'), ('Vue', 'frontend'), ('Angular', 'frontend'),
    ('Flask', 'backend'), ('Django', 'backend'), ('FastAPI', 'backend'),
    ('Node.js', 'backend'), ('Go', 'backend'), ('Rust', 'backend'),
    ('Java', 'backend'), ('C#', 'backend'), ('PHP', 'backend'),
    ('PostgreSQL', 'database'), ('MySQL', 'database'), ('MongoDB', 'database'),
    ('Redis', 'database'), ('Docker', 'devops'), ('Kubernetes', 'devops'),
    ('AWS', 'devops'), ('Linux', 'devops'), ('Git', 'devops'),
    ('Machine Learning', 'ml'), ('TensorFlow', 'ml'), ('PyTorch', 'ml'),
    ('Data Science', 'ml'), ('NLP', 'ml'), ('Computer Vision', 'ml'),
    ('Figma', 'design'), ('UI/UX', 'design'),
    ('Swift', 'mobile'), ('Kotlin', 'mobile'), ('Flutter', 'mobile'),
    ('SQL', 'database'), ('GraphQL', 'backend'), ('REST API', 'backend')
ON CONFLICT (name) DO NOTHING;

INSERT INTO roles (name, label, icon) VALUES
    ('backend', 'Backend-разработчик', 'fa-server'),
    ('frontend', 'Frontend-разработчик', 'fa-code'),
    ('fullstack', 'Fullstack-разработчик', 'fa-layer-group'),
    ('ml', 'ML-инженер', 'fa-brain'),
    ('devops', 'DevOps-инженер', 'fa-cogs'),
    ('designer', 'Дизайнер', 'fa-palette'),
    ('pm', 'Project Manager', 'fa-tasks')
ON CONFLICT (name) DO NOTHING;
