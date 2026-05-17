-- Migration: IT Social Network
-- Run: psql -U svyaz -d svyaz -f migrations/001_it_social_network.sql

-- 1. Soft delete fields for User
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_users_is_deleted ON users(is_deleted);

-- 2. GitHub & developer role fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_username VARCHAR(39);
ALTER TABLE users ADD COLUMN IF NOT EXISTS developer_role VARCHAR(20);

-- 3. Technology table
CREATE TABLE IF NOT EXISTS technologies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    category VARCHAR(30),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies(name);

-- 4. Role table (developer roles for ideas)
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(30) UNIQUE NOT NULL,
    label VARCHAR(50) NOT NULL,
    icon VARCHAR(20)
);

-- 5. User-Technology ManyToMany
CREATE TABLE IF NOT EXISTS user_technologies (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    technology_id INTEGER REFERENCES technologies(id) ON DELETE CASCADE,
    skill_level VARCHAR(20) DEFAULT 'intermediate',
    PRIMARY KEY (user_id, technology_id)
);

-- 6. Idea table
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
CREATE INDEX IF NOT EXISTS idx_ideas_created ON ideas(created_at DESC);

-- 7. IdeaVote table
CREATE TABLE IF NOT EXISTS idea_votes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    idea_id INTEGER REFERENCES ideas(id) ON DELETE CASCADE NOT NULL,
    vote_type VARCHAR(4) NOT NULL CHECK (vote_type IN ('up', 'down')),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_idea_votes_unique ON idea_votes(user_id, idea_id);
CREATE INDEX IF NOT EXISTS idx_idea_votes_idea ON idea_votes(idea_id);

-- 8. Idea-Technology ManyToMany
CREATE TABLE IF NOT EXISTS idea_technologies (
    idea_id INTEGER REFERENCES ideas(id) ON DELETE CASCADE,
    technology_id INTEGER REFERENCES technologies(id) ON DELETE CASCADE,
    PRIMARY KEY (idea_id, technology_id)
);

-- 9. Idea-Role ManyToMany
CREATE TABLE IF NOT EXISTS idea_roles (
    idea_id INTEGER REFERENCES ideas(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (idea_id, role_id)
);

-- 10. Chat idea_id link
ALTER TABLE chats ADD COLUMN IF NOT EXISTS idea_id INTEGER REFERENCES ideas(id) ON DELETE SET NULL;

-- Seed default technologies
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

-- Seed default roles
INSERT INTO roles (name, label, icon) VALUES
    ('backend', 'Backend-разработчик', 'fa-server'),
    ('frontend', 'Frontend-разработчик', 'fa-code'),
    ('fullstack', 'Fullstack-разработчик', 'fa-layer-group'),
    ('ml', 'ML-инженер', 'fa-brain'),
    ('devops', 'DevOps-инженер', 'fa-cogs'),
    ('designer', 'Дизайнер', 'fa-palette'),
    ('pm', 'Project Manager', 'fa-tasks')
ON CONFLICT (name) DO NOTHING;
