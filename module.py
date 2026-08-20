from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
import base64
from database import db
import html
import re
import nh3

# ============================================================
# Many-to-Many Tables
# ============================================================
chat_participants = db.Table('chat_participants',
    db.Column('chat_id', db.Integer, db.ForeignKey('chats.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)
idea_roles = db.Table('idea_roles',
    db.Column('idea_id', db.Integer, db.ForeignKey('ideas.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)
idea_technologies = db.Table('idea_technologies',
    db.Column('idea_id', db.Integer, db.ForeignKey('ideas.id'), primary_key=True),
    db.Column('technology_id', db.Integer, db.ForeignKey('technologies.id'), primary_key=True)
)
idea_likes = db.Table('idea_likes',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('idea_id', db.Integer, db.ForeignKey('ideas.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)
)
idea_join_requests = db.Table('idea_join_requests',
    db.Column('id', db.Integer, primary_key=True),
    db.Column('idea_id', db.Integer, db.ForeignKey('ideas.id'), nullable=False, index=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False, index=True),
    db.Column('status', db.String(20), default='pending'),
    db.Column('created_at', db.DateTime, default=datetime.utcnow),
    db.UniqueConstraint('idea_id', 'user_id', name='unique_idea_join_request')
)
user_technologies = db.Table('user_technologies',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('technology_id', db.Integer, db.ForeignKey('technologies.id'), primary_key=True),
    db.Column('skill_level', db.String(20), default='intermediate')
)
channel_members = db.Table('channel_members',
    db.Column('id', db.Integer, primary_key=True),
    db.Column('channel_id', db.Integer, db.ForeignKey('channels.id'), nullable=False, index=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False, index=True),
    db.Column('role', db.String(20), default='member'),
    db.Column('status', db.String(20), default='active'),
    db.Column('joined_at', db.DateTime, default=datetime.utcnow),
    db.UniqueConstraint('channel_id', 'user_id', name='unique_channel_member')
)
post_hashtags = db.Table('post_hashtags',
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id'), primary_key=True),
    db.Column('hashtag_id', db.Integer, db.ForeignKey('hashtags.id'), primary_key=True)
)

# ============================================================
# Constants
# ============================================================
DEVELOPER_ROLES = [
    'backend', 'frontend', 'fullstack', 'ml', 'devops', 'designer', 'pm',
    'mobile', 'game-dev', 'data-engineer', 'qa', 'security', 'architect',
    'tech-lead', 'sre', 'sysadmin', 'embedded', 'gamedesigner', '3d-artist',
    'animator', 'sound-designer', 'narrative-designer', 'community-manager',
]
SKILL_LEVELS = ['beginner', 'intermediate', 'advanced', 'expert']
PROJECT_TYPES = [
    'game', 'website', 'app', 'library', 'framework',
    'cli', 'api', 'plugin', 'bot', 'saas',
    'browser-ext', 'desktop', 'embedded', 'other',
]

ALLOWED_TAGS = frozenset({
    'b', 'i', 'u', 'strong', 'em', 'code', 'pre', 'blockquote',
    'ul', 'ol', 'li', 'a', 'p', 'br', 'hr', 'h1', 'h2', 'h3',
    'h4', 'h5', 'h6', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'img', 'span', 'div', 'del', 'ins', 'sub', 'sup',
})
ALLOWED_ATTRIBUTES = {
    'a': {'href', 'title'},
    'img': {'src', 'alt', 'title'},
    'td': {'colspan', 'rowspan'},
    'th': {'colspan', 'rowspan'},
    '*': {'class'},
}
ALLOWED_URL_SCHEMES = {'http', 'https', 'mailto'}

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')

# ============================================================
# User Model (with 2FA + E2EE support)
# ============================================================
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(500), default='https://ui-avatars.com/api/?background=random&name=User')
    bio = db.Column(db.Text, default='')
    location = db.Column(db.String(100), default='')
    website = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='default')
    is_blocked = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False, index=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    github_username = db.Column(db.String(39), nullable=True)
    developer_role = db.Column(db.String(20), nullable=True)
    verified = db.Column(db.Boolean, default=False)

    # 2FA / TOTP
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)

    # E2EE: identity keypair (X25519) — base64 encoded
    identity_public_key = db.Column(db.Text, nullable=True)

    # Backup encryption key for message recovery (encrypted with user's password)
    encrypted_backup_key = db.Column(db.Text, nullable=True)

    # Sessions for JWT-like token rotation
    session_version = db.Column(db.Integer, default=1)

    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    following = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower', lazy='dynamic', cascade='all, delete-orphan')
    followers = db.relationship('Follow', foreign_keys='Follow.followed_id', backref='followed', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    chats = db.relationship('Chat', secondary=chat_participants, lazy='dynamic', backref=db.backref('participants', lazy='dynamic'))
    tech_stack = db.relationship('Technology', secondary=user_technologies, lazy='dynamic', backref=db.backref('users', lazy='dynamic'))
    ideas = db.relationship('Idea', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    owned_channels = db.relationship('Channel', backref='owner', lazy='dynamic')
    channel_memberships = db.relationship('Channel', secondary=channel_members, lazy='dynamic',
                                          backref=db.backref('members', lazy='dynamic'))

    # E2EE prekeys
    prekeys = db.relationship('PreKey', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    # 2FA recovery codes
    recovery_codes = db.relationship('RecoveryCode', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_following(self, user):
        return self.following.filter_by(followed_id=user.id).first() is not None

    def get_feed_posts(self):
        followed_users = [u.id for u in self.following.all()] + [self.id]
        return Post.query.filter(Post.user_id.in_(followed_users)).order_by(Post.created_at.desc())

    def can_delete_post(self, post):
        return self.id == post.user_id or self.role in ('admin', 'moderator')

    def is_superadmin(self):
        return self.role == 'admin' or self.is_admin

    def is_moderator(self):
        return self.role in ('admin', 'moderator') or self.is_admin

    def warning_count(self):
        return self.warnings.count()

    def anonymize(self):
        self.username = f"user_{self.id}"
        self.avatar = "https://ui-avatars.com/api/?background=gray&name=Deleted"
        self.bio = ""
        self.location = ""
        self.website = ""
        self.github_username = None
        self.developer_role = None
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()
        self.is_active = False
        self.totp_secret = None
        self.totp_enabled = False
        self.identity_public_key = None
        self.encrypted_backup_key = None

    @property
    def display_name(self):
        return "Deleted user" if self.is_deleted else self.username

    @property
    def is_viewable(self):
        return not self.is_deleted

    def regenerate_session_version(self):
        self.session_version += 1
        db.session.add(self)
        db.session.commit()


class PreKey(db.Model):
    """E2EE pre-key bundle for Signal-style protocol."""
    __tablename__ = 'prekeys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    key_id = db.Column(db.Integer, nullable=False)
    public_key = db.Column(db.Text, nullable=False)  # base64 X25519
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================================
# Encrypted Message Model
# ============================================================
class EncryptedMessage(db.Model):
    """E2EE encrypted message — server stores only ciphertext."""
    __tablename__ = 'encrypted_messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    ciphertext = db.Column(db.Text, nullable=False)
    ephemeral_key = db.Column(db.Text, nullable=False)  # Curve25519 public key
    salt = db.Column(db.String(64), nullable=False)
    nonce = db.Column(db.String(64), nullable=False)   # AEAD nonce
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_at = db.Column(db.DateTime, nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id])
    chat = db.relationship('Chat', backref=db.backref('encrypted_messages', lazy='dynamic'))

    __table_args__ = (
        db.Index('idx_enc_msg_chat_created', 'chat_id', 'created_at'),
    )


# ============================================================
# Signal-style Session Store
# ============================================================
class SignalSession(db.Model):
    """Per-participant session state for a chat."""
    __tablename__ = 'signal_sessions'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    their_identity_key = db.Column(db.Text, nullable=False)
    our_ephemeral_key = db.Column(db.Text, nullable=False)
    session_data = db.Column(db.Text, nullable=False)  # Serialized ratchet state
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint('chat_id', 'user_id', name='unique_signal_session'),
    )


# ============================================================
# Content Models
# ============================================================
class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    media_url = db.Column(db.String(500), nullable=True)
    media_type = db.Column(db.String(20), nullable=True)
    media_name = db.Column(db.String(255), nullable=True)
    media_size = db.Column(db.BigInteger, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    is_pinned = db.Column(db.Boolean, default=False)
    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    @property
    def like_count(self): return self.likes.count()
    @property
    def comment_count(self): return self.comments.count()
    def is_liked_by(self, user): return self.likes.filter_by(user_id=user.id).first() is not None


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False, index=True)


class Hashtag(db.Model):
    __tablename__ = 'hashtags'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts_count = db.Column(db.Integer, default=0)
    posts = db.relationship('Post', secondary='post_hashtags', lazy='dynamic', backref=db.backref('hashtags', lazy='dynamic'))


class Technology(db.Model):
    __tablename__ = 'technologies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    category = db.Column(db.String(30), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)
    label = db.Column(db.String(50), nullable=False)
    icon = db.Column(db.String(20), nullable=True)


class Idea(db.Model):
    __tablename__ = 'ideas'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    problem = db.Column(db.Text, nullable=True)
    solution = db.Column(db.Text, nullable=True)
    project_type = db.Column(db.String(30), nullable=True, default='other')
    github_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id', use_alter=True), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    technologies = db.relationship('Technology', secondary=idea_technologies, lazy='select', backref=db.backref('ideas', lazy='dynamic'))
    roles_needed = db.relationship('Role', secondary=idea_roles, lazy='select', backref=db.backref('ideas', lazy='dynamic'))
    likers = db.relationship('User', secondary=idea_likes, lazy='dynamic', backref=db.backref('liked_ideas', lazy='dynamic'))
    join_requests = db.relationship('User', secondary=idea_join_requests, lazy='dynamic',
                                     backref=db.backref('requested_ideas', lazy='dynamic'))
    chat = db.relationship('Chat', foreign_keys='Idea.chat_id', backref='idea', uselist=False)

    @property
    def likes_count(self):
        return self.likers.count()

    def is_liked_by(self, user):
        if not user or not user.is_authenticated:
            return False
        return self.likers.filter_by(id=user.id).first() is not None

    def has_pending_request(self, user):
        if not user or not user.is_authenticated:
            return False
        req = db.session.query(idea_join_requests).filter_by(
            idea_id=self.id, user_id=user.id
        ).first()
        return req and req.status == 'pending'

    def is_member(self, user):
        if not user or not user.is_authenticated:
            return False
        if self.author_id == user.id:
            return True
        if self.chat_id:
            return user in self.chat.participants
        req = db.session.query(idea_join_requests).filter_by(
            idea_id=self.id, user_id=user.id, status='approved'
        ).first()
        return req is not None


class Like(db.Model):
    __tablename__ = 'likes'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False, index=True)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)


class Follow(db.Model):
    __tablename__ = 'follows'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    __table_args__ = (db.UniqueConstraint('follower_id', 'followed_id', name='unique_follow'),)


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(500))
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)


# ============================================================
# 2FA Recovery Codes
# ============================================================
class RecoveryCode(db.Model):
    __tablename__ = 'recovery_codes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    code_hash = db.Column(db.String(128), nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)


# ============================================================
# Chat with E2EE support
# ============================================================
class Chat(db.Model):
    __tablename__ = 'chats'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_group = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(500), nullable=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    description = db.Column(db.Text, nullable=True)
    idea_id = db.Column(db.Integer, db.ForeignKey('ideas.id', use_alter=True), nullable=True)
    is_e2ee = db.Column(db.Boolean, default=False)  # Is E2EE enabled for this chat
    messages = db.relationship('Message', backref='chat', lazy='dynamic', cascade='all, delete-orphan')

    def get_other_participant(self, user):
        if self.is_group: return None
        for p in self.participants:
            if p.id != user.id: return p
        return None

    def get_display_name(self, user):
        if self.is_group: return self.name or "Group Chat"
        other = self.get_other_participant(user)
        return other.username if other else "Chat"

    def get_avatar(self, user):
        if self.is_group: return self.avatar or "https://ui-avatars.com/api/?background=random&name=Group"
        other = self.get_other_participant(user)
        return other.avatar if other else "https://ui-avatars.com/api/?background=random"

    @property
    def last_message(self):
        if self.is_e2ee:
            em = self.encrypted_messages.order_by(EncryptedMessage.created_at.desc()).first()
            return {'content': '[Encrypted]', 'created_at': em.created_at, 'sender_id': em.sender_id} if em else None
        return self.messages.order_by(Message.created_at.desc()).first()

    def unread_count(self, user):
        if self.is_e2ee:
            return self.encrypted_messages.filter(
                EncryptedMessage.sender_id != user.id,
                EncryptedMessage.read_at.is_(None)
            ).count()
        return self.messages.filter(Message.sender_id != user.id, Message.read_at.is_(None)).count()

    def is_admin(self, user):
        return self.admin_id == user.id


class Message(db.Model):
    """Unencrypted message model (used for public / non-E2EE chats)."""
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False, default='')
    media_url = db.Column(db.String(500), nullable=True)
    media_type = db.Column(db.String(20), nullable=True)
    media_name = db.Column(db.String(255), nullable=True)
    media_size = db.Column(db.BigInteger, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_at = db.Column(db.DateTime, nullable=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    is_edited = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime, nullable=True)
    is_voice = db.Column(db.Boolean, default=False)
    sender = db.relationship('User', foreign_keys=[sender_id])
    reply_to = db.relationship('Message', remote_side=[id], backref='replies')
    __table_args__ = (
        db.Index('idx_messages_chat_id_created', 'chat_id', 'created_at'),
        db.Index('idx_messages_sender_id', 'sender_id'),
    )
    @property
    def is_read(self): return self.read_at is not None
    def mark_as_read(self):
        if not self.read_at: self.read_at = datetime.utcnow()


class PinnedMessage(db.Model):
    __tablename__ = 'pinned_messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    pinned_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    pinned_at = db.Column(db.DateTime, default=datetime.utcnow)


class Reaction(db.Model):
    __tablename__ = 'reactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    reaction = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'message_id', name='unique_user_message_reaction'),)


# ============================================================
# Channels (Communities)
# ============================================================
class Channel(db.Model):
    __tablename__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default='')
    type = db.Column(db.String(20), default='public')
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    post_permission = db.Column(db.String(20), default='admins')  # 'admins' | 'members'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    avatar_url = db.Column(db.String(500), nullable=True)
    cover_url = db.Column(db.String(500), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    posts = db.relationship('ChannelPost', backref='channel', lazy='dynamic', cascade='all, delete-orphan')
    invites = db.relationship('ChannelInvite', backref='channel', lazy='dynamic', cascade='all, delete-orphan')

    def member_count(self):
        return db.session.query(channel_members).filter_by(channel_id=self.id, status='active').count()
    def pending_count(self):
        return db.session.query(channel_members).filter_by(channel_id=self.id, status='pending').count()
    def get_membership(self, user):
        if not user or not user.is_authenticated: return None
        return db.session.query(channel_members).filter_by(channel_id=self.id, user_id=user.id).first()
    def has_member(self, user):
        m = self.get_membership(user); return m and m.status == 'active'
    def is_admin(self, user):
        m = self.get_membership(user); return m and m.role == 'admin'
    def is_moderator(self, user):
        m = self.get_membership(user); return m and m.role in ('admin', 'moderator')
    def can_post(self, user):
        if not self.has_member(user):
            return False
        if self.post_permission == 'members':
            return True
        # 'admins' (default): only admins and moderators may post
        return self.is_moderator(user)


class ChannelPost(db.Model):
    __tablename__ = 'channel_posts'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    media_url = db.Column(db.String(500), nullable=True)
    media_type = db.Column(db.String(20), nullable=True)
    media_name = db.Column(db.String(255), nullable=True)
    media_size = db.Column(db.BigInteger, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    likes_count = db.Column(db.Integer, default=0)
    comments_count = db.Column(db.Integer, default=0)
    author = db.relationship('User', foreign_keys=[author_id])


class ChannelPostLike(db.Model):
    __tablename__ = 'channel_post_likes'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('channel_posts.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('post_id', 'user_id', name='unique_channel_post_like'),)


class ChannelPostComment(db.Model):
    __tablename__ = 'channel_post_comments'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('channel_posts.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship('User', foreign_keys=[user_id])
    post = db.relationship('ChannelPost', backref=db.backref('comments', lazy='dynamic', cascade='all, delete-orphan'))


class ChannelInvite(db.Model):
    __tablename__ = 'channel_invites'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False, index=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    invitee_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    invitee_email = db.Column(db.String(120), nullable=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    inviter = db.relationship('User', foreign_keys=[inviter_id])


# ============================================================
# Moderation: warnings
# ============================================================
class Warning(db.Model):
    __tablename__ = 'warnings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('warnings', lazy='dynamic', cascade='all, delete-orphan'))
    actor = db.relationship('User', foreign_keys=[actor_id])

    def __repr__(self):
        return f'<Warning user={self.user_id} actor={self.actor_id}>'


# ============================================================
# Helpers
# ============================================================
def generate_api_key():
    return secrets.token_urlsafe(32)


def sanitize_html(text):
    if not text:
        return ''
    return nh3.clean(text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, url_schemes=ALLOWED_URL_SCHEMES)


def validate_email(email):
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_RE.match(email))


def validate_username(username):
    if not username or len(username) < 3 or len(username) > 32:
        return False
    return bool(USERNAME_RE.match(username))


def validate_password(password):
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if len(password) > 128:
        return False, "Password is too long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\\|,.<>\/?]', password):
        return False, "Password must contain at least one special character"
    return True, ""


def validate_url(url):
    if not url:
        return ''
    url = url.strip()
    if not url:
        return ''
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme in ('http', 'https') and parsed.netloc:
            return url
    except Exception:
        pass
    return ''


HASHTAG_RE = re.compile(r'#(\w+)')

# Programming languages (code files) — any language is welcome
CODE_EXTENSIONS = frozenset({
    'py', 'pyw', 'pyi',
    'java', 'kt', 'kts', 'scala', 'sc',
    'c', 'h', 'cpp', 'cxx', 'hpp', 'hh', 'hxx', 'cc',
    'cs', 'fs', 'fsx', 'fsscript',
    'go', 'rs',
    'rb', 'pl', 'pm',
    'css', 'scss', 'sass', 'less', 'vue', 'svelte',
    'json', 'jsonc', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf',
    'swift', 'dart', 'sol', 'lua', 'r', 'sql', 'm', 'mm', 'asm', 's',
    'clj', 'cljs', 'elixir', 'ex', 'exs', 'erl', 'hrl',
    'hs', 'lhs', 'ml', 'groovy', 'gradle', 'zig', 'nim', 'cr', 'pas',
    'd', 'ada', 'ads', 'adb', 'cob', 'cobol', 'f', 'f90', 'f95', 'pro',
    'diff', 'patch', 'tf', 'tfvars', 'hcl', 'prisma', 'gd', 'gml',
    'md', 'markdown', 'rst', 'tex', 'xml', 'xsl',
})
ARCHIVE_EXTENSIONS = frozenset({
    'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'tbz', 'tbz2', 'xz',
    'txz', 'zst', 'lz', 'lz4', 'cpio', 'iso', 'jar', 'war', 'ear', 'apk',
    'whl', 'deb', 'rpm', 'dmg', 'cab',
})
DOC_EXTENSIONS = frozenset({
    'pdf', 'doc', 'docx', 'txt', 'csv', 'rtf', 'odt', 'odp', 'ods',
    'xls', 'xlsx', 'ppt', 'pptx',
})
AUDIO_EXTENSIONS = frozenset({'mp3', 'wav', 'flac', 'ogg', 'aac', 'm4a'})
VIDEO_EXTENSIONS = frozenset({'mp4', 'webm', 'mov', 'mkv', 'avi'})
IMAGE_EXTENSIONS = frozenset({'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'bmp'})

ALLOWED_EXTENSIONS = frozenset(
    CODE_EXTENSIONS | ARCHIVE_EXTENSIONS | DOC_EXTENSIONS |
    AUDIO_EXTENSIONS | VIDEO_EXTENSIONS | IMAGE_EXTENSIONS
)


def extract_and_link_hashtags(content, post):
    from module import Hashtag
    hashtags = HASHTAG_RE.findall(content)
    for name in set(hashtags):
        name = name.lower()
        tag = Hashtag.query.filter_by(name=name).first()
        if not tag:
            tag = Hashtag(name=name)
            db.session.add(tag)
            db.session.flush()
        post.hashtags.append(tag)


def get_file_type(filepath, ext=''):
    """Detect media category (image/video/audio/document/archive/code) by
    magic bytes, falling back to the extension. Returns short types that match
    the templates (image, video, audio, document, archive, code)."""
    ext = (ext or os.path.splitext(filepath)[1].lower().lstrip('.')).lower()
    with open(filepath, 'rb') as f:
        header = f.read(16)
    # --- magic-byte detection (binary formats) ---
    if header.startswith(b'\x89PNG\r\n\x1a\n') or header.startswith(b'\xff\xd8\xff') or header.startswith(b'GIF8'):
        return 'image'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'image'
    if header.startswith(b'\x1a\x45\xdf\xa3'):
        return 'video'
    if b'ftyp' in header[:8]:
        return 'video'
    if header.startswith(b'%PDF'):
        return 'document'
    if header.startswith(b'PK\x03\x04'):
        return 'archive'
    if header.startswith(b'\x1f\x8b'):
        return 'archive'
    if header.startswith(b'BZh'):
        return 'archive'
    if header.startswith(b'\xfd7zXZ\x00'):
        return 'archive'
    if header.startswith(b'7z\xbc\xaf\x27\x1c'):
        return 'archive'
    if header.startswith(b'Rar!'):
        return 'archive'
    if header.startswith(b'ID3') or header[:2] in (b'\xff\xfb', b'\xff\xf3', b'\xff\xf2', b'\xff\xfa'):
        return 'audio'
    if header[:4] == b'RIFF' and header[8:12] == b'WAVE':
        return 'audio'
    if header.startswith(b'fLaC'):
        return 'audio'
    if header.startswith(b'\x00\x00\x00\x18ftypM4A') or header.startswith(b'ftypM4A'):
        return 'audio'
    # --- extension-based classification ---
    if ext in IMAGE_EXTENSIONS:
        return 'image'
    if ext in VIDEO_EXTENSIONS:
        return 'video'
    if ext in AUDIO_EXTENSIONS:
        return 'audio'
    if ext in ARCHIVE_EXTENSIONS:
        return 'archive'
    if ext in CODE_EXTENSIONS:
        return 'code'
    if ext in DOC_EXTENSIONS:
        return 'document'
    return 'document'


def _verify_signature(filepath, ext):
    """Verify that a binary upload's content matches its claimed extension.

    Prevents polyglot uploads (e.g. an HTML/script file renamed to .png). Text
    formats and container formats without a reliable signature are allowed.
    """
    ext = ext.lower()
    if ext in ('png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'mov',
               'pdf', 'mp3', 'wav', 'flac', 'zip', 'docx', 'gz', 'tgz',
               'rar', '7z', 'bz2', 'tbz', 'tbz2', 'xz', 'zst', 'jar', 'apk',
               'aac', 'm4a'):
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
        except OSError:
            return False
        if ext == 'png':
            return header.startswith(b'\x89PNG\r\n\x1a\n')
        if ext in ('jpg', 'jpeg'):
            return header.startswith(b'\xff\xd8\xff')
        if ext == 'gif':
            return header.startswith(b'GIF8')
        if ext == 'webp':
            return header.startswith(b'RIFF') and header[8:12] == b'WEBP'
        if ext in ('mp4', 'mov'):
            return b'ftyp' in header[:8]
        if ext == 'webm':
            return header.startswith(b'\x1a\x45\xdf\xa3')
        if ext == 'pdf':
            return header.startswith(b'%PDF')
        if ext == 'mp3':
            return (header.startswith(b'ID3')
                    or header[:2] in (b'\xff\xfb', b'\xff\xf3', b'\xff\xf2', b'\xff\xfa'))
        if ext == 'wav':
            return header.startswith(b'RIFF') and header[8:12] == b'WAVE'
        if ext == 'flac':
            return header.startswith(b'fLaC')
        if ext in ('aac', 'm4a'):
            return b'ftyp' in header[:8] or header.startswith(b'\xff\xf1')
        if ext in ('zip', 'docx', 'jar', 'apk'):
            return header.startswith(b'PK\x03\x04')
        if ext in ('gz', 'tgz'):
            return header.startswith(b'\x1f\x8b')
        if ext == 'rar':
            return header.startswith(b'Rar!')
        if ext == '7z':
            return header.startswith(b'7z\xbc\xaf\x27\x1c')
        if ext in ('bz2', 'tbz', 'tbz2'):
            return header.startswith(b'BZh')
        if ext == 'xz':
            return header.startswith(b'\xfd7zXZ\x00')
        if ext == 'zst':
            return header.startswith(b'\x28\xb5\x2f\xfd')
    return True


def safe_save_file(file_obj, prefix, allowed_types=None):
    """Save an uploaded file, returning (url, media_type, filename, size)
    or (None, None, None, None)."""
    import uuid
    from werkzeug.utils import secure_filename
    from flask import current_app
    filename = secure_filename(file_obj.filename or 'file')
    if not filename:
        return None, None, None, None
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return None, None, None, None
    # Uploads are served as static assets (with nosniff); store under static/uploads
    # so the /static/uploads/... URLs actually resolve and require no auth.
    static_upload_dir = os.path.join(current_app.static_folder, 'uploads')
    os.makedirs(static_upload_dir, exist_ok=True)
    unique_name = f"{prefix}_{uuid.uuid4().hex[:12]}.{ext}"
    dest = os.path.join(static_upload_dir, unique_name)
    file_obj.save(dest)
    if not _verify_signature(dest, ext):
        try:
            os.remove(dest)
        except OSError:
            pass
        return None, None, None, None
    media_type = get_file_type(dest, ext)
    size = os.path.getsize(dest)
    url = f"/static/uploads/{unique_name}"
    return url, media_type, filename, size
