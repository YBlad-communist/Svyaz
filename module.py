from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from database import db
import html

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

DEVELOPER_ROLES = ['backend', 'frontend', 'fullstack', 'ml', 'devops', 'designer', 'pm']
SKILL_LEVELS = ['beginner', 'intermediate', 'advanced', 'expert']


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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def is_following(self, user):
        return self.following.filter_by(followed_id=user.id).first() is not None
    def get_feed_posts(self):
        followed_users = [u.id for u in self.following.all()] + [self.id]
        return Post.query.filter(Post.user_id.in_(followed_users)).order_by(Post.created_at.desc())
    def can_delete_post(self, post):
        return self.id == post.user_id or self.role in ('admin', 'moderator')
    def anonymize(self):
        self.username = f"user_{self.id}"
        self.email = f"deleted_{self.id}@deleted.local"
        self.avatar = "https://ui-avatars.com/api/?background=gray&name=Deleted"
        self.bio = ""
        self.location = ""
        self.website = ""
        self.github_username = None
        self.developer_role = None
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()
        self.is_active = False


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    media_url = db.Column(db.String(500), nullable=True)
    media_type = db.Column(db.String(20), nullable=True)
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

post_hashtags = db.Table('post_hashtags',
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id'), primary_key=True),
    db.Column('hashtag_id', db.Integer, db.ForeignKey('hashtags.id'), primary_key=True)
)


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=True)
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
    idea_id = db.Column(db.Integer, db.ForeignKey('ideas.id'), nullable=True)
    messages = db.relationship('Message', backref='chat', lazy='dynamic', cascade='all, delete-orphan')

    def get_other_participant(self, user):
        if self.is_group: return None
        for p in self.participants:
            if p.id != user.id: return p
        return None
    def get_display_name(self, user):
        if self.is_group: return self.name or "Групповой чат"
        other = self.get_other_participant(user)
        return other.username if other else "Чат"
    def get_avatar(self, user):
        if self.is_group: return self.avatar or "https://ui-avatars.com/api/?background=random&name=Group"
        other = self.get_other_participant(user)
        return other.avatar if other else "https://ui-avatars.com/api/?background=random"
    @property
    def last_message(self): return self.messages.order_by(Message.created_at.desc()).first()
    def unread_count(self, user): return self.messages.filter(Message.sender_id != user.id, Message.read_at.is_(None)).count()
    def is_admin(self, user): return self.admin_id == user.id


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False, default='')
    media_url = db.Column(db.String(500), nullable=True)
    media_type = db.Column(db.String(20), nullable=True)
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
# CHANNELS (Communities)
# ============================================================

class Channel(db.Model):
    __tablename__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default='')
    type = db.Column(db.String(20), default='public')
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    avatar_url = db.Column(db.String(500), nullable=True)
    cover_url = db.Column(db.String(500), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)

    posts = db.relationship('ChannelPost', backref='channel', lazy='dynamic', cascade='all, delete-orphan')
    invites = db.relationship('ChannelInvite', backref='channel', lazy='dynamic', cascade='all, delete-orphan')

    def member_count(self):
        return db.session.query(channel_members).filter_by(
            channel_id=self.id, status='active'
        ).count()

    def pending_count(self):
        return db.session.query(channel_members).filter_by(
            channel_id=self.id, status='pending'
        ).count()

    def get_membership(self, user):
        if not user or not user.is_authenticated:
            return None
        return db.session.query(channel_members).filter_by(
            channel_id=self.id, user_id=user.id
        ).first()

    def has_member(self, user):
        m = self.get_membership(user)
        return m and m.status == 'active'

    def is_admin(self, user):
        m = self.get_membership(user)
        return m and m.role == 'admin'

    def is_moderator(self, user):
        m = self.get_membership(user)
        return m and m.role in ('admin', 'moderator')

    def can_post(self, user):
        return self.has_member(user)


class ChannelPost(db.Model):
    __tablename__ = 'channel_posts'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    media_url = db.Column(db.String(500), nullable=True)
    media_type = db.Column(db.String(20), nullable=True)
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
    __table_args__ = (
        db.UniqueConstraint('post_id', 'user_id', name='unique_channel_post_like'),
    )


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


def generate_api_key(): return secrets.token_urlsafe(32)


import html

def sanitize_html(text):
    if not text:
        return ''
    return html.escape(text, quote=True)


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
