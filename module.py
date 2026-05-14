from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from database import db
import bleach

chat_participants = db.Table('chat_participants',
    db.Column('chat_id', db.Integer, db.ForeignKey('chats.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)

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
    role = db.Column(db.String(20), default='default')  # admin, moderator, betatester, default
    is_blocked = db.Column(db.Boolean, default=False)
    # Premium
    premium_expires_at = db.Column(db.DateTime, nullable=True)  # подписка (не премиум)
    # Premium extra fields
    premium_badge = db.Column(db.String(50), nullable=True)  # custom badge text
    profile_accent_color = db.Column(db.String(20), default='#6366f1')
    verified = db.Column(db.Boolean, default=False)  # verified checkmark

    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    following = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower', lazy='dynamic', cascade='all, delete-orphan')
    followers = db.relationship('Follow', foreign_keys='Follow.followed_id', backref='followed', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    chats = db.relationship('Chat', secondary=chat_participants, lazy='dynamic', backref=db.backref('participants', lazy='dynamic'))
    customization = db.relationship('UserCustomization', uselist=False, backref='user', cascade='all, delete-orphan')
    #Frames
    frames = db.relationship('UserFrame', backref='user', lazy='dynamic')
    current_frame = db.Column(db.String(50), default='premium_ring')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def is_following(self, user):
        return self.following.filter_by(followed_id=user.id).first() is not None
    def get_feed_posts(self):
        followed_users = [user.id for user in self.following.all()] + [self.id]
        return Post.query.filter(Post.user_id.in_(followed_users)).order_by(Post.created_at.desc())
    def has_role(self, role_name):
        return self.role == role_name or (role_name == 'admin' and self.role == 'admin')
    def can_delete_post(self, post):
        return self.id == post.user_id or self.role in ('admin', 'moderator')
    def is_premium_active(self):
        """Алиас для совместимости — проверяет подписку."""
        return self.is_subscribed()

    def is_subscribed(self):
        """Активна ли подписка (безлимитные посты + рамки)."""
        if self.premium_expires_at is None:
            return False
        return self.premium_expires_at > datetime.utcnow()


class UserCustomization(db.Model):
    __tablename__ = 'user_customizations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    avatar_border_style = db.Column(db.String(50), default='none')   # none, glow, rainbow, pulse
    avatar_border_color = db.Column(db.String(20), default='#6366f1')
    profile_background_type = db.Column(db.String(20), default='none')   # none, image, gradient
    profile_background_url = db.Column(db.String(500), nullable=True)
    profile_background_gradient = db.Column(db.String(200), nullable=True)
    message_style = db.Column(db.String(50), default='default')   # default, rounded, glass, neon
    post_style = db.Column(db.String(50), default='default')      # default, card-glass, border-gradient
    # New premium customization fields
    chat_theme = db.Column(db.String(50), default='default')       # default, aurora, midnight, rose
    font_style = db.Column(db.String(50), default='default')       # default, mono, serif, cursive
    status_emoji = db.Column(db.String(10), nullable=True)         # custom status emoji
    status_text = db.Column(db.String(80), nullable=True)          # custom status text
    post_style_gradient = db.Column(db.String(500), nullable=True) # custom post gradient css
    message_style_gradient = db.Column(db.String(500), nullable=True) # custom msg gradient css
        # внутри class UserCustomization
    avatar_frame_key = db.Column(db.String(50), default='premium_ring')


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    media_url = db.Column(db.String(500), nullable=True)
    media_type = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    is_pinned = db.Column(db.Boolean, default=False)  # premium: pin own posts
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
    description = db.Column(db.Text, nullable=True)  # group description
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
    is_voice = db.Column(db.Boolean, default=False)  # voice message flag
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


class UserFrame(db.Model):
    __tablename__ = 'user_frames'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    frame_key = db.Column(db.String(50), nullable=False)
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)
    price_paid = db.Column(db.Integer, default=0)

class AvatarFrame(db.Model):
    __tablename__ = 'avatar_frames'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), nullable=True)
    emoji = db.Column(db.String(10), default='✨')
    image_url = db.Column(db.String(500), nullable=False)          # SVG путь
    price = db.Column(db.Integer, default=0)                       # 0 = бесплатно для премиум
    rarity = db.Column(db.String(20), default='common')            # common, rare, epic, legendary
    is_default = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Статистика
    owners_count = db.Column(db.Integer, default=0)


def generate_api_key(): return secrets.token_urlsafe(32)


def sanitize_html(text):
    if not text: return ''
    allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'a']
    allowed_attrs = {'a': ['href', 'title']}
    return bleach.clean(text, tags=allowed_tags, attributes=allowed_attrs, strip=True)
