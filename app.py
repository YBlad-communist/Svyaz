import os
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, g, send_from_directory, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy.orm import joinedload, selectinload
from flask_limiter import Limiter, util
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from flask_talisman import Talisman
import redis

from database import db
from module import User, Post, Like, Comment, Follow, Message, Notification, Chat, chat_participants,PinnedMessage, Reaction, sanitize_html, validate_url,Hashtag, post_hashtags, Technology, Role, Idea, idea_technologies, idea_roles, user_technologies, idea_likes, idea_join_requests, DEVELOPER_ROLES, SKILL_LEVELS,Channel, ChannelPost, ChannelPostLike, ChannelPostComment, ChannelInvite, channel_members


_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    raise RuntimeError(
        "SECRET_KEY is not set! Generate: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','webp','mp4','webm','ogg','mov','pdf','doc','docx','txt'}
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = _secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///social_media.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

for folder in ['images', 'videos', 'files', 'avatars', 'group_avatars', 'temp']:
    os.makedirs(os.path.join(UPLOAD_FOLDER, folder), exist_ok=True)

db.init_app(app)

import re as _re

def extract_and_link_hashtags(text, post_obj=None):
    if not text:
        return text
    tags = set(_re.findall(r'#([\w\u0400-\u04ff]+)', text, _re.UNICODE))
    if post_obj and tags:
        for tag_name in tags:
            tag_name_lower = tag_name.lower()
            ht = Hashtag.query.filter_by(name=tag_name_lower).first()
            if not ht:
                ht = Hashtag(name=tag_name_lower, posts_count=1)
                db.session.add(ht)
            else:
                ht.posts_count = (ht.posts_count or 0) + 1
            if ht not in post_obj.hashtags.all():
                post_obj.hashtags.append(ht)
    return text


def encrypt_text(text): return text
def decrypt_text(encrypted): return encrypted


def get_file_type(filepath):
    with open(filepath, 'rb') as f:
        header = f.read(12)
    if header[:2] == b'\xff\xd8': return 'image/jpeg'
    if header[:8] == b'\x89PNG\r\n\x1a\n': return 'image/png'
    if header[:6] in (b'GIF87a', b'GIF89a'): return 'image/gif'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP': return 'image/webp'
    if header[4:8] == b'ftyp' or (len(header) >= 8 and header[4:8] == b'moov'): return 'video/mp4'
    if header[:4] == b'\x1a\x45\xdf\xa3': return 'video/webm'
    if header[:4] == b'OggS': return 'video/ogg'
    if header[:4] == b'%PDF': return 'application/pdf'
    if header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': return 'application/msword'
    if header[:4] == b'PK\x03\x04': return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    return 'text/plain'


def safe_save_file(file, prefix):
    if not file or file.filename == '':
        return None, None
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return None, None
    random_name = secrets.token_urlsafe(16)
    filename = f"{random_name}.{ext}"
    temp_dir = os.path.join(UPLOAD_FOLDER, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, filename)
    file.save(temp_path)
    mime = get_file_type(temp_path)
    allowed_mimes = [
        'image/jpeg','image/png','image/gif','image/webp',
        'video/mp4','video/webm','video/ogg',
        'application/pdf','text/plain','application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ]
    if mime not in allowed_mimes:
        os.remove(temp_path)
        return None, None
    if mime.startswith('image/'): folder, media_type = 'images', 'image'
    elif mime.startswith('video/'): folder, media_type = 'videos', 'video'
    else: folder, media_type = 'files', 'file'
    final_dir = os.path.join(UPLOAD_FOLDER, folder)
    os.makedirs(final_dir, exist_ok=True)
    final_path = os.path.join(final_dir, filename)
    os.renames(temp_path, final_path)
    return f"/uploads/{folder}/{filename}", media_type

# ------------------------------
# Redis / Limiter
# ------------------------------
redis_available = False
redis_client = None
try:
    redis_client = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'),
                               port=int(os.environ.get('REDIS_PORT', 6379)),
                               db=0, decode_responses=True, socket_connect_timeout=2)
    redis_client.ping()
    redis_available = True
except:
    pass

limiter = Limiter(app,
                  default_limits=["200 per day", "50 per hour"],
                  storage_uri="redis://localhost:6379" if redis_available else "memory://")
limiter.key_func = util.get_remote_address

# ------------------------------
# Talisman
# ------------------------------
is_production = os.environ.get('FLASK_ENV', 'development') == 'production'

csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
    'style-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com",
    'font-src': "'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com",
    'img-src': "'self' https://ui-avatars.com data: blob:",
}
Talisman(app, content_security_policy=csp,
         force_https=is_production,
         strict_transport_security=is_production,
         strict_transport_security_max_age=31536000 if is_production else 0,
         session_cookie_secure=is_production,
         force_https_permanent=is_production)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ------------------------------
# Flask-Login and CSRF
# ------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token
app.jinja_env.globals['now'] = datetime.utcnow
app.jinja_env.globals['datetime'] = datetime.utcnow

@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if user and user.is_deleted:
        return None
    return user

# ------------------------------
# Before/After request
# ------------------------------
@app.before_request
def before_request():
    g.user = current_user
    if current_user.is_authenticated:
        current_user.last_activity = datetime.utcnow()
        db.session.commit()
    if redis_available and request.remote_addr:
        try:
            failed = redis_client.get(f"failed_attempts:{request.remote_addr}")
            if failed and int(failed) > 10:
                return jsonify({'error': 'Too many attempts'}), 429
        except:
            pass

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

# ------------------------------
# Error handlers
# ------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error_code=404, message="Страница не найдена"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', error_code=500, message="Внутренняя ошибка сервера"), 500

@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify({'error': 'Too many requests'}), 429

@app.route('/favicon.ico')
def favicon():
    return '', 204

# ------------------------------
# Authentication
# ------------------------------
@app.route('/')
def index():
    return render_template('index.html') if not current_user.is_authenticated else redirect(url_for('feed'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not username or not email or not password:
            flash('Все поля обязательны', 'error')
            return redirect(url_for('register'))
        if len(username) < 3 or len(username) > 32:
            flash('Имя от 3 до 32 символов', 'error')
            return redirect(url_for('register'))
        if not username.replace('_', '').replace('-', '').isalnum():
            flash('Имя может содержать только буквы, цифры, _ и -', 'error')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Пароль минимум 6 символов', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email уже используется', 'error')
            return redirect(url_for('register'))
        user = User(username=username, email=email,
                    password_hash=generate_password_hash(password),
                    avatar=f"https://ui-avatars.com/api/?background=random&name={username}",
                    role='default')
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Регистрация успешна!', 'success')
        return redirect(url_for('feed'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if redis_available:
            ip = request.remote_addr
            try:
                attempts = redis_client.incr(f"login_attempts:{ip}")
                redis_client.expire(f"login_attempts:{ip}", 300)
                if attempts > 5:
                    flash('Слишком много попыток, подождите 5 минут', 'error')
                    return redirect(url_for('login'))
            except:
                pass
        user = User.query.filter_by(username=username).first()
        if user and user.is_blocked:
            flash('Ваш аккаунт заблокирован', 'error')
            return redirect(url_for('login'))
        if user and user.is_deleted:
            flash('Аккаунт удалён', 'error')
            return redirect(url_for('login'))
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()
            if redis_available:
                try: redis_client.delete(f"login_attempts:{request.remote_addr}")
                except: pass
            flash('Добро пожаловать!', 'success')
            return redirect(url_for('feed'))
        else:
            flash('Неверное имя или пароль', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ------------------------------
# Posts and feed
# ------------------------------
@app.route('/feed')
@login_required
def feed():
    page = request.args.get('page', 1, int)
    per_page = 20
    posts = Post.query.options(joinedload(Post.author)).order_by(Post.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    for post in posts.items:
        post.recent_comments = post.comments.order_by(Comment.created_at.desc()).limit(5).all()
        post.content = decrypt_text(post.content)
        for c in post.recent_comments:
            c.content = decrypt_text(c.content)
    return render_template('feed.html', posts=posts)

@app.route('/post/create', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content', '').strip()
    media_url, media_type = None, None
    if 'media' in request.files:
        media_url, media_type = safe_save_file(request.files['media'], 'post')
    if not content and not media_url:
        flash('Пост не может быть пустым', 'error')
        return redirect(request.referrer or url_for('feed'))
    if len(content) > 10000:
        flash('Пост слишком длинный', 'error')
        return redirect(request.referrer or url_for('feed'))
    clean = sanitize_html(content)
    encrypted = encrypt_text(clean)
    post = Post(content=encrypted, media_url=media_url, media_type=media_type, user_id=current_user.id)
    db.session.add(post)
    db.session.flush()
    extract_and_link_hashtags(clean, post)
    db.session.commit()
    flash('Пост опубликован!', 'success')
    return redirect(url_for('feed'))

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = post.comments.options(joinedload(Comment.author)).order_by(Comment.created_at.desc()).all()
    post.content = decrypt_text(post.content)
    for c in comments:
        c.content = decrypt_text(c.content)
    return render_template('post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    if like:
        db.session.delete(like)
        liked = False
    else:
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        liked = True
        if post.user_id != current_user.id:
            notif = Notification(user_id=post.user_id, type='like',
                                 content=f"{current_user.username} лайкнул ваш пост",
                                 link=f"/post/{post_id}")
            db.session.add(notif)
    db.session.commit()
    return jsonify({'liked': liked, 'count': post.likes.count()})

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content', '').strip()
    if not content or len(content) > 5000:
        return jsonify({'error': 'Comment empty or too long'}), 400
    encrypted = encrypt_text(sanitize_html(content))
    comment = Comment(content=encrypted, user_id=current_user.id, post_id=post_id)
    db.session.add(comment)
    if post.user_id != current_user.id:
        notif = Notification(user_id=post.user_id, type='comment',
                             content=f"{current_user.username} прокомментировал: {content[:50]}",
                             link=f"/post/{post_id}")
        db.session.add(notif)
    db.session.commit()
    return jsonify({
        'success': True,
        'comment': {
            'id': comment.id,
            'content': sanitize_html(content),
            'username': current_user.username,
            'avatar': current_user.avatar,
            'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M')
        }
    })

@app.route('/post/<int:post_id>/edit', methods=['PUT'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        return jsonify({'error': 'Нет прав'}), 403
    data = request.get_json()
    new_content = data.get('content', '').strip()
    if not new_content:
        return jsonify({'error': 'Содержимое не может быть пустым'}), 400
    if len(new_content) > 10000:
        return jsonify({'error': 'Слишком длинный пост'}), 400
    post.content = encrypt_text(sanitize_html(new_content))
    post.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True, 'content': sanitize_html(new_content)})

@app.route('/post/<int:post_id>/delete', methods=['DELETE'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not current_user.can_delete_post(post):
        return jsonify({'error': 'Нет прав'}), 403
    db.session.delete(post)
    db.session.commit()
    return jsonify({'success': True})

# ------------------------------
# Profile
# ------------------------------
@app.route('/user/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username, is_deleted=False).first_or_404()
    page = request.args.get('page', 1, int)
    per_page = 20
    posts = Post.query.filter_by(user_id=user.id).options(joinedload(Post.author)).order_by(Post.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    for p in posts.items:
        p.content = decrypt_text(p.content)
    is_following = Follow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first() is not None
    return render_template('profile.html', profile_user=user, posts=posts, is_following=is_following)

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('Файл не выбран', 'error')
        return redirect(url_for('profile', username=current_user.username))
    url, _ = safe_save_file(request.files['avatar'], f"user_{current_user.id}")
    if url:
        current_user.avatar = url
        db.session.commit()
        flash('Аватар обновлён!', 'success')
    else:
        flash('Недопустимый формат', 'error')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    bio = request.form.get('bio', '').strip()
    location = request.form.get('location', '').strip()
    website = validate_url(request.form.get('website', '').strip())
    github_username = request.form.get('github_username', '').strip()
    developer_role = request.form.get('developer_role', '').strip() or None
    if developer_role and developer_role not in DEVELOPER_ROLES:
        developer_role = None
    current_user.bio = sanitize_html(bio)
    current_user.location = sanitize_html(location)
    current_user.website = website
    current_user.github_username = github_username[:39] if github_username else None
    current_user.developer_role = developer_role
    db.session.commit()
    flash('Профиль обновлён', 'success')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def profile_edit():
    technologies = Technology.query.order_by(Technology.name).all()
    user_tech_ids = {t.id for t in current_user.tech_stack.all()}
    if request.method == 'POST':
        bio = request.form.get('bio', '').strip()
        location = request.form.get('location', '').strip()
        website = validate_url(request.form.get('website', '').strip())
        github_username = request.form.get('github_username', '').strip()
        developer_role = request.form.get('developer_role', '').strip() or None
        if developer_role and developer_role not in DEVELOPER_ROLES:
            developer_role = None
        current_user.bio = sanitize_html(bio)
        current_user.location = sanitize_html(location)
        current_user.website = website
        current_user.github_username = github_username[:39] if github_username else None
        current_user.developer_role = developer_role
        selected_techs = request.form.getlist('technologies')
        current_user.tech_stack = Technology.query.filter(Technology.id.in_(selected_techs)).all() if selected_techs else []
        db.session.commit()
        flash('Профиль обновлён', 'success')
        return redirect(url_for('profile', username=current_user.username))
    return render_template('profile_edit.html', technologies=technologies,
                           user_tech_ids=user_tech_ids, developer_roles=DEVELOPER_ROLES,
                           skill_levels=SKILL_LEVELS)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    current_user.anonymize()
    db.session.commit()
    logout_user()
    flash('Аккаунт удалён', 'success')
    return redirect(url_for('index'))

@app.route('/user/<username>/follow', methods=['POST'])
@login_required
def follow_user(username):
    user = User.query.filter_by(username=username, is_deleted=False).first_or_404()
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot follow yourself'}), 400
    follow = Follow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first()
    if follow:
        db.session.delete(follow)
        following = False
    else:
        follow = Follow(follower_id=current_user.id, followed_id=user.id)
        db.session.add(follow)
        following = True
        notif = Notification(user_id=user.id, type='follow',
                             content=f"{current_user.username} подписался на вас",
                             link=f"/user/{current_user.username}")
        db.session.add(notif)
    db.session.commit()
    return jsonify({
        'following': following,
        'followers_count': user.followers.count(),
        'following_count': user.following.count()
    })

@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, int)
    per_page = 30
    notifs = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    for n in notifs.items:
        n.read = True
    db.session.commit()
    return render_template('notifications.html', notifications=notifs)

@app.route('/api/notifications/poll')
@login_required
def poll_notifications():
    only_type = request.args.get('type', 'message').strip()
    limit = request.args.get('limit', 5, type=int)
    after_id = request.args.get('after_id', type=int)
    q = Notification.query.filter_by(user_id=current_user.id, read=False)
    if only_type:
        q = q.filter(Notification.type == only_type)
    if after_id:
        q = q.filter(Notification.id > after_id)
    items = q.order_by(Notification.id.asc()).limit(max(1, min(limit, 20))).all()
    result = []
    max_id = after_id or 0
    for n in items:
        max_id = max(max_id, n.id)
        result.append({
            'id': n.id, 'type': n.type, 'content': n.content,
            'link': n.link or '', 'created_at': n.created_at.isoformat()
        })
        n.read = True
    if items:
        db.session.commit()
    return jsonify({'items': result, 'max_id': max_id})

# ------------------------------
# Search
# ------------------------------
@app.route('/search')
@login_required
def search():
    q_param = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all')
    if not q_param:
        return render_template('search.html', users=[], posts=[], ideas=[], channels=[], query='', search_type='all')
    search_param = f'%{q_param}%'
    users, posts, ideas, channels, hashtags = [], [], [], [], []
    if search_type in ('all', 'users'):
        users = User.query.filter(User.username.ilike(search_param), User.is_deleted == False).limit(20).all()
    if search_type in ('all', 'posts'):
        posts = Post.query.filter(Post.content.ilike(search_param)).options(joinedload(Post.author)).order_by(Post.created_at.desc()).limit(20).all()
        for p in posts:
            p.content = decrypt_text(p.content)
    if search_type in ('all', 'ideas'):
        ideas = Idea.query.filter(Idea.title.ilike(search_param) | Idea.description.ilike(search_param), Idea.is_active == True).options(joinedload(Idea.author)).order_by(Idea.created_at.desc()).limit(20).all()
    if search_type in ('all', 'channels'):
        channels = Channel.query.filter(
            (Channel.title.ilike(search_param)) | (Channel.description.ilike(search_param)) | (Channel.name.ilike(search_param))
        ).order_by(Channel.created_at.desc()).limit(20).all()
    ht_q = q_param.lstrip('#')
    if ht_q:
        hashtags = Hashtag.query.filter(Hashtag.name.ilike(f'%{ht_q}%')).order_by(Hashtag.posts_count.desc()).limit(10).all()
    return render_template('search.html', users=users, posts=posts, ideas=ideas, channels=channels,
                           query=q_param, hashtags=hashtags, search_type=search_type)

# ------------------------------
# IDEAS
# ------------------------------
@app.route('/ideas')
@login_required
def ideas_feed():
    page = request.args.get('page', 1, int)
    per_page = 20
    sort = request.args.get('sort', 'hot')
    tech_filter = request.args.get('tech', '').strip()
    role_filter = request.args.get('role', '').strip()
    query = Idea.query.filter_by(is_active=True).options(joinedload(Idea.author))
    if tech_filter:
        query = query.filter(Idea.technologies.any(Technology.name == tech_filter))
    if role_filter:
        query = query.filter(Idea.roles_needed.any(Role.name == role_filter))
    query = query.order_by(Idea.created_at.desc())
    ideas = query.paginate(page=page, per_page=per_page, error_out=False)
    technologies = Technology.query.order_by(Technology.name).all()
    roles = Role.query.order_by(Role.name).all()
    for idea in ideas.items:
        idea.liked_by_user = idea.is_liked_by(current_user)
    return render_template('ideas.html', ideas=ideas, technologies=technologies,
                           roles=roles, sort=sort, tech_filter=tech_filter, role_filter=role_filter)

@app.route('/idea/create', methods=['GET', 'POST'])
@login_required
def idea_create():
    technologies = Technology.query.order_by(Technology.name).all()
    roles = Role.query.order_by(Role.name).all()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        problem = request.form.get('problem', '').strip()
        solution = request.form.get('solution', '').strip()
        selected_techs = request.form.getlist('technologies')
        selected_roles = request.form.getlist('roles')
        if not title or not description:
            flash('Название и описание обязательны', 'error')
            return render_template('idea_create.html', technologies=technologies, roles=roles)
        if len(title) > 200:
            flash('Название слишком длинное', 'error')
            return render_template('idea_create.html', technologies=technologies, roles=roles)
        idea = Idea(
            title=sanitize_html(title), description=sanitize_html(description),
            problem=sanitize_html(problem) if problem else None,
            solution=sanitize_html(solution) if solution else None,
            author_id=current_user.id
        )
        db.session.add(idea)
        db.session.flush()
        if selected_techs:
            techs = Technology.query.filter(Technology.id.in_(selected_techs)).all()
            for t in techs:
                idea.technologies.append(t)
        if selected_roles:
            rs = Role.query.filter(Role.id.in_(selected_roles)).all()
            for r in rs:
                idea.roles_needed.append(r)
        group_chat = Chat(is_group=True, name=f"Чат идеи: {title[:50]}", admin_id=current_user.id, idea_id=idea.id)
        db.session.add(group_chat)
        group_chat.participants.append(current_user)
        db.session.flush()
        idea.chat_id = group_chat.id
        db.session.commit()
        flash('Идея создана! Командный чат доступен.', 'success')
        return redirect(url_for('idea_detail', idea_id=idea.id))
    return render_template('idea_create.html', technologies=technologies, roles=roles)

@app.route('/idea/<int:idea_id>')
@login_required
def idea_detail(idea_id):
    idea = Idea.query.options(
        joinedload(Idea.author), selectinload(Idea.technologies), selectinload(Idea.roles_needed),
    ).get_or_404(idea_id)
    if not idea.is_active:
        abort(404)
    idea.liked_by_user = idea.is_liked_by(current_user)
    idea.is_author = idea.author_id == current_user.id
    idea.is_member = idea.is_member(current_user)
    idea.has_pending = idea.has_pending_request(current_user)
    pending_requests = []
    if idea.is_author:
        reqs = db.session.query(
            idea_join_requests.c.user_id, idea_join_requests.c.created_at, idea_join_requests.c.status
        ).filter_by(idea_id=idea.id, status='pending').all()
        for r in reqs:
            user = db.session.get(User, r.user_id)
            if user and not user.is_deleted:
                pending_requests.append({'user': user, 'created_at': r.created_at})
    return render_template('idea_detail.html', idea=idea, pending_requests=pending_requests)

@app.route('/idea/<int:idea_id>/like', methods=['POST'])
@login_required
def idea_like(idea_id):
    idea = Idea.query.get_or_404(idea_id)
    if not idea.is_active:
        return jsonify({'error': 'Идея не активна'}), 404
    existing = idea.likers.filter_by(id=current_user.id).first()
    if existing:
        idea.likers.remove(existing)
        liked = False
    else:
        idea.likers.append(current_user)
        liked = True
        if idea.author_id != current_user.id:
            notif = Notification(user_id=idea.author_id, type='like',
                                 content=f"{current_user.username} поддержал вашу идею",
                                 link=f"/idea/{idea_id}")
            db.session.add(notif)
    db.session.commit()
    return jsonify({'liked': liked, 'count': idea.likes_count})

@app.route('/idea/<int:idea_id>/join', methods=['POST'])
@login_required
def idea_join_request(idea_id):
    idea = Idea.query.get_or_404(idea_id)
    if not idea.is_active:
        return jsonify({'error': 'Идея не активна'}), 404
    if idea.author_id == current_user.id:
        flash('Вы автор идеи', 'info')
        return redirect(url_for('idea_detail', idea_id=idea_id))
    existing = db.session.query(idea_join_requests).filter_by(
        idea_id=idea.id, user_id=current_user.id
    ).first()
    if existing:
        if existing.status == 'pending':
            flash('Заявка уже подана', 'info')
        elif existing.status == 'approved':
            flash('Вы уже в группе обсуждения', 'info')
        else:
            flash('Ваша заявка была отклонена', 'error')
        return redirect(url_for('idea_detail', idea_id=idea_id))
    db.session.execute(idea_join_requests.insert().values(
        idea_id=idea.id, user_id=current_user.id, status='pending', created_at=datetime.utcnow()
    ))
    db.session.commit()
    notif = Notification(user_id=idea.author_id, type='follow',
                         content=f"{current_user.username} хочет присоединиться к обсуждению идеи",
                         link=f"/idea/{idea_id}")
    db.session.add(notif)
    db.session.commit()
    flash('Заявка на участие отправлена!', 'success')
    return redirect(url_for('idea_detail', idea_id=idea_id))

@app.route('/idea/<int:idea_id>/join/<int:user_id>/approve', methods=['POST'])
@login_required
def idea_approve_join(idea_id, user_id):
    idea = Idea.query.get_or_404(idea_id)
    if idea.author_id != current_user.id:
        return jsonify({'error': 'Нет прав'}), 403
    db.session.execute(idea_join_requests.update().where(
        idea_join_requests.c.idea_id == idea.id,
        idea_join_requests.c.user_id == user_id,
        idea_join_requests.c.status == 'pending'
    ).values(status='approved'))
    if idea.chat_id:
        chat = db.session.get(Chat, idea.chat_id)
        if chat:
            user = db.session.get(User, user_id)
            if user and user not in chat.participants:
                chat.participants.append(user)
    db.session.commit()
    flash('Участник добавлен в группу', 'success')
    return redirect(url_for('idea_detail', idea_id=idea_id))

@app.route('/idea/<int:idea_id>/join/<int:user_id>/reject', methods=['POST'])
@login_required
def idea_reject_join(idea_id, user_id):
    idea = Idea.query.get_or_404(idea_id)
    if idea.author_id != current_user.id:
        return jsonify({'error': 'Нет прав'}), 403
    db.session.execute(idea_join_requests.update().where(
        idea_join_requests.c.idea_id == idea.id,
        idea_join_requests.c.user_id == user_id,
        idea_join_requests.c.status == 'pending'
    ).values(status='rejected'))
    db.session.commit()
    flash('Заявка отклонена', 'success')
    return redirect(url_for('idea_detail', idea_id=idea_id))

@app.route('/idea/<int:idea_id>/delete', methods=['POST'])
@login_required
def idea_delete(idea_id):
    idea = Idea.query.get_or_404(idea_id)
    if idea.author_id != current_user.id and current_user.role not in ('admin', 'moderator'):
        return jsonify({'error': 'Нет прав'}), 403
    idea.is_active = False
    db.session.commit()
    flash('Идея удалена', 'success')
    return redirect(url_for('ideas_feed'))

# ============================================================
# CHANNELS
# ============================================================

@app.route('/channels')
@login_required
def channels_list():
    page = request.args.get('page', 1, int)
    per_page = 20
    q_param = request.args.get('q', '').strip()
    type_filter = request.args.get('type', 'all')
    query = Channel.query
    if q_param:
        search_param = f'%{q_param}%'
        query = query.filter(
            (Channel.title.ilike(search_param)) |
            (Channel.description.ilike(search_param)) |
            (Channel.name.ilike(search_param))
        )
    if type_filter == 'public':
        query = query.filter_by(type='public')
    elif type_filter == 'private':
        query = query.filter_by(type='private')
    channels = query.order_by(Channel.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    my_channels = current_user.owned_channels.all() if current_user.is_authenticated else []
    return render_template('channels.html', channels=channels, my_channels=my_channels,
                           query=q_param, type_filter=type_filter)

@app.route('/channel/create', methods=['GET', 'POST'])
@login_required
def channel_create():
    if request.method == 'POST':
        name = request.form.get('name', '').strip().lower()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        channel_type = request.form.get('type', 'public')
        if channel_type not in ('public', 'private'):
            channel_type = 'public'
        if not name or not title:
            flash('Название и адрес обязательны', 'error')
            return render_template('channel_create.html')
        if not name.replace('_', '').replace('-', '').isalnum():
            flash('Адрес может содержать только буквы, цифры, _ и -', 'error')
            return render_template('channel_create.html')
        if len(name) > 50:
            flash('Адрес слишком длинный', 'error')
            return render_template('channel_create.html')
        if Channel.query.filter_by(name=name).first():
            flash('Такой адрес уже занят', 'error')
            return render_template('channel_create.html')
        channel = Channel(
            name=name, title=sanitize_html(title),
            description=sanitize_html(description), type=channel_type,
            owner_id=current_user.id
        )
        db.session.add(channel)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=channel.id, user_id=current_user.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()
        flash('Канал создан!', 'success')
        return redirect(url_for('channel_page', channel_name=name))
    return render_template('channel_create.html')

@app.route('/channel/<channel_name>')
@login_required
def channel_page(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    page = request.args.get('page', 1, int)
    per_page = 20
    posts = channel.posts.options(joinedload(ChannelPost.author)).order_by(ChannelPost.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    membership = channel.get_membership(current_user)
    is_member = membership and membership.status == 'active'
    is_admin = membership and membership.role == 'admin'
    is_mod = membership and membership.role in ('admin', 'moderator')
    pending_requests = []
    if is_admin and channel.type == 'private':
        pending_requests = db.session.query(
            channel_members.c.user_id, channel_members.c.joined_at
        ).filter_by(channel_id=channel.id, status='pending').all()
    liked_post_ids = set()
    if is_member:
        likes = ChannelPostLike.query.filter(
            ChannelPostLike.post_id.in_([p.id for p in posts.items]),
            ChannelPostLike.user_id == current_user.id
        ).all()
        liked_post_ids = {l.post_id for l in likes}
    return render_template('channel_page.html', channel=channel, posts=posts,
                           membership=membership, is_member=is_member,
                           is_admin=is_admin, is_mod=is_mod,
                           pending_requests=pending_requests,
                           liked_post_ids=liked_post_ids)

@app.route('/channel/<channel_name>/join', methods=['POST'])
@login_required
def channel_join(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    existing = channel.get_membership(current_user)
    if existing and existing.status == 'active':
        flash('Вы уже участник', 'info')
        return redirect(url_for('channel_page', channel_name=channel_name))
    if existing and existing.status == 'pending':
        flash('Заявка уже подана', 'info')
        return redirect(url_for('channel_page', channel_name=channel_name))
    if channel.type == 'public':
        db.session.execute(channel_members.insert().values(
            channel_id=channel.id, user_id=current_user.id,
            role='member', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()
        flash('Вы вступили в канал!', 'success')
    else:
        db.session.execute(channel_members.insert().values(
            channel_id=channel.id, user_id=current_user.id,
            role='member', status='pending', joined_at=datetime.utcnow()
        ))
        db.session.commit()
        flash('Заявка на вступление отправлена', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/leave', methods=['POST'])
@login_required
def channel_leave(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    membership = channel.get_membership(current_user)
    if not membership:
        return redirect(url_for('channel_page', channel_name=channel_name))
    db.session.execute(channel_members.delete().where(
        channel_members.c.channel_id == channel.id,
        channel_members.c.user_id == current_user.id
    ))
    db.session.commit()
    flash('Вы покинули канал', 'success')
    return redirect(url_for('channels_list'))

@app.route('/channel/<channel_name>/post', methods=['POST'])
@login_required
def channel_post_create(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.can_post(current_user):
        flash('Только участники могут публиковать', 'error')
        return redirect(url_for('channel_page', channel_name=channel_name))
    content = request.form.get('content', '').strip()
    if not content:
        flash('Пост не может быть пустым', 'error')
        return redirect(url_for('channel_page', channel_name=channel_name))
    if len(content) > 10000:
        flash('Пост слишком длинный', 'error')
        return redirect(url_for('channel_page', channel_name=channel_name))
    media_url, media_type = None, None
    if 'media' in request.files:
        media_url, media_type = safe_save_file(request.files['media'], 'ch_post')
    post = ChannelPost(
        channel_id=channel.id, author_id=current_user.id,
        content=sanitize_html(content), media_url=media_url, media_type=media_type
    )
    db.session.add(post)
    db.session.commit()
    flash('Пост опубликован!', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/post/<int:post_id>/like', methods=['POST'])
@login_required
def channel_post_like(channel_name, post_id):
    post = ChannelPost.query.get_or_404(post_id)
    if post.channel_id != Channel.query.filter_by(name=channel_name).first().id:
        return jsonify({'error': 'Not found'}), 404
    existing = ChannelPostLike.query.filter_by(post_id=post_id, user_id=current_user.id).first()
    if existing:
        db.session.delete(existing)
        post.likes_count = max(0, post.likes_count - 1)
        liked = False
    else:
        db.session.add(ChannelPostLike(post_id=post_id, user_id=current_user.id))
        post.likes_count += 1
        liked = True
    db.session.commit()
    return jsonify({'liked': liked, 'count': post.likes_count})

@app.route('/channel/<channel_name>/post/<int:post_id>/comment', methods=['POST'])
@login_required
def channel_post_comment(channel_name, post_id):
    post = ChannelPost.query.get_or_404(post_id)
    channel = Channel.query.filter_by(name=channel_name).first()
    if post.channel_id != channel.id:
        return jsonify({'error': 'Not found'}), 404
    content = request.form.get('content', '').strip()
    if not content or len(content) > 5000:
        return jsonify({'error': 'Invalid content'}), 400
    comment = ChannelPostComment(post_id=post_id, user_id=current_user.id, content=sanitize_html(content))
    db.session.add(comment)
    post.comments_count += 1
    db.session.commit()
    return jsonify({
        'success': True,
        'comment': {
            'id': comment.id, 'content': sanitize_html(content),
            'username': current_user.username, 'avatar': current_user.avatar,
            'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M')
        }
    })

@app.route('/channel/<channel_name>/post/<int:post_id>/delete', methods=['POST'])
@login_required
def channel_post_delete(channel_name, post_id):
    post = ChannelPost.query.get_or_404(post_id)
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if post.channel_id != channel.id:
        abort(404)
    if post.author_id != current_user.id and not channel.is_admin(current_user):
        return jsonify({'error': 'Нет прав'}), 403
    db.session.delete(post)
    db.session.commit()
    flash('Пост удалён', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/edit', methods=['GET', 'POST'])
@login_required
def channel_edit(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_admin(current_user):
        abort(403)
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        channel_type = request.form.get('type', 'public')
        if channel_type not in ('public', 'private'):
            channel_type = 'public'
        channel.title = sanitize_html(title)
        channel.description = sanitize_html(description)
        channel.type = channel_type
        if 'avatar' in request.files:
            url, _ = safe_save_file(request.files['avatar'], f"ch_av_{channel.id}")
            if url:
                channel.avatar_url = url
        if 'cover' in request.files:
            url, _ = safe_save_file(request.files['cover'], f"ch_cv_{channel.id}")
            if url:
                channel.cover_url = url
        db.session.commit()
        flash('Канал обновлён', 'success')
        return redirect(url_for('channel_page', channel_name=channel_name))
    return render_template('channel_edit.html', channel=channel)

@app.route('/channel/<channel_name>/members')
@login_required
def channel_members_page(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.has_member(current_user):
        abort(403)
    is_admin = channel.is_admin(current_user)
    members = db.session.query(
        channel_members.c.user_id, channel_members.c.role,
        channel_members.c.status, channel_members.c.joined_at
    ).filter_by(channel_id=channel.id).all()
    member_users = []
    for m in members:
        user = db.session.get(User, m.user_id)
        if user and not user.is_deleted:
            member_users.append({
                'user': user, 'role': m.role,
                'status': m.status, 'joined_at': m.joined_at
            })
    return render_template('channel_members.html', channel=channel,
                           member_users=member_users, is_admin=is_admin)

@app.route('/channel/<channel_name>/member/<int:user_id>/role', methods=['POST'])
@login_required
def channel_change_role(channel_name, user_id):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_admin(current_user):
        abort(403)
    target = db.session.get(User, user_id)
    if not target:
        abort(404)
    new_role = request.form.get('role', 'member')
    if new_role not in ('admin', 'moderator', 'member'):
        new_role = 'member'
    db.session.execute(channel_members.update().where(
        channel_members.c.channel_id == channel.id,
        channel_members.c.user_id == user_id
    ).values(role=new_role))
    db.session.commit()
    flash(f'Роль {target.username} изменена на {new_role}', 'success')
    return redirect(url_for('channel_members_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/member/<int:user_id>/ban', methods=['POST'])
@login_required
def channel_ban_member(channel_name, user_id):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_admin(current_user):
        abort(403)
    db.session.execute(channel_members.update().where(
        channel_members.c.channel_id == channel.id,
        channel_members.c.user_id == user_id
    ).values(status='banned'))
    db.session.commit()
    flash('Пользователь заблокирован в канале', 'success')
    return redirect(url_for('channel_members_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/member/<int:user_id>/remove', methods=['POST'])
@login_required
def channel_remove_member(channel_name, user_id):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_moderator(current_user):
        abort(403)
    db.session.execute(channel_members.delete().where(
        channel_members.c.channel_id == channel.id,
        channel_members.c.user_id == user_id
    ))
    db.session.commit()
    flash('Пользователь удалён из канала', 'success')
    return redirect(url_for('channel_members_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/requests/<int:user_id>/approve', methods=['POST'])
@login_required
def channel_approve_request(channel_name, user_id):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_admin(current_user):
        abort(403)
    db.session.execute(channel_members.update().where(
        channel_members.c.channel_id == channel.id,
        channel_members.c.user_id == user_id,
        channel_members.c.status == 'pending'
    ).values(status='active'))
    db.session.commit()
    flash('Заявка одобрена', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/requests/<int:user_id>/reject', methods=['POST'])
@login_required
def channel_reject_request(channel_name, user_id):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_admin(current_user):
        abort(403)
    db.session.execute(channel_members.delete().where(
        channel_members.c.channel_id == channel.id,
        channel_members.c.user_id == user_id,
        channel_members.c.status == 'pending'
    ))
    db.session.commit()
    flash('Заявка отклонена', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/invite/create', methods=['POST'])
@login_required
def channel_create_invite(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_moderator(current_user):
        abort(403)
    token = secrets.token_urlsafe(32)
    expires_hours = request.form.get('expires_hours', 72, type=int)
    expires_at = datetime.utcnow() + timedelta(hours=min(expires_hours, 720))
    invite = ChannelInvite(
        channel_id=channel.id, inviter_id=current_user.id,
        token=token, expires_at=expires_at
    )
    db.session.add(invite)
    db.session.commit()
    invite_url = url_for('channel_accept_invite', token=token, _external=True)
    flash(f'Пригласительная ссылка создана: {invite_url}', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/invite/<token>')
@login_required
def channel_accept_invite(token):
    invite = ChannelInvite.query.filter_by(token=token).first_or_404()
    if invite.used_at:
        flash('Приглашение уже использовано', 'error')
        return redirect(url_for('channels_list'))
    if invite.expires_at and invite.expires_at < datetime.utcnow():
        flash('Приглашение истекло', 'error')
        return redirect(url_for('channels_list'))
    channel = db.session.get(Channel, invite.channel_id)
    if not channel:
        abort(404)
    existing = channel.get_membership(current_user)
    if existing and existing.status == 'active':
        flash('Вы уже участник', 'info')
        return redirect(url_for('channel_page', channel_name=channel.name))
    if existing:
        db.session.execute(channel_members.update().where(
            channel_members.c.channel_id == channel.id,
            channel_members.c.user_id == current_user.id
        ).values(status='active'))
    else:
        db.session.execute(channel_members.insert().values(
            channel_id=channel.id, user_id=current_user.id,
            role='member', status='active', joined_at=datetime.utcnow()
        ))
    invite.used_at = datetime.utcnow()
    db.session.commit()
    flash(f'Вы вступили в канал "{channel.title}"!', 'success')
    return redirect(url_for('channel_page', channel_name=channel.name))

# ------------------------------
# Chats
# ------------------------------
@app.route('/chats')
@login_required
def chats():
    return render_template('chats.html')

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Название обязательно', 'error')
            return redirect(url_for('create_group'))
        chat = Chat(is_group=True, name=name, admin_id=current_user.id)
        db.session.add(chat)
        chat.participants.append(current_user)
        for uname in request.form.getlist('participants'):
            user = User.query.filter_by(username=uname, is_deleted=False).first()
            if user and user != current_user:
                chat.participants.append(user)
        if 'avatar' in request.files:
            url, _ = safe_save_file(request.files['avatar'], f"group_{secrets.token_urlsafe(8)}")
            if url:
                chat.avatar = url
        db.session.commit()
        flash('Группа создана!', 'success')
        return redirect(url_for('chats'))
    users = User.query.filter(User.id != current_user.id, User.is_deleted == False).limit(50).all()
    return render_template('create_group.html', users=users)

@app.route('/group/<int:chat_id>/add_members', methods=['POST'])
@login_required
def add_group_members(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if not chat.is_group or chat.admin_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403
    usernames = request.form.getlist('usernames')
    added = []
    for uname in usernames:
        user = User.query.filter_by(username=uname, is_deleted=False).first()
        if user and user not in chat.participants:
            chat.participants.append(user)
            added.append(uname)
    db.session.commit()
    flash(f'Добавлены: {", ".join(added)}', 'success')
    return redirect(url_for('chats', chat=chat_id))

# ------------------------------
# Chat API
# ------------------------------
@app.route('/api/chats')
@login_required
def get_chats():
    user_chats = current_user.chats.order_by(Chat.updated_at.desc()).all()
    result = []
    for chat in user_chats:
        if chat.is_group:
            last = chat.last_message
            result.append({
                'id': chat.id, 'username': chat.name,
                'avatar': chat.avatar or "https://ui-avatars.com/api/?background=random&name=Group",
                'last_message': decrypt_text(last.content)[:50] if last else '',
                'last_time': last.created_at.strftime('%d.%m %H:%M') if last else '',
                'unread': chat.unread_count(current_user), 'is_group': True
            })
        else:
            other = None
            for p in chat.participants:
                if p.id != current_user.id:
                    other = p
                    break
            if not other:
                continue
            last = chat.last_message
            result.append({
                'id': chat.id, 'username': other.username, 'avatar': other.avatar,
                'last_message': decrypt_text(last.content)[:50] if last else '',
                'last_time': last.created_at.strftime('%d.%m %H:%M') if last else '',
                'unread': chat.unread_count(current_user), 'is_group': False, 'user_id': other.id
            })
    return jsonify(result)

@app.route('/api/chat/<int:chat_id>/messages')
@login_required
def get_messages(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if current_user not in chat.participants:
        return jsonify({'error': 'Access denied'}), 403
    after = request.args.get('after', type=float)
    if after:
        after_dt = datetime.fromtimestamp(after)
        messages = chat.messages.filter(Message.created_at > after_dt).order_by(Message.created_at.asc()).all()
    else:
        limit = request.args.get('limit', 30, type=int)
        offset = request.args.get('offset', 0, type=int)
        messages = chat.messages.order_by(Message.created_at.desc()).offset(offset).limit(limit).all()
        messages.reverse()
    for msg in messages:
        if msg.sender_id != current_user.id and not msg.read_at:
            msg.mark_as_read()
    db.session.commit()
    result = []
    for msg in messages:
        reply_data = None
        if msg.reply_to_id:
            replied = Message.query.get(msg.reply_to_id)
            if replied:
                reply_data = {
                    'id': replied.id, 'sender_username': replied.sender.username,
                    'content': decrypt_text(replied.content), 'media_type': replied.media_type
                }
        reactions = Reaction.query.filter_by(message_id=msg.id).all()
        reaction_counts = {}
        for r in reactions:
            reaction_counts[r.reaction] = reaction_counts.get(r.reaction, 0) + 1
        result.append({
            'id': msg.id, 'sender_id': msg.sender_id, 'sender_username': msg.sender.username,
            'sender_avatar': msg.sender.avatar,
            'content': decrypt_text(msg.content), 'media_url': msg.media_url,
            'media_type': msg.media_type, 'created_at': msg.created_at.strftime('%H:%M'),
            'created_at_full': msg.created_at.timestamp(),
            'is_mine': msg.sender_id == current_user.id,
            'is_edited': msg.is_edited, 'edited_at': msg.edited_at.isoformat() if msg.edited_at else None,
            'reply_to': reply_data, 'read_at': msg.read_at.isoformat() if msg.read_at else None,
            'reactions': reaction_counts
        })
    return jsonify(result)

@app.route('/api/chat/<int:chat_id>/send', methods=['POST'])
@login_required
def send_message(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if current_user not in chat.participants:
        return jsonify({'error': 'Access denied'}), 403
    content = request.form.get('content', '').strip()
    media_url, media_type = None, None
    if 'media' in request.files:
        media_url, media_type = safe_save_file(request.files['media'], f"msg_{secrets.token_urlsafe(8)}")
    reply_to_id = request.form.get('reply_to', type=int)
    if not content and not media_url:
        return jsonify({'error': 'Пустое сообщение'}), 400
    encrypted = encrypt_text(sanitize_html(content))
    msg = Message(content=encrypted, media_url=media_url, media_type=media_type,
                  sender_id=current_user.id, chat_id=chat.id)
    if reply_to_id:
        reply_msg = Message.query.get(reply_to_id)
        if reply_msg and reply_msg.chat_id == chat_id:
            msg.reply_to_id = reply_to_id
    db.session.add(msg)
    chat.updated_at = datetime.utcnow()
    db.session.commit()
    for p in chat.participants:
        if p.id != current_user.id:
            notif = Notification(user_id=p.id, type='message',
                                 content=f"Новое сообщение от {current_user.username}",
                                 link=f"/chats?chat={chat.id}")
            db.session.add(notif)
    db.session.commit()
    return jsonify({
        'id': msg.id, 'sender_id': msg.sender_id, 'sender_username': current_user.username,
        'sender_avatar': current_user.avatar, 'content': sanitize_html(content),
        'media_url': media_url, 'media_type': media_type,
        'created_at': msg.created_at.strftime('%H:%M'),
        'created_at_full': msg.created_at.timestamp(),
        'is_mine': True, 'reply_to_id': msg.reply_to_id
    })

@app.route('/api/chat/<int:chat_id>/edit/<int:message_id>', methods=['PUT'])
@login_required
def edit_message(chat_id, message_id):
    msg = Message.query.get_or_404(message_id)
    if msg.sender_id != current_user.id or msg.chat_id != chat_id:
        return jsonify({'error': 'Нет прав'}), 403
    if datetime.utcnow() - msg.created_at > timedelta(minutes=5):
        return jsonify({'error': 'Время редактирования истекло'}), 403
    data = request.get_json()
    new_content = data.get('content', '').strip()
    if not new_content:
        return jsonify({'error': 'Сообщение не может быть пустым'}), 400
    msg.content = encrypt_text(sanitize_html(new_content))
    msg.is_edited = True
    msg.edited_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True, 'content': sanitize_html(new_content), 'edited_at': msg.edited_at.isoformat()})

@app.route('/api/chat/<int:chat_id>/delete_message/<int:message_id>', methods=['DELETE'])
@login_required
def delete_message(chat_id, message_id):
    msg = Message.query.get_or_404(message_id)
    chat = Chat.query.get_or_404(chat_id)
    if msg.sender_id != current_user.id and not (chat.is_group and chat.admin_id == current_user.id):
        return jsonify({'error': 'Нет прав'}), 403
    db.session.delete(msg)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/chat/create', methods=['POST'])
@login_required
def create_chat():
    username = request.form.get('username', '').strip()
    other = User.query.filter_by(username=username, is_deleted=False).first()
    if not other:
        return jsonify({'error': 'User not found'}), 404
    if other.id == current_user.id:
        return jsonify({'error': 'Cannot chat with yourself'}), 400
    existing = Chat.query.filter(
        Chat.participants.any(id=current_user.id),
        Chat.participants.any(id=other.id),
        Chat.is_group == False
    ).first()
    if existing:
        return jsonify({'chat_id': existing.id})
    chat = Chat()
    chat.participants.append(current_user)
    chat.participants.append(other)
    db.session.add(chat)
    db.session.commit()
    return jsonify({'chat_id': chat.id})

@app.route('/api/chat/<int:chat_id>/delete', methods=['POST'])
@login_required
def delete_chat(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if chat.is_group and chat.admin_id != current_user.id:
        return jsonify({'error': 'Only admin can delete group'}), 403
    if not chat.is_group and current_user not in chat.participants:
        return jsonify({'error': 'Access denied'}), 403
    db.session.delete(chat)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/chat/<int:chat_id>/leave', methods=['POST'])
@login_required
def leave_group(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if not chat.is_group or current_user not in chat.participants:
        return jsonify({'error': 'Not a member'}), 403
    if current_user.id == chat.admin_id:
        others = [p for p in chat.participants if p.id != current_user.id]
        if others:
            chat.admin_id = others[0].id
        else:
            db.session.delete(chat)
            db.session.commit()
            return jsonify({'success': True})
    chat.participants.remove(current_user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/group/<int:chat_id>/members')
@login_required
def get_group_members(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if not chat.is_group or current_user not in chat.participants:
        return jsonify({'error': 'Access denied'}), 403
    members = [{'id': u.id, 'username': u.username, 'avatar': u.avatar, 'is_admin': (u.id == chat.admin_id)} for u in chat.participants]
    return jsonify({'members': members, 'current_user_id': current_user.id, 'admin_id': chat.admin_id})

@app.route('/api/group/<int:chat_id>/remove_member', methods=['POST'])
@login_required
def remove_group_member(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if not chat.is_group or chat.admin_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    user = User.query.get(data.get('user_id'))
    if not user or user not in chat.participants:
        return jsonify({'error': 'User not in group'}), 404
    if user.id == chat.admin_id:
        return jsonify({'error': 'Cannot remove admin'}), 400
    chat.participants.remove(user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/users/search')
@login_required
def search_users():
    q_param = request.args.get('q', '').strip()
    if len(q_param) < 2:
        return jsonify([])
    search_param = f'%{q_param}%'
    users = User.query.filter(
        User.username.ilike(search_param), User.id != current_user.id, User.is_deleted == False
    ).limit(10).all()
    return jsonify([{'id': u.id, 'username': u.username, 'avatar': u.avatar} for u in users])

@app.route('/api/users/search_for_group')
@login_required
def search_users_for_group():
    q_param = request.args.get('q', '').strip()
    chat_id = request.args.get('chat_id', type=int)
    if len(q_param) < 2:
        return jsonify([])
    search_param = f'%{q_param}%'
    query = User.query.filter(
        User.username.ilike(search_param), User.id != current_user.id, User.is_deleted == False
    )
    if chat_id:
        query = query.filter(~User.chats.any(id=chat_id))
    users = query.limit(20).all()
    return jsonify([{'id': u.id, 'username': u.username, 'avatar': u.avatar} for u in users])

@app.route('/api/message/<int:message_id>/react', methods=['POST'])
@login_required
def add_reaction(message_id):
    data = request.get_json()
    reaction = data.get('reaction')
    if reaction not in ['\U0001f44d', '\u2764\ufe0f', '\U0001f602', '\U0001f62e', '\U0001f622', '\U0001f621']:
        return jsonify({'error': 'Invalid reaction'}), 400
    existing = Reaction.query.filter_by(user_id=current_user.id, message_id=message_id).first()
    if existing:
        if existing.reaction == reaction:
            db.session.delete(existing)
        else:
            existing.reaction = reaction
    else:
        db.session.add(Reaction(user_id=current_user.id, message_id=message_id, reaction=reaction))
    db.session.commit()
    reactions = Reaction.query.filter_by(message_id=message_id).all()
    reaction_counts = {}
    for r in reactions:
        reaction_counts[r.reaction] = reaction_counts.get(r.reaction, 0) + 1
    return jsonify({'success': True, 'reactions': reaction_counts})

@app.route('/api/user/<int:user_id>/online')
@login_required
def user_online(user_id):
    user = User.query.get_or_404(user_id)
    is_online = user.last_activity and (datetime.utcnow() - user.last_activity) < timedelta(minutes=5)
    return jsonify({'online': is_online})

@app.route('/api/chat/<int:chat_id>/info')
@login_required
def chat_info(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if current_user not in chat.participants:
        return jsonify({'error': 'Access denied'}), 403
    return jsonify({
        'is_group': chat.is_group, 'is_admin': chat.is_admin(current_user) if chat.is_group else False,
        'name': chat.name, 'avatar': chat.avatar, 'description': chat.description
    })

@app.route('/api/github/<username>')
@login_required
def github_repos(username):
    import urllib.request, json
    gh_user = User.query.filter_by(github_username=username, is_deleted=False).first()
    if not gh_user:
        return jsonify({'error': 'GitHub username not set'}), 404
    try:
        url = f"https://api.github.com/users/{username}/repos?sort=updated&per_page=10"
        req = urllib.request.Request(url, headers={'User-Agent': 'Svyaz-App'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            repos = json.loads(resp.read().decode())
        result = []
        for r in repos:
            result.append({
                'name': r['name'], 'description': r.get('description', ''),
                'language': r.get('language', ''), 'stars': r.get('stargazers_count', 0),
                'forks': r.get('forks_count', 0), 'url': r['html_url'],
                'updated_at': r.get('updated_at', '')
            })
        return jsonify({'repos': result, 'username': username})
    except Exception as e:
        logger.error(f"GitHub API error: {e}")
        return jsonify({'error': 'Failed to fetch repos'}), 502

# ------------------------------
# Admin
# ------------------------------
@app.route('/admin/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    if current_user.role not in ('admin', 'moderator'):
        return jsonify({'error': 'Нет прав'}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'error': 'Нельзя заблокировать себя'}), 400
    user.is_blocked = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/set_role/<int:user_id>', methods=['POST'])
@login_required
def set_user_role(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Нет прав'}), 403
    data = request.get_json()
    new_role = data.get('role')
    if new_role not in ['admin', 'moderator', 'betatester', 'default']:
        return jsonify({'error': 'Недопустимая роль'}), 400
    target_user = User.query.get_or_404(user_id)
    if target_user.id == current_user.id:
        return jsonify({'error': 'Нельзя изменить свою роль'}), 400
    target_user.role = new_role
    db.session.commit()
    return jsonify({'success': True, 'new_role': new_role})

# ------------------------------
# Files
# ------------------------------
@app.route('/uploads/<folder>/<filename>')
@login_required
def download_file(folder, filename):
    allowed_folders = {'images', 'videos', 'files', 'avatars', 'group_avatars'}
    if folder not in allowed_folders:
        abort(403)
    clean_folder = secure_filename(folder)
    clean_filename = secure_filename(filename)
    if not clean_folder or not clean_filename:
        abort(403)
    upload_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
    folder_path = os.path.join(upload_dir, clean_folder)
    if not os.path.isdir(folder_path):
        abort(404)
    file_path = os.path.join(folder_path, clean_filename)
    if not os.path.isfile(file_path):
        abort(404)
    if not os.path.abspath(file_path).startswith(upload_dir):
        abort(403)
    return send_from_directory(folder_path, clean_filename)

# ------------------------------
# Hashtags
# ------------------------------
@app.route('/hashtag/<tag_name>')
@login_required
def hashtag_feed(tag_name):
    tag_name = tag_name.lower().lstrip('#')
    ht = Hashtag.query.filter_by(name=tag_name).first()
    if not ht:
        flash(f'Хештег #{tag_name} не найден', 'error')
        return redirect(url_for('feed'))
    page = request.args.get('page', 1, int)
    posts = ht.posts.order_by(Post.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    for p in posts.items:
        p.content = decrypt_text(p.content)
    return render_template('hashtag.html', tag=ht, posts=posts)

@app.route('/api/hashtags/trending')
@login_required
def trending_hashtags():
    tags = Hashtag.query.order_by(Hashtag.posts_count.desc()).limit(15).all()
    return jsonify([{'name': t.name, 'count': t.posts_count} for t in tags])

@app.route('/api/hashtags/search')
@login_required
def search_hashtags():
    q_param = request.args.get('q', '').strip().lstrip('#')
    if len(q_param) < 1:
        return jsonify([])
    search_param = f'%{q_param}%'
    tags = Hashtag.query.filter(Hashtag.name.ilike(search_param)).order_by(Hashtag.posts_count.desc()).limit(10).all()
    return jsonify([{'name': t.name, 'count': t.posts_count} for t in tags])

# ------------------------------
# Seed data
# ------------------------------
def seed_default_data():
    default_techs = [
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
        ('SQL', 'database'), ('GraphQL', 'backend'), ('REST API', 'backend'),
    ]
    for name, cat in default_techs:
        if not Technology.query.filter_by(name=name).first():
            db.session.add(Technology(name=name, category=cat))
    default_roles = [
        ('backend', 'Backend-разработчик', 'fa-server'),
        ('frontend', 'Frontend-разработчик', 'fa-code'),
        ('fullstack', 'Fullstack-разработчик', 'fa-layer-group'),
        ('ml', 'ML-инженер', 'fa-brain'),
        ('devops', 'DevOps-инженер', 'fa-cogs'),
        ('designer', 'Дизайнер', 'fa-palette'),
        ('pm', 'Project Manager', 'fa-tasks'),
    ]
    for name, label, icon in default_roles:
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name, label=label, icon=icon))
    db.session.commit()

# ------------------------------
# Start
# ------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_default_data()
        admin = User.query.filter_by(username='admin').first()
        if admin and admin.role == 'default':
            admin.role = 'admin'
            db.session.commit()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
