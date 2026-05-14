import os
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, g, send_file, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy.orm import joinedload
from flask_limiter import Limiter, util
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from flask_talisman import Talisman
import redis

from database import db
from module import User, Post, Like, Comment, Follow, Message, Notification, Chat, chat_participants, PinnedMessage, Reaction, sanitize_html, UserCustomization, AvatarFrame, Hashtag, post_hashtags, UserFrame

# ------------------------------
# Планы подписки
# ------------------------------
PLANS = {
    'week':    {'name': 'Неделя',   'price': 69,   'days': 7},
    'month':   {'name': 'Месяц',    'price': 199,  'days': 30},
    'year':    {'name': 'Год',      'price': 999,  'days': 365},
    'forever': {'name': 'Навсегда', 'price': 2999, 'days': 0},
}
SUBSCRIPTION_PLANS = PLANS  # алиас

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','webp','mp4','webm','ogg','mov','pdf','doc','docx','txt'}
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///social_media.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

for folder in ['images', 'videos', 'files', 'avatars', 'group_avatars', 'temp']:
    os.makedirs(os.path.join(UPLOAD_FOLDER, folder), exist_ok=True)

db.init_app(app)

import re as _re

def extract_and_link_hashtags(text, post_obj=None):
    """Находит #хештеги в тексте, сохраняет в БД, возвращает текст без изменений."""
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


# ------------------------------
# Шифрование (отключено)
# ------------------------------
def encrypt_text(text): return text
def decrypt_text(encrypted): return encrypted

# ------------------------------
# Проверка файлов
# ------------------------------
def get_file_type(filepath):
    with open(filepath, 'rb') as f:
        header = f.read(12)
    if header[:2] == b'\xff\xd8': return 'image/jpeg'
    if header[:8] == b'\x89PNG\r\n\x1a\n': return 'image/png'
    if header[:6] in (b'GIF87a', b'GIF89a'): return 'image/gif'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP': return 'image/webp'
    if header[:4] == b'ftyp' or header[4:8] == b'moov': return 'video/mp4'
    if header[:4] == b'\x1a\x45\xdf\xa3': return 'video/webm'
    if header[:4] == b'OggS': return 'video/ogg'
    if header[:4] == b'%PDF': return 'application/pdf'
    if header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': return 'application/msword'
    if header[:4] == b'PK\x03\x04': return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    return 'text/plain'

def safe_save_file(file, prefix):
    if not file or file.filename == '': return None, None
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS: return None, None
    filename = secure_filename(f"{prefix}_{int(datetime.utcnow().timestamp())}_{file.filename}")
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
# Безопасные заголовки
# ------------------------------
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
    'style-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com",
    'font-src': "'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com",
    'img-src': "'self' https://ui-avatars.com data: blob:",
}, force_https=False)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ------------------------------
# Flask-Login и CSRF
# ------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE'):
            token = session.get('_csrf_token')
            if not token:
                return jsonify({'error': 'CSRF token missing'}), 400
            form_token = request.form.get('_csrf_token')
            json_token = request.get_json().get('_csrf_token') if request.is_json else None
            header_token = request.headers.get('X-CSRFToken')
            valid = (form_token and form_token == token) or \
                    (json_token and json_token == token) or \
                    (header_token and header_token == token)
            if not valid:
                return jsonify({'error': 'CSRF token invalid'}), 400
        return f(*args, **kwargs)
    return decorated

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token
app.jinja_env.globals['now'] = datetime.utcnow
app.jinja_env.globals['datetime'] = datetime

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

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
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ------------------------------
# Ошибки
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
# Аутентификация
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
# Посты и лента
# ------------------------------
@app.route('/feed')
@login_required
def feed():
    page = request.args.get('page', 1, int)
    per_page = 20
    posts = Post.query.options(joinedload(Post.author).joinedload(User.customization)).order_by(Post.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
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
    db.session.flush()  # получаем post.id
    extract_and_link_hashtags(clean, post)
    db.session.commit()
    flash('Пост опубликован!', 'success')
    return redirect(url_for('feed'))

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = post.comments.options(joinedload(Comment.author).joinedload(User.customization)).order_by(Comment.created_at.desc()).all()
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

# Premium: закрепить пост на профиле
@app.route('/post/<int:post_id>/pin', methods=['POST'])
@login_required
def pin_post(post_id):
    if not current_user.is_premium_active():
        return jsonify({'error': 'Только для премиум-подписчиков'}), 403
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        return jsonify({'error': 'Нет прав'}), 403
    # Снять закрепление со старых
    Post.query.filter_by(user_id=current_user.id, is_pinned=True).update({'is_pinned': False})
    post.is_pinned = True
    db.session.commit()
    return jsonify({'success': True})

# ------------------------------
# Профиль
# ------------------------------
@app.route('/user/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, int)
    per_page = 20
    posts = Post.query.filter_by(user_id=user.id).options(joinedload(Post.author).joinedload(User.customization)).order_by(Post.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    for p in posts.items:
        p.content = decrypt_text(p.content)
    is_following = Follow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first() is not None
    pinned_post = Post.query.filter_by(user_id=user.id, is_pinned=True).first()
    if pinned_post:
        pinned_post.content = decrypt_text(pinned_post.content)
    return render_template('profile.html', profile_user=user, posts=posts, is_following=is_following, pinned_post=pinned_post)

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
    website = request.form.get('website', '').strip()
    current_user.bio = sanitize_html(bio)
    current_user.location = sanitize_html(location)
    current_user.website = sanitize_html(website)
    # Premium: обновление статуса
    if current_user.is_premium_active():
        status_emoji = request.form.get('status_emoji', '').strip()
        status_text = request.form.get('status_text', '').strip()
        cust = current_user.customization
        if not cust:
            cust = UserCustomization(user_id=current_user.id)
            db.session.add(cust)
        cust.status_emoji = status_emoji[:10] if status_emoji else None
        cust.status_text = status_text[:80] if status_text else None
    db.session.commit()
    flash('Профиль обновлён', 'success')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    user.username = "Аккаунт удален"
    user.avatar = "https://ui-avatars.com/api/?background=gray&name=Deleted"
    user.bio = ""
    user.location = ""
    user.website = ""
    user.email = f"deleted_{user.id}@deleted.com"
    user.is_active = False
    db.session.commit()
    logout_user()
    flash('Аккаунт удалён', 'success')
    return redirect(url_for('index'))

@app.route('/user/<username>/follow', methods=['POST'])
@login_required
def follow_user(username):
    user = User.query.filter_by(username=username).first_or_404()
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
    """
    Лёгкий polling для "toast" уведомлений.
    Возвращает непрочитанные уведомления (по умолчанию только type='message'),
    помечая их прочитанными, чтобы не показывать повторно.
    """
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
            'id': n.id,
            'type': n.type,
            'content': n.content,
            'link': n.link or '',
            'created_at': n.created_at.isoformat()
        })
        n.read = True
    if items:
        db.session.commit()

    return jsonify({'items': result, 'max_id': max_id})

@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip()
    if not q:
        return render_template('search.html', users=[], posts=[])
    users = User.query.filter(User.username.ilike(f'%{q}%')).options(joinedload(User.customization)).limit(20).all()
    posts = Post.query.filter(Post.content.ilike(f'%{q}%')).options(joinedload(Post.author).joinedload(User.customization)).order_by(Post.created_at.desc()).limit(20).all()
    for p in posts:
        p.content = decrypt_text(p.content)
    hashtags = []
    if q.startswith('#') or not q.startswith('@'):
        ht_q = q.lstrip('#')
        if ht_q:
            hashtags = Hashtag.query.filter(Hashtag.name.ilike(f'%{ht_q}%')).order_by(Hashtag.posts_count.desc()).limit(10).all()
    return render_template('search.html', users=users, posts=posts, query=q, hashtags=hashtags)

# ------------------------------
# Чаты
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
            user = User.query.filter_by(username=uname).first()
            if user and user != current_user:
                chat.participants.append(user)
        if 'avatar' in request.files:
            url, _ = safe_save_file(request.files['avatar'], f"group_{int(datetime.utcnow().timestamp())}")
            if url:
                chat.avatar = url
        db.session.commit()
        flash('Группа создана!', 'success')
        return redirect(url_for('chats'))
    users = User.query.filter(User.id != current_user.id).limit(50).all()
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
        user = User.query.filter_by(username=uname).first()
        if user and user not in chat.participants:
            chat.participants.append(user)
            added.append(uname)
    db.session.commit()
    flash(f'Добавлены: {", ".join(added)}', 'success')
    return redirect(url_for('chats', chat=chat_id))

# ------------------------------
# API Чаты
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
                'id': chat.id,
                'username': chat.name,
                'avatar': chat.avatar or "https://ui-avatars.com/api/?background=random&name=Group",
                'last_message': decrypt_text(last.content)[:50] if last else '',
                'last_time': last.created_at.strftime('%d.%m %H:%M') if last else '',
                'unread': chat.unread_count(current_user),
                'is_group': True
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
            frame_key = 'premium_gold'
            if other.is_premium_active() and other.customization and other.customization.avatar_frame_key:
                frame_key = other.customization.avatar_frame_key
            result.append({
                'id': chat.id,
                'username': other.username,
                'avatar': other.avatar,
                'is_premium': other.is_premium_active(),
                'frame_path': f'/static/frames/{frame_key}.svg' if other.is_premium_active() else '',
                'last_message': decrypt_text(last.content)[:50] if last else '',
                'last_time': last.created_at.strftime('%d.%m %H:%M') if last else '',
                'unread': chat.unread_count(current_user),
                'is_group': False,
                'user_id': other.id
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
                    'id': replied.id,
                    'sender_username': replied.sender.username,
                    'content': decrypt_text(replied.content),
                    'media_type': replied.media_type
                }
        reactions = Reaction.query.filter_by(message_id=msg.id).all()
        reaction_counts = {}
        for r in reactions:
            reaction_counts[r.reaction] = reaction_counts.get(r.reaction, 0) + 1
        sender_fk = 'premium_gold'
        if msg.sender.is_premium_active() and msg.sender.customization and msg.sender.customization.avatar_frame_key:
            sender_fk = msg.sender.customization.avatar_frame_key
        result.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'sender_username': msg.sender.username,
            'sender_avatar': msg.sender.avatar,
            'sender_is_premium': msg.sender.is_premium_active(),
            'sender_frame_path': f'/static/frames/{sender_fk}.svg' if msg.sender.is_premium_active() else '',
            'content': decrypt_text(msg.content),
            'media_url': msg.media_url,
            'media_type': msg.media_type,
            'created_at': msg.created_at.strftime('%H:%M'),
            'created_at_full': msg.created_at.timestamp(),
            'is_mine': msg.sender_id == current_user.id,
            'is_edited': msg.is_edited,
            'edited_at': msg.edited_at.isoformat() if msg.edited_at else None,
            'reply_to': reply_data,
            'read_at': msg.read_at.isoformat() if msg.read_at else None,
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
        media_url, media_type = safe_save_file(request.files['media'], f"msg_{current_user.id}")
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
        'id': msg.id,
        'sender_id': msg.sender_id,
        'sender_username': current_user.username,
        'sender_avatar': current_user.avatar,
        'content': sanitize_html(content),
        'media_url': media_url,
        'media_type': media_type,
        'created_at': msg.created_at.strftime('%H:%M'),
        'created_at_full': msg.created_at.timestamp(),
        'is_mine': True,
        'reply_to_id': msg.reply_to_id
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

@app.route('/api/chat/<int:chat_id>/forward', methods=['POST'])
@login_required
def forward_messages(chat_id):
    data = request.get_json()
    message_ids = data.get('message_ids', [])
    target_chat_id = data.get('target_chat_id')
    target_chat = Chat.query.get_or_404(target_chat_id)
    if current_user not in target_chat.participants:
        return jsonify({'error': 'Нет доступа к целевому чату'}), 403
    forwarded = []
    for msg_id in message_ids:
        original = Message.query.get(msg_id)
        if not original or original.chat_id != chat_id:
            continue
        forwarded_msg = Message(content=original.content, media_url=original.media_url,
                                media_type=original.media_type, sender_id=current_user.id,
                                chat_id=target_chat_id)
        db.session.add(forwarded_msg)
        forwarded.append(forwarded_msg.id)
    target_chat.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'forwarded_ids': forwarded})

@app.route('/api/chat/<int:chat_id>/pin/<int:message_id>', methods=['POST'])
@login_required
def pin_message(chat_id, message_id):
    chat = Chat.query.get_or_404(chat_id)
    if chat.is_group and chat.admin_id != current_user.id:
        return jsonify({'error': 'Только админ может закреплять'}), 403
    msg = Message.query.get_or_404(message_id)
    if msg.chat_id != chat_id:
        return jsonify({'error': 'Сообщение не принадлежит чату'}), 400
    existing = PinnedMessage.query.filter_by(chat_id=chat_id, message_id=message_id).first()
    if existing:
        return jsonify({'error': 'Уже закреплено'}), 400
    pin = PinnedMessage(chat_id=chat_id, message_id=message_id, pinned_by_id=current_user.id)
    db.session.add(pin)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/chat/<int:chat_id>/unpin/<int:message_id>', methods=['DELETE'])
@login_required
def unpin_message(chat_id, message_id):
    chat = Chat.query.get_or_404(chat_id)
    if chat.is_group and chat.admin_id != current_user.id:
        return jsonify({'error': 'Только админ может откреплять'}), 403
    pin = PinnedMessage.query.filter_by(chat_id=chat_id, message_id=message_id).first()
    if not pin:
        return jsonify({'error': 'Не закреплено'}), 404
    db.session.delete(pin)
    db.session.commit()
    return jsonify({'success': True})

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
    other = User.query.filter_by(username=username).first()
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

# ------------------------------
# API группы
# ------------------------------
@app.route('/api/group/<int:chat_id>/members')
@login_required
def get_group_members(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if not chat.is_group or current_user not in chat.participants:
        return jsonify({'error': 'Access denied'}), 403
    members = [{'id': u.id, 'username': u.username, 'avatar': u.avatar, 'is_admin': (u.id == chat.admin_id)} for u in chat.participants]
    return jsonify({'members': members, 'current_user_id': current_user.id, 'admin_id': chat.admin_id})

@app.route('/api/group/<int:chat_id>/members_list')
@login_required
def get_group_members_list(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if not chat.is_group or current_user not in chat.participants:
        return jsonify({'error': 'Access denied'}), 403
    members = [{'id': u.id, 'username': u.username, 'avatar': u.avatar} for u in chat.participants]
    return jsonify({'members': members})

@app.route('/api/group/<int:chat_id>/make_admin', methods=['POST'])
@login_required
def make_group_admin(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if not chat.is_group or chat.admin_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    user = User.query.get(data.get('user_id'))
    if not user or user not in chat.participants:
        return jsonify({'error': 'User not in group'}), 404
    chat.admin_id = user.id
    db.session.commit()
    return jsonify({'success': True})

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

# ------------------------------
# API поиск пользователей
# ------------------------------
@app.route('/api/users/search')
@login_required
def search_users():
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify([])
    users = User.query.filter(User.username.ilike(f'%{q}%'), User.id != current_user.id).limit(10).all()
    return jsonify([{'id': u.id, 'username': u.username, 'avatar': u.avatar} for u in users])

@app.route('/api/users/search_for_group')
@login_required
def search_users_for_group():
    q = request.args.get('q', '').strip()
    chat_id = request.args.get('chat_id', type=int)
    if len(q) < 2:
        return jsonify([])
    query = User.query.filter(User.username.ilike(f'%{q}%'), User.id != current_user.id)
    if chat_id:
        query = query.filter(~User.chats.any(id=chat_id))
    users = query.limit(20).all()
    return jsonify([{'id': u.id, 'username': u.username, 'avatar': u.avatar} for u in users])

# ------------------------------
# API реакции и статус
# ------------------------------
@app.route('/api/message/<int:message_id>/react', methods=['POST'])
@login_required
def add_reaction(message_id):
    data = request.get_json()
    reaction = data.get('reaction')
    if reaction not in ['👍', '❤️', '😂', '😮', '😢', '😡']:
        return jsonify({'error': 'Invalid reaction'}), 400
    existing = Reaction.query.filter_by(user_id=current_user.id, message_id=message_id).first()
    if existing:
        if existing.reaction == reaction:
            db.session.delete(existing)
        else:
            existing.reaction = reaction
    else:
        reaction_obj = Reaction(user_id=current_user.id, message_id=message_id, reaction=reaction)
        db.session.add(reaction_obj)
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
        'is_group': chat.is_group,
        'is_admin': chat.is_admin(current_user) if chat.is_group else False,
        'name': chat.name,
        'avatar': chat.avatar,
        'description': chat.description
    })

# ------------------------------
# Админские функции
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

@app.route('/admin/delete_user_post/<int:post_id>', methods=['DELETE'])
@login_required
def admin_delete_post(post_id):
    if current_user.role not in ('admin', 'moderator'):
        return jsonify({'error': 'Нет прав'}), 403
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
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

@app.route('/admin/transfer_admin/<int:user_id>', methods=['POST'])
@login_required
def transfer_admin(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Нет прав'}), 403
    target_user = User.query.get_or_404(user_id)
    if target_user.id == current_user.id:
        return jsonify({'error': 'Нельзя передать права самому себе'}), 400
    current_user.role = 'default'
    target_user.role = 'admin'
    db.session.commit()
    return jsonify({'success': True})

# ------------------------------
# Премиум: покупка и настройка
# ------------------------------
@app.route('/premium')
@app.route('/subscription')
@login_required
def premium_page():
    return render_template('premium.html', plans=PLANS)

@app.route('/buy_premium', methods=['POST'])
@login_required
def buy_premium():
    plan_key = request.form.get('plan')
    if plan_key not in PLANS:
        flash('Неверный тариф', 'error')
        return redirect(url_for('premium_page'))
    plan = PLANS[plan_key]
    now = datetime.utcnow()
    current_expires = current_user.premium_expires_at
    if plan['days'] == 0:
        new_expires = datetime.max
    else:
        if current_expires and current_expires > now:
            new_expires = current_expires + timedelta(days=plan['days'])
        else:
            new_expires = now + timedelta(days=plan['days'])
    current_user.premium_expires_at = new_expires
    # Создаём кастомизацию если нет
    cust = current_user.customization
    if not cust:
        cust = UserCustomization(user_id=current_user.id)
        db.session.add(cust)
        db.session.flush()
    # Устанавливаем дефолтную рамку если ещё нет
    if not cust.avatar_frame_key or cust.avatar_frame_key == 'premium_ring':
        cust.avatar_frame_key = 'premium_gold'
    db.session.commit()
    flash(f'Подписка «{plan["name"]}» активирована! 🎉', 'success')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/admin/manage_premium/<int:user_id>', methods=['POST'])
@login_required
def admin_manage_premium(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Нет прав'}), 403
    user = User.query.get_or_404(user_id)
    action = request.form.get('action')
    if action == 'give_forever':
        user.premium_expires_at = datetime.max
    elif action == 'give_month':
        user.premium_expires_at = datetime.utcnow() + timedelta(days=30)
    elif action == 'give_year':
        user.premium_expires_at = datetime.utcnow() + timedelta(days=365)
    elif action == 'remove':
        user.premium_expires_at = None
    else:
        return jsonify({'error': 'Неизвестное действие'}), 400
    if not user.customization and user.premium_expires_at:
        cust = UserCustomization(user_id=user.id)
        db.session.add(cust)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/save_customization', methods=['POST'])
@login_required
def save_customization():
    if not current_user.is_premium_active():
        flash('Только для премиум-подписчиков', 'error')
        return redirect(url_for('profile', username=current_user.username))
    cust = current_user.customization
    if not cust:
        cust = UserCustomization(user_id=current_user.id)
        db.session.add(cust)
    # Только фон профиля (картинка)
    bg_type = request.form.get('profile_background_type', 'none')
    cust.profile_background_type = bg_type
    if bg_type == 'none':
        cust.profile_background_url = None
    if 'profile_background' in request.files:
        file = request.files['profile_background']
        if file and file.filename:
            url, _ = safe_save_file(file, f"bg_{current_user.id}")
            if url:
                cust.profile_background_url = url
                cust.profile_background_type = 'image'
    db.session.commit()
    flash('Настройки сохранены', 'success')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/api/customization')
@login_required
def get_customization():
    if not current_user.is_premium_active() or not current_user.customization:
        return jsonify({})
    cust = current_user.customization
    return jsonify({
        'profile_background_type': cust.profile_background_type,
        'profile_background_url': cust.profile_background_url,
        'profile_background_gradient': cust.profile_background_gradient,
        'message_style': cust.message_style,
        'post_style': cust.post_style,
        'avatar_border_style': cust.avatar_border_style,
        'avatar_border_color': cust.avatar_border_color,
        'chat_theme': cust.chat_theme,
        'font_style': cust.font_style,
        'status_emoji': cust.status_emoji,
        'status_text': cust.status_text,
        'post_style_gradient': getattr(cust, 'post_style_gradient', None),
        'message_style_gradient': getattr(cust, 'message_style_gradient', None),
    })

# Premium: обновить статус
@app.route('/api/premium/status', methods=['POST'])
@login_required
def update_premium_status():
    if not current_user.is_premium_active():
        return jsonify({'error': 'Только для премиум'}), 403
    data = request.get_json()
    cust = current_user.customization
    if not cust:
        cust = UserCustomization(user_id=current_user.id)
        db.session.add(cust)
    cust.status_emoji = (data.get('emoji', '') or '')[:10]
    cust.status_text = (data.get('text', '') or '')[:80]
    db.session.commit()
    return jsonify({'success': True})

# ------------------------------
# Файлы
# ------------------------------
@app.route('/uploads/<path:filepath>')
@login_required
def download_file(filepath):
    # Windows-safe: normalize slashes and build absolute path
    upload_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
    # Join safely using os.path
    parts = [p for p in filepath.replace('\\', '/').split('/') if p and p != '..']
    full = os.path.abspath(os.path.join(upload_dir, *parts))
    # Security: must stay inside uploads dir
    if not full.startswith(upload_dir):
        abort(403)
    if not os.path.isfile(full):
        abort(404)
    return send_file(full)


# ============================================================
# МАРКЕТ РАМОК
# ============================================================
RARITY_ORDER = {'common':0,'rare':1,'epic':2,'legendary':3}
RARITY_LABELS = {'common':'Обычная','rare':'Редкая','epic':'Эпическая','legendary':'Легендарная'}
RARITY_COLORS = {'common':'#94a3b8','rare':'#3b82f6','epic':'#8b5cf6','legendary':'#f59e0b'}

@app.route('/market')
@login_required
def market():
    frames = AvatarFrame.query.filter_by(is_active=True).order_by(AvatarFrame.price.asc()).all()
    owned_keys = {uf.frame_key for uf in current_user.frames.all()}
    current_key = current_user.customization.avatar_frame_key if current_user.customization else 'premium_gold'
    return render_template('market.html', frames=frames, owned_keys=owned_keys,
                           current_key=current_key, rarity_labels=RARITY_LABELS,
                           rarity_colors=RARITY_COLORS)

@app.route('/market/buy/<frame_key>', methods=['POST'])
@login_required
def buy_frame(frame_key):
    frame = AvatarFrame.query.filter_by(key=frame_key, is_active=True).first_or_404()
    # Уже куплена?
    if UserFrame.query.filter_by(user_id=current_user.id, frame_key=frame_key).first():
        flash('Эта рамка уже у тебя есть!', 'info')
        return redirect(url_for('market'))
    # Бесплатная — только для premium
    if frame.price == 0:
        if not current_user.is_premium_active():
            flash('Эта рамка только для Premium пользователей', 'error')
            return redirect(url_for('market'))
    else:
        # Платная — нужен premium
        if not current_user.is_premium_active():
            flash('Для покупки рамок нужен Premium', 'error')
            return redirect(url_for('market'))
        # Здесь будет оплата (демо-режим)
        flash(f'Демо: рамка «{frame.name}» добавлена бесплатно (оплата не реализована)', 'info')

    uf = UserFrame(user_id=current_user.id, frame_key=frame_key, price_paid=frame.price)
    db.session.add(uf)
    frame.owners_count = (frame.owners_count or 0) + 1
    db.session.commit()
    flash(f'Рамка «{frame.name}» {frame.emoji} добавлена в коллекцию!', 'success')
    return redirect(url_for('market'))

@app.route('/market/equip/<frame_key>', methods=['POST'])
@login_required
def equip_frame(frame_key):
    # Проверяем что рамка есть у пользователя или она бесплатная для premium
    frame = AvatarFrame.query.filter_by(key=frame_key, is_active=True).first_or_404()
    owned = UserFrame.query.filter_by(user_id=current_user.id, frame_key=frame_key).first()
    if not owned and not (frame.price == 0 and current_user.is_premium_active()):
        return jsonify({'error': 'Рамка не в коллекции'}), 403

    cust = current_user.customization
    if not cust:
        cust = UserCustomization(user_id=current_user.id)
        db.session.add(cust)
    cust.avatar_frame_key = frame_key
    db.session.commit()
    return jsonify({'success': True, 'frame_url': frame.image_url})

@app.route('/api/market/frames')
@login_required
def api_market_frames():
    frames = AvatarFrame.query.filter_by(is_active=True).all()
    owned_keys = {uf.frame_key for uf in current_user.frames.all()}
    current_key = current_user.customization.avatar_frame_key if current_user.customization else 'premium_gold'
    result = []
    for f in frames:
        is_owned = f.key in owned_keys or (f.price == 0 and current_user.is_premium_active())
        result.append({
            'key': f.key, 'name': f.name, 'emoji': f.emoji,
            'description': f.description, 'image_url': f.image_url,
            'price': f.price, 'rarity': f.rarity,
            'rarity_label': RARITY_LABELS.get(f.rarity, f.rarity),
            'rarity_color': RARITY_COLORS.get(f.rarity, '#94a3b8'),
            'is_owned': is_owned, 'is_equipped': f.key == current_key,
            'owners_count': f.owners_count or 0,
        })
    result.sort(key=lambda x: RARITY_ORDER.get(x['rarity'], 0))
    return jsonify(result)

# ------------------------------
# Запуск
# ------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # ===== ДОБАВЛЯЕМ НЕДОСТАЮЩИЕ КОЛОНКИ И ТАБЛИЦЫ РАМОК =====
        try:
            db.session.execute('ALTER TABLE user_customizations ADD COLUMN avatar_frame_key VARCHAR(50) DEFAULT "premium_ring"')
            db.session.commit()
        except Exception: pass
        try:
            db.session.execute('ALTER TABLE users ADD COLUMN current_frame VARCHAR(50) DEFAULT "premium_ring"')
            db.session.commit()
        except Exception: pass
        # Создаём таблицы рамок, если их нет (модели уже добавлены в module.py)
        db.create_all()
        # Заполняем дефолтную рамку
        # Инициализация рамок
        FRAMES_DATA = [
            dict(key='premium_gold', name='Золотая', emoji='👑',
                 description='Анимированная золотая рамка для Premium пользователей',
                 image_url='/static/frames/premium_gold.svg', price=0,
                 rarity='common', is_default=True, is_active=True),
            dict(key='neon_pulse', name='Неон', emoji='⚡',
                 description='Электрический неоновый пульс — заметна в любой ленте',
                 image_url='/static/frames/neon_pulse.svg', price=199,
                 rarity='rare', is_default=False, is_active=True),
            dict(key='galaxy', name='Галактика', emoji='🌌',
                 description='Глубокий космос со звёздами и туманностями',
                 image_url='/static/frames/galaxy.svg', price=299,
                 rarity='rare', is_default=False, is_active=True),
            dict(key='fire_ring', name='Огонь', emoji='🔥',
                 description='Кольцо живого огня с летящими искрами',
                 image_url='/static/frames/fire_ring.svg', price=399,
                 rarity='epic', is_default=False, is_active=True),
            dict(key='aurora', name='Аврора', emoji='🌈',
                 description='Северное сияние с переливающимися цветами',
                 image_url='/static/frames/aurora.svg', price=499,
                 rarity='epic', is_default=False, is_active=True),
            dict(key='diamond', name='Бриллиант', emoji='💎',
                 description='Кристальная рамка с бликами и гранями',
                 image_url='/static/frames/diamond.svg', price=699,
                 rarity='legendary', is_default=False, is_active=True),
            dict(key='sakura', name='Сакура', emoji='🌸',
                 description='Нежные лепестки японской сакуры',
                 image_url='/static/frames/sakura.svg', price=349,
                 rarity='rare', is_default=False, is_active=True),
            dict(key='cyber', name='Кибер', emoji='🤖',
                 description='Футуристический хекс-интерфейс в стиле киберпанк',
                 image_url='/static/frames/cyber.svg', price=599,
                 rarity='epic', is_default=False, is_active=True),
        ]
        for fd in FRAMES_DATA:
            if not AvatarFrame.query.filter_by(key=fd['key']).first():
                db.session.add(AvatarFrame(**fd))
        db.session.commit()

        admin = User.query.filter_by(username='admin').first()
        if admin and admin.role == 'default':
            admin.role = 'admin'
            db.session.commit()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)






# Надо дописать чтобы из чата появлялась плашка с уведомлениями, у чата отсутствует прокрутка, надо залочить поле для написания сообщения

# ==========================================
# Хештеги
# ==========================================
@app.route('/hashtag/<tag_name>')
@login_required
def hashtag_feed(tag_name):
    tag_name = tag_name.lower().lstrip('#')
    ht = Hashtag.query.filter_by(name=tag_name).first()
    if not ht:
        flash(f'Хештег #{tag_name} не найден', 'error')
        return redirect(url_for('feed'))
    page = request.args.get('page', 1, int)
    posts = ht.posts.order_by(Post.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False)
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
    q = request.args.get('q', '').strip().lstrip('#')
    if len(q) < 1:
        return jsonify([])
    tags = (Hashtag.query
            .filter(Hashtag.name.ilike(f'%{q}%'))
            .order_by(Hashtag.posts_count.desc())
            .limit(10).all())
    return jsonify([{'name': t.name, 'count': t.posts_count} for t in tags])

