import os
import secrets
import logging
import base64
import io
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

# nh3 import guard
try:
    import nh3
except ImportError:
    raise RuntimeError(
        "nh3[security] is not installed! Run: pip install 'nh3[security]>=0.2.18'"
    )

from flask import (Flask, render_template, request, jsonify, session,
                   redirect, url_for, flash, g, send_from_directory, abort)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy.orm import joinedload, selectinload
from flask_limiter import Limiter, util
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    HAS_SOCKETIO = True
except ImportError:
    HAS_SOCKETIO = False
try:
    from flask_caching import Cache
    HAS_CACHING = True
except ImportError:
    HAS_CACHING = False
try:
    from prometheus_flask_exporter import PrometheusMetrics
    HAS_METRICS = True
except ImportError:
    HAS_METRICS = False
try:
    from pythonjsonlogger import jsonlogger
    HAS_JSON_LOG = True
except ImportError:
    HAS_JSON_LOG = False
try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
    HAS_SENTRY = True
except ImportError:
    HAS_SENTRY = False
import redis

from database import db
from module import (User, Post, Like, Comment, Follow, Message, Notification, Chat,
    chat_participants, PinnedMessage, Reaction, EncryptedMessage, PreKey, SignalSession,
    sanitize_html, validate_url, validate_password, Hashtag, post_hashtags, Technology,
    Role, Idea, idea_technologies, idea_roles, user_technologies, idea_likes,
    idea_join_requests, DEVELOPER_ROLES, SKILL_LEVELS, PROJECT_TYPES,
    Channel, ChannelPost, ChannelPostLike, ChannelPostComment, ChannelInvite,
    channel_members, validate_email, validate_username,
    get_file_type, extract_and_link_hashtags, safe_save_file)


# ============================================================
# Secret key validation
# ============================================================
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    raise RuntimeError(
        "SECRET_KEY is not set! Generate: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )


# Support Docker Secrets for DB password
def _resolve_db_uri():
    uri = os.environ.get('DATABASE_URL', '')
    if uri:
        return uri
    password_file = os.environ.get('POSTGRES_PASSWORD_FILE')
    if password_file:
        try:
            with open(password_file) as f:
                pw = f.read().strip()
            return f"postgresql+psycopg2://svyaz:{pw}@db:5432/svyaz"
        except (FileNotFoundError, IOError):
            pass
    pw = os.environ.get('POSTGRES_PASSWORD', '')
    if pw:
        return f"postgresql+psycopg2://svyaz:{pw}@db:5432/svyaz"
    return os.environ.get('DATABASE_URL', 'sqlite:///social_media.db')


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','webp','mp4','webm','ogg','mov','pdf','doc','docx','txt'}


# ============================================================
# Sentry (error tracking) — enable if SENTRY_DSN is set
if HAS_SENTRY:
    sentry_dsn = os.environ.get('SENTRY_DSN', '')
    if sentry_dsn:
        sentry_sdk.init(
            dsn=sentry_dsn,
            integrations=[FlaskIntegration()],
            traces_sample_rate=0.1,
            environment=os.environ.get('FLASK_ENV', 'production'),
        )


# JSON logger for production (stdout)
if HAS_JSON_LOG:
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(jsonlogger.JsonFormatter(
        fmt='%(asctime)s %(name)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    ))
    logging.basicConfig(level=logging.INFO, handlers=[log_handler])
else:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
audit_logger = logging.getLogger('audit')
if HAS_JSON_LOG:
    audit_handler = logging.StreamHandler()
    audit_handler.setFormatter(jsonlogger.JsonFormatter(
        fmt='%(asctime)s audit %(message)s',
    ))
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
else:
    audit_logger = logger


# ============================================================
# Redis with Sentinel support
# ============================================================
redis_available = False
redis_client = None
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', '')
REDIS_SENTINEL_HOSTS = os.environ.get('REDIS_SENTINEL_HOSTS', '')
try:
    if REDIS_SENTINEL_HOSTS:
        sentinel_hosts = [
            (part.split(':')[0], int(part.split(':')[1]) if ':' in part else 26379)
            for part in REDIS_SENTINEL_HOSTS.split(',')
        ]
        from redis.sentinel import Sentinel
        sentinel = Sentinel(sentinel_hosts, password=REDIS_PASSWORD or None,
                            socket_connect_timeout=2, decode_responses=True)
        redis_client = sentinel.master_for('mymaster', db=0, password=REDIS_PASSWORD or None)
        redis_client.ping()
        redis_available = True
        logger.info('Connected via Redis Sentinel (%s)', REDIS_SENTINEL_HOSTS)
    else:
        redis_client = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'),
                                   port=int(os.environ.get('REDIS_PORT', 6379)),
                                   db=0, decode_responses=True, socket_connect_timeout=2,
                                   password=REDIS_PASSWORD or None)
        redis_client.ping()
        redis_available = True
except redis.ConnectionError:
    logger.warning('Redis not available — in-memory fallback')
except Exception:
    logger.exception('Redis connection error')


def regenerate_session():
    """Regenerate session ID to prevent session fixation attacks."""
    preserved = dict(session)
    session.clear()
    session.update(preserved)


def get_real_ip():
    """Extract real IP considering X-Forwarded-For."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


app = Flask(__name__)


is_testing = os.environ.get('FLASK_ENV') == 'testing'
limiter = Limiter(
    app=app,
    key_func=get_real_ip,
    default_limits=[] if is_testing else ["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379" if (redis_available and not is_testing) else "memory://",
    enabled=not is_testing)


app.config['SECRET_KEY'] = _secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = _resolve_db_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

db.init_app(app)

# ---------------------------------------------------------------------------
# Talisman (HTTPS / Security Headers / CSP)
# ---------------------------------------------------------------------------
if not is_testing:
    csp = {
        'default-src': "'none'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        'img-src': "'self' data: https://ui-avatars.com",
        'connect-src': "'self' wss:",
        'font-src': "'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
        'form-action': "'self'",
        'frame-ancestors': "'none'",
        'base-uri': "'self'",
    }
    Talisman(app,
             force_https=os.environ.get('FLASK_ENV') == 'production',
             strict_transport_security=os.environ.get('FLASK_ENV') == 'production',
             strict_transport_security_max_age=31536000,
             strict_transport_security_include_subdomains=True,
             strict_transport_security_preload=True,
             content_security_policy=csp,
             content_security_policy_nonce_in=[],
             session_cookie_secure=os.environ.get('FLASK_ENV') == 'production',
             referrer_policy='strict-origin-when-cross-origin',
             )

# SocketIO for real-time (optional)
if HAS_SOCKETIO:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet',
                        message_queue=f"redis://{os.environ.get('REDIS_HOST', 'localhost')}:{os.environ.get('REDIS_PORT', 6379)}/4"
                        if os.environ.get('REDIS_HOST') else None)
else:
    socketio = None

# Prometheus metrics (optional)
if HAS_METRICS:
    metrics = PrometheusMetrics(app, group_by='endpoint')
    metrics.info('svyaz_info', 'Svyaz application info', version='2.0.0')
else:
    metrics = None

# Flask-Caching
if HAS_CACHING:
    app.config['CACHE_TYPE'] = 'RedisCache' if os.environ.get('REDIS_HOST') else 'SimpleCache'
    app.config['CACHE_REDIS_URL'] = f"redis://{os.environ.get('REDIS_HOST', 'localhost')}:{os.environ.get('REDIS_PORT', 6379)}/3"
    cache = Cache(app)

# Flask-WTF CSRF is disabled — we use our own csrf_required decorator
# to support both form and JSON/AJAX requests with a custom token field.
app.config['WTF_CSRF_ENABLED'] = False
csrf = CSRFProtect(app)


# ---------------------------------------------------------------------------
# Flask-Login + CSRF validation
# ---------------------------------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"


def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        return False
    form_token = request.form.get('_csrf_token') or request.headers.get('X-CSRFToken')
    if request.is_json:
        data = request.get_json(silent=True)
        if data:
            form_token = form_token or data.get('_csrf_token')
    return form_token is not None and secrets.compare_digest(token, form_token)


def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE'):
            if not validate_csrf_token():
                logger.warning('CSRF failed: %s from %s', request.path, request.remote_addr)
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'error': 'CSRF token missing'}), 403
                flash('Security check failed. Refresh and try again.', 'error')
                return redirect(request.referrer or url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


app.jinja_env.globals['csrf_token'] = generate_csrf_token
app.jinja_env.globals['now'] = datetime.utcnow


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if user and (user.is_deleted or user.is_blocked):
        return None
    return user


# ---------------------------------------------------------------------------
# Before/After request
# ---------------------------------------------------------------------------
@app.before_request
def before_request():
    g.user = current_user
    if current_user.is_authenticated:
        current_user.last_activity = datetime.utcnow()
        db.session.add(current_user)
        db.session.flush()
    if redis_available:
        real_ip = get_real_ip()
        try:
            failed = redis_client.get(f"failed_attempts:{real_ip}")
            if failed and int(failed) >= 5:
                logger.warning('Lockout IP %s (%s attempts)', real_ip, failed)
                if request.is_json:
                    return jsonify({'error': 'Too many attempts. Try again in 15 minutes.'}), 429
                flash('Too many attempts. Try again later.', 'error')
                return redirect(url_for('login'))
        except Exception:
            pass


@app.teardown_appcontext
def teardown_session(exception):
    db.session.remove()


@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


# ---------------------------------------------------------------------------
# .well-known / security
# ---------------------------------------------------------------------------
@app.route('/.well-known/security.txt')
def security_txt():
    return send_from_directory(os.path.join(app.static_folder, '.well-known'), 'security.txt', mimetype='text/plain')


@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt', mimetype='text/plain')


# ---------------------------------------------------------------------------
# Health / Readiness
# ---------------------------------------------------------------------------
@app.route('/health')
@csrf.exempt
def health():
    db_ok = False
    redis_ok = False
    try:
        db.session.execute(db.text('SELECT 1'))
        db_ok = True
    except Exception:
        pass
    try:
        if redis_available:
            redis_client.ping()
            redis_ok = True
    except Exception:
        pass
    status = 200 if db_ok else 503
    response = jsonify({
        'status': 'healthy' if status == 200 else 'degraded',
        'database': 'ok' if db_ok else 'down',
        'redis': 'ok' if redis_ok else 'down',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat(),
    })
    return response, status


@app.route('/readiness')
def readiness():
    try:
        db.session.execute(db.text('SELECT 1'))
        return jsonify({'status': 'ready'}), 200
    except Exception:
        return jsonify({'status': 'not ready'}), 503


# ---------------------------------------------------------------------------
# TOTP / 2FA
# ---------------------------------------------------------------------------
try:
    import pyotp
    import qrcode
    from qrcode.image.pil import PilImage
    HAS_TOTP = True
except ImportError:
    HAS_TOTP = False
    logger.warning('pyotp/qrcode not installed — 2FA disabled')


@app.route('/totp/verify', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def totp_verify():
    if not HAS_TOTP:
        return '2FA not available', 503
    user_id = session.get('totp_user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = db.session.get(User, user_id)
    if not user or not user.totp_enabled:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code, valid_window=1):
            session.pop('totp_user_id', None)
            regenerate_session()
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.add(user)
            db.session.commit()
            flash('Welcome!', 'success')
            return redirect(url_for('feed'))
        # Check recovery codes
        from module import RecoveryCode
        recovery = RecoveryCode.query.filter_by(user_id=user.id, is_used=False).all()
        for rc in recovery:
            if check_password_hash(rc.code_hash, code):
                rc.is_used = True
                rc.used_at = datetime.utcnow()
                db.session.add(rc)
                db.session.commit()
                session.pop('totp_user_id', None)
                regenerate_session()
                login_user(user, remember=True)
                user.last_login = datetime.utcnow()
                db.session.add(user)
                db.session.commit()
                flash('Recovery code used. Please set up a new 2FA device.', 'warning')
                return redirect(url_for('totp_setup'))
        flash('Invalid 2FA code', 'error')
        audit_logger.warning('TOTP failed', extra={'user_id': user.id, 'ip': get_real_ip()})
    return render_template('totp_verify.html')


@app.route('/totp/setup', methods=['GET', 'POST'])
@login_required
def totp_setup():
    if not HAS_TOTP:
        return '2FA not available', 503
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        secret = session.get('totp_setup_secret')
        if not secret:
            flash('Session expired. Try again.', 'error')
            return redirect(url_for('totp_setup'))
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            current_user.totp_secret = secret
            current_user.totp_enabled = True
            db.session.add(current_user)
            # Generate 10 recovery codes
            from module import RecoveryCode
            RecoveryCode.query.filter_by(user_id=current_user.id).delete()
            raw_codes = []
            for _ in range(10):
                raw = secrets.token_hex(8)
                raw_codes.append(raw)
                db.session.add(RecoveryCode(
                    user_id=current_user.id,
                    code_hash=generate_password_hash(raw, method='pbkdf2:sha256', salt_length=16),
                ))
            db.session.commit()
            session.pop('totp_setup_secret', None)
            flash('2FA enabled! Save your recovery codes — they won\'t be shown again.', 'success')
            audit_logger.info('TOTP enabled', extra={'username': current_user.username})
            return render_template('totp_recovery_codes.html', codes=raw_codes)
        flash('Invalid code', 'error')
        return redirect(url_for('totp_setup'))
    secret = pyotp.random_base32()
    session['totp_setup_secret'] = secret
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(current_user.email, issuer_name="Svyaz")
    qr = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template('totp_setup.html', secret=secret, qr_data=qr_b64)


@app.route('/totp/disable', methods=['POST'])
@login_required
def totp_disable():
    current_user.totp_secret = None
    current_user.totp_enabled = False
    db.session.add(current_user)
    db.session.commit()
    flash('2FA disabled', 'success')
    audit_logger.info('TOTP disabled', extra={'username': current_user.username})
    return redirect(url_for('profile_edit'))


# ---------------------------------------------------------------------------
# E2EE Key Exchange
# ---------------------------------------------------------------------------
@app.route('/api/e2ee/identity-key', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per hour")
def e2ee_identity_key():
    if request.method == 'POST':
        data = request.get_json(silent=True)
        if not data or not data.get('public_key'):
            return jsonify({'error': 'public_key required'}), 400
        current_user.identity_public_key = data['public_key']
        db.session.add(current_user)
        db.session.commit()
        audit_logger.info('E2EE identity key set', extra={'username': current_user.username})
        return jsonify({'success': True})
    # GET: return this user's identity key
    if current_user.identity_public_key:
        return jsonify({'public_key': current_user.identity_public_key})
    return jsonify({'error': 'No key set'}), 404


@app.route('/api/e2ee/prekeys', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
def e2ee_upload_prekeys():
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get('prekeys'), list):
        return jsonify({'error': 'prekeys list required'}), 400
    for pk in data['prekeys']:
        if pk.get('key_id') is None or not pk.get('public_key'):
            continue
        existing = PreKey.query.filter_by(user_id=current_user.id, key_id=pk['key_id']).first()
        if not existing:
            db.session.add(PreKey(user_id=current_user.id, key_id=pk['key_id'], public_key=pk['public_key']))
    db.session.commit()
    return jsonify({'success': True, 'count': len(data['prekeys'])})


@app.route('/api/e2ee/prekeys/<int:user_id>', methods=['GET'])
@login_required
@limiter.limit("60 per hour")
def e2ee_get_prekeys(user_id):
    user = db.session.get(User, user_id)
    if not user or not user.identity_public_key:
        return jsonify({'error': 'User not found or no key'}), 404
    prekeys = PreKey.query.filter_by(user_id=user_id, is_used=False).order_by(PreKey.key_id).limit(10).all()
    return jsonify({
        'identity_key': user.identity_public_key,
        'prekeys': [{'key_id': pk.key_id, 'public_key': pk.public_key} for pk in prekeys],
    })


@app.route('/api/e2ee/send', methods=['POST'])
@login_required
@limiter.limit("60 per hour")
def e2ee_send():
    data = request.get_json(silent=True)
    if not data or not data.get('chat_id') or not data.get('ciphertext'):
        return jsonify({'error': 'chat_id, ciphertext required'}), 400
    chat = db.session.get(Chat, data['chat_id'])
    if not chat or current_user not in chat.participants:
        return jsonify({'error': 'Chat not found'}), 404
    msg = EncryptedMessage(
        chat_id=chat.id,
        sender_id=current_user.id,
        ciphertext=data['ciphertext'],
        ephemeral_key=data.get('ephemeral_key', ''),
        salt=data.get('salt', ''),
        nonce=data.get('nonce', ''),
    )
    db.session.add(msg)
    db.session.commit()
    # Notify via WebSocket
    if HAS_SOCKETIO and socketio:
        socketio.emit('new_encrypted_message', {
            'chat_id': chat.id,
            'message_id': msg.id,
            'sender_id': current_user.id,
            'created_at': msg.created_at.isoformat(),
        }, room=f'chat_{chat.id}')
    return jsonify({'success': True, 'message_id': msg.id})


@app.route('/api/e2ee/messages/<int:chat_id>')
@login_required
@limiter.limit("60 per hour")
def e2ee_messages(chat_id):
    chat = db.session.get(Chat, chat_id)
    if not chat or current_user not in chat.participants:
        return jsonify([]), 404
    since = request.args.get('since')
    query = EncryptedMessage.query.filter_by(chat_id=chat.id)
    if since:
        try:
            query = query.filter(EncryptedMessage.created_at > datetime.fromisoformat(since))
        except ValueError:
            pass
    messages = query.order_by(EncryptedMessage.created_at).limit(100).all()
    return jsonify([{
        'id': m.id,
        'sender_id': m.sender_id,
        'ciphertext': m.ciphertext,
        'ephemeral_key': m.ephemeral_key,
        'salt': m.salt,
        'nonce': m.nonce,
        'created_at': m.created_at.isoformat(),
        'read_at': m.read_at.isoformat() if m.read_at else None,
    } for m in messages])


# ---------------------------------------------------------------------------
# Group E2EE session management
# ---------------------------------------------------------------------------
@app.route('/api/e2ee/session', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
def e2ee_save_session():
    """Save or update a Signal session for a group participant."""
    data = request.get_json(silent=True)
    if not data or not data.get('chat_id') or not data.get('their_identity_key'):
        return jsonify({'error': 'chat_id, their_identity_key required'}), 400
    chat = db.session.get(Chat, data['chat_id'])
    if not chat or current_user not in chat.participants:
        return jsonify({'error': 'Chat not found'}), 404
    session_obj = SignalSession.query.filter_by(
        chat_id=chat.id, user_id=current_user.id
    ).first()
    if session_obj:
        session_obj.their_identity_key = data['their_identity_key']
        session_obj.our_ephemeral_key = data.get('our_ephemeral_key', session_obj.our_ephemeral_key)
        session_obj.session_data = data.get('session_data', session_obj.session_data)
    else:
        session_obj = SignalSession(
            chat_id=chat.id,
            user_id=current_user.id,
            their_identity_key=data['their_identity_key'],
            our_ephemeral_key=data.get('our_ephemeral_key', ''),
            session_data=data.get('session_data', ''),
        )
        db.session.add(session_obj)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/e2ee/session/<int:chat_id>')
@login_required
@limiter.limit("30 per hour")
def e2ee_get_session(chat_id):
    """Get the current user's Signal session for a chat."""
    chat = db.session.get(Chat, chat_id)
    if not chat or current_user not in chat.participants:
        return jsonify({'error': 'Chat not found'}), 404
    session_obj = SignalSession.query.filter_by(
        chat_id=chat.id, user_id=current_user.id
    ).first()
    if not session_obj:
        return jsonify({'error': 'No session'}), 404
    return jsonify({
        'their_identity_key': session_obj.their_identity_key,
        'our_ephemeral_key': session_obj.our_ephemeral_key,
        'session_data': session_obj.session_data,
        'created_at': session_obj.created_at.isoformat(),
    })


@app.route('/api/e2ee/session/<int:chat_id>/delete', methods=['DELETE'])
@login_required
def e2ee_delete_session(chat_id):
    """Delete the current user's Signal session for a chat."""
    SignalSession.query.filter_by(chat_id=chat_id, user_id=current_user.id).delete()
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/e2ee/group-keys/<int:chat_id>')
@login_required
def e2ee_group_keys(chat_id):
    """Get all participants' identity keys for a group chat (E2EE)."""
    chat = db.session.get(Chat, chat_id)
    if not chat or not chat.is_group or current_user not in chat.participants:
        return jsonify({'error': 'Group chat not found'}), 404
    participants = User.query.join(chat_participants).filter(
        chat_participants.c.chat_id == chat.id,
        User.identity_public_key.isnot(None),
        User.id != current_user.id,
    ).all()
    return jsonify([{
        'user_id': p.id,
        'username': p.username,
        'identity_key': p.identity_public_key,
    } for p in participants])


# ---------------------------------------------------------------------------
# WebSocket events (conditional)
if HAS_SOCKETIO and socketio:

    @socketio.on('join')
    def handle_join(data):
        if data.get('chat_id'):
            join_room(f"chat_{data['chat_id']}")

    @socketio.on('leave')
    def handle_leave(data):
        if data.get('chat_id'):
            leave_room(f"chat_{data['chat_id']}")

    @socketio.on('typing')
    def handle_typing(data):
        emit('typing', {
            'chat_id': data.get('chat_id'),
            'user_id': current_user.id,
            'username': current_user.username,
        }, room=f"chat_{data.get('chat_id')}", include_self=False)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error_code=404, message="Page not found"), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    logger.error('Internal server error: %s', e, exc_info=True)
    return render_template('error.html', error_code=500, message="Внутренняя ошибка сервера"), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error_code=403, message="Access denied"), 403

@app.errorhandler(Exception)
def handle_exception(e):
    """Global handler — does not expose error details to the client."""
    db.session.rollback()
    logger.error('Unhandled exception: %s', str(e), exc_info=True)
    if request.is_json:
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('error.html', error_code=500, message="Internal server error"), 500

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
@csrf_required
def register():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        if not validate_username(username):
            flash('Username must be 3-32 characters: letters, digits, _ and -', 'error')
            return redirect(url_for('register'))
        if not validate_email(email):
            flash('Invalid email address', 'error')
            return redirect(url_for('register'))
        valid_pw, pw_msg = validate_password(password)
        if not valid_pw:
            flash(pw_msg, 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already in use', 'error')
            return redirect(url_for('register'))
        user = User(username=username, email=email,
                    password_hash=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16),
                    avatar=f"https://ui-avatars.com/api/?background=random&name={username}",
                    role='default')
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Registration successful!', 'success')
        return redirect(url_for('feed'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@csrf_required
def login():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        real_ip = get_real_ip()

        user = User.query.filter_by(username=username, is_deleted=False).first()
        if user and user.is_blocked:
            flash('Your account has been blocked', 'error')
            return redirect(url_for('login'))

        if user and check_password_hash(user.password_hash, password):
            audit_logger.info('Login password OK', extra={'username': username, 'ip': real_ip})
            regenerate_session()
            # Enforce 2FA for admins
            if user.is_admin and not user.totp_enabled:
                flash('Admins must enable 2FA. Please set it up.', 'warning')
                login_user(user, remember=False)
                return redirect(url_for('totp_setup'))
            if user.totp_enabled:
                session['totp_user_id'] = user.id
                return redirect(url_for('totp_verify'))
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.add(user)
            db.session.commit()
            if redis_available:
                try:
                    redis_client.delete(f"failed_attempts:{real_ip}")
                except Exception:
                    logger.warning('Failed to clear failed attempts for %s', real_ip)
            flash('Welcome!', 'success')
            return redirect(url_for('feed'))
        else:
            audit_logger.info('Login failed', extra={'username': username, 'ip': real_ip})
            if redis_available:
                try:
                    failed = redis_client.incr(f"failed_attempts:{real_ip}")
                    redis_client.expire(f"failed_attempts:{real_ip}", 900)
                    if int(failed) >= 5:
                        audit_logger.warning('Brute-force threshold reached', extra={'ip': real_ip, 'attempts': failed})
                except Exception:
                    logger.warning('Failed to track failed attempts for IP %s', real_ip)
            flash('Invalid username or password', 'error')
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
    return render_template('feed.html', posts=posts)

@app.route('/post/create', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
@csrf_required
def create_post():
    content = request.form.get('content', '').strip()
    media_url, media_type = None, None
    if 'media' in request.files:
        media_url, media_type = safe_save_file(request.files['media'], 'post')
    if not content and not media_url:
        flash('Post cannot be empty', 'error')
        return redirect(request.referrer or url_for('feed'))
    if len(content) > 10000:
        flash('Post is too long', 'error')
        return redirect(request.referrer or url_for('feed'))
    clean = sanitize_html(content)
    post = Post(content=clean, media_url=media_url, media_type=media_type, user_id=current_user.id)
    db.session.add(post)
    db.session.flush()
    extract_and_link_hashtags(clean, post)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash('Error creating post', 'error')
        return redirect(request.referrer or url_for('feed'))
    flash('Post published!', 'success')
    return redirect(url_for('feed'))

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)
    comments = post.comments.options(joinedload(Comment.author)).order_by(Comment.created_at.desc()).all()
    return render_template('post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
@limiter.limit("60 per hour")
@csrf_required
def like_post(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({'error': 'Post not found'}), 404
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
                                  content=f"{current_user.username} liked your post",
                                 link=f"/post/{post_id}")
            db.session.add(notif)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500
    return jsonify({'liked': liked, 'count': post.likes.count()})

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
@limiter.limit("60 per hour")
@csrf_required
def add_comment(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    content = request.form.get('content', '').strip()
    if not content or len(content) > 5000:
        return jsonify({'error': 'Comment empty or too long'}), 400
    comment = Comment(content=sanitize_html(content), user_id=current_user.id, post_id=post_id)
    db.session.add(comment)
    if post.user_id != current_user.id:
        notif = Notification(user_id=post.user_id, type='comment',
                              content=f"{current_user.username} commented: {content[:50]}",
                             link=f"/post/{post_id}")
        db.session.add(notif)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500
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
@limiter.limit("30 per hour")
@csrf_required
def edit_post(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    if post.user_id != current_user.id:
        return jsonify({'error': 'No permission'}), 403
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid data format'}), 400
    new_content = data.get('content', '').strip()
    if not new_content:
        return jsonify({'error': 'Content cannot be empty'}), 400
    if len(new_content) > 10000:
        return jsonify({'error': 'Post is too long'}), 400
    post.content = sanitize_html(new_content)
    post.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True, 'content': sanitize_html(new_content)})

@app.route('/post/<int:post_id>/delete', methods=['DELETE'])
@login_required
@csrf_required
def delete_post(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    if not current_user.can_delete_post(post):
        return jsonify({'error': 'No permission'}), 403
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
    is_following = Follow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first() is not None
    return render_template('profile.html', profile_user=user, posts=posts, is_following=is_following)

@app.route('/upload_avatar', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
@csrf_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('profile', username=current_user.username))
    file = request.files['avatar']
    if not file or file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('profile', username=current_user.username))
    url, _ = safe_save_file(file, f"user_{current_user.id}")
    if url:
        current_user.avatar = url
        db.session.commit()
        flash('Avatar updated!', 'success')
    else:
        flash('Invalid format', 'error')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/update_profile', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
@csrf_required
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
    flash('Profile updated', 'success')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
@csrf_required
def profile_edit():
    technologies = Technology.query.order_by(Technology.category, Technology.name).all()
    user_tech_ids = {t.id for t in current_user.tech_stack.all()}
    tech_by_category = {}
    for t in technologies:
        cat = t.category or 'Other'
        tech_by_category.setdefault(cat, []).append(t)
    developer_roles_dict = {}
    for r in Role.query.order_by(Role.name).all():
        if r.name in DEVELOPER_ROLES:
            developer_roles_dict[r.name] = r.label
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
        flash('Profile updated', 'success')
        return redirect(url_for('profile', username=current_user.username))
    return render_template('profile_edit.html', tech_by_category=tech_by_category,
                           user_tech_ids=user_tech_ids, developer_roles=developer_roles_dict)

@app.route('/delete_account', methods=['POST'])
@login_required
@csrf_required
def delete_account():
    current_user.anonymize()
    db.session.commit()
    logout_user()
    flash('Account deleted', 'success')
    return redirect(url_for('index'))

@app.route('/user/<username>/follow', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
@csrf_required
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
                              content=f"{current_user.username} followed you",
                             link=f"/user/{current_user.username}")
        db.session.add(notif)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500
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
        if not n.read:
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
    type_filter = request.args.get('type', '').strip()
    query = Idea.query.filter_by(is_active=True).options(joinedload(Idea.author))
    if type_filter and type_filter in PROJECT_TYPES:
        query = query.filter_by(project_type=type_filter)
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
                           roles=roles, sort=sort, tech_filter=tech_filter, role_filter=role_filter,
                           type_filter=type_filter, project_types=PROJECT_TYPE_LABELS)

PROJECT_TYPE_LABELS = {
    'game': 'Game', 'website': 'Website', 'app': 'Application',
    'library': 'Library', 'framework': 'Framework', 'cli': 'CLI Tool',
    'api': 'API / Service', 'plugin': 'Plugin', 'bot': 'Bot',
    'saas': 'SaaS', 'browser-ext': 'Browser Extension',
    'desktop': 'Desktop', 'embedded': 'Embedded', 'other': 'Other',
}

@app.route('/idea/create', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per hour")
@csrf_required
def idea_create():
    technologies = Technology.query.order_by(Technology.category, Technology.name).all()
    roles = Role.query.order_by(Role.name).all()
    tech_by_category = {}
    for t in technologies:
        cat = t.category or 'Other'
        tech_by_category.setdefault(cat, []).append(t)
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        project_type = request.form.get('project_type', 'other').strip()
        github_url = request.form.get('github_url', '').strip()
        selected_techs = request.form.getlist('technologies')
        selected_roles = request.form.getlist('roles')
        if project_type not in PROJECT_TYPES:
            project_type = 'other'
        if github_url:
            if not (github_url.startswith('http://') or github_url.startswith('https://')):
                github_url = 'https://' + github_url
            if 'github.com' not in github_url.lower():
                github_url = ''
        if not title or not description:
            flash('Title and description are required', 'error')
            return render_template('idea_create.html', tech_by_category=tech_by_category,
                                   roles=roles, project_types=PROJECT_TYPE_LABELS)
        if len(title) > 200:
            flash('Title is too long', 'error')
            return render_template('idea_create.html', tech_by_category=tech_by_category,
                                   roles=roles, project_types=PROJECT_TYPE_LABELS)
        if len(description) > 10000:
            flash('Description is too long', 'error')
            return render_template('idea_create.html', tech_by_category=tech_by_category,
                                   roles=roles, project_types=PROJECT_TYPE_LABELS)
        try:
            idea = Idea(
                title=sanitize_html(title), description=sanitize_html(description),
                project_type=project_type, author_id=current_user.id,
                github_url=github_url or None
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
            group_chat = Chat(is_group=True, name=f"Idea Chat: {title[:50]}", admin_id=current_user.id, idea_id=idea.id)
            db.session.add(group_chat)
            group_chat.participants.append(current_user)
            db.session.flush()
            idea.chat_id = group_chat.id
            db.session.commit()
            flash('Idea created! Team chat is available.', 'success')
            return redirect(url_for('idea_detail', idea_id=idea.id))
        except Exception as e:
            db.session.rollback()
            logger.error('Idea create error: %s', e, exc_info=True)
            flash('Error creating idea', 'error')
            return render_template('idea_create.html', tech_by_category=tech_by_category,
                                   roles=roles, project_types=PROJECT_TYPE_LABELS)
    return render_template('idea_create.html', tech_by_category=tech_by_category,
                           roles=roles, project_types=PROJECT_TYPE_LABELS)

@app.route('/idea/<int:idea_id>')
@login_required
def idea_detail(idea_id):
    idea = db.session.get(Idea, idea_id)
    if not idea or not idea.is_active:
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
    return render_template('idea_detail.html', idea=idea, pending_requests=pending_requests,
                           project_type_labels=PROJECT_TYPE_LABELS)

@app.route('/idea/<int:idea_id>/like', methods=['POST'])
@login_required
@limiter.limit("60 per hour")
@csrf_required
def idea_like(idea_id):
    idea = db.session.get(Idea, idea_id)
    if not idea or not idea.is_active:
        return jsonify({'error': 'Idea is not active'}), 404
    existing = idea.likers.filter_by(id=current_user.id).first()
    if existing:
        idea.likers.remove(existing)
        liked = False
    else:
        idea.likers.append(current_user)
        liked = True
        if idea.author_id != current_user.id:
            notif = Notification(user_id=idea.author_id, type='like',
                                 content=f"{current_user.username} supported your idea",
                                 link=f"/idea/{idea_id}")
            db.session.add(notif)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500
    return jsonify({'liked': liked, 'count': idea.likes_count})

@app.route('/idea/<int:idea_id>/join', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
@csrf_required
def idea_join_request(idea_id):
    idea = db.session.get(Idea, idea_id)
    if not idea or not idea.is_active:
        return jsonify({'error': 'Idea is not active'}), 404
    if idea.author_id == current_user.id:
        flash('You are the author of this idea', 'info')
        return redirect(url_for('idea_detail', idea_id=idea_id))
    existing = db.session.query(idea_join_requests).filter_by(
        idea_id=idea.id, user_id=current_user.id
    ).first()
    if existing:
        if existing.status == 'pending':
            flash('Request already submitted', 'info')
        elif existing.status == 'approved':
            flash('You are already in the discussion group', 'info')
        else:
            flash('Your request was rejected', 'error')
        return redirect(url_for('idea_detail', idea_id=idea_id))
    db.session.execute(idea_join_requests.insert().values(
        idea_id=idea.id, user_id=current_user.id, status='pending', created_at=datetime.utcnow()
    ))
    notif = Notification(user_id=idea.author_id, type='follow',
                         content=f"{current_user.username} wants to join the idea discussion",
                         link=f"/idea/{idea_id}")
    db.session.add(notif)
    db.session.commit()
    flash('Join request sent!', 'success')
    return redirect(url_for('idea_detail', idea_id=idea_id))

@app.route('/idea/<int:idea_id>/join/<int:user_id>/approve', methods=['POST'])
@login_required
@csrf_required
def idea_approve_join(idea_id, user_id):
    idea = db.session.get(Idea, idea_id)
    if not idea:
        abort(404)
    if idea.author_id != current_user.id:
        return jsonify({'error': 'No permission'}), 403
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot approve your own request'}), 400
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
    flash('Member added to group', 'success')
    return redirect(url_for('idea_detail', idea_id=idea_id))

@app.route('/idea/<int:idea_id>/join/<int:user_id>/reject', methods=['POST'])
@login_required
@csrf_required
def idea_reject_join(idea_id, user_id):
    idea = db.session.get(Idea, idea_id)
    if not idea:
        abort(404)
    if idea.author_id != current_user.id:
        return jsonify({'error': 'No permission'}), 403
    db.session.execute(idea_join_requests.update().where(
        idea_join_requests.c.idea_id == idea.id,
        idea_join_requests.c.user_id == user_id,
        idea_join_requests.c.status == 'pending'
    ).values(status='rejected'))
    db.session.commit()
    flash('Request rejected', 'success')
    return redirect(url_for('idea_detail', idea_id=idea_id))

@app.route('/idea/<int:idea_id>/delete', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
@csrf_required
def idea_delete(idea_id):
    idea = db.session.get(Idea, idea_id)
    if not idea or not idea.is_active:
        abort(404)
    if idea.author_id != current_user.id and current_user.role not in ('admin', 'moderator'):
        abort(403)
    idea.is_active = False
    db.session.commit()
    flash('Idea deleted', 'success')
    return redirect(url_for('ideas_feed'))

@app.route('/idea/<int:idea_id>/edit', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per hour")
@csrf_required
def idea_edit(idea_id):
    idea = db.session.get(Idea, idea_id)
    if not idea or not idea.is_active:
        abort(404)
    if idea.author_id != current_user.id:
        abort(403)
    technologies = Technology.query.order_by(Technology.category, Technology.name).all()
    roles = Role.query.order_by(Role.name).all()
    tech_by_category = {}
    for t in technologies:
        cat = t.category or 'Other'
        tech_by_category.setdefault(cat, []).append(t)
    user_tech_ids = {t.id for t in idea.technologies}
    user_role_ids = {r.id for r in idea.roles_needed}
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        project_type = request.form.get('project_type', 'other').strip()
        github_url = request.form.get('github_url', '').strip()
        selected_techs = request.form.getlist('technologies')
        selected_roles = request.form.getlist('roles')
        if project_type not in PROJECT_TYPES:
            project_type = 'other'
        if github_url:
            if not (github_url.startswith('http://') or github_url.startswith('https://')):
                github_url = 'https://' + github_url
            if 'github.com' not in github_url.lower():
                github_url = ''
        if not title or not description:
            flash('Title and description are required', 'error')
            return render_template('idea_edit.html', idea=idea, tech_by_category=tech_by_category,
                                   roles=roles, project_types=PROJECT_TYPE_LABELS,
                                   user_tech_ids=user_tech_ids, user_role_ids=user_role_ids)
        if len(title) > 200:
            flash('Title is too long', 'error')
            return render_template('idea_edit.html', idea=idea, tech_by_category=tech_by_category,
                                   roles=roles, project_types=PROJECT_TYPE_LABELS,
                                   user_tech_ids=user_tech_ids, user_role_ids=user_role_ids)
        if len(description) > 10000:
            flash('Description is too long', 'error')
            return render_template('idea_edit.html', idea=idea, tech_by_category=tech_by_category,
                                   roles=roles, project_types=PROJECT_TYPE_LABELS,
                                   user_tech_ids=user_tech_ids, user_role_ids=user_role_ids)
        try:
            idea.title = sanitize_html(title)
            idea.description = sanitize_html(description)
            idea.project_type = project_type
            idea.github_url = github_url or None
            idea.technologies = Technology.query.filter(Technology.id.in_(selected_techs)).all() if selected_techs else []
            idea.roles_needed = Role.query.filter(Role.id.in_(selected_roles)).all() if selected_roles else []
            db.session.commit()
            flash('Idea updated!', 'success')
            return redirect(url_for('idea_detail', idea_id=idea.id))
        except Exception as e:
            db.session.rollback()
            logger.error('Idea edit error: %s', e, exc_info=True)
            flash('Error updating idea', 'error')
    return render_template('idea_edit.html', idea=idea, tech_by_category=tech_by_category,
                           roles=roles, project_types=PROJECT_TYPE_LABELS,
                           user_tech_ids=user_tech_ids, user_role_ids=user_role_ids)

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
@limiter.limit("10 per hour")
@csrf_required
def channel_create():
    if request.method == 'POST':
        name = request.form.get('name', '').strip().lower()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        channel_type = request.form.get('type', 'public')
        if channel_type not in ('public', 'private'):
            channel_type = 'public'
        if not name or not title:
            flash('Name and handle are required', 'error')
            return render_template('channel_create.html')
        if not name.replace('_', '').replace('-', '').isalnum():
            flash('Handle can only contain letters, digits, _ and -', 'error')
            return render_template('channel_create.html')
        if len(name) > 50:
            flash('Handle is too long', 'error')
            return render_template('channel_create.html')
        if Channel.query.filter_by(name=name).first():
            flash('Handle is already taken', 'error')
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
        flash('Channel created!', 'success')
        return redirect(url_for('channel_page', channel_name=name))
    return render_template('channel_create.html')

@app.route('/channel/<channel_name>')
@login_required
def channel_page(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if channel.type == 'private':
        membership = channel.get_membership(current_user)
        if not membership or membership.status != 'active':
            if not channel.is_admin(current_user):
                flash('This is a private channel', 'error')
                return redirect(url_for('channels_list'))
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
@limiter.limit("20 per hour")
@csrf_required
def channel_join(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    existing = channel.get_membership(current_user)
    if existing and existing.status == 'active':
        flash('You are already a member', 'info')
        return redirect(url_for('channel_page', channel_name=channel_name))
    if existing and existing.status == 'pending':
        flash('Request already submitted', 'info')
        return redirect(url_for('channel_page', channel_name=channel_name))
    if channel.type == 'public':
        db.session.execute(channel_members.insert().values(
            channel_id=channel.id, user_id=current_user.id,
            role='member', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()
        flash('You joined the channel!', 'success')
    else:
        db.session.execute(channel_members.insert().values(
            channel_id=channel.id, user_id=current_user.id,
            role='member', status='pending', joined_at=datetime.utcnow()
        ))
        db.session.commit()
        flash('Join request sent', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/leave', methods=['POST'])
@login_required
@csrf_required
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
    flash('You left the channel', 'success')
    return redirect(url_for('channels_list'))

@app.route('/channel/<channel_name>/post', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
@csrf_required
def channel_post_create(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.can_post(current_user):
        flash('Only members can post', 'error')
        return redirect(url_for('channel_page', channel_name=channel_name))
    content = request.form.get('content', '').strip()
    if not content:
        flash('Post cannot be empty', 'error')
        return redirect(url_for('channel_page', channel_name=channel_name))
    if len(content) > 10000:
        flash('Post is too long', 'error')
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
    flash('Post published!', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

def _check_channel_access(channel):
    """For private channels, ensure the current user is an active member."""
    if channel.type == 'private':
        membership = channel.get_membership(current_user)
        if not membership or membership.status != 'active':
            return False
    return True

@app.route('/channel/<channel_name>/post/<int:post_id>/like', methods=['POST'])
@login_required
@limiter.limit("60 per hour")
@csrf_required
def channel_post_like(channel_name, post_id):
    post = db.session.get(ChannelPost, post_id)
    if not post:
        return jsonify({'error': 'Not found'}), 404
    channel = Channel.query.filter_by(name=channel_name).first()
    if not channel or post.channel_id != channel.id:
        return jsonify({'error': 'Not found'}), 404
    if not _check_channel_access(channel):
        return jsonify({'error': 'Not found'}), 404
    existing = ChannelPostLike.query.filter_by(post_id=post_id, user_id=current_user.id).first()
    if existing:
        db.session.delete(existing)
        liked = False
    else:
        db.session.add(ChannelPostLike(post_id=post_id, user_id=current_user.id))
        liked = True
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500
    return jsonify({'liked': liked, 'count': post.likes_count})

@app.route('/channel/<channel_name>/post/<int:post_id>/comment', methods=['POST'])
@login_required
@limiter.limit("60 per hour")
@csrf_required
def channel_post_comment(channel_name, post_id):
    post = db.session.get(ChannelPost, post_id)
    if not post:
        return jsonify({'error': 'Not found'}), 404
    channel = Channel.query.filter_by(name=channel_name).first()
    if not channel or post.channel_id != channel.id:
        return jsonify({'error': 'Not found'}), 404
    if not _check_channel_access(channel):
        return jsonify({'error': 'Not found'}), 404
    content = request.form.get('content', '').strip()
    if not content or len(content) > 5000:
        return jsonify({'error': 'Invalid content'}), 400
    comment = ChannelPostComment(post_id=post_id, user_id=current_user.id, content=sanitize_html(content))
    db.session.add(comment)
    post.comments_count += 1
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500
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
@csrf_required
def channel_post_delete(channel_name, post_id):
    post = db.session.get(ChannelPost, post_id)
    if not post:
        abort(404)
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if post.channel_id != channel.id:
        abort(404)
    if not _check_channel_access(channel):
        return jsonify({'error': 'No permission'}), 403
    if post.author_id != current_user.id and not channel.is_admin(current_user):
        return jsonify({'error': 'No permission'}), 403
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/edit', methods=['GET', 'POST'])
@login_required
@csrf_required
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
        flash('Channel updated', 'success')
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
@csrf_required
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
    flash(f'Role for {target.username} changed to {new_role}', 'success')
    return redirect(url_for('channel_members_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/member/<int:user_id>/ban', methods=['POST'])
@login_required
@csrf_required
def channel_ban_member(channel_name, user_id):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_admin(current_user):
        abort(403)
    db.session.execute(channel_members.update().where(
        channel_members.c.channel_id == channel.id,
        channel_members.c.user_id == user_id
    ).values(status='banned'))
    db.session.commit()
    flash('User banned from channel', 'success')
    return redirect(url_for('channel_members_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/member/<int:user_id>/remove', methods=['POST'])
@login_required
@csrf_required
def channel_remove_member(channel_name, user_id):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_moderator(current_user):
        abort(403)
    db.session.execute(channel_members.delete().where(
        channel_members.c.channel_id == channel.id,
        channel_members.c.user_id == user_id
    ))
    db.session.commit()
    flash('User removed from channel', 'success')
    return redirect(url_for('channel_members_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/requests/<int:user_id>/approve', methods=['POST'])
@login_required
@csrf_required
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
    flash('Request approved', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/requests/<int:user_id>/reject', methods=['POST'])
@login_required
@csrf_required
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
    flash('Request rejected', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/<channel_name>/invite/create', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
@csrf_required
def channel_create_invite(channel_name):
    channel = Channel.query.filter_by(name=channel_name).first_or_404()
    if not channel.is_moderator(current_user):
        abort(403)
    token = secrets.token_urlsafe(32)
    expires_hours = request.form.get('expires_hours', 72, type=int)
    if expires_hours < 1:
        expires_hours = 1
    expires_at = datetime.utcnow() + timedelta(hours=min(expires_hours, 720))
    invite = ChannelInvite(
        channel_id=channel.id, inviter_id=current_user.id,
        token=token, expires_at=expires_at
    )
    db.session.add(invite)
    db.session.commit()
    invite_url = url_for('channel_accept_invite', token=token, _external=True)
    flash(f'Invite link created: {invite_url}', 'success')
    return redirect(url_for('channel_page', channel_name=channel_name))

@app.route('/channel/invite/<token>')
@login_required
def channel_accept_invite(token):
    invite = ChannelInvite.query.filter_by(token=token).first_or_404()
    if invite.used_at:
        flash('Invite already used', 'error')
        return redirect(url_for('channels_list'))
    if invite.expires_at and invite.expires_at < datetime.utcnow():
        flash('Invite expired', 'error')
        return redirect(url_for('channels_list'))
    channel = db.session.get(Channel, invite.channel_id)
    if not channel:
        abort(404)
    existing = channel.get_membership(current_user)
    if existing and existing.status == 'active':
        flash('You are already a member', 'info')
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
    flash(f'You joined "{channel.title}"!', 'success')
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
@limiter.limit("10 per hour")
@csrf_required
def create_group():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Name is required', 'error')
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
        flash('Group created!', 'success')
        return redirect(url_for('chats'))
    users = User.query.filter(User.id != current_user.id, User.is_deleted == False).limit(50).all()
    return render_template('create_group.html', users=users)

@app.route('/group/<int:chat_id>/add_members', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
@csrf_required
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
    flash(f'Added: {", ".join(added)}', 'success')
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
                'last_message': last.content[:50] if last else '',
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
                'last_message': last.content[:50] if last else '',
                'last_time': last.created_at.strftime('%d.%m %H:%M') if last else '',
                'unread': chat.unread_count(current_user), 'is_group': False, 'user_id': other.id
            })
    return jsonify(result)

@app.route('/api/chat/<int:chat_id>/messages')
@login_required
def get_messages(chat_id):
    chat = db.session.get(Chat, chat_id)
    if not chat:
        return jsonify({'error': 'Access denied'}), 403
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
            replied = db.session.get(Message, msg.reply_to_id)
            if replied:
                reply_data = {
                    'id': replied.id, 'sender_username': replied.sender.username,
                    'content': replied.content, 'media_type': replied.media_type
                }
        reactions = Reaction.query.filter_by(message_id=msg.id).all()
        reaction_counts = {}
        for r in reactions:
            reaction_counts[r.reaction] = reaction_counts.get(r.reaction, 0) + 1
        result.append({
            'id': msg.id, 'sender_id': msg.sender_id, 'sender_username': msg.sender.username,
            'sender_avatar': msg.sender.avatar,
            'content': msg.content, 'media_url': msg.media_url,
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
@limiter.limit("60 per hour")
@csrf_required
def send_message(chat_id):
    chat = db.session.get(Chat, chat_id)
    if not chat:
        return jsonify({'error': 'Access denied'}), 403
    if current_user not in chat.participants:
        return jsonify({'error': 'Access denied'}), 403
    content = request.form.get('content', '').strip()
    media_url, media_type = None, None
    if 'media' in request.files:
        media_url, media_type = safe_save_file(request.files['media'], f"msg_{secrets.token_urlsafe(8)}")
    reply_to_id = request.form.get('reply_to', type=int)
    if not content and not media_url:
        return jsonify({'error': 'Empty message'}), 400
    msg = Message(content=sanitize_html(content), media_url=media_url, media_type=media_type,
                  sender_id=current_user.id, chat_id=chat.id)
    if reply_to_id:
        reply_msg = db.session.get(Message, reply_to_id)
        if reply_msg and reply_msg.chat_id == chat_id:
            msg.reply_to_id = reply_to_id
    db.session.add(msg)
    chat.updated_at = datetime.utcnow()
    db.session.commit()
    for p in chat.participants:
        if p.id != current_user.id:
            notif = Notification(user_id=p.id, type='message',
                                  content=f"New message from {current_user.username}",
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
@limiter.limit("30 per hour")
@csrf_required
def edit_message(chat_id, message_id):
    msg = db.session.get(Message, message_id)
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
    if msg.sender_id != current_user.id or msg.chat_id != chat_id:
        return jsonify({'error': 'No permission'}), 403
    if datetime.utcnow() - msg.created_at > timedelta(minutes=5):
        return jsonify({'error': 'Edit time expired'}), 403
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid data format'}), 400
    new_content = data.get('content', '').strip()
    if not new_content:
        return jsonify({'error': 'Message cannot be empty'}), 400
    msg.content = sanitize_html(new_content)
    msg.is_edited = True
    msg.edited_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True, 'content': sanitize_html(new_content), 'edited_at': msg.edited_at.isoformat()})

@app.route('/api/chat/<int:chat_id>/delete_message/<int:message_id>', methods=['DELETE'])
@login_required
@csrf_required
def delete_message(chat_id, message_id):
    msg = db.session.get(Message, message_id)
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
    chat = db.session.get(Chat, chat_id)
    if not chat:
        return jsonify({'error': 'Chat not found'}), 404
    if msg.sender_id != current_user.id and not (chat.is_group and chat.admin_id == current_user.id):
        return jsonify({'error': 'No permission'}), 403
    db.session.delete(msg)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/chat/create', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
@csrf_required
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
@csrf_required
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
@csrf_required
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
@csrf_required
def remove_group_member(chat_id):
    chat = db.session.get(Chat, chat_id)
    if not chat:
        return jsonify({'error': 'Chat not found'}), 404
    if not chat.is_group or chat.admin_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid data format'}), 400
    user = db.session.get(User, data.get('user_id'))
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
@limiter.limit("60 per hour")
@csrf_required
def add_reaction(message_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Неверный формат данных'}), 400
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
    except Exception:
        logger.error("GitHub API error for user %s", username, exc_info=True)
        return jsonify({'error': 'Failed to fetch repos'}), 502

# ------------------------------
# Admin
# ------------------------------
@app.route('/admin/block_user/<int:user_id>', methods=['POST'])
@login_required
@csrf_required
def block_user(user_id):
    if current_user.role not in ('admin', 'moderator'):
        return jsonify({'error': 'No permission'}), 403
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot block yourself'}), 400
    user.is_blocked = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/set_role/<int:user_id>', methods=['POST'])
@login_required
@csrf_required
def set_user_role(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'No permission'}), 403
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid data format'}), 400
    new_role = data.get('role')
    if new_role not in ['admin', 'moderator', 'betatester', 'default']:
        return jsonify({'error': 'Invalid role'}), 400
    target_user = db.session.get(User, user_id)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    if target_user.id == current_user.id:
        return jsonify({'error': 'Cannot change your own role'}), 400
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
        flash(f'Hashtag #{tag_name} not found', 'error')
        return redirect(url_for('feed'))
    page = request.args.get('page', 1, int)
    posts = ht.posts.order_by(Post.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
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
        # Programming Languages
        ('Python', 'language'), ('JavaScript', 'language'), ('TypeScript', 'language'),
        ('C', 'language'), ('C++', 'language'), ('C#', 'language'),
        ('Java', 'language'), ('Kotlin', 'language'), ('Scala', 'language'),
        ('Go', 'language'), ('Rust', 'language'), ('Swift', 'language'),
        ('Ruby', 'language'), ('PHP', 'language'), ('Dart', 'language'),
        ('R', 'language'), ('Lua', 'language'), ('Perl', 'language'),
        ('Haskell', 'language'), ('Elixir', 'language'), ('Clojure', 'language'),
        ('Zig', 'language'), ('Nim', 'language'), ('Assembly', 'language'),
        ('Shell', 'language'), ('SQL', 'language'), ('MATLAB', 'language'),
        ('Groovy', 'language'), ('Objective-C', 'language'), ('F#', 'language'),
        ('VB.NET', 'language'), ('Delphi', 'language'), ('OCaml', 'language'),

        # Backend frameworks and libraries
        ('Flask', 'backend'), ('Django', 'backend'), ('FastAPI', 'backend'),
        ('Node.js', 'backend'), ('Express', 'backend'), ('NestJS', 'backend'),
        ('Spring Boot', 'backend'), ('ASP.NET', 'backend'), ('Ruby on Rails', 'backend'),
        ('Laravel', 'backend'), ('Symfony', 'backend'), ('Phoenix', 'backend'),
        ('Actix', 'backend'), ('Gin', 'backend'), ('Fiber', 'backend'),
        ('Echo', 'backend'), ('Tornado', 'backend'), ('Celery', 'backend'),
        ('gRPC', 'backend'),

        # Frontend frameworks and libraries
        ('React', 'frontend'), ('Vue', 'frontend'), ('Angular', 'frontend'),
        ('Svelte', 'frontend'), ('Next.js', 'frontend'), ('Nuxt', 'frontend'),
        ('jQuery', 'frontend'), ('Tailwind CSS', 'frontend'), ('Bootstrap', 'frontend'),
        ('Webpack', 'frontend'), ('Vite', 'frontend'), ('Astro', 'frontend'),
        ('Remix', 'frontend'), ('SolidJS', 'frontend'), ('Alpine.js', 'frontend'),
        ('Three.js', 'frontend'), ('D3.js', 'frontend'), ('Chart.js', 'frontend'),

        # Mobile development
        ('React Native', 'mobile'), ('Flutter', 'mobile'), ('SwiftUI', 'mobile'),
        ('Jetpack Compose', 'mobile'), ('Xamarin', 'mobile'), ('Ionic', 'mobile'),
        ('Unity', 'mobile'), ('Unreal Engine', 'mobile'), ('Godot', 'mobile'),

        # Databases
        ('PostgreSQL', 'database'), ('MySQL', 'database'), ('SQLite', 'database'),
        ('MongoDB', 'database'), ('Redis', 'database'), ('MariaDB', 'database'),
        ('Cassandra', 'database'), ('Elasticsearch', 'database'), ('Neo4j', 'database'),
        ('DynamoDB', 'database'), ('Firebase', 'database'), ('Supabase', 'database'),
        ('ClickHouse', 'database'), ('TimescaleDB', 'database'), ('InfluxDB', 'database'),

        # DevOps and infrastructure
        ('Docker', 'devops'), ('Kubernetes', 'devops'), ('Terraform', 'devops'),
        ('Ansible', 'devops'), ('CI/CD', 'devops'), ('GitHub Actions', 'devops'),
        ('Jenkins', 'devops'), ('Nginx', 'devops'), ('Traefik', 'devops'),
        ('AWS', 'devops'), ('GCP', 'devops'), ('Azure', 'devops'),
        ('Linux', 'devops'), ('Git', 'devops'), ('Prometheus', 'devops'),
        ('Grafana', 'devops'), ('Vagrant', 'devops'), ('Packer', 'devops'),

        # ML / AI
        ('Machine Learning', 'ml'), ('Deep Learning', 'ml'), ('TensorFlow', 'ml'),
        ('PyTorch', 'ml'), ('scikit-learn', 'ml'), ('Data Science', 'ml'),
        ('NLP', 'ml'), ('Computer Vision', 'ml'), ('OpenCV', 'ml'),
        ('Hugging Face', 'ml'), ('LangChain', 'ml'), ('ONNX', 'ml'),
        ('MLOps', 'ml'), ('LLM', 'ml'), ('RAG', 'ml'),

        # Design
        ('Figma', 'design'), ('UI/UX', 'design'), ('Adobe XD', 'design'),
        ('Sketch', 'design'), ('Photoshop', 'design'), ('Illustrator', 'design'),
        ('Blender', 'design'), ('After Effects', 'design'),

        # Other tools
        ('GraphQL', 'tools'), ('REST API', 'tools'), ('WebSocket', 'tools'),
        ('OAuth', 'tools'), ('JWT', 'tools'), ('WebRTC', 'tools'),
        ('RabbitMQ', 'tools'), ('Kafka', 'tools'), ('Selenium', 'tools'),
        ('Playwright', 'tools'), ('Cypress', 'tools'), ('Jest', 'tools'),
        ('pytest', 'tools'), ('Prettier', 'tools'), ('ESLint', 'tools'),
        ('GitLab', 'tools'), ('Jira', 'tools'), ('Notion', 'tools'),
    ]
    for name, cat in default_techs:
        if not Technology.query.filter_by(name=name).first():
            db.session.add(Technology(name=name, category=cat))
    default_roles = [
        ('backend', 'Backend Developer', 'fa-server'),
        ('frontend', 'Frontend Developer', 'fa-code'),
        ('fullstack', 'Fullstack Developer', 'fa-layer-group'),
        ('ml', 'ML/AI Engineer', 'fa-brain'),
        ('devops', 'DevOps Engineer', 'fa-cogs'),
        ('designer', 'UI/UX Designer', 'fa-palette'),
        ('pm', 'Project Manager', 'fa-tasks'),
        ('mobile', 'Mobile Developer', 'fa-mobile-alt'),
        ('game-dev', 'Game Developer', 'fa-gamepad'),
        ('data-engineer', 'Data Engineer', 'fa-database'),
        ('qa', 'QA Engineer', 'fa-bug'),
        ('security', 'Security Engineer', 'fa-shield-alt'),
        ('architect', 'Software Architect', 'fa-sitemap'),
        ('tech-lead', 'Tech Lead', 'fa-users-cog'),
        ('sre', 'SRE Engineer', 'fa-heartbeat'),
        ('sysadmin', 'System Administrator', 'fa-terminal'),
        ('embedded', 'Embedded Developer', 'fa-microchip'),
        ('gamedesigner', 'Game Designer', 'fa-dice-d20'),
        ('3d-artist', '3D Artist', 'fa-cube'),
        ('animator', 'Animator', 'fa-film'),
        ('sound-designer', 'Sound Designer', 'fa-music'),
        ('narrative-designer', 'Narrative Designer', 'fa-book'),
        ('community-manager', 'Community Manager', 'fa-comments'),
    ]
    for name, label, icon in default_roles:
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name, label=label, icon=icon))
    db.session.commit()

# ------------------------------
# Start
# ------------------------------
def init_db():
    """DB initialization with auto-adding missing columns."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    if not inspector.get_table_names():
        db.create_all()
        logger.info('Database tables created via db.create_all()')
    else:
        # Check and add missing columns to ideas
        idea_columns = {col['name'] for col in inspector.get_columns('ideas')}
        with db.engine.connect() as conn:
            if 'github_url' not in idea_columns:
                conn.execute(text("ALTER TABLE ideas ADD COLUMN github_url VARCHAR(500)"))
                conn.commit()
                logger.info('Added github_url column to ideas table')
            if 'is_active' not in idea_columns:
                conn.execute(text("ALTER TABLE ideas ADD COLUMN is_active BOOLEAN DEFAULT 1"))
                conn.commit()
                logger.info('Added is_active column to ideas table')
            if 'problem' not in idea_columns:
                conn.execute(text("ALTER TABLE ideas ADD COLUMN problem TEXT"))
                conn.commit()
                logger.info('Added problem column to ideas table')
            if 'solution' not in idea_columns:
                conn.execute(text("ALTER TABLE ideas ADD COLUMN solution TEXT"))
                conn.commit()
                logger.info('Added solution column to ideas table')
        # Check users table
        user_columns = {col['name'] for col in inspector.get_columns('users')}
        with db.engine.connect() as conn:
            if 'github_username' not in user_columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN github_username VARCHAR(39)"))
                conn.commit()
                logger.info('Added github_username column to users table')
            if 'developer_role' not in user_columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN developer_role VARCHAR(20)"))
                conn.commit()
                logger.info('Added developer_role column to users table')
            if 'verified' not in user_columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN verified BOOLEAN DEFAULT 0"))
                conn.commit()
                logger.info('Added verified column to users table')
            if 'is_deleted' not in user_columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_deleted BOOLEAN DEFAULT 0"))
                conn.commit()
                logger.info('Added is_deleted column to users table')
            if 'deleted_at' not in user_columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN deleted_at DATETIME"))
                conn.commit()
                logger.info('Added deleted_at column to users table')

if __name__ == '__main__':
    with app.app_context():
        init_db()
        seed_default_data()
        admin = User.query.filter_by(username='admin').first()
        if admin and admin.role == 'default':
            admin.role = 'admin'
            db.session.commit()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

# Auto-initialization for WSGI servers (gunicorn etc.)
with app.app_context():
    init_db()
