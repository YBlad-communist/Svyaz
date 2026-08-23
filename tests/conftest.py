import os
import io
import re
import pytest
import warnings
from datetime import datetime, timedelta

warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', category=PendingDeprecationWarning)

pytestmark = pytest.mark.filterwarnings(
    'ignore::sqlalchemy.exc.SAWarning',
    'ignore::sqlalchemy.exc.LegacyAPIWarning',
    'ignore::DeprecationWarning',
)

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-purposes-only-change-in-production')
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['FLASK_ENV'] = 'testing'
# Never let tests talk to a real SMTP server
os.environ['SMTP_HOST'] = ''

from app import app, db
import app as _app_module
from module import (
    User, Post, Comment, Like, Follow, Idea, Technology, Role,
    Channel, ChannelPost, ChannelPostLike, ChannelPostComment,
    Notification, Chat, Message, sanitize_html, validate_email, validate_username,
    idea_join_requests, channel_members,
)

CSRF_TOKEN = 'test-csrf-token-12345'


@pytest.fixture(autouse=True)
def _app_ctx():
    with app.app_context():
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['LOGIN_DISABLED'] = False
    with app.test_client() as c:
        with app.app_context():
            yield c


@pytest.fixture
def user1():
    u = User(username='alice', email='alice@test.com', role='default')
    u.set_password('password123')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def user2():
    u = User(username='bob', email='bob@test.com', role='default')
    u.set_password('password123')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def admin_user():
    u = User(username='admin', email='admin@test.com', role='admin')
    u.set_password('adminpass123')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def tech_python():
    t = Technology(name='Python', category='backend')
    db.session.add(t)
    db.session.commit()
    return t


@pytest.fixture
def tech_js():
    t = Technology(name='JavaScript', category='frontend')
    db.session.add(t)
    db.session.commit()
    return t


@pytest.fixture
def role_backend():
    r = Role(name='backend', label='Backend-разработчик', icon='fa-server')
    db.session.add(r)
    db.session.commit()
    return r


def setup_csrf(client):
    with client.session_transaction() as sess:
        sess['_csrf_token'] = CSRF_TOKEN
    return CSRF_TOKEN


# ---------------------------------------------------------------------------
# Global SMTP mock: mandatory email 2FA means every login sends a code.
# Capture the bodies instead of hitting a real server, and give tests a
# one-call login() that transparently completes the code gate.
# ---------------------------------------------------------------------------
SENT_EMAILS = []


@pytest.fixture(autouse=True)
def _fake_smtp(monkeypatch):
    SENT_EMAILS.clear()

    def _capture(to_addr, subject, body):
        SENT_EMAILS.append({'to': to_addr, 'subject': subject, 'body': body})
        return True

    monkeypatch.setattr(_app_module, '_send_email', _capture)
    yield
    SENT_EMAILS.clear()


def last_login_code():
    m = re.search(r'\b(\d{6})\b', SENT_EMAILS[-1]['body'])
    assert m, f'no 6-digit code in email: {SENT_EMAILS[-1]!r}'
    return m.group(1)


def login(client, username, password):
    client.get('/login')
    setup_csrf(client)
    rv = client.post('/login', data={
        'username': username, 'password': password, '_csrf_token': CSRF_TOKEN,
    }, follow_redirects=True)
    # Mandatory email 2FA: if we landed on the code page, complete it.
    if b'Verify code' in rv.data and 'email_2fa_user_id' in _session(client):
        setup_csrf(client)
        rv = client.post('/login/email-code', data={
            'code': last_login_code(), '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
    return rv


def _session(client):
    holder = {}
    with client.session_transaction() as sess:
        for k in sess.keys():
            holder[k] = sess[k]
    return holder


def logout(client):
    client.get('/login')
    setup_csrf(client)
    return client.post('/logout', data={'_csrf_token': CSRF_TOKEN}, follow_redirects=True)


def csrf_post(client, url, data, follow_redirects=False, headers=None, content_type=None):
    setup_csrf(client)
    d = dict(data)
    d['_csrf_token'] = CSRF_TOKEN
    return client.post(url, data=d, follow_redirects=follow_redirects, headers=headers, content_type=content_type)


def csrf_json(client, url, data, method='POST', headers=None):
    setup_csrf(client)
    h = headers or {}
    h['X-CSRFToken'] = CSRF_TOKEN
    h['Content-Type'] = 'application/json'
    body = dict(data)
    body['_csrf_token'] = CSRF_TOKEN
    return client.open(url, method=method, json=body, headers=h)
