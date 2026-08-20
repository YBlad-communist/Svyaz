import os
import io
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

from app import app, db
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


def login(client, username, password):
    client.get('/login')
    setup_csrf(client)
    return client.post('/login', data={
        'username': username, 'password': password, '_csrf_token': CSRF_TOKEN,
    }, follow_redirects=True)


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
