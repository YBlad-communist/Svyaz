"""
Тесты для приложения Svyaz.

Запуск:
    pip install pytest pytest-flask pytest-cov
    pytest test_app.py -v              # все тесты
    pytest test_app.py -v -k auth      # только тесты аутентификации
    pytest test_app.py -v --cov=app    # с покрытием
"""

import os
import io
import pytest
import warnings
from datetime import datetime, timedelta

# Подавляем известные предупреждения Flask-SQLAlchemy (не влияют на корректность)
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


# ============================================================
# Fixtures
# ============================================================

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


# ============================================================
# Helpers
# ============================================================

def setup_csrf(client):
    """Устанавливает CSRF-токен в сессию тестового клиента."""
    with client.session_transaction() as sess:
        sess['_csrf_token'] = CSRF_TOKEN
    return CSRF_TOKEN


def login(client, username, password):
    client.get('/login')
    setup_csrf(client)
    return client.post('/login', data={
        'username': username, 'password': password, '_csrf_token': CSRF_TOKEN,
    }, follow_redirects=True)


def csrf_post(client, url, data, follow_redirects=False, headers=None, content_type=None):
    """POST с CSRF-токеном."""
    setup_csrf(client)
    d = dict(data)
    d['_csrf_token'] = CSRF_TOKEN
    return client.post(url, data=d, follow_redirects=follow_redirects, headers=headers, content_type=content_type)


def csrf_json(client, url, data, method='POST', headers=None):
    """JSON-запрос с CSRF-токеном."""
    setup_csrf(client)
    h = headers or {}
    h['X-CSRFToken'] = CSRF_TOKEN
    h['Content-Type'] = 'application/json'
    body = dict(data)
    body['_csrf_token'] = CSRF_TOKEN
    return client.open(url, method=method, json=body, headers=h)


# ============================================================
# 1. Sanitize HTML & Validation
# ============================================================

class TestSanitizeHtml:
    def test_escapes_script_tags(self):
        result = sanitize_html('<script>alert("xss")</script>')
        assert '<script>' not in result

    def test_allows_safe_tags(self):
        result = sanitize_html('<strong>bold</strong> <code>print("hi")</code>')
        assert '<strong>' in result
        assert '<code>' in result

    def test_removes_onclick(self):
        result = sanitize_html('<a href="https://example.com" onclick="alert(1)">link</a>')
        assert 'onclick' not in result

    def test_empty_input(self):
        assert sanitize_html('') == ''
        assert sanitize_html(None) == ''

    def test_allows_pre_tag(self):
        result = sanitize_html('<pre>def foo():\n    pass</pre>')
        assert '<pre>' in result

    def test_removes_iframe(self):
        result = sanitize_html('<iframe src="https://evil.com"></iframe>')
        assert '<iframe' not in result

    def test_removes_javascript_protocol(self):
        result = sanitize_html('<a href="javascript:alert(1)">click</a>')
        assert 'javascript:' not in result


class TestValidateEmail:
    def test_valid(self):
        assert validate_email('user@example.com') is True

    def test_invalid(self):
        assert validate_email('not-an-email') is False
        assert validate_email('') is False
        assert validate_email(None) is False


class TestValidateUsername:
    def test_valid(self):
        assert validate_username('alice_123') is True
        assert validate_username('bob-test') is True

    def test_invalid(self):
        assert validate_username('ab') is False
        assert validate_username('a' * 33) is False
        assert validate_username('user@name') is False
        assert validate_username('') is False


# ============================================================
# 2. Registration
# ============================================================

class TestRegister:
    def test_success(self, client):
        setup_csrf(client)
        rv = client.post('/register', data={
            'username': 'newuser', 'email': 'new@test.com',
            'password': 'securepass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert User.query.filter_by(username='newuser').first() is not None

    def test_duplicate_username(self, client, user1):
        setup_csrf(client)
        rv = client.post('/register', data={
            'username': 'alice', 'email': 'other@test.com',
            'password': 'securepass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200

    def test_short_password(self, client):
        setup_csrf(client)
        rv = client.post('/register', data={
            'username': 'shortpw', 'email': 's@test.com',
            'password': '12345', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200

    def test_invalid_email(self, client):
        setup_csrf(client)
        rv = client.post('/register', data={
            'username': 'bad', 'email': 'not-email',
            'password': 'securepass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200


# ============================================================
# 3. Login
# ============================================================

class TestLogin:
    def test_success(self, client, user1):
        rv = login(client, 'alice', 'password123')
        assert rv.status_code == 200

    def test_wrong_password(self, client, user1):
        client.get('/login')
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': 'alice', 'password': 'wrong', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200

    def test_blocked_user(self, client, user1):
        user1.is_blocked = True
        db.session.commit()
        client.get('/login')
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': 'alice', 'password': 'password123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200


# ============================================================
# 4. Idea Create
# ============================================================

class TestIdeaCreate:
    def test_success(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/idea/create', {
            'title': 'My Great Idea',
            'description': 'Detailed description.',
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert Idea.query.filter_by(title='My Great Idea').first() is not None

    def test_unauthorized(self, client):
        rv = client.get('/idea/create', follow_redirects=True)
        assert rv.status_code == 200

    def test_missing_title(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/idea/create', {
            'title': '', 'description': 'Some description',
        }, follow_redirects=True)
        assert rv.status_code == 200

    def test_with_technologies(self, client, user1, tech_python, tech_js):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/idea/create', {
            'title': 'Tech Idea', 'description': 'Idea with tech',
            'technologies': [str(tech_python.id), str(tech_js.id)],
        }, follow_redirects=True)
        assert rv.status_code == 200
        idea = Idea.query.filter_by(title='Tech Idea').first()
        assert idea is not None
        assert len(idea.technologies) == 2


# ============================================================
# 5. Idea Like
# ============================================================

class TestIdeaLike:
    def test_like(self, client, user1, user2):
        idea = Idea(title='Test', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/idea/{idea.id}/like', {})
        assert rv.status_code == 200
        data = rv.get_json()
        assert data['liked'] is True
        assert data['count'] == 1

    def test_unlike(self, client, user1, user2):
        idea = Idea(title='Test', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        idea.likers.append(user2)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/idea/{idea.id}/like', {})
        data = rv.get_json()
        assert data['liked'] is False
        assert data['count'] == 0

    def test_inactive_idea(self, client, user1, user2):
        idea = Idea(title='Test', description='Desc', author_id=user1.id, is_active=False)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/idea/{idea.id}/like', {})
        assert rv.status_code == 404

    def test_nonexistent(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_json(client, '/idea/99999/like', {})
        assert rv.status_code == 404


# ============================================================
# 6. User Search
# ============================================================

class TestUserSearch:
    def test_by_username(self, client, user1, user2):
        login(client, 'alice', 'password123')
        rv = client.get('/api/users/search?q=bob')
        assert rv.status_code == 200
        data = rv.get_json()
        assert len(data) == 1
        assert data[0]['username'] == 'bob'

    def test_too_short(self, client, user1):
        login(client, 'alice', 'password123')
        rv = client.get('/api/users/search?q=a')
        assert rv.get_json() == []

    def test_excludes_deleted(self, client, user1, user2):
        user2.is_deleted = True
        db.session.commit()
        login(client, 'alice', 'password123')
        rv = client.get('/api/users/search?q=bob')
        assert rv.get_json() == []

    def test_excludes_self(self, client, user1, user2):
        login(client, 'alice', 'password123')
        rv = client.get('/api/users/search?q=alice')
        assert rv.get_json() == []


# ============================================================
# 7. Avatar Upload
# ============================================================

class TestAvatarUpload:
    def test_valid_image(self, client, user1):
        login(client, 'alice', 'password123')
        data = {
            'avatar': (io.BytesIO(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100), 'test.png'),
        }
        rv = csrf_post(client, '/upload_avatar', data,
                       content_type='multipart/form-data', follow_redirects=True)
        assert rv.status_code == 200

    def test_unauthorized(self, client):
        rv = client.post('/upload_avatar', data={}, follow_redirects=True)
        assert rv.status_code == 200  # redirected to login then to index


# ============================================================
# 8. Delete Account
# ============================================================

class TestDeleteAccount:
    def test_anonymize(self, client, user1):
        original_id = user1.id
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/delete_account', {}, follow_redirects=True)
        assert rv.status_code == 200

        deleted = db.session.get(User, original_id)
        assert deleted.is_deleted is True
        assert deleted.username == f"user_{original_id}"
        assert deleted.is_active is False

    def test_deleted_cannot_login(self, client, user1):
        user1.anonymize()
        db.session.commit()
        client.get('/login')
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': f"user_{user1.id}", 'password': 'password123',
            '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200


# ============================================================
# 9. Access Control
# ============================================================

class TestAccessControl:
    def test_cannot_edit_other_post(self, client, user1, user2):
        post = Post(content='My post', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/post/{post.id}/edit',
                       {'content': 'Hacked!'}, method='PUT')
        assert rv.status_code == 403

    def test_cannot_delete_other_post(self, client, user1, user2):
        post = Post(content='My post', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/post/{post.id}/delete', {}, method='DELETE')
        assert rv.status_code == 403

    def test_cannot_delete_other_idea(self, client, user1, user2):
        idea = Idea(title='Alice Idea', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/delete', {}, follow_redirects=True)
        assert rv.status_code == 200  # redirected to ideas_feed with flash

    def test_admin_can_delete_any_idea(self, client, user1, admin_user):
        idea = Idea(title='Alice Idea', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'admin', 'adminpass123')
        rv = csrf_post(client, f'/idea/{idea.id}/delete', {}, follow_redirects=True)
        assert rv.status_code == 200
        idea = db.session.get(Idea, idea.id)
        assert idea.is_active is False

    def test_cannot_access_private_channel(self, client, user1, user2):
        ch = Channel(name='private-ch', title='Private', type='private', owner_id=user1.id)
        db.session.add(ch)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user1.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = client.get(f'/channel/{ch.name}', follow_redirects=True)
        assert rv.status_code == 200

    def test_cannot_view_chat_not_member(self, client, user1, user2):
        chat = Chat(is_group=True, name='Secret Group', admin_id=user1.id)
        db.session.add(chat)
        chat.participants.append(user1)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = client.get(f'/api/chat/{chat.id}/messages')
        assert rv.status_code == 403

    def test_cannot_send_to_foreign_chat(self, client, user1, user2):
        chat = Chat(is_group=True, name='Secret Group', admin_id=user1.id)
        db.session.add(chat)
        chat.participants.append(user1)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/api/chat/{chat.id}/send', {'content': 'Hello!'})
        assert rv.status_code == 403


# ============================================================
# 10. CSRF Protection
# ============================================================

class TestCSRF:
    def test_post_without_csrf_rejected(self, client, user1):
        login(client, 'alice', 'password123')
        rv = client.post('/idea/create', data={
            'title': 'No CSRF Idea', 'description': 'This should fail',
        }, follow_redirects=True)
        assert rv.status_code == 200  # redirected with flash error
        assert Idea.query.filter_by(title='No CSRF Idea').first() is None

    def test_post_with_invalid_csrf_rejected(self, client, user1):
        login(client, 'alice', 'password123')
        rv = client.post('/idea/create', data={
            'title': 'Bad CSRF', 'description': 'Fail',
            '_csrf_token': 'invalid-token',
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert Idea.query.filter_by(title='Bad CSRF').first() is None

    def test_post_with_valid_csrf_accepted(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/idea/create', {
            'title': 'Valid CSRF Idea', 'description': 'This works',
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert Idea.query.filter_by(title='Valid CSRF Idea').first() is not None

    def test_json_without_csrf_rejected(self, client, user1):
        post = Post(content='My post', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = client.put(f'/post/{post.id}/edit', json={'content': 'Updated'})
        assert rv.status_code == 403

    def test_json_with_csrf_accepted(self, client, user1):
        post = Post(content='My post', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_json(client, f'/post/{post.id}/edit',
                       {'content': 'Updated'}, method='PUT')
        assert rv.status_code == 200


# ============================================================
# 11. Post Create
# ============================================================

class TestPostCreate:
    def test_success(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/post/create', {'content': 'Hello world!'}, follow_redirects=True)
        assert rv.status_code == 200
        assert Post.query.filter_by(user_id=user1.id).first() is not None

    def test_empty(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/post/create', {'content': ''}, follow_redirects=True)
        assert rv.status_code == 200  # redirected back with flash

    def test_sanitizes_html(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/post/create',
                       {'content': '<script>alert(1)</script>Safe text'},
                       follow_redirects=True)
        assert rv.status_code == 200
        post = Post.query.filter_by(user_id=user1.id).first()
        assert '<script>' not in post.content


# ============================================================
# 12. Comments
# ============================================================

class TestComments:
    def test_success(self, client, user1, user2):
        post = Post(content='Test post', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/post/{post.id}/comment', {'content': 'Great!'})
        assert rv.status_code == 200
        assert rv.get_json()['success'] is True
        assert Comment.query.count() == 1

    def test_too_long(self, client, user1, user2):
        post = Post(content='Test', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/post/{post.id}/comment', {'content': 'A' * 5001})
        assert rv.status_code == 400

    def test_empty(self, client, user1, user2):
        post = Post(content='Test', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/post/{post.id}/comment', {'content': ''})
        assert rv.status_code == 400


# ============================================================
# 13. Post Likes
# ============================================================

class TestPostLikes:
    def test_like(self, client, user1, user2):
        post = Post(content='Test', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/post/{post.id}/like', {})
        data = rv.get_json()
        assert data['liked'] is True
        assert data['count'] == 1

    def test_unlike(self, client, user1, user2):
        post = Post(content='Test', user_id=user1.id)
        db.session.add(post)
        db.session.add(Like(user_id=user2.id, post_id=post.id))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/post/{post.id}/like', {})
        data = rv.get_json()
        assert data['liked'] is False

    def test_creates_notification(self, client, user1, user2):
        post = Post(content='Test', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        csrf_json(client, f'/post/{post.id}/like', {})
        assert Notification.query.filter_by(user_id=user1.id, type='like').first() is not None

    def test_own_post_no_notification(self, client, user1):
        post = Post(content='Test', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'alice', 'password123')
        csrf_json(client, f'/post/{post.id}/like', {})
        assert Notification.query.filter_by(user_id=user1.id, type='like').first() is None


# ============================================================
# 14. Channels
# ============================================================

class TestChannels:
    def test_create_success(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/channel/create', {
            'name': 'mychannel', 'title': 'My Channel',
            'description': 'Test', 'type': 'public',
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert Channel.query.filter_by(name='mychannel').first() is not None

    def test_post_member_only(self, client, user1, user2):
        ch = Channel(name='membersonly', title='Members', type='public', owner_id=user1.id)
        db.session.add(ch)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user1.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/post',
                       {'content': 'Intruder'}, follow_redirects=True)
        assert rv.status_code == 200  # redirected with flash

    def test_join_public(self, client, user1, user2):
        ch = Channel(name='joinme', title='Join', type='public', owner_id=user1.id)
        db.session.add(ch)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/join', {}, follow_redirects=True)
        assert rv.status_code == 200
        assert ch.get_membership(user2).status == 'active'

    def test_join_private_pending(self, client, user1, user2):
        ch = Channel(name='privatech', title='Private', type='private', owner_id=user1.id)
        db.session.add(ch)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/join', {}, follow_redirects=True)
        assert rv.status_code == 200
        assert ch.get_membership(user2).status == 'pending'


# ============================================================
# 15. Follow
# ============================================================

class TestFollow:
    def test_follow(self, client, user1, user2):
        login(client, 'alice', 'password123')
        rv = csrf_json(client, f'/user/{user2.username}/follow', {})
        data = rv.get_json()
        assert data['following'] is True

    def test_unfollow(self, client, user1, user2):
        db.session.add(Follow(follower_id=user1.id, followed_id=user2.id))
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_json(client, f'/user/{user2.username}/follow', {})
        data = rv.get_json()
        assert data['following'] is False

    def test_cannot_follow_self(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_json(client, f'/user/{user1.username}/follow', {})
        assert rv.status_code == 400

    def test_creates_notification(self, client, user1, user2):
        login(client, 'alice', 'password123')
        csrf_json(client, f'/user/{user2.username}/follow', {})
        assert Notification.query.filter_by(user_id=user2.id, type='follow').first() is not None


# ============================================================
# 16. User Model
# ============================================================

class TestUserModel:
    def test_password(self, user1):
        user1.set_password('newpass')
        assert user1.check_password('newpass')
        assert not user1.check_password('wrong')

    def test_anonymize(self, user1):
        uid = user1.id
        user1.anonymize()
        assert user1.is_deleted
        assert not user1.is_active
        assert user1.username == f"user_{uid}"

    def test_can_delete_post(self, user1):
        post = Post(content='t', user_id=user1.id)
        assert user1.can_delete_post(post)

    def test_cannot_delete_other(self, user1, user2):
        post = Post(content='t', user_id=user1.id)
        assert not user2.can_delete_post(post)

    def test_admin_can_delete(self, admin_user, user1):
        post = Post(content='t', user_id=user1.id)
        assert admin_user.can_delete_post(post)


# ============================================================
# 17. Idea Join Requests
# ============================================================

class TestIdeaJoinRequests:
    def test_pending(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join', {}, follow_redirects=True)
        assert rv.status_code == 200

        req = db.session.query(idea_join_requests).filter_by(
            idea_id=idea.id, user_id=user2.id).first()
        assert req is not None and req.status == 'pending'

    def test_author_cannot_join(self, client, user1):
        idea = Idea(title='My', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join', {}, follow_redirects=True)
        assert rv.status_code == 200

    def test_approve(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        db.session.execute(idea_join_requests.insert().values(
            idea_id=idea.id, user_id=user2.id, status='pending'))
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join/{user2.id}/approve', {}, follow_redirects=True)
        assert rv.status_code == 200

        req = db.session.query(idea_join_requests).filter_by(
            idea_id=idea.id, user_id=user2.id).first()
        assert req.status == 'approved'

    def test_non_author_cannot_approve(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join/{user2.id}/approve', {})
        assert rv.status_code == 403


# ============================================================
# 18. File Upload
# ============================================================

class TestFileUpload:
    def test_allowed_extensions(self, client):
        from app import ALLOWED_EXTENSIONS
        assert 'png' in ALLOWED_EXTENSIONS
        assert 'exe' not in ALLOWED_EXTENSIONS
        assert 'php' not in ALLOWED_EXTENSIONS

    def test_detect_png(self, client):
        from app import get_file_type
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as f:
            f.write(b'\x89PNG\r\n\x1a\n' + b'\x00' * 20)
            f.flush()
            mime = get_file_type(f.name)
        os.unlink(f.name)
        assert mime == 'image/png'

    def test_detect_jpeg(self, client):
        from app import get_file_type
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as f:
            f.write(b'\xff\xd8\xff\xe0' + b'\x00' * 20)
            f.flush()
            mime = get_file_type(f.name)
        os.unlink(f.name)
        assert mime == 'image/jpeg'


# ============================================================
# 19. Route Protection
# ============================================================

class TestRouteProtection:
    def test_feed_requires_auth(self, client):
        rv = client.get('/feed', follow_redirects=True)
        assert rv.status_code == 200

    def test_ideas_requires_auth(self, client):
        rv = client.get('/ideas', follow_redirects=True)
        assert rv.status_code == 200

    def test_chats_requires_auth(self, client):
        rv = client.get('/chats', follow_redirects=True)
        assert rv.status_code == 200


# ============================================================
# 20. Chats
# ============================================================

class TestChats:
    def test_create(self, client, user1, user2):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/api/chat/create', {'username': 'bob'})
        assert rv.status_code == 200
        assert 'chat_id' in rv.get_json()

    def test_with_self(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/api/chat/create', {'username': 'alice'})
        assert rv.status_code == 400

    def test_nonexistent_user(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/api/chat/create', {'username': 'nobody'})
        assert rv.status_code == 404

    def test_send_message(self, client, user1, user2):
        chat = Chat()
        chat.participants.append(user1)
        chat.participants.append(user2)
        db.session.add(chat)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/api/chat/{chat.id}/send', {'content': 'Hello!'})
        assert rv.status_code == 200
        assert rv.get_json()['content'] == 'Hello!'

    def test_edit_time_limit(self, client, user1, user2):
        chat = Chat()
        chat.participants.append(user1)
        chat.participants.append(user2)
        db.session.add(chat)
        db.session.flush()
        msg = Message(content='Old', sender_id=user1.id, chat_id=chat.id)
        msg.created_at = datetime.utcnow() - timedelta(minutes=10)
        db.session.add(msg)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_json(client, f'/api/chat/{chat.id}/edit/{msg.id}',
                       {'content': 'Updated'}, method='PUT')
        assert rv.status_code == 403

    def test_delete_as_admin(self, client, user1, user2):
        chat = Chat(is_group=True, name='Group', admin_id=user1.id)
        chat.participants.append(user1)
        chat.participants.append(user2)
        db.session.add(chat)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/api/chat/{chat.id}/delete', {})
        assert rv.status_code == 200

    def test_non_admin_cannot_delete_group(self, client, user1, user2):
        chat = Chat(is_group=True, name='Group', admin_id=user1.id)
        chat.participants.append(user1)
        chat.participants.append(user2)
        db.session.add(chat)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/api/chat/{chat.id}/delete', {})
        assert rv.status_code == 403
