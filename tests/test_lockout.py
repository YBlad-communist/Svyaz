import time
import pytest
from app import app, db, _failed_attempts, _lockout_key
from module import User
from conftest import login, setup_csrf, CSRF_TOKEN


@pytest.fixture(autouse=True)
def _clear_lockouts():
    _failed_attempts.clear()
    yield
    _failed_attempts.clear()


@pytest.fixture
def victim():
    u = User(username='vic', email='vic@test.com', role='default')
    u.set_password('rightpass123')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def neighbor():
    u = User(username='bob', email='bob@test.com', role='default')
    u.set_password('bobpass123')
    db.session.add(u)
    db.session.commit()
    return u


def _fail_login(client, username='vic', n=1):
    for _ in range(n):
        setup_csrf(client)
        client.post('/login', data={
            'username': username, 'password': 'wrongpass', '_csrf_token': CSRF_TOKEN,
        })


class TestLockoutKey:
    def test_key_is_composite_and_normalized(self):
        assert _lockout_key('1.2.3.4', 'Alice') == _lockout_key('1.2.3.4', '  alice ')
        assert _lockout_key('1.2.3.4', 'alice') != _lockout_key('5.6.7.8', 'alice')
        assert _lockout_key('1.2.3.4', None).endswith(':-')


class TestScopedLockout:

    def test_no_lockout_before_threshold(self, client, victim):
        """Fewer than 5 failures under one account — POST still processed normally."""
        _fail_login(client, 'vic', 4)
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': 'vic', 'password': 'wrongpass', '_csrf_token': CSRF_TOKEN,
        })
        assert rv.status_code == 200
        assert b'lockClock' not in rv.data

    def test_lockout_blocks_after_5_failures(self, client, victim):
        """After 5 failed attempts for an account, its POST /login gets 429 + countdown."""
        _fail_login(client, 'vic', 5)
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': 'vic', 'password': 'wrongpass', '_csrf_token': CSRF_TOKEN,
        })
        assert rv.status_code == 429
        assert b'lockClock' in rv.data

    def test_other_username_same_ip_not_blocked(self, client, victim, neighbor):
        """Locking 'vic' from this IP must NOT block 'bob' from the same IP."""
        _fail_login(client, 'vic', 5)
        rv = login(client, 'bob', 'bobpass123')
        assert rv.status_code == 200
        feed = client.get('/feed')
        assert feed.status_code == 200

    def test_json_xhr_gets_retry_after(self, client, victim):
        """AJAX login attempts get JSON 429 with retry_after seconds."""
        _fail_login(client, 'vic', 5)
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': 'vic', 'password': 'wrongpass', '_csrf_token': CSRF_TOKEN,
        }, headers={'X-Requested-With': 'XMLHttpRequest'})
        assert rv.status_code == 429
        data = rv.get_json()
        assert 0 < data['retry_after'] <= 900

    def test_authenticated_user_unaffected_by_lockout(self, client, victim, neighbor):
        """A logged-in user keeps using the site even while their IP has an active login lockout."""
        # Bob logs in fine
        assert login(client, 'bob', 'bobpass123').status_code == 200
        # Vic's account gets brute-locked from bob's IP (simulated)
        _failed_attempts[_lockout_key('127.0.0.1', 'vic')] = (
            5, time.time())
        # Bob's session is untouched — all normal routes work
        assert client.get('/feed').status_code == 200
        assert client.get('/chats').status_code == 200
        # Anonymous GETs are also not blocked globally anymore
        anon_gate = client.get('/ideas')
        assert anon_gate.status_code == 200
        # But vic's own login attempts are still gated
        setup_csrf(client)
        rv = client.post('/logout', data={'_csrf_token': CSRF_TOKEN})
        rv = client.post('/login', data={
            'username': 'vic', 'password': 'wrongpass', '_csrf_token': CSRF_TOKEN,
        }, headers={'X-Requested-With': 'XMLHttpRequest'})
        assert rv.status_code == 429

    def test_anon_feed_not_blocked_while_locked(self, client, victim):
        """Lockout is not global: anonymous users still get normal route behaviour."""
        _failed_attempts[_lockout_key('127.0.0.1', 'vic')] = (5, time.time())
        rv = client.get('/feed')  # requires login -> normal redirect to /login
        assert rv.status_code == 302
        assert '/login' in rv.headers['Location']
        assert client.get('/static/css/style.css').status_code == 200

    def test_unlock_after_window_expires(self, client, victim):
        """Backdating the timestamp lifts the lockout."""
        _fail_login(client, 'vic', 5)
        key = list(_failed_attempts.keys())[0]
        count, _ts = _failed_attempts[key]
        _failed_attempts[key] = (count, time.time() - 901)
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': 'vic', 'password': 'rightpass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200

    def test_successful_login_clears_counter(self, client, victim):
        """A successful login resets that account's failure counter."""
        _fail_login(client, 'vic', 3)
        assert len(_failed_attempts) == 1
        login(client, 'vic', 'rightpass123')
        assert len(_failed_attempts) == 0

    def test_nonexistent_user_counts_isolated(self, client, victim):
        """Unknown usernames get their own counter; existing accounts unaffected."""
        _fail_login(client, 'ghost', 5)
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': 'ghost', 'password': 'x', '_csrf_token': CSRF_TOKEN,
        }, headers={'X-Requested-With': 'XMLHttpRequest'})
        assert rv.status_code == 429
        # vic was never attempted — not locked
        setup_csrf(client)
        rv = client.post('/login', data={
            'username': 'vic', 'password': 'wrongpass', '_csrf_token': CSRF_TOKEN,
        })
        assert rv.status_code == 200