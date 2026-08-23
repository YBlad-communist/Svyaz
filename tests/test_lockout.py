import time
import pytest
from app import app, db, _failed_attempts
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


def _fail_login(client, n=1):
    for _ in range(n):
        setup_csrf(client)
        client.post('/login', data={
            'username': 'vic', 'password': 'wrongpass', '_csrf_token': CSRF_TOKEN,
        })


def _trigger_lockout(client):
    _fail_login(client, 5)


class TestLockoutScreen:

    def test_no_lockout_before_threshold(self, client, victim):
        """Fewer than 5 failures — normal login page (200)."""
        _fail_login(client, 4)
        rv = client.get('/login')
        assert rv.status_code == 200
        assert b'lockClock' not in rv.data

    def test_lockout_screen_after_5_failures(self, client, victim):
        """After 5 failures GET /login renders the lockout panel with a countdown."""
        _trigger_lockout(client)
        rv = client.get('/login')
        assert rv.status_code == 429
        assert b'lockClock' in rv.data
        assert b'lockout-panel' in rv.data

    def test_no_redirect_loop_when_locked(self, client, victim):
        """Locked /login must NOT answer with a redirect to itself."""
        _trigger_lockout(client)
        rv = client.get('/login')
        assert rv.status_code != 302

    def test_post_login_blocked_while_locked(self, client, victim):
        """Even the correct password is rejected while locked out."""
        _fail_login(client, 3)
        _trigger_lockout(client)
        rv = client.post('/login', data={
            'username': 'vic', 'password': 'rightpass123', '_csrf_token': CSRF_TOKEN,
        })
        assert rv.status_code == 429

    def test_json_request_gets_retry_after(self, client, victim):
        """JSON/AJAX requests get 429 with retry_after seconds."""
        _trigger_lockout(client)
        rv = client.get('/feed', headers={'X-Requested-With': 'XMLHttpRequest'})
        assert rv.status_code == 429
        data = rv.get_json()
        assert 'retry_after' in data
        assert 0 < data['retry_after'] <= 900

    def test_static_assets_not_blocked(self, client, victim):
        """CSS/JS keep loading so the lockout page renders styled."""
        _trigger_lockout(client)
        rv = client.get('/static/css/style.css')
        assert rv.status_code == 200

    def test_unlock_after_window_expires(self, client, victim):
        """Backdating the timestamp unlocks the IP."""
        _trigger_lockout(client)
        ip_entry = list(_failed_attempts.values())[0]
        _failed_attempts[list(_failed_attempts.keys())[0]] = (
            ip_entry[0], time.time() - 901)
        rv = client.get('/login')
        assert rv.status_code == 200
        assert b'lockClock' not in rv.data

    def test_successful_login_clears_counter(self, client, victim):
        """A successful login resets the failure counter."""
        _fail_login(client, 3)
        login(client, 'vic', 'rightpass123')
        assert len(_failed_attempts) == 0

    def test_nonexistent_user_also_counts(self, client):
        """Failed logins for unknown usernames increment the counter too."""
        _fail_login(client, 5)
        rv = client.get('/login')
        assert rv.status_code == 429
