import re
import time
import pytest
from datetime import datetime, timedelta

import app as app_module
from app import db
from module import User, EmailLoginCode
from conftest import login, logout, setup_csrf, CSRF_TOKEN


@pytest.fixture(autouse=True)
def fake_smtp(monkeypatch):
    """Capture outgoing emails instead of really sending them."""
    sent = []

    def _capture(to_addr, subject, body):
        sent.append({'to': to_addr, 'subject': subject, 'body': body})
        return True

    monkeypatch.setattr(app_module, '_send_email', _capture)
    monkeypatch.setattr(app_module, 'HAS_SMTP', True)
    return sent


def _last_code(sent):
    m = re.search(r'\b(\d{6})\b', sent[-1]['body'])
    return m.group(1)


@pytest.fixture
def emma():
    u = User(username='emma', email='emma@test.com', role='default')
    u.set_password('emmapass123')
    db.session.add(u)
    db.session.commit()
    return u


def _enable(client):
    setup_csrf(client)
    return client.post('/settings/email-2fa', data={
        'enable': '1', 'password': 'emmapass123', '_csrf_token': CSRF_TOKEN,
    })


class TestEmail2FA:

    def test_enable_requires_password(self, client, emma):
        assert login(client, 'emma', 'emmapass123').status_code == 200
        setup_csrf(client)
        rv = client.post('/settings/email-2fa', data={
            'enable': '1', 'password': 'wrongpass', '_csrf_token': CSRF_TOKEN,
        })
        assert rv.status_code == 302  # back to profile_edit with error flash
        assert not emma.email_2fa_enabled

    def test_enable_with_correct_password(self, client, emma, fake_smtp):
        assert login(client, 'emma', 'emmapass123').status_code == 200
        rv = _enable(client)
        assert rv.status_code == 302
        assert emma.email_2fa_enabled is True

    def test_full_login_flow(self, client, emma, fake_smtp):
        # Enable while logged in
        login(client, 'emma', 'emmapass123')
        _enable(client)

        # Fresh login: password accepted but NOT logged in yet
        logout(client)
        rv = login(client, 'emma', 'emmapass123')
        assert rv.status_code == 200  # landed on /login/email-code page
        assert b'Verify code' in rv.data
        with client.session_transaction() as sess:
            assert sess.get('email_2fa_user_id') == emma.id

        # Code was emailed
        assert len(fake_smtp) == 1
        assert fake_smtp[0]['to'] == 'emma@test.com'
        code = _last_code(fake_smtp)

        # Wrong code first
        setup_csrf(client)
        rv = client.post('/login/email-code', data={'code': '000000', '_csrf_token': CSRF_TOKEN})
        assert b'Invalid code' in rv.data or rv.status_code == 302

        # Correct code -> logged in
        setup_csrf(client)
        rv = client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                         follow_redirects=True)
        assert rv.status_code == 200
        feed = client.get('/feed')
        assert feed.status_code == 200

    def test_code_is_single_use(self, client, emma, fake_smtp):
        login(client, 'emma', 'emmapass123')
        _enable(client)
        logout(client)
        login(client, 'emma', 'emmapass123')
        code = _last_code(fake_smtp)

        setup_csrf(client)
        client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                    follow_redirects=True)

        # Second login sends a NEW code; old one must be rejected
        logout(client)
        fake_smtp.clear()
        login(client, 'emma', 'emmapass123')
        assert len(fake_smtp) == 1
        setup_csrf(client)
        rv = client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN})
        assert rv.status_code == 200  # still on verify page, not logged in
        feed = client.get('/feed')
        assert feed.status_code == 302

    def test_expired_code_rejected(self, client, emma, fake_smtp):
        login(client, 'emma', 'emmapass123')
        _enable(client)
        logout(client)
        login(client, 'emma', 'emmapass123')
        code = _last_code(fake_smtp)

        row = EmailLoginCode.query.order_by(EmailLoginCode.id.desc()).first()
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.add(row)
        db.session.commit()

        setup_csrf(client)
        rv = client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                         follow_redirects=True)
        assert b'expired' in rv.data
        assert client.get('/feed').status_code == 302

    def test_resend_cooldown_then_new_code(self, client, emma, fake_smtp):
        login(client, 'emma', 'emmapass123')
        _enable(client)
        logout(client)
        login(client, 'emma', 'emmapass123')

        # Immediate resend -> blocked by cooldown
        setup_csrf(client)
        rv = client.post('/login/email-code/resend', data={'_csrf_token': CSRF_TOKEN})
        assert len(fake_smtp) == 1

        # Simulate cooldown elapsed
        with client.session_transaction() as sess:
            sess['email_2fa_sent_at'] = time.time() - 120
        client.post('/login/email-code/resend', data={'_csrf_token': CSRF_TOKEN})
        assert len(fake_smtp) == 2

        # New code works
        code = _last_code(fake_smtp)
        setup_csrf(client)
        rv = client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                         follow_redirects=True)
        assert client.get('/feed').status_code == 200

    def test_disable_restores_direct_login(self, client, emma, fake_smtp):
        login(client, 'emma', 'emmapass123')
        _enable(client)

        setup_csrf(client)
        client.post('/settings/email-2fa', data={
            'enable': '0', 'password': 'emmapass123', '_csrf_token': CSRF_TOKEN,
        })
        assert emma.email_2fa_enabled is False

        logout(client)
        rv = login(client, 'emma', 'emmapass123')
        assert client.get('/feed').status_code == 200  # straight in, no code asked
        assert len(fake_smtp) == 0

    def test_toggle_blocked_without_smtp(self, client, emma, fake_smtp, monkeypatch):
        monkeypatch.setattr(app_module, 'HAS_SMTP', False)
        login(client, 'emma', 'emmapass123')
        rv = _enable(client)
        assert rv.status_code == 302
        assert not emma.email_2fa_enabled
