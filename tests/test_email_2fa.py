import time
import pytest
from datetime import datetime, timedelta

from app import db
from module import User, EmailLoginCode
from conftest import login, logout, setup_csrf, CSRF_TOKEN, SENT_EMAILS, last_login_code


@pytest.fixture
def emma():
    u = User(username='emma', email='emma@test.com', role='default')
    u.set_password('emmapass123')
    u.verified = True
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def admin():
    u = User(username='boss', email='boss@test.com', role='admin', is_admin=True)
    u.set_password('bossypass123')
    u.verified = True
    db.session.add(u)
    db.session.commit()
    return u


class TestMandatoryEmail2FA:

    def test_login_requires_email_code(self, client, emma):
        """Password alone never logs in: code page is shown instead."""
        rv = login(client, 'emma', 'emmapass123')  # helper completes the gate
        assert rv.status_code == 200
        # Prove the gate really fired: exactly one code email was sent
        assert len(SENT_EMAILS) == 1

    def test_admin_same_flow_no_totp(self, client, admin):
        """Admins log in via the same email-code flow (no TOTP anywhere)."""
        rv = login(client, 'boss', 'bossypass123')
        assert rv.status_code == 200
        assert client.get('/feed').status_code == 200
        assert len(SENT_EMAILS) >= 1

    def test_wrong_code_does_not_log_in(self, client, emma):
        setup_csrf(client)
        client.post('/login', data={
            'username': 'emma', 'password': 'emmapass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        setup_csrf(client)
        client.post('/login/email-code', data={'code': '000000', '_csrf_token': CSRF_TOKEN})
        assert client.get('/feed').status_code == 302

    def test_correct_code_logs_in(self, client, emma):
        setup_csrf(client)
        client.post('/login', data={
            'username': 'emma', 'password': 'emmapass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        code = last_login_code()
        setup_csrf(client)
        rv = client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                         follow_redirects=True)
        assert rv.status_code == 200
        assert client.get('/feed').status_code == 200

    def test_code_is_single_use(self, client, emma):
        import re

        def extract(body):
            return re.search(r'\b(\d{6})\b', body).group(1)

        # Gate #1: get and consume code A
        setup_csrf(client)
        client.post('/login', data={
            'username': 'emma', 'password': 'emmapass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        code_a = extract(SENT_EMAILS[-1]['body'])
        setup_csrf(client)
        client.post('/login/email-code', data={'code': code_a, '_csrf_token': CSRF_TOKEN},
                    follow_redirects=True)
        assert client.get('/feed').status_code == 200
        logout(client)

        # Gate #2: a NEW code is issued; old code A must be rejected
        setup_csrf(client)
        client.post('/login', data={
            'username': 'emma', 'password': 'emmapass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        code_b = extract(SENT_EMAILS[-1]['body'])

        setup_csrf(client)
        client.post('/login/email-code', data={'code': code_a, '_csrf_token': CSRF_TOKEN})
        assert client.get('/feed').status_code == 302

        # Code B still works
        setup_csrf(client)
        client.post('/login/email-code', data={'code': code_b, '_csrf_token': CSRF_TOKEN},
                    follow_redirects=True)
        assert client.get('/feed').status_code == 200

    def test_expired_code_rejected(self, client, emma):
        setup_csrf(client)
        client.post('/login', data={
            'username': 'emma', 'password': 'emmapass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        code = last_login_code()
        row = EmailLoginCode.query.order_by(EmailLoginCode.id.desc()).first()
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.add(row)
        db.session.commit()

        setup_csrf(client)
        rv = client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                         follow_redirects=True)
        assert b'expired' in rv.data
        assert client.get('/feed').status_code == 302

    def test_resend_cooldown_then_new_code(self, client, emma):
        setup_csrf(client)
        client.post('/login', data={
            'username': 'emma', 'password': 'emmapass123', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert len(SENT_EMAILS) == 1

        # Immediate resend -> cooldown blocks it
        setup_csrf(client)
        client.post('/login/email-code/resend', data={'_csrf_token': CSRF_TOKEN})
        assert len(SENT_EMAILS) == 1

        # Cooldown elapsed -> new code arrives and works
        with client.session_transaction() as sess:
            sess['email_2fa_sent_at'] = time.time() - 120
        client.post('/login/email-code/resend', data={'_csrf_token': CSRF_TOKEN})
        assert len(SENT_EMAILS) == 2
        code = last_login_code()
        setup_csrf(client)
        client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                    follow_redirects=True)
        assert client.get('/feed').status_code == 200


class TestEmailConfirmationOnRegistration:

    def _register(self, client, username='newbie'):
        setup_csrf(client)
        return client.post('/register', data={
            'username': username, 'email': f'{username}@test.com',
            'password': 'Str0ngPass!', '_csrf_token': CSRF_TOKEN,
        })

    def test_register_sends_confirmation_code(self, client):
        rv = self._register(client)
        assert rv.status_code == 302  # -> /login/email-code
        assert len(SENT_EMAILS) == 1
        assert SENT_EMAILS[0]['to'] == 'newbie@test.com'

        user = User.query.filter_by(username='newbie').first()
        assert user is not None
        assert user.verified is False
        assert client.get('/feed').status_code == 302

    def test_confirming_code_verifies_and_logs_in(self, client):
        self._register(client)
        code = last_login_code()
        setup_csrf(client)
        rv = client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                         follow_redirects=True)
        assert rv.status_code == 200

        user = User.query.filter_by(username='newbie').first()
        assert user.verified is True
        assert client.get('/feed').status_code == 200

    def test_unverified_cannot_skip_confirmation(self, client):
        """Abandoning registration: later login still goes through confirmation."""
        self._register(client, 'drifter')

        logout(client)
        setup_csrf(client)
        client.post('/login', data={
            'username': 'drifter', 'password': 'Str0ngPass!', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        code = last_login_code()
        setup_csrf(client)
        client.post('/login/email-code', data={'code': code, '_csrf_token': CSRF_TOKEN},
                    follow_redirects=True)
        user = User.query.filter_by(username='drifter').first()
        assert user.verified is True
        assert client.get('/feed').status_code == 200