import io
import pyotp
import pytest
from app import app, db
from module import User
from conftest import login, csrf_post, setup_csrf


@pytest.fixture
def admin_2fa_user():
    """Admin with is_admin=True (column), triggering mandatory 2FA enforcement."""
    u = User(username='admin2fa', email='admin2fa@test.com', role='admin', is_admin=True)
    u.set_password('adminpass123')
    db.session.add(u)
    db.session.commit()
    return u


class TestAdmin2FASetup:
    """Verify that admins MUST complete 2FA setup before getting a real session."""

    def test_admin_not_authenticated_before_totp(self, client, admin_2fa_user):
        """After /login, admin should NOT be authenticated until TOTP is set up."""
        rv = login(client, 'admin2fa', 'adminpass123')
        assert rv.status_code == 200
        with client.session_transaction() as sess:
            assert sess.get('pending_admin_setup_id') == admin_2fa_user.id
        # Verify NOT logged in — accessing a @login_required route should redirect
        rv = client.get('/feed')
        assert rv.status_code == 302
        assert '/login' in rv.headers['Location']

    def test_admin_totp_setup_accessible_without_login(self, client, admin_2fa_user):
        """Admin can reach /totp/setup via pending_admin_setup_id."""
        login(client, 'admin2fa', 'adminpass123')
        rv = client.get('/totp/setup')
        assert rv.status_code == 200

    def test_totp_setup_requires_valid_session(self, client, admin_2fa_user):
        """Without pending_admin_setup_id AND without login, /totp/setup redirects to /login."""
        rv = client.get('/totp/setup')
        assert rv.status_code == 302
        assert '/login' in rv.headers['Location']

    def test_admin_gets_session_after_totp_verification(self, client, admin_2fa_user):
        """After successful TOTP setup, admin gets a real session."""
        login(client, 'admin2fa', 'adminpass123')

        # GET totp/setup to generate secret
        rv = client.get('/totp/setup')
        assert rv.status_code == 200

        # Extract the secret from session
        with client.session_transaction() as sess:
            secret = sess.get('totp_setup_secret')
        assert secret is not None

        # Generate valid TOTP code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # POST the code
        rv = csrf_post(client, '/totp/setup', {'code': code}, follow_redirects=True)
        assert rv.status_code == 200

        # Verify now logged in
        with client.session_transaction() as sess:
            assert sess.get('pending_admin_setup_id') is None

        # Should be able to access protected routes
        rv = client.get('/feed')
        assert rv.status_code == 200

    def test_admin_totp_wrong_code_stays_unauthenticated(self, client, admin_2fa_user):
        """Wrong TOTP code should NOT create a session."""
        login(client, 'admin2fa', 'adminpass123')
        client.get('/totp/setup')

        rv = csrf_post(client, '/totp/setup', {'code': '000000'}, follow_redirects=True)
        assert rv.status_code == 200

        # Still NOT authenticated
        with client.session_transaction() as sess:
            assert sess.get('pending_admin_setup_id') is not None

        rv = client.get('/feed')
        assert rv.status_code == 302
        assert '/login' in rv.headers['Location']

    def test_non_admin_totp_setup_requires_login(self, client):
        """Non-admin accessing /totp/setup without login should redirect to /login."""
        u = User(username='alice', email='alice@test.com', role='default')
        u.set_password('password123')
        db.session.add(u)
        db.session.commit()

        rv = client.get('/totp/setup')
        assert rv.status_code == 302
        assert '/login' in rv.headers['Location']

    def test_non_admin_gets_immediate_session(self, client):
        """Non-admin with no 2FA gets a real session immediately after login."""
        u = User(username='alice', email='alice@test.com', role='default')
        u.set_password('password123')
        db.session.add(u)
        db.session.commit()

        rv = login(client, 'alice', 'password123')
        assert rv.status_code == 200
        # Should be able to access protected routes
        rv = client.get('/feed')
        assert rv.status_code == 200
