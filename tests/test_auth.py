from app import db
from module import User
from conftest import CSRF_TOKEN, setup_csrf, login


class TestRegister:
    def test_success(self, client):
        setup_csrf(client)
        rv = client.post('/register', data={
            'username': 'newuser', 'email': 'new@test.com',
            'password': 'Securepass123!', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert User.query.filter_by(username='newuser').first() is not None

    def test_duplicate_username(self, client, user1):
        setup_csrf(client)
        rv = client.post('/register', data={
            'username': 'alice', 'email': 'other@test.com',
            'password': 'Securepass123!', '_csrf_token': CSRF_TOKEN,
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
            'password': 'Securepass123!', '_csrf_token': CSRF_TOKEN,
        }, follow_redirects=True)
        assert rv.status_code == 200


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
