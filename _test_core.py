import pytest, sys, io, traceback

from app import app, db
from database import User, Post, Comment, Idea, Notification, Message, Chat, ChatParticipant, FileUpload

@pytest.fixture(autouse=True)
def setup():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SERVER_NAME'] = 'test.local'
    app.config['PREFERRED_URL_SCHEME'] = 'http'

    with app.app_context():
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()


def client():
    return app.test_client()


class TestAuth:
    def test_login_get(self):
        resp = client().get('/login')
        assert resp.status_code == 200, resp.get_json() if resp.is_json else resp.data[:200]

    def test_register(self):
        resp = client().post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'Secret123!',
            'confirm_password': 'Secret123!',
        }, follow_redirects=True)
        assert resp.status_code == 200, (resp.status_code, resp.get_json() if resp.is_json else resp.data[:300])

    def test_login(self):
        client().post('/register', data={
            'username': 'testuser', 'email': 'test@example.com',
            'password': 'Secret123!', 'confirm_password': 'Secret123!',
        })
        resp = client().post('/login', data={
            'username': 'testuser', 'password': 'Secret123!',
        }, follow_redirects=True)
        assert resp.status_code == 200, (resp.status_code, resp.get_json() if resp.is_json else resp.data[:300])

    def test_invalid_login(self):
        resp = client().post('/login', data={
            'username': 'nonexistent', 'password': 'wrong',
        }, follow_redirects=True)
        assert resp.status_code == 200


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
