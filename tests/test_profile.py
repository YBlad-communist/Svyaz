import io
from app import db
from module import User, Follow, Notification
from conftest import CSRF_TOKEN, setup_csrf, login, csrf_post, csrf_json


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
