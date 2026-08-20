from app import db
from module import Post, Comment, Like, Notification
from conftest import login, csrf_post, csrf_json


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
