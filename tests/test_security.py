from app import db
from module import Post, Idea
from conftest import CSRF_TOKEN, setup_csrf, login, csrf_post, csrf_json


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
        assert mime == 'image'

    def test_detect_jpeg(self, client):
        from app import get_file_type
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as f:
            f.write(b'\xff\xd8\xff\xe0' + b'\x00' * 20)
            f.flush()
            mime = get_file_type(f.name)
        os.unlink(f.name)
        assert mime == 'image'

    def test_upload_code_post(self, client, user1):
        import io
        from app import Post
        login(client, 'alice', 'password123')
        code = b'def hello():\n    return "svyaz"\n'
        rv = csrf_post(client, '/post/create', {
            'content': 'sharing code',
            'media': (io.BytesIO(code), 'hello.py'),
        }, follow_redirects=True, content_type='multipart/form-data')
        assert rv.status_code == 200
        p = Post.query.order_by(Post.id.desc()).first()
        assert p is not None
        assert p.media_type == 'code'
        assert p.media_name == 'hello.py'
        assert p.media_size == len(code)
        assert p.media_url.endswith('.py')
        assert 'file-card' in rv.get_data(as_text=True)

    def test_upload_archive_post(self, client, user1):
        import io, zipfile
        from app import Post
        login(client, 'alice', 'password123')
        zio = io.BytesIO()
        with zipfile.ZipFile(zio, 'w') as z:
            z.writestr('main.py', 'print(1)')
        zio.seek(0)
        rv = csrf_post(client, '/post/create', {
            'content': 'archive',
            'media': (zio, 'project.zip'),
        }, follow_redirects=True, content_type='multipart/form-data')
        assert rv.status_code == 200
        p = Post.query.order_by(Post.id.desc()).first()
        assert p is not None
        assert p.media_type == 'archive'
        assert p.media_name == 'project.zip'
        assert 'file-card' in rv.get_data(as_text=True)

    def test_reject_disallowed_extension(self, client, user1):
        import io
        from app import Post
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/post/create', {
            'content': 'bad',
            'media': (io.BytesIO(b'MZ...'), 'evil.exe'),
        }, follow_redirects=True, content_type='multipart/form-data')
        # .exe is not allowed -> no media saved, post still created with content only
        assert rv.status_code == 200
        p = Post.query.order_by(Post.id.desc()).first()
        assert p.media_url is None
        assert p.media_type is None
        assert p.content == 'bad'
