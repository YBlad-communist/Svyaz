import io
import os
import pytest
from module import Chat, Message, db
from conftest import login, logout, setup_csrf


def _make_image_file():
    """Create a minimal valid PNG file for upload testing."""
    import struct, zlib
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff
    ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
    raw = b'\x00\xff\x00\x00'
    idat_data = zlib.compress(raw)
    idat_crc = zlib.crc32(b'IDAT' + idat_data) & 0xffffffff
    idat = struct.pack('>I', len(idat_data)) + b'IDAT' + idat_data + struct.pack('>I', idat_crc)
    iend_crc = zlib.crc32(b'IEND') & 0xffffffff
    iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    return io.BytesIO(sig + ihdr + idat + iend)


@pytest.fixture
def user_a():
    from module import User
    u = User(username='alice', email='alice@test.com', role='default')
    u.set_password('password123')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def user_b():
    from module import User
    u = User(username='bob', email='bob@test.com', role='default')
    u.set_password('password123')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def user_c():
    from module import User
    u = User(username='charlie', email='charlie@test.com', role='default')
    u.set_password('password123')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def private_chat(user_a, user_b):
    chat = Chat(is_group=False)
    chat.participants = [user_a, user_b]
    db.session.add(chat)
    db.session.commit()
    return chat


class TestChatMediaPrivacy:
    """Chat attachments must only be accessible to chat participants."""

    def test_private_chat_saves_to_private_dir(self, client, user_a, user_b, private_chat):
        """File sent in a private chat must NOT be saved in static/uploads/."""
        login(client, 'alice', 'password123')
        img = _make_image_file()
        setup_csrf(client)
        rv = client.post(
            f'/api/chat/{private_chat.id}/send',
            data={'content': '', 'media': (img, 'photo.png'), '_csrf_token': 'test-csrf-token-12345'},
            content_type='multipart/form-data',
            headers={'X-CSRFToken': 'test-csrf-token-12345'},
        )
        assert rv.status_code == 200
        data = rv.get_json()
        assert data['media_url'].startswith(f'/api/chat/{private_chat.id}/media/')
        filename = data['media_url'].split('/')[-1]
        # Must NOT exist in static/uploads
        static_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'uploads', filename)
        assert not os.path.exists(static_path), 'Chat media must not be in static/uploads'
        # Must exist in private chat_media dir
        from flask import current_app
        private_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'chat_media', filename)
        assert os.path.exists(private_path), 'Chat media must be in private chat_media dir'

    def test_participant_can_access_chat_media(self, client, user_a, user_b, private_chat):
        """A chat participant can access the media file."""
        login(client, 'alice', 'password123')
        img = _make_image_file()
        setup_csrf(client)
        rv = client.post(
            f'/api/chat/{private_chat.id}/send',
            data={'content': '', 'media': (img, 'photo.png'), '_csrf_token': 'test-csrf-token-12345'},
            content_type='multipart/form-data',
            headers={'X-CSRFToken': 'test-csrf-token-12345'},
        )
        data = rv.get_json()
        media_url = data['media_url']

        # Bob (participant) accesses the file
        logout(client)
        login(client, 'bob', 'password123')
        rv = client.get(media_url)
        assert rv.status_code == 200
        assert rv.content_type.startswith('image/')

    def test_non_participant_cannot_access_chat_media(self, client, user_a, user_b, user_c, private_chat):
        """A user NOT in the chat gets 403 from the protected endpoint."""
        login(client, 'alice', 'password123')
        img = _make_image_file()
        setup_csrf(client)
        rv = client.post(
            f'/api/chat/{private_chat.id}/send',
            data={'content': '', 'media': (img, 'photo.png'), '_csrf_token': 'test-csrf-token-12345'},
            content_type='multipart/form-data',
            headers={'X-CSRFToken': 'test-csrf-token-12345'},
        )
        data = rv.get_json()
        media_url = data['media_url']

        # Charlie (not in chat) tries to access the file
        logout(client)
        login(client, 'charlie', 'password123')
        rv = client.get(media_url)
        assert rv.status_code == 403

    def test_non_participant_cannot_find_file_in_static(self, client, user_a, user_b, user_c, private_chat):
        """Chat media is NOT in static/uploads, so direct static access returns 404."""
        login(client, 'alice', 'password123')
        img = _make_image_file()
        setup_csrf(client)
        rv = client.post(
            f'/api/chat/{private_chat.id}/send',
            data={'content': '', 'media': (img, 'photo.png'), '_csrf_token': 'test-csrf-token-12345'},
            content_type='multipart/form-data',
            headers={'X-CSRFToken': 'test-csrf-token-12345'},
        )
        data = rv.get_json()
        filename = data['media_url'].split('/')[-1]

        # Even without auth, try static path — file shouldn't exist there
        logout(client)
        rv = client.get(f'/static/uploads/{filename}')
        assert rv.status_code == 404

    def test_unauthenticated_cannot_access_chat_media(self, client, user_a, user_b, private_chat):
        """Unauthenticated user gets redirected (302) from the protected endpoint."""
        login(client, 'alice', 'password123')
        img = _make_image_file()
        setup_csrf(client)
        rv = client.post(
            f'/api/chat/{private_chat.id}/send',
            data={'content': '', 'media': (img, 'photo.png'), '_csrf_token': 'test-csrf-token-12345'},
            content_type='multipart/form-data',
            headers={'X-CSRFToken': 'test-csrf-token-12345'},
        )
        data = rv.get_json()
        media_url = data['media_url']

        # Logout and try
        logout(client)
        rv = client.get(media_url)
        assert rv.status_code == 302
        assert '/login' in rv.headers['Location']

    def test_channel_post_media_stays_public(self, client, user_a):
        """Channel posts still use public static/uploads (private=False default)."""
        from module import Channel, channel_members
        ch = Channel(name='public', title='Public', type='public', owner_id=user_a.id)
        db.session.add(ch)
        db.session.commit()
        # Add user_a as admin so they can post
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user_a.id, role='admin', status='active'))
        db.session.commit()

        login(client, 'alice', 'password123')
        img = _make_image_file()
        setup_csrf(client)
        rv = client.post(
            f'/channel/public/post',
            data={'content': 'test', 'media': (img, 'photo.png'), '_csrf_token': 'test-csrf-token-12345'},
            content_type='multipart/form-data',
            headers={'X-CSRFToken': 'test-csrf-token-12345'},
        )
        assert rv.status_code == 302  # redirect after post
        # Verify channel posts still save to static/uploads
        from module import ChannelPost
        post = ChannelPost.query.filter_by(channel_id=ch.id).first()
        assert post is not None
        assert post.media_url.startswith('/static/uploads/')
