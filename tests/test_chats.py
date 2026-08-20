from datetime import datetime, timedelta
from app import db
from module import Chat, Message
from conftest import login, csrf_post, csrf_json


class TestChats:
    def test_create(self, client, user1, user2):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/api/chat/create', {'username': 'bob'})
        assert rv.status_code == 200
        assert 'chat_id' in rv.get_json()

    def test_with_self(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/api/chat/create', {'username': 'alice'})
        assert rv.status_code == 400

    def test_nonexistent_user(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/api/chat/create', {'username': 'nobody'})
        assert rv.status_code == 404

    def test_send_message(self, client, user1, user2):
        chat = Chat()
        chat.participants.append(user1)
        chat.participants.append(user2)
        db.session.add(chat)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/api/chat/{chat.id}/send', {'content': 'Hello!'})
        assert rv.status_code == 200
        assert rv.get_json()['content'] == 'Hello!'

    def test_edit_time_limit(self, client, user1, user2):
        chat = Chat()
        chat.participants.append(user1)
        chat.participants.append(user2)
        db.session.add(chat)
        db.session.flush()
        msg = Message(content='Old', sender_id=user1.id, chat_id=chat.id)
        msg.created_at = datetime.utcnow() - timedelta(minutes=10)
        db.session.add(msg)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_json(client, f'/api/chat/{chat.id}/edit/{msg.id}',
                       {'content': 'Updated'}, method='PUT')
        assert rv.status_code == 403

    def test_delete_as_admin(self, client, user1, user2):
        chat = Chat(is_group=True, name='Group', admin_id=user1.id)
        chat.participants.append(user1)
        chat.participants.append(user2)
        db.session.add(chat)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/api/chat/{chat.id}/delete', {})
        assert rv.status_code == 200

    def test_non_admin_cannot_delete_group(self, client, user1, user2):
        chat = Chat(is_group=True, name='Group', admin_id=user1.id)
        chat.participants.append(user1)
        chat.participants.append(user2)
        db.session.add(chat)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/api/chat/{chat.id}/delete', {})
        assert rv.status_code == 403
