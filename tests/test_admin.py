from datetime import datetime
from app import db
from module import User, Post, Comment, Idea, Channel, Chat, channel_members
from conftest import CSRF_TOKEN, setup_csrf, login, logout, csrf_post, csrf_json


class TestAccessControl:
    def test_cannot_edit_other_post(self, client, user1, user2):
        post = Post(content='My post', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/post/{post.id}/edit',
                       {'content': 'Hacked!'}, method='PUT')
        assert rv.status_code == 403

    def test_cannot_delete_other_post(self, client, user1, user2):
        post = Post(content='My post', user_id=user1.id)
        db.session.add(post)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/post/{post.id}/delete', {}, method='DELETE')
        assert rv.status_code == 403

    def test_cannot_delete_other_idea(self, client, user1, user2):
        idea = Idea(title='Alice Idea', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/delete', {})
        assert rv.status_code == 403

    def test_admin_can_delete_any_idea(self, client, user1, admin_user):
        idea = Idea(title='Alice Idea', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'admin', 'adminpass123')
        rv = csrf_post(client, f'/idea/{idea.id}/delete', {}, follow_redirects=True)
        assert rv.status_code == 200
        idea = db.session.get(Idea, idea.id)
        assert idea.is_active is False

    def test_cannot_access_private_channel(self, client, user1, user2):
        ch = Channel(name='private-ch', title='Private', type='private', owner_id=user1.id)
        db.session.add(ch)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user1.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = client.get(f'/channel/{ch.name}', follow_redirects=True)
        assert rv.status_code == 200

    def test_cannot_view_chat_not_member(self, client, user1, user2):
        chat = Chat(is_group=True, name='Secret Group', admin_id=user1.id)
        db.session.add(chat)
        chat.participants.append(user1)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = client.get(f'/api/chat/{chat.id}/messages')
        assert rv.status_code == 403

    def test_cannot_send_to_foreign_chat(self, client, user1, user2):
        chat = Chat(is_group=True, name='Secret Group', admin_id=user1.id)
        db.session.add(chat)
        chat.participants.append(user1)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/api/chat/{chat.id}/send', {'content': 'Hello!'})
        assert rv.status_code == 403


class TestAdminModeration:
    def test_admin_dashboard_access(self, client, admin_user, user1):
        login(client, 'alice', 'password123')
        rv = client.get('/admin')
        assert rv.status_code == 403
        logout(client)
        login(client, 'admin', 'adminpass123')
        rv = client.get('/admin')
        assert rv.status_code == 200

    def test_admin_ban_unban(self, client, admin_user, user1):
        login(client, 'admin', 'adminpass123')
        rv = csrf_post(client, f'/admin/user/{user1.id}/ban', {})
        assert rv.status_code == 200
        assert db.session.get(User, user1.id).is_blocked is True
        rv = csrf_post(client, f'/admin/user/{user1.id}/unban', {})
        assert rv.status_code == 200
        assert db.session.get(User, user1.id).is_blocked is False

    def test_admin_warn_user(self, client, admin_user, user1):
        login(client, 'admin', 'adminpass123')
        rv = csrf_json(client, f'/admin/user/{user1.id}/warn', {'reason': 'Spam'})
        assert rv.status_code == 200
        data = rv.get_json()
        assert data['success'] is True
        assert db.session.get(User, user1.id).warning_count() == 1

    def test_admin_set_role(self, client, admin_user, user1):
        login(client, 'admin', 'adminpass123')
        rv = csrf_json(client, f'/admin/set_role/{user1.id}', {'role': 'moderator'})
        assert rv.status_code == 200
        assert db.session.get(User, user1.id).role == 'moderator'

    def test_non_admin_cannot_moderate(self, client, user1, user2):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/admin/user/{user2.id}/ban', {})
        assert rv.status_code == 403
        assert db.session.get(User, user2.id).is_blocked is False

    def test_admin_delete_post(self, client, admin_user, user1):
        p = Post(content='To delete', user_id=user1.id)
        db.session.add(p)
        db.session.commit()
        login(client, 'admin', 'adminpass123')
        rv = csrf_post(client, f'/admin/delete/post/{p.id}', {})
        assert rv.status_code == 200
        assert db.session.get(Post, p.id) is None

    def test_moderator_can_delete_others_comment(self, client, admin_user, user1):
        p = Post(content='Target', user_id=user1.id)
        db.session.add(p)
        db.session.flush()
        c = Comment(content='Bad comment', user_id=user1.id, post_id=p.id)
        db.session.add(c)
        db.session.commit()
        login(client, 'admin', 'adminpass123')
        setup_csrf(client)
        rv = client.delete(f'/comment/{c.id}/delete', headers={'X-CSRFToken': CSRF_TOKEN})
        assert rv.status_code == 200
        assert db.session.get(Comment, c.id) is None

    def test_admin_delete_user_keeps_deleted_placeholder(self, client, admin_user, user1):
        login(client, 'admin', 'adminpass123')
        uid = user1.id
        rv = csrf_post(client, f'/admin/user/{uid}/delete', {})
        assert rv.status_code == 200
        row = db.session.get(User, uid)
        assert row is not None  # account stays in DB
        assert row.is_deleted is True
        assert row.display_name == 'Deleted user'
        assert row.username.startswith('user_')
        assert row.email == 'alice@test.com'
