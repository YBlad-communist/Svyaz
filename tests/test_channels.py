from datetime import datetime
from app import db
from module import Channel, ChannelPost, channel_members
from conftest import login, logout, csrf_post


class TestChannels:
    def test_create_success(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/channel/create', {
            'name': 'mychannel', 'title': 'My Channel',
            'description': 'Test', 'type': 'public',
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert Channel.query.filter_by(name='mychannel').first() is not None

    def test_post_member_only(self, client, user1, user2):
        ch = Channel(name='membersonly', title='Members', type='public', owner_id=user1.id)
        db.session.add(ch)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user1.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/post',
                       {'content': 'Intruder'}, follow_redirects=True)
        assert rv.status_code == 200  # redirected with flash

    def test_admin_can_post(self, client, user1, user2):
        ch = Channel(name='adminch', title='Admin', type='public', owner_id=user1.id)
        db.session.add(ch)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user1.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/post',
                       {'content': 'Hello'}, follow_redirects=True)
        assert rv.status_code == 200
        assert ChannelPost.query.filter_by(channel_id=ch.id, content='Hello').first() is not None

    def test_member_cannot_post_admin_only(self, client, user1, user2):
        ch = Channel(name='adminonly', title='AdminOnly', type='public',
                     owner_id=user1.id, post_permission='admins')
        db.session.add(ch)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user1.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user2.id,
            role='member', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/post',
                       {'content': 'Nope'}, follow_redirects=True)
        assert rv.status_code == 200  # redirected with flash
        assert ChannelPost.query.filter_by(channel_id=ch.id, content='Nope').first() is None

    def test_member_can_post_when_allowed(self, client, user1, user2):
        ch = Channel(name='opench', title='Open', type='public',
                     owner_id=user1.id, post_permission='members')
        db.session.add(ch)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user1.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user2.id,
            role='member', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/post',
                       {'content': 'Allowed'}, follow_redirects=True)
        assert rv.status_code == 200
        assert ChannelPost.query.filter_by(channel_id=ch.id, content='Allowed').first() is not None

    def test_delete_channel_admin_only(self, client, user1, user2):
        ch = Channel(name='delch', title='Delete', type='public', owner_id=user1.id)
        db.session.add(ch)
        db.session.flush()
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user1.id,
            role='admin', status='active', joined_at=datetime.utcnow()
        ))
        db.session.execute(channel_members.insert().values(
            channel_id=ch.id, user_id=user2.id,
            role='member', status='active', joined_at=datetime.utcnow()
        ))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/delete', {}, follow_redirects=True)
        assert Channel.query.filter_by(id=ch.id).first() is not None  # member cannot delete

        logout(client)
        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/delete', {}, follow_redirects=True)
        assert rv.status_code == 200
        assert Channel.query.filter_by(id=ch.id).first() is None
        assert db.session.query(channel_members).filter_by(channel_id=ch.id).count() == 0

    def test_join_public(self, client, user1, user2):
        ch = Channel(name='joinme', title='Join', type='public', owner_id=user1.id)
        db.session.add(ch)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/join', {}, follow_redirects=True)
        assert rv.status_code == 200
        assert ch.get_membership(user2).status == 'active'

    def test_join_private_pending(self, client, user1, user2):
        ch = Channel(name='privatech', title='Private', type='private', owner_id=user1.id)
        db.session.add(ch)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/channel/{ch.name}/join', {}, follow_redirects=True)
        assert rv.status_code == 200
        assert ch.get_membership(user2).status == 'pending'
