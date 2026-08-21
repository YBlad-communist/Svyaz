from app import db
from module import Idea, idea_join_requests, Notification
from conftest import login, csrf_post, csrf_json


class TestIdeaCreate:
    def test_success(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/idea/create', {
            'title': 'My Great Idea',
            'description': 'Detailed description.',
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert Idea.query.filter_by(title='My Great Idea').first() is not None

    def test_unauthorized(self, client):
        rv = client.get('/idea/create', follow_redirects=True)
        assert rv.status_code == 200

    def test_missing_title(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/idea/create', {
            'title': '', 'description': 'Some description',
        }, follow_redirects=True)
        assert rv.status_code == 200

    def test_with_technologies(self, client, user1, tech_python, tech_js):
        login(client, 'alice', 'password123')
        rv = csrf_post(client, '/idea/create', {
            'title': 'Tech Idea', 'description': 'Idea with tech',
            'technologies': [str(tech_python.id), str(tech_js.id)],
        }, follow_redirects=True)
        assert rv.status_code == 200
        idea = Idea.query.filter_by(title='Tech Idea').first()
        assert idea is not None
        assert len(idea.technologies) == 2


class TestIdeaLike:
    def test_like(self, client, user1, user2):
        idea = Idea(title='Test', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/idea/{idea.id}/like', {})
        assert rv.status_code == 200
        data = rv.get_json()
        assert data['liked'] is True
        assert data['count'] == 1

    def test_unlike(self, client, user1, user2):
        idea = Idea(title='Test', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        idea.likers.append(user2)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/idea/{idea.id}/like', {})
        data = rv.get_json()
        assert data['liked'] is False
        assert data['count'] == 0

    def test_inactive_idea(self, client, user1, user2):
        idea = Idea(title='Test', description='Desc', author_id=user1.id, is_active=False)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_json(client, f'/idea/{idea.id}/like', {})
        assert rv.status_code == 404

    def test_nonexistent(self, client, user1):
        login(client, 'alice', 'password123')
        rv = csrf_json(client, '/idea/99999/like', {})
        assert rv.status_code == 404


class TestIdeaJoinRequests:
    def test_pending(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join', {}, follow_redirects=True)
        assert rv.status_code == 200

        req = db.session.query(idea_join_requests).filter_by(
            idea_id=idea.id, user_id=user2.id).first()
        assert req is not None and req.status == 'pending'

    def test_author_cannot_join(self, client, user1):
        idea = Idea(title='My', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join', {}, follow_redirects=True)
        assert rv.status_code == 200

    def test_approve(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        db.session.execute(idea_join_requests.insert().values(
            idea_id=idea.id, user_id=user2.id, status='pending'))
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join/{user2.id}/approve', {}, follow_redirects=True)
        assert rv.status_code == 200

        req = db.session.query(idea_join_requests).filter_by(
            idea_id=idea.id, user_id=user2.id).first()
        assert req.status == 'approved'

    def test_approve_sends_notification(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        db.session.execute(idea_join_requests.insert().values(
            idea_id=idea.id, user_id=user2.id, status='pending'))
        db.session.commit()

        login(client, 'alice', 'password123')
        csrf_post(client, f'/idea/{idea.id}/join/{user2.id}/approve', {})
        notif = Notification.query.filter_by(user_id=user2.id, type='idea_approved').first()
        assert notif is not None
        assert 'approved' in notif.content.lower()

    def test_reject_sends_notification(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        db.session.execute(idea_join_requests.insert().values(
            idea_id=idea.id, user_id=user2.id, status='pending'))
        db.session.commit()

        login(client, 'alice', 'password123')
        csrf_post(client, f'/idea/{idea.id}/join/{user2.id}/reject', {})
        notif = Notification.query.filter_by(user_id=user2.id, type='idea_rejected').first()
        assert notif is not None

    def test_non_author_cannot_approve(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join/{user2.id}/approve', {})
        assert rv.status_code == 403

    def test_cancel_join_request(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        db.session.execute(idea_join_requests.insert().values(
            idea_id=idea.id, user_id=user2.id, status='pending'))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join/cancel', {}, follow_redirects=True)
        assert rv.status_code == 200
        req = db.session.query(idea_join_requests).filter_by(
            idea_id=idea.id, user_id=user2.id).first()
        assert req is None

    def test_rerequest_after_rejection(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        db.session.execute(idea_join_requests.insert().values(
            idea_id=idea.id, user_id=user2.id, status='rejected'))
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join', {}, follow_redirects=True)
        assert rv.status_code == 200
        req = db.session.query(idea_join_requests).filter_by(
            idea_id=idea.id, user_id=user2.id).first()
        assert req.status == 'pending'


class TestIdeaLifecycle:
    def test_set_status(self, client, user1):
        idea = Idea(title='Lifecycle', description='Desc', author_id=user1.id, status='open')
        db.session.add(idea)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/status', {'status': 'in_progress'}, follow_redirects=True)
        assert rv.status_code == 200
        assert idea.status == 'in_progress'

    def test_set_status_invalid(self, client, user1):
        idea = Idea(title='Lifecycle', description='Desc', author_id=user1.id, status='open')
        db.session.add(idea)
        db.session.commit()

        login(client, 'alice', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/status', {'status': 'invalid'}, follow_redirects=True)
        assert rv.status_code == 200
        assert idea.status == 'open'

    def test_archive_sets_inactive(self, client, user1):
        idea = Idea(title='Lifecycle', description='Desc', author_id=user1.id, status='open')
        db.session.add(idea)
        db.session.commit()

        login(client, 'alice', 'password123')
        csrf_post(client, f'/idea/{idea.id}/status', {'status': 'archived'})
        assert idea.is_active is False
        assert idea.status == 'archived'

    def test_non_author_cannot_change_status(self, client, user1, user2):
        idea = Idea(title='Lifecycle', description='Desc', author_id=user1.id, status='open')
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/status', {'status': 'completed'}, follow_redirects=True)
        assert idea.status == 'open'

    def test_get_members(self, client, user1, user2):
        idea = Idea(title='Members', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()
        db.session.execute(idea_join_requests.insert().values(
            idea_id=idea.id, user_id=user2.id, status='approved'))
        db.session.commit()

        members = idea.get_members()
        member_ids = [m.id for m in members]
        assert user1.id in member_ids
        assert user2.id in member_ids
