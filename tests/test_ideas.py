from app import db
from module import Idea, idea_join_requests
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

    def test_non_author_cannot_approve(self, client, user1, user2):
        idea = Idea(title='Join', description='Desc', author_id=user1.id)
        db.session.add(idea)
        db.session.commit()

        login(client, 'bob', 'password123')
        rv = csrf_post(client, f'/idea/{idea.id}/join/{user2.id}/approve', {})
        assert rv.status_code == 403
