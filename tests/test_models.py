from module import (
    Post, sanitize_html, validate_email, validate_username,
)


class TestSanitizeHtml:
    def test_escapes_script_tags(self):
        result = sanitize_html('<script>alert("xss")</script>')
        assert '<script>' not in result

    def test_allows_safe_tags(self):
        result = sanitize_html('<strong>bold</strong> <code>print("hi")</code>')
        assert '<strong>' in result
        assert '<code>' in result

    def test_removes_onclick(self):
        result = sanitize_html('<a href="https://example.com" onclick="alert(1)">link</a>')
        assert 'onclick' not in result

    def test_empty_input(self):
        assert sanitize_html('') == ''
        assert sanitize_html(None) == ''

    def test_allows_pre_tag(self):
        result = sanitize_html('<pre>def foo():\n    pass</pre>')
        assert '<pre>' in result

    def test_removes_iframe(self):
        result = sanitize_html('<iframe src="https://evil.com"></iframe>')
        assert '<iframe' not in result

    def test_removes_javascript_protocol(self):
        result = sanitize_html('<a href="javascript:alert(1)">click</a>')
        assert 'javascript:' not in result


class TestValidateEmail:
    def test_valid(self):
        assert validate_email('user@example.com') is True

    def test_invalid(self):
        assert validate_email('not-an-email') is False
        assert validate_email('') is False
        assert validate_email(None) is False


class TestValidateUsername:
    def test_valid(self):
        assert validate_username('alice_123') is True
        assert validate_username('bob-test') is True

    def test_invalid(self):
        assert validate_username('ab') is False
        assert validate_username('a' * 33) is False
        assert validate_username('user@name') is False
        assert validate_username('') is False


class TestUserModel:
    def test_password(self, user1):
        user1.set_password('newpass')
        assert user1.check_password('newpass')
        assert not user1.check_password('wrong')

    def test_anonymize(self, user1):
        uid = user1.id
        user1.anonymize()
        assert user1.is_deleted
        assert not user1.is_active
        assert user1.username == f"user_{uid}"

    def test_can_delete_post(self, user1):
        post = Post(content='t', user_id=user1.id)
        assert user1.can_delete_post(post)

    def test_cannot_delete_other(self, user1, user2):
        post = Post(content='t', user_id=user1.id)
        assert not user2.can_delete_post(post)

    def test_admin_can_delete(self, admin_user, user1):
        post = Post(content='t', user_id=user1.id)
        assert admin_user.can_delete_post(post)
