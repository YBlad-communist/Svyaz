from module import Chat, db
from conftest import login


class TestPollingRateLimits:
    """Regression: chat list/messages polling must never exhaust the
    global rate-limit budget (it used to make chats 'disappear' after
    a couple of minutes of use when the old 50/hour default hit)."""

    def test_chat_list_polling_survives_burst(self, client, user1, user2):
        chat = Chat(is_group=False)
        chat.participants = [user1, user2]
        db.session.add(chat)
        db.session.commit()

        assert login(client, 'alice', 'password123').status_code == 200
        for _ in range(100):  # ~3+ minutes worth of 2.5s polling
            rv = client.get('/api/chats')
            assert rv.status_code == 200
            assert isinstance(rv.get_json(), list)

    def test_message_polling_survives_burst(self, client, user1, user2):
        chat = Chat(is_group=False)
        chat.participants = [user1, user2]
        db.session.add(chat)
        db.session.commit()

        assert login(client, 'alice', 'password123').status_code == 200
        for _ in range(120):
            rv = client.get(f'/api/chat/{chat.id}/messages')
            assert rv.status_code == 200
            assert isinstance(rv.get_json(), list)
