"""Initial schema — all tables from module.py.

Revision ID: 001_initial
Revises:
Create Date: 2026-05-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('username', sa.String(32), nullable=False, unique=True),
        sa.Column('email', sa.String(120), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(128), nullable=False),
        sa.Column('avatar', sa.String(500), nullable=True),
        sa.Column('bio', sa.Text(), nullable=True),
        sa.Column('location', sa.String(100), nullable=True),
        sa.Column('website', sa.String(200), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('last_activity', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('is_admin', sa.Boolean(), nullable=True),
        sa.Column('role', sa.String(20), nullable=True),
        sa.Column('is_blocked', sa.Boolean(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('github_username', sa.String(39), nullable=True),
        sa.Column('developer_role', sa.String(20), nullable=True),
        sa.Column('verified', sa.Boolean(), nullable=True),
        sa.Index('ix_users_username', 'username'),
        sa.Index('ix_users_email', 'email'),
        sa.Index('ix_users_is_deleted', 'is_deleted'),
    )

    op.create_table('posts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('media_url', sa.String(500), nullable=True),
        sa.Column('media_type', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('is_pinned', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_posts_user_id', 'user_id'),
    )

    op.create_table('comments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('post_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['post_id'], ['posts.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_comments_post_id', 'post_id'),
        sa.Index('ix_comments_user_id', 'user_id'),
    )

    op.create_table('likes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('post_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['post_id'], ['posts.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_likes_post_id', 'post_id'),
        sa.Index('ix_likes_user_id', 'user_id'),
    )

    op.create_table('follows',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('follower_id', sa.Integer(), nullable=False),
        sa.Column('followed_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['followed_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['follower_id'], ['users.id'], ),
        sa.Index('ix_follows_followed_id', 'followed_id'),
        sa.Index('ix_follows_follower_id', 'follower_id'),
        sa.UniqueConstraint('follower_id', 'followed_id', name='unique_follow'),
    )

    op.create_table('messages',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('sender_id', sa.Integer(), nullable=False),
        sa.Column('receiver_id', sa.Integer(), nullable=False),
        sa.Column('is_read', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['receiver_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['sender_id'], ['users.id'], ),
        sa.Index('ix_messages_receiver_id', 'receiver_id'),
        sa.Index('ix_messages_sender_id', 'sender_id'),
    )

    op.create_table('notifications',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('is_read', sa.Boolean(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('post_id', sa.Integer(), nullable=True),
        sa.Column('sender_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['post_id'], ['posts.id'], ),
        sa.ForeignKeyConstraint(['sender_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_notifications_user_id', 'user_id'),
    )

    op.create_table('chats',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(100), nullable=True),
        sa.Column('is_group', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('avatar_url', sa.String(500), nullable=True),
        sa.Column('creator_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['creator_id'], ['users.id'], ),
    )

    op.create_table('chat_participants',
        sa.Column('chat_id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), primary_key=True),
        sa.ForeignKeyConstraint(['chat_id'], ['chats.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    )

    op.create_table('pinned_messages',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('message_id', sa.Integer(), nullable=False),
        sa.Column('chat_id', sa.Integer(), nullable=False),
        sa.Column('pinned_by_id', sa.Integer(), nullable=False),
        sa.Column('pinned_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['chat_id'], ['chats.id'], ),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ),
        sa.ForeignKeyConstraint(['pinned_by_id'], ['users.id'], ),
    )

    op.create_table('reactions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('emoji', sa.String(10), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('message_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_reactions_message_id', 'message_id'),
        sa.Index('ix_reactions_user_id', 'user_id'),
    )

    op.create_table('hashtags',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(50), nullable=False, unique=True),
        sa.Column('posts_count', sa.Integer(), nullable=True),
    )

    op.create_table('post_hashtags',
        sa.Column('post_id', sa.Integer(), primary_key=True),
        sa.Column('hashtag_id', sa.Integer(), primary_key=True),
        sa.ForeignKeyConstraint(['hashtag_id'], ['hashtags.id'], ),
        sa.ForeignKeyConstraint(['post_id'], ['posts.id'], ),
    )

    op.create_table('technologies',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(50), nullable=False, unique=True),
        sa.Column('category', sa.String(50), nullable=True),
    )

    op.create_table('roles',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(50), nullable=False, unique=True),
        sa.Column('label', sa.String(100), nullable=True),
        sa.Column('icon', sa.String(50), nullable=True),
    )

    op.create_table('ideas',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('author_id', sa.Integer(), nullable=False),
        sa.Column('likes_count', sa.Integer(), nullable=True),
        sa.Column('chat_id', sa.Integer(), nullable=True),
        sa.Column('project_type', sa.String(30), nullable=True),
        sa.Column('github_url', sa.String(500), nullable=True),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['chat_id'], ['chats.id'], ),
        sa.Index('ix_ideas_author_id', 'author_id'),
    )

    op.create_table('idea_technologies',
        sa.Column('idea_id', sa.Integer(), primary_key=True),
        sa.Column('technology_id', sa.Integer(), primary_key=True),
        sa.ForeignKeyConstraint(['idea_id'], ['ideas.id'], ),
        sa.ForeignKeyConstraint(['technology_id'], ['technologies.id'], ),
    )

    op.create_table('idea_roles',
        sa.Column('idea_id', sa.Integer(), primary_key=True),
        sa.Column('role_id', sa.Integer(), primary_key=True),
        sa.ForeignKeyConstraint(['idea_id'], ['ideas.id'], ),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ),
    )

    op.create_table('idea_likes',
        sa.Column('user_id', sa.Integer(), primary_key=True),
        sa.Column('idea_id', sa.Integer(), primary_key=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['idea_id'], ['ideas.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    )

    op.create_table('idea_join_requests',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('idea_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['idea_id'], ['ideas.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_idea_join_requests_idea_id', 'idea_id'),
        sa.Index('ix_idea_join_requests_user_id', 'user_id'),
        sa.UniqueConstraint('idea_id', 'user_id', name='unique_idea_join_request'),
    )

    op.create_table('user_technologies',
        sa.Column('user_id', sa.Integer(), primary_key=True),
        sa.Column('technology_id', sa.Integer(), primary_key=True),
        sa.Column('skill_level', sa.String(20), nullable=True),
        sa.ForeignKeyConstraint(['technology_id'], ['technologies.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    )

    op.create_table('channels',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(50), nullable=False, unique=True),
        sa.Column('title', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('avatar_url', sa.String(500), nullable=True),
        sa.Column('is_private', sa.Boolean(), nullable=True),
        sa.Column('invite_code', sa.String(10), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
        sa.Index('ix_channels_name', 'name'),
        sa.Index('ix_channels_owner_id', 'owner_id'),
    )

    op.create_table('channel_posts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('channel_id', sa.Integer(), nullable=False),
        sa.Column('author_id', sa.Integer(), nullable=False),
        sa.Column('media_url', sa.String(500), nullable=True),
        sa.Column('media_type', sa.String(20), nullable=True),
        sa.Column('is_pinned', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['channel_id'], ['channels.id'], ),
        sa.Index('ix_channel_posts_channel_id', 'channel_id'),
        sa.Index('ix_channel_posts_author_id', 'author_id'),
    )

    op.create_table('channel_post_likes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('post_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['post_id'], ['channel_posts.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_channel_post_likes_post_id', 'post_id'),
        sa.Index('ix_channel_post_likes_user_id', 'user_id'),
    )

    op.create_table('channel_post_comments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('post_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['post_id'], ['channel_posts.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_channel_post_comments_post_id', 'post_id'),
        sa.Index('ix_channel_post_comments_user_id', 'user_id'),
    )

    op.create_table('channel_invites',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('channel_id', sa.Integer(), nullable=False),
        sa.Column('inviter_id', sa.Integer(), nullable=False),
        sa.Column('invitee_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['channel_id'], ['channels.id'], ),
        sa.ForeignKeyConstraint(['invitee_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['inviter_id'], ['users.id'], ),
        sa.Index('ix_channel_invites_channel_id', 'channel_id'),
        sa.Index('ix_channel_invites_invitee_id', 'invitee_id'),
        sa.Index('ix_channel_invites_inviter_id', 'inviter_id'),
    )

    op.create_table('channel_members',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('channel_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role', sa.String(20), nullable=True),
        sa.Column('status', sa.String(20), nullable=True),
        sa.Column('joined_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['channel_id'], ['channels.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.Index('ix_channel_members_channel_id', 'channel_id'),
        sa.Index('ix_channel_members_user_id', 'user_id'),
        sa.UniqueConstraint('channel_id', 'user_id', name='unique_channel_member'),
    )


def downgrade() -> None:
    op.drop_table('channel_members')
    op.drop_table('channel_invites')
    op.drop_table('channel_post_comments')
    op.drop_table('channel_post_likes')
    op.drop_table('channel_posts')
    op.drop_table('channels')
    op.drop_table('user_technologies')
    op.drop_table('idea_join_requests')
    op.drop_table('idea_likes')
    op.drop_table('idea_roles')
    op.drop_table('idea_technologies')
    op.drop_table('ideas')
    op.drop_table('roles')
    op.drop_table('technologies')
    op.drop_table('post_hashtags')
    op.drop_table('hashtags')
    op.drop_table('reactions')
    op.drop_table('pinned_messages')
    op.drop_table('chat_participants')
    op.drop_table('chats')
    op.drop_table('notifications')
    op.drop_table('messages')
    op.drop_table('follows')
    op.drop_table('likes')
    op.drop_table('comments')
    op.drop_table('posts')
    op.drop_table('users')
