"""Celery application for Svyaz background tasks."""
import os
from celery import Celery
from celery.schedules import crontab

celery_app = Celery(
    'svyaz',
    broker=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1'),
    backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2'),
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,
    task_soft_time_limit=240,
    worker_max_tasks_per_child=100,
    beat_schedule={
        'cleanup-old-sessions': {
            'task': 'celery_app.tasks.cleanup_expired_sessions',
            'schedule': crontab(hour=3, minute=0),
        },
        'cleanup-old-notifications': {
            'task': 'celery_app.tasks.cleanup_old_notifications',
            'schedule': crontab(hour=4, minute=0),
        },
        'backup-database': {
            'task': 'celery_app.tasks.backup_database',
            'schedule': crontab(hour='*/6', minute=0),
        },
        'send-digest-emails': {
            'task': 'celery_app.tasks.send_digest_emails',
            'schedule': crontab(hour=8, minute=0),
        },
    },
)


class tasks:

    @staticmethod
    @celery_app.task
    def cleanup_expired_sessions():
        """Remove expired sessions from Redis."""
        from flask import Flask
        from database import db as _db
        app = Flask(__name__)
        _db.init_app(app)
        with app.app_context():
            # Placeholder: actual cleanup logic
            pass

    @staticmethod
    @celery_app.task
    def cleanup_old_notifications():
        """Delete notifications older than 90 days."""
        from datetime import datetime, timedelta
        from database import db as _db
        from module import Notification
        from flask import Flask
        app = Flask(__name__)
        _db.init_app(app)
        with app.app_context():
            cutoff = datetime.utcnow() - timedelta(days=90)
            deleted = Notification.query.filter(Notification.created_at < cutoff).delete()
            _db.session.commit()

    @staticmethod
    @celery_app.task
    def backup_database():
        """Run pg_dump and upload to S3."""
        import subprocess
        import tempfile
        import os
        from datetime import datetime

        db_url = os.environ.get('DATABASE_URL', '')
        s3_bucket = os.environ.get('S3_BACKUP_BUCKET', '')
        if not db_url or not s3_bucket:
            return

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"svyaz_db_{timestamp}.sql.gz"
        filepath = os.path.join(tempfile.gettempdir(), filename)

        try:
            subprocess.run(
                f"pg_dump {db_url} --clean --if-exists | gzip > {filepath}",
                shell=True, check=True, timeout=300,
            )
            if s3_bucket:
                import boto3
                s3 = boto3.client('s3')
                s3.upload_file(filepath, s3_bucket, f"db/{filename}")
            os.remove(filepath)
        except Exception:
            pass

    @staticmethod
    @celery_app.task
    def send_digest_emails():
        """Send daily digest emails (placeholder)."""
        pass
