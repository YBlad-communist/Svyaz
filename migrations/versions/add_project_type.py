"""Add project_type column to ideas table.

Run: python migrate_add_project_type.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('ideas')]
        if 'project_type' in columns:
            print('Column project_type already exists.')
            return
        with db.engine.connect() as conn:
            conn.execute(text(
                "ALTER TABLE ideas ADD COLUMN project_type VARCHAR(30) DEFAULT 'other'"
            ))
            conn.commit()
        print('Added project_type column to ideas table.')

if __name__ == '__main__':
    migrate()
