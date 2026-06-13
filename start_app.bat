@echo off
set SECRET_KEY=dev-secret-key-change-in-production-123456
set DATABASE_URL=sqlite:///social_media.db
set FLASK_ENV=development
set REDIS_HOST=127.0.0.1
set REDIS_PORT=6379
cd /d C:\Users\User\Desktop\Svyaz.git
python app.py
