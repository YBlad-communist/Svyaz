# СвяZь — IT-соцсеть для разработчиков

Платформа, где разработчики делятся идеями, ищут единомышленников и собирают команды для проектов.

---

## 1. Исправленные уязвимости

| Уязвимость | Решение |
|---|---|
| **SECRET_KEY генерировался при каждом запуске** | Читается из `os.environ['SECRET_KEY']`. При отсутствии — `RuntimeError` с инструкцией генерации |
| **SQL-инъекция через `ilike`** | Все запросы параметризованы через SQLAlchemy (`ilike(search_param)` где `search_param = f'%{q}%'`) |
| **XSS через самодельную `sanitize_html`** | Заменена на `nh3.clean()` с белым списком тегов и атрибутов |
| **Cookie без флагов** | `SESSION_COOKIE_SECURE=True`, `HTTPONLY=True`, `SAMESITE='Lax'` |
| **Загрузка файлов** | Случайные имена через `secrets.token_urlsafe(16)`, проверка magic bytes, хранение вне `static/` |
| **Удаление аккаунта** | Soft delete: `is_deleted=True`, `anonymize()` очищает PII |
| **HTTPS** | Talisman `force_https=True`, `strict_transport_security=True`, nginx + Let's Encrypt |

---

## 2. Быстрый старт (локально)

```bash
# 1. Генерация SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"

# 2. Копирование .env
cp .env.example .env
# Вставьте SECRET_KEY в .env

# 3. Установка зависимостей
pip install -r requirements.txt

# 4. Запуск (SQLite по умолчанию)
python app.py
```

---

## 3. Деплой через Docker Compose

```bash
# 1. Подготовка
cp .env.example .env
echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" >> .env

# 2. Запуск
docker compose up -d

# 3. SSL (первый раз)
docker compose run --rm certbot certonly \
  --webroot --webroot-path=/var/www/certbot \
  -d your-domain.com \
  --email admin@your-domain.com --agree-tos --no-eff-email

# 4. Обновите nginx.conf: замените your-domain.com на ваш домен
# 5. Перезапуск
docker compose up -d nginx
```

### Nginx + Let's Encrypt без Docker

```bash
# Установка
sudo apt install nginx certbot python3-certbot-nginx

# SSL
sudo certbot --nginx -d your-domain.com

# Конфиг /etc/nginx/sites-available/svyaz:
# (см. nginx.conf в репозитории)

# Gunicorn
gunicorn --bind 127.0.0.1:8000 --workers 4 app:app
```

---

## 4. Тестирование сценариев

### Регистрация
1. Откройте `http://localhost:5000/register`
2. Введите имя (3-32 символа), email, пароль (6+ символов)
3. После регистрации — редирект на `/feed`

### Создание идеи
1. Перейдите на `/ideas` → кнопка «Создать идею»
2. Заполните: название, описание, проблема, решение
3. Выберите технологии (чекбоксы) и нужные роли
4. Нажмите «Опубликовать» — автоматически создаётся групповой чат
5. Проверьте: идея появилась в ленте, чат доступен

### Голосование
1. Откройте любую идею на `/idea/<id>`
2. Нажмите ▲ (upvote) или ▼ (downvote)
3. Счёт обновляется через AJAX
4. Повторный клик на тот же голос — отмена
5. Клик на противоположный — смена голоса

### Поиск команды
1. Перейдите в `/profile/edit`
2. Выберите основную роль (backend, frontend, etc.)
3. Отметьте технологии в стеке
4. Сохраните — теперь вы появляетесь в поиске по технологиям
5. Поиск: `/search?q=Python&type=users`

### Удаление аккаунта
1. `/profile/edit` → «Опасная зона» → «Удалить аккаунт»
2. Подтвердите — профиль анонимизирован (`user_<id>`, email `deleted_<id>@deleted.local`)
3. `is_deleted=True`, `is_active=False` — вход невозможен
4. Посты и идеи остаются (автор — анонимизирован)

### GitHub интеграция
1. `/profile/edit` → введите `github_username`
2. На странице идеи автора — блок «GitHub автора» с репозиториями
3. Данные загружаются через публичное GitHub API

---

## 5. Структура файлов

```
Svyaz/
├── app.py                 # Все роуты + конфиг
├── database.py            # SQLAlchemy инициализация
├── module.py              # Модели (User, Idea, Technology, Role, etc.)
├── requirements.txt       # Python зависимости
├── .env.example           # Шаблон переменных окружения
├── Dockerfile             # Образ приложения
├── docker-compose.yml     # Оркестрация сервисов
├── nginx.conf             # Nginx конфиг + SSL
├── migrations/
│   └── 001_it_social_network.sql  # SQL миграция
├── templates/
│   ├── base.html          # Базовый шаблон
│   ├── feed.html          # Лента постов
│   ├── profile.html       # Профиль пользователя
│   ├── profile_edit.html  # Редактирование профиля
│   ├── search.html        # Поиск
│   ├── ideas.html         # Лента идей
│   ├── idea_create.html   # Создание идеи
│   └── idea_detail.html   # Страница идеи
├── static/                # CSS, JS, frames
└── uploads/               # Загруженные файлы (вне static)
```

---

## 6. Переменные окружения

| Переменная | Обязательная | Описание |
|---|---|---|
| `SECRET_KEY` | Да | Криптографический ключ. Генерация: `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `DATABASE_URL` | Нет | SQLAlchemy URI. По умолчанию: `sqlite:///social_media.db` |
| `REDIS_HOST` | Нет | Хост Redis для rate limiting. По умолчанию: `localhost` |
| `REDIS_PORT` | Нет | Порт Redis. По умолчанию: `6379` |

---

## 7. Безопасность — чеклист продакшена

- [x] `SECRET_KEY` из переменной окружения
- [x] `SESSION_COOKIE_SECURE = True` (только HTTPS)
- [x] Talisman `force_https = True`
- [x] `nh3` для санитизации HTML
- [x] Параметризованные SQL-запросы
- [x] Случайные имена файлов + проверка magic bytes
- [x] Soft delete с анонимизацией
- [x] CSRF токены на всех формах
- [x] Rate limiting на аутентификации
- [x] `X-Content-Type-Options: nosniff`
- [x] `X-Frame-Options: DENY`
- [x] `Referrer-Policy: strict-origin-when-cross-origin`
- [x] `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- [ ] SSL-сертификат (Let's Encrypt)
- [ ] Firewall (открыты только 80/443)
- [ ] Регулярные обновления зависимостей
