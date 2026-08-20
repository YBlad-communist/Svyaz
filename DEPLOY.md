# Демо-деплой Svyaz (IP, self-signed HTTPS)

Инструкция развёртывания полного стека на Linux-сервере (VPS) с публичным IP,
без домена — HTTPS на самоподписанном сертификате. Подходит для демо.

## Архитектура стека

`docker-compose.yml` поднимает:

- `db` — PostgreSQL 16 (схема из `migrations/001_it_social_network.sql`)
- `redis-master` / `redis-replica` / `redis-sentinel` — Redis с репликацией и паролем
- `web` — Gunicorn (Flask), порт `8000`, healthcheck `/health`
- `celery-worker` / `celery-beat` — фоновые и периодические задачи
- `nginx` — реверс-прокси, HTTPS, WebSocket, раздача статики/uploads
- `certbot` — автообновление сертификатов (для self-signed не нужен)
- `prometheus` / `grafana` — метрики и дашборды

## Требования

- Linux VPS (Ubuntu/Debian), не менее 1 CPU / 1 GB RAM
- Docker Engine + Compose plugin
- Порты открыты: `22`, `80`, `443`

## Шаг 1. Подготовка каталога

Скопируйте репозиторий на сервер (например, в `/opt/svyaz`):

```bash
git clone <repo-url> /opt/svyaz
cd /opt/svyaz
```

## Шаг 2. Секреты и .env

Задайте публичный IP сервера как DOMAIN (файлы `.env` и `secrets/*.txt` в репозиторий **не попадают** — см. `.gitignore`/`.dockerignore`):

```bash
IP=$(curl -4 -s ifconfig.me)
echo "DOMAIN=$IP" >> .env
```

Сгенерируйте недостающие секреты:

```bash
openssl rand -hex 32 > secrets/db_password.txt
openssl rand -hex 32 > secrets/db_replication_password.txt
openssl rand -hex 24 > secrets/grafana_admin_password.txt
```

Впишите в `.env` (обязательно для redis):

```
SECRET_KEY=<надёжный, >=32 символов>
REDIS_PASSWORD=<тот же, что задан в стеке; по умолчанию сток требует changeme>
FLASK_ENV=production
FLASK_DEBUG=0
```

> `DATABASE_URL` можно не задавать: web-контейнер соберёт URI сам из
> `POSTGRES_PASSWORD_FILE` (docker secret `db_password`).

## Шаг 3. Самоподписанный сертификат (первый запуск без домена)

nginx в 443-блоке требует сертификат. Пока нет реального домена — сгенерируйте
self-signed в каталог, который nginx монтирует из `certbot/conf`:

```bash
DOMAIN=$IP
mkdir -p "certbot/conf/live/$DOMAIN"
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout "certbot/conf/live/$DOMAIN/privkey.pem" \
  -out   "certbot/conf/live/$DOMAIN/fullchain.pem" \
  -subj "/CN=$DOMAIN"
```

(Тот же шаг автоматически делает Ansible-плейбук `deploy.yml`.)

## Шаг 4. Запуск

```bash
docker compose up -d --build
```

Первый запуск создаёт БД из `migrations/001_it_social_network.sql`; Flask
дополнительно прогоняет `db.create_all()` — схема создаётся идемпотентно
(проверено на PostgreSQL 18).

## Шаг 5. Проверка

```bash
curl -f http://localhost/health        # → 200 (nginx, порт 80)
curl -k https://$IP/health            # → 200 (self-signed)
docker compose ps                     # все сервисы healthy/up
```

Откройте `https://$IP/` в браузере. Предупреждение о сертификате — ожидаемо для
демо; обойдите его, чтобы попасть в приложение.

## Шаг 6. Обновление

```bash
git pull                      # или git clone заново
docker compose up -d --build  # пересборка только изменённых сервисов
```

## Бэкапы

```bash
# перед запуском задайте путь к реальным uploads (они в static/uploads)
export UPLOAD_FOLDER=/app/static/uploads
export DATABASE_URL="postgresql+psycopg2://svyaz:$(cat secrets/db_password.txt)@localhost:5432/svyaz"
./backup.sh
```

Резервные копии: `backups/svyaz_db_*.sql.gz` (pg_dump) + `svyaz_uploads_*.tar.gz`.
Восстановление — `./restore.sh`.

## Переход на реальный домен + Let's Encrypt (позже)

1. В `.env` задайте `DOMAIN=<ваш домен>`.
2. Удалите self-signed серт и снимите 443-фолбэк при необходимости.
3. Один раз выдайте сертификат:
   `docker compose run --rm certbot certonly --webroot -w /var/www/certbot -d <домен>`
4. `docker compose restart nginx` — certbot далее обновляет автоматически.

## Автоматизация (опционально)

`deploy.yml` — Ansible-плейбук: ставит Docker/UFW/fail2ban, клонирует репо,
генерирует секреты и self-signed серт, поднимает стек и проверяет `/health`.

```bash
ansible-playbook -i inventory deploy.yml
```

Укажите актуальный `repo`/`dest`/`inventory` под ваш сервер.