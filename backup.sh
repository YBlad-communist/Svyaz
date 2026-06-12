#!/bin/bash
# Automated backup script for Svyaz
# Usage: ./backup.sh [output_dir]
# Requires: pg_dump, rsync (or cp), gzip

set -euo pipefail

BACKUP_DIR="${1:-./backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DB_NAME="${POSTGRES_DB:-svyaz}"
DB_USER="${POSTGRES_USER:-svyaz}"
DB_PASS="${POSTGRES_PASSWORD:-}"
DB_HOST="${DB_HOST:-db}"
UPLOADS_DIR="${UPLOADS_DIR:-./uploads}"

mkdir -p "$BACKUP_DIR"

# Backup PostgreSQL
if command -v pg_dump &>/dev/null; then
    echo "[$(date +%H:%M:%S)] Backing up database $DB_NAME..."
    export PGPASSWORD="$DB_PASS"
    pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" --clean --if-exists \
        | gzip > "$BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.sql.gz"
    echo "[$(date +%H:%M:%S)] Database backup: $BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.sql.gz"
else
    echo "[WARN] pg_dump not found. Skipping database backup."
fi

# Backup uploads
if [ -d "$UPLOADS_DIR" ]; then
    echo "[$(date +%H:%M:%S)] Backing up uploads from $UPLOADS_DIR..."
    tar -czf "$BACKUP_DIR/uploads_${TIMESTAMP}.tar.gz" -C "$(dirname "$UPLOADS_DIR")" "$(basename "$UPLOADS_DIR")"
    echo "[$(date +%H:%M:%S)] Uploads backup: $BACKUP_DIR/uploads_${TIMESTAMP}.tar.gz"
else
    echo "[WARN] Uploads directory $UPLOADS_DIR not found. Skipping."
fi

# Clean backups older than 30 days
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "uploads_*.tar.gz" -mtime +30 -delete

echo "[$(date +%H:%M:%S)] Backup completed."
