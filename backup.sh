#!/bin/bash
# ============================================================
# backup.sh — Automated backup for Svyaz
# Usage: ./backup.sh
# Backups: PostgreSQL + uploads → local + S3
# ============================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
S3_BUCKET="${S3_BACKUP_BUCKET:-}"
DB_URL="${DATABASE_URL:-}"
UPLOADS_DIR="${UPLOAD_FOLDER:-./uploads}"

mkdir -p "$BACKUP_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# --- Database ---
if command -v pg_dump &>/dev/null && [ -n "$DB_URL" ]; then
    log "Backing up database..."
    DB_FILE="${BACKUP_DIR}/svyaz_db_${TIMESTAMP}.sql.gz"
    pg_dump "$DB_URL" --clean --if-exists | gzip > "$DB_FILE"
    log "Database backup: $DB_FILE ($(du -h "$DB_FILE" | cut -f1))"

    # Encrypt with age or gpg if key is available
    if [ -n "${BACKUP_ENCRYPT_KEY:-}" ]; then
        gpg --batch --yes --recipient "$BACKUP_ENCRYPT_KEY" --encrypt "$DB_FILE" 2>/dev/null && rm -f "$DB_FILE"
        log "Encrypted: ${DB_FILE}.gpg"
    fi

    # Upload to S3
    if [ -n "$S3_BUCKET" ]; then
        aws s3 cp "${DB_FILE}.gpg" "s3://${S3_BUCKET}/db/$(basename ${DB_FILE}).gpg" --only-show-errors 2>/dev/null || \
        aws s3 cp "$DB_FILE" "s3://${S3_BUCKET}/db/$(basename ${DB_FILE})" --only-show-errors 2>/dev/null || true
        log "Uploaded to S3"
    fi
else
    log "WARN: pg_dump or DATABASE_URL not available — skipping DB backup"
fi

# --- Uploads ---
if [ -d "$UPLOADS_DIR" ]; then
    log "Backing up uploads..."
    UPLOADS_FILE="${BACKUP_DIR}/svyaz_uploads_${TIMESTAMP}.tar.gz"
    tar -czf "$UPLOADS_FILE" -C "$(dirname "$UPLOADS_DIR")" "$(basename "$UPLOADS_DIR")"
    log "Uploads backup: $UPLOADS_FILE ($(du -h "$UPLOADS_FILE" | cut -f1))"

    if [ -n "$S3_BUCKET" ]; then
        aws s3 cp "$UPLOADS_FILE" "s3://${S3_BUCKET}/uploads/$(basename ${UPLOADS_FILE})" --only-show-errors 2>/dev/null || true
    fi
fi

# --- Retention cleanup ---
find "$BACKUP_DIR" -name 'svyaz_db_*.sql.gz*' -mtime +90 -delete
find "$BACKUP_DIR" -name 'svyaz_uploads_*.tar.gz' -mtime +90 -delete

log "Backup complete"

# Retention:
#   Daily:   keep 7   (—mtime -7)
#   Weekly:  keep 4   (—mtime -30)
#   Monthly: keep 12  (—mtime -365)
#   Beyond:  delete
