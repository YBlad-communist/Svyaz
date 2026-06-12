#!/bin/bash
# ============================================================
# restore.sh — Restore Svyaz from backup
# Usage: ./restore.sh <backup_file.sql.gz> [uploads_backup.tar.gz]
# ============================================================
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <database_backup.sql.gz> [uploads_backup.tar.gz]"
    exit 1
fi

DB_BACKUP="$1"
UPLOADS_BACKUP="${2:-}"
DB_URL="${DATABASE_URL:-postgresql+psycopg2://svyaz:password@localhost:5432/svyaz}"
UPLOADS_DIR="${UPLOAD_FOLDER:-./uploads}"

# Decrypt if needed
if [[ "$DB_BACKUP" == *.gpg ]]; then
    echo "[*] Decrypting..."
    gpg --decrypt "$DB_BACKUP" > "${DB_BACKUP%.gpg}" 2>/dev/null
    DB_BACKUP="${DB_BACKUP%.gpg}"
fi

echo "[*] Restoring database..."
gunzip -c "$DB_BACKUP" | psql "$(echo $DB_URL | sed 's/+psycopg2//')" 2>/dev/null || {
    echo "[!] DB restore failed — check DATABASE_URL"
    exit 1
}
echo "[+] Database restored from $DB_BACKUP"

if [ -n "$UPLOADS_BACKUP" ] && [ -f "$UPLOADS_BACKUP" ]; then
    echo "[*] Restoring uploads..."
    tar -xzf "$UPLOADS_BACKUP" -C "$(dirname "$UPLOADS_DIR")"
    echo "[+] Uploads restored from $UPLOADS_BACKUP"
fi

echo "[✓] Restore complete"
