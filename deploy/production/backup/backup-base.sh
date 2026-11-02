#!/bin/sh
# Nightly base backup for both production clusters (PROD-013).
# Runs inside the backup service: streams a compressed tar base per
# cluster with spanned WAL (-X stream), writes a sha256 manifest,
# and prunes bases older than 7 days. WAL segments archive
# continuously from the primaries (archive_command) and prune past
# 8 days, bounding PITR depth. Exit non-zero fails the container
# (restart + alert); a missed night is visible, never silent.
set -eu
: "${SOVRA_BACKUP_DB_PASSWORD:?SOVRA_BACKUP_DB_PASSWORD is required}"
export PGPASSWORD="$SOVRA_BACKUP_DB_PASSWORD"
STAMP=$(date -u +%F-%H%M)
BACKUPS=${SOVRA_BACKUP_DIR:-/backups}
RETENTION_DAYS=${SOVRA_BACKUP_RETENTION_DAYS:-7}

backup_cluster() {
  host="$1"
  user="$2"
  name="$3"
  dest="$BACKUPS/$name/base-$STAMP"
  mkdir -p "$dest"
  pg_basebackup -h "$host" -U sovra_backup -Ft -z -D "$dest" -X stream -c fast \
    -l "sovra-prod-$name-$STAMP"
  (cd "$dest" && sha256sum ./* > MANIFEST.sha256)
  echo "base backup complete: $name $dest $(du -sh "$dest" | cut -f1)"
}

backup_cluster db sovra app
backup_cluster keycloak-db keycloak keycloak

find "$BACKUPS/app" "$BACKUPS/keycloak" -maxdepth 1 -name 'base-*' -mtime +"$RETENTION_DAYS" \
  -exec rm -rf {} + -print | sed 's/^/pruned old base: /' || true
find /wal/app /wal/keycloak -type f -mtime +8 -delete 2>/dev/null || true
echo "backup cycle complete: $STAMP"
