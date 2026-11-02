#!/bin/sh
# Point-in-time restore into an ISOLATED scratch cluster (PROD-013).
# Never restores over a live primary: the drill and the real
# recovery both land on scratch volumes, reconcile there, and only
# then promote by re-pointing the app (see recovery.md).
#
# Usage (admin host with docker):
#   BACKUP_SRC=/path/to/backups WAL_SRC=/path/to/wal \
#     ./restore.sh app 2026-11-02T15:00:00Z sovra-restore-drill
# Target "latest" replays to the newest consistent point.
set -eu
CLUSTER="${1:?usage: $0 <app|keycloak> <target-time|latest> <scratch-name>}"
TARGET="${2:?usage: $0 <app|keycloak> <target-time|latest> <scratch-name>}"
NAME="${3:?usage: $0 <app|keycloak> <target-time|latest> <scratch-name>}"
: "${BACKUP_SRC:?BACKUP_SRC (backups volume path) is required}"
: "${WAL_SRC:?WAL_SRC (wal archive path) is required}"
case "$CLUSTER" in
  app) DBNAME=sovra ;;
  keycloak) DBNAME=keycloak ;;
  *) echo "cluster must be app or keycloak" >&2; exit 2 ;;
esac
BASE=$(ls -d "$BACKUP_SRC/$CLUSTER"/base-* 2>/dev/null | sort | tail -1)
test -n "$BASE" || { echo "no base backup for $CLUSTER in $BACKUP_SRC" >&2; exit 2; }
(cd "$BASE" && sha256sum -c MANIFEST.sha256)
VOLUME="$NAME-pgdata"
docker volume create "$VOLUME" >/dev/null
docker run --rm -i \
  -v "$VOLUME:/var/lib/postgresql/data" \
  -v "$BASE:/base:ro" \
  -v "$WAL_SRC:/wal:ro" \
  postgres:17.7 sh -eu <<EOF
rm -rf /var/lib/postgresql/data/*
cd /var/lib/postgresql/data
for t in /base/*.tar.gz; do tar -xzf "\$t"; done
rm -f backup_label.old postmaster.pid
cat > postgresql.auto.conf <<CONF
restore_command = 'cp /wal/$CLUSTER/%f %p'
CONF
if [ "$TARGET" != "latest" ]; then
  echo "recovery_target_time = '$TARGET'" >> postgresql.auto.conf
fi
touch standby.signal
EOF
echo "restored $CLUSTER base $(basename "$BASE") into volume $VOLUME (target: $TARGET)"
echo "next: start the scratch cluster, run reconcile.sql, verify, then promote per recovery.md"
