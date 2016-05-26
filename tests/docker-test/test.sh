#!/bin/bash
set -e

# TODO: Run `cargo build` to ensure that `preserve` is built

mkdir -p logs

# Create temporary folders to hold the backup data and then restored result
BACKUP_DIR=`mktemp -d -t preserve-docker-test-backup-XXXXXXXXXX`
RESTORE_DIR=`mktemp -d -t preserve-docker-test-restore-XXXXXXXXXX`

# Copy `preserve` locally for Docker
cp ../../target/debug/preserve ./src/

# Build the two test images (one for backup, one for restore)
echo "Building Docker images..."
docker build -t preserve-test-backup -f src/Dockerfile.backup src > logs/docker.build.backup.txt
docker build -t preserve-test-restore -f src/Dockerfile.restore src > logs/docker.build.restore.txt

# Backup
echo "Running backing container..."
docker run -v $BACKUP_DIR:/backup --name preserve-test-backup preserve-test-backup > logs/docker.run.backup.txt
docker export preserve-test-backup > exported-backup-image.tar
docker rm preserve-test-backup

# Restore
echo "Running restore container..."
docker run -v $BACKUP_DIR:/backup -v $RESTORE_DIR:/restore --rm preserve-test-restore > logs/docker.run.restore.txt

# Compare
# NOTE: We filter out messages about missing /dev, /proc, /sys, and /backup, because those aren't included
# in the backup (no point in backing those up).
# NOTE: We filter out messages about /etc/hostname, /etc/hosts, and /etc/resolv.conf because those are
# mounted files in a Docker container, so they get skipped by a --one-file-system backup.
# NOTE: We filter out messages about Gid differing because Preserve does not currently support restoring
# uid/gid.
echo ""
echo "---------- DIFF ----------"
tar --diff -f exported-backup-image.tar -C $RESTORE_DIR |& grep -vE "^tar: (dev|proc|sys|backup)[:/].*No such file or directory$" | grep -vE "^tar: etc/(hostname|hosts|resolv.conf): Warning: Cannot stat: No such file or directory$" | grep -v "^.*Gid differs$" | grep -v "^preserve/cache.sqlite: .*$" || true

echo ""
echo "--------------------------"
echo ""
echo "NOTE: "
echo "Left behind the following folders/files, in case they're needed for inspection:"
echo "$BACKUP_DIR"
echo "$RESTORE_DIR"
echo "exported-backup-image.tar"
echo "logs/*"
