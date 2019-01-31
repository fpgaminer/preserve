#!/bin/bash
set -e

./preserve restore --keyfile /backup/keyfile --backend file:///backup testbackup2 /restore

# Compare
# NOTE: We filter out messages about missing /dev, /proc, /sys, and /backup, because those aren't included
# in the backup (no point in backing those up).
# NOTE: We filter out messages about /etc/hostname, /etc/hosts, and /etc/resolv.conf because those are
# mounted files in a Docker container.
# NOTE: We filter out messages about Gid differing because Preserve does not currently support restoring
# uid/gid.
DIFFOUTPUT=`tar --diff -f /exported-backup-image.tar -C /restore |& grep -vE "^tar: (dev|proc|sys|backup|run|tmp)[:/].*No such file or directory$" | grep -vE "^etc/(hostname|hosts|resolv.conf): .*$" | grep -v "^.*Gid differs$" | grep -v "^tar: preserve/cache.sqlite: .*$" | grep -v "^preserve/log.txt: .*$" || true`

>&2 echo ""
>&2 echo "---------- DIFF ----------"
>&2 echo "$DIFFOUTPUT"
>&2 echo ""
>&2 echo "--------------------------"