#!/bin/bash
set -e
cat > tee /etc/ceph/ceph.conf <<EOF
[global]
fsid = $(uuidgen)
mon_host = 127.0.0.1
auth_cluster_required = none
auth_service_required = none
auth_client_required = none
filestore_xattr_use_omap = true
osd pool default size = 1
osd crush chooseleaf type = 0
osd max object name len = 256
osd max object namespace len = 64
EOF
ceph-mon --cluster ceph --mkfs -i a --keyring /dev/null
ceph-mon -i a

# Setup an osd
# sudo chown -R ceph:ceph /var/lib/ceph
mkdir /var/lib/ceph/osd/ceph-0
chown -R ceph:ceph /var/lib/ceph/osd/ceph-0
ceph-disk prepare --data-dir /var/lib/ceph/osd/ceph-0
ceph-disk activate /var/lib/ceph/osd/ceph-0
ceph-osd -i 0
