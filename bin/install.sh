#!/bin/bash

set -euf -o pipefail

VAULT=$HOME/bin/vault

install_ceph() {
  echo -e "install ceph"
  echo -e "\tInstalling PPA"
  add-apt-repository cloud-archive:mitaka -y > /dev/null 2>&1
  echo -e "\tapt update"
  apt update -qq
  echo -e "\tinstalling deps"
  apt install -yq librados-dev ceph
}

setup_ceph() {
  echo -e "setup ceph"
  cat > /etc/ceph/ceph.conf <<EOF
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
  cat > $HOME/.config/ceph.json <<EOF
{
 "config_file": "/etc/ceph/ceph.conf",
 "user_id": "admin",
 "data_pool": "rbd",
}
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
}

install_gluster() {
  echo -e "install gluster"
  echo -e "\tInstalling PPA"
  add-apt-repository ppa:gluster/glusterfs-3.8 -y > /dev/null 2>&1
  echo -e "\tapt update"
  apt update -qq
  echo -e "\tinstalling deps"
  apt install glusterfs-common glusterfs-server -yq
}

setup_gluster() {
  echo -e "setup gluster"
  echo -e "\tcreate vol"
  gluster vol create test $HOSTNAME:/mnt/gluster-brick force
  echo -e "\tstart vol"
  gluster vol start test
  cat > $HOME/.config/gluster.json <<EOF
{
    "server": "127.0.0.1",
    "port": 24007,
    "volume_name": "test"
}
EOF
}

install_vault() {
  echo -e "install vault"
  VAULT_VERSION=${VAULT_VERSION:-0.6.1}

  mkdir -p $HOME/bin

  cd /tmp

  wget -q https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip
  unzip -q vault_${VAULT_VERSION}_linux_amd64.zip
  mv vault $HOME/bin
}

setup_vault() {
  echo -e "setup vault"
  $VAULT server -dev &
  sleep 1
  VAULT_ADDR=http://127.0.0.1:8200 $VAULT token-create -id="test12345" -ttl="720h"
  cat > $HOME/.config/vault.json <<EOF
{
 "host": "http://127.0.0.1:8200",
 "token": "test12345"
}
EOF
}

_ceph() {
  install_ceph
  setup_ceph
}

_gluster() {
  install_gluster
  setup_gluster
}

_vault() {
  install_vault
  setup_vault
}

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

mkdir -p $HOME/.config
_vault
echo -e "Features to install: $FEATURES\n"
for APP in $FEATURES
do
  echo "About to setup $APP"
  _$APP
done
