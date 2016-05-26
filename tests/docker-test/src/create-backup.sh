#!/bin/bash
set -e

cd /preserve
./preserve keygen --keyfile /backup/keyfile
./preserve create --keyfile /backup/keyfile --backend file --backend-path /backup testbackup1 /
apt-get install -y git
./preserve create --keyfile /backup/keyfile --backend file --backend-path /backup testbackup2 /
