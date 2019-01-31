#!/bin/bash
set -e

./preserve keygen --keyfile /backup/keyfile
./preserve create --keyfile /backup/keyfile --backend file:///backup --exclude /backup testbackup1 /
apt-get install -y fish
./preserve create --keyfile /backup/keyfile --backend file:///backup --exclude /backup testbackup2 /
