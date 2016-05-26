#!/bin/bash
set -e

cd /preserve
./preserve restore --keyfile /backup/keyfile --backend file --backend-path /backup testbackup2 /restore
