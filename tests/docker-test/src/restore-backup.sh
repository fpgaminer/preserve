#!/bin/bash
set -e

cd /preserve
./preserve restore --keyfile /backup/keyfile --backend file:///backup testbackup2 /restore
