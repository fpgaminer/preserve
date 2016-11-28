#!/bin/bash
set -e
mkdir /mnt/gluster-brick
sudo apt-get install glusterfs-server
sudo gluster vol create test $HOSTNAME:/mnt/gluster-brick
sudo gluster vol start test
