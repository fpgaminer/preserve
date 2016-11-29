#!/bin/bash
set -e
sudo mkdir /mnt/gluster-brick
sudo apt-get install glusterfs-server
sudo gluster vol create test $HOSTNAME:/mnt/gluster-brick force
sudo gluster vol start test
