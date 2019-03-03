This test suite uses Docker containers to do integration testing of Preserve.  The Rust driven integration testing cannot fully isolate Preserve during tests, so it can't, for example, muck around with the OS itself, install packages, etc.  This Docker based integration test can install packages in the container, back them up, and then do a restore in a fresh container to see if Preserve restores those system files.  This is a nice way to do testing that is more akin to the real world (Preserve isn't really designed to backup packages, but it's a good test of its flexibility).


How it works:
	* A docker image is created with preserve on it.
	* The image is run, backing up the system, storing the backup to a "backup" volume.  It also installs some packages, backs up again, etc.
	* The image is run again with the same "backup" volume mounted, but performs a restore.
	* The restore container restores the latest backup and compares the result against the filesystem state of the backup container.
	* They restored filesystem and the backup container's filesystem should match, outside of expected variation (e.g. /dev isn't backed up).


How to test:
	Run `test.py` and ensure that when it prints "---------- DIFF ----------" that the diff is empty.
