This test suite uses Docker containers to do integration testing of Preserve.  The Rust driven integration testing cannot fully isolate Preserve during tests, so it can't, for example, muck around with the OS itself, install packages, etc.  This Docker based integration test can install packages in the container, back them up, and then do a restore in a fresh container to see if Preserve restores those system files.  This is a nice way to do testing that is more akin to the real world.


How it works:
	* Two docker images are created, one for backup and one for restore.
	* The backup image is run with a "backup" volume mounted.
	* The backup image backs up the system, storing Preserve's backup data in the "backup" volume.
	* The backup image also installs some packages, backs up again, and does other things to simulate a real use case.
	* The restore image is run with the same "backup" volume mounted and a "restore" volume.
	* The restore image restores the latest backup to the "restore" volume.
	* Now we can compare the state of the filesystem on the backup container versus the state of the filesystem in the "restore" volume.  They should match, outside of expected variation (e.g. /dev isn't backed up).


How to test:
	Run `test.sh` and ensure that when it prints "---------- DIFF ----------" that the diff is empty.
