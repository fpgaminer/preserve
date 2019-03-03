 * Clean up TODOs and improve error reporting.
 * Test individual components of backup system (unit testing)
 * Add a config option, --dereference, which will handle symlinks by "dereferencing" them.  A symlink will become a regular file in the archive with the contents set to the the contents of the target.  This can be applied either during archive creation, or during extraction (implemented for create, but not restore).
 * Audit crypto
 * Have a service that actively tests the backups.  Download blocks and archives and check their HMAC.  Download an archive, decrypt, and try a block or two.  Do this every so often; often enough that everything is probabilistically checked at a reasonable frequency.
 * Option to backup to multiple backends
 * Clean up crypto-spec.md
 * Config file
 * Diehard randomness testing
 * Clean old entries out of mtime_cache
 * Restore file owner/group
 * At the top level of archive, store a table mapping uids/gids to names.  Then, during extraction, do a remap.  For every entry in the table, check the local system for the given user name or group name.  Use that to remap the archive's uid/gid to the local system's uid/gid.
 * Add tests for --one-file-system flag
 * During archive creation, after reading all files, sleep for a second and then rescan the metadata on all files.  If there are any mismatches, reread those files.  This should catch any file modification that the existing file modification detection scheme misses (due to lag in mtime updates).
 * When warning that a symlink was backed up but its link was not, we should also print the link.
 * The Docker based integration test should do more manipulation between backups.
 * The Docker based integration test script should more clearly indicate whether the test passed or not.
 * The Docker based integration test should be integrated into Travis-CI.
 * Add the ability to extract specific files/folders during a restore.
 * verbose flag
 * Rename "current_filesystem" variable in create code; generally re-work how one-file-system works
 * The help message for "--exclude" says that it is a required option ... which isn't true.  Something weird with clap.
 * Maybe use the flexi_logger crate instead of our custom logger?
 * Remove Comparison functions from newtype and replace with a constant_time_compare function so it's explicit (also remove hashing, partialord, etc, etc)
 * Add a test that backs up to one backend, and then to another, and then restores from each.  This should make sure that the cache mechanism doesn't accidentally cause preserve to skip uploading blocks.  Also we should try copying over half of a backend and making sure it still works after another archive creation and restore; again verifying that the cache doesn't prevent preserve from correctly backing up.
 * Use failure crate
 * Add tests for diff command.
 * Backup keyfile to backend(s) (encrypted using HellishKDF)
 * Use progress bar crate
 * Refcounting on the backend (need to implement the new backend API)
 * Add tests for verify command.
 * Add tests for list command.