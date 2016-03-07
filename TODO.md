Critical:

Major:
 * Minimal testing
 * Test archiving and extracting an entire linux system (maybe live CD?).  This should test all sorts of bizarre filesystem properties.

Minor:
 * Cleanup rust-acd
 * Clean up TODOs, panics, and unwraps.
 * Test individual components of backup system
 * Tests for entire backup program
 * Usage text
 * Restore file owner/group
 * Audit crypto
 * Have a service that actively tests the backups.  Download blocks and archives and check their HMAC.  Download an archive, decrypt, and try a block or two.  Do this every so often; often enough that everything is probabilistically checked at a reasonable frequency.
 * While reading file, watch for changes.
 * List all archive names (implemented for File, but not ACD backend)
 * Backup to multiple backends
 * Clean up crypto-spec.md
 * Config file
 * Add a config option, --dereference, which will handle symlinks by "dereferencing" them.  A symlink will become a regular file in the archive with the contents set to the the contents of the target.  This can be applied either during archive creation, or during extraction (implemented for create, but not restore).
 * Proper logging
 * At the top level of archive, store a table mapping uids/gids to names.  Then, during extraction, do a remap.  For every entry in the table, check the local system for the given user name or group name.  Use that to remap the archive's uid/gid to the local system's uid/gid.
 * Diehard randomness testing
 * ACD: Try adding Keep-Alive header?
 * Clean old entries out of mtime_cache
 * Grab the inodes of our cache files, and then skip those during backup.
 * File backend should create blocks and archives with full read permission, no write permission, no execute permission.
 * Add repeated data to the test case, to exercise block deduplication
