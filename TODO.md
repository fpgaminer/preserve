Critical:

Major:
 * Minimal testing
 * Test archiving and extracting an entire linux system (maybe live CD?).  This should test all sorts of bizarre filesystem properties.

Minor:
 * Clean up TODOs, panics, and unwraps.
 * Proper logging
 * Cleanup rust-acd
 * Test individual components of backup system
 * Tests for entire backup program
 * Grab the inodes of our cache files, and then skip those during backup.
 * Add a config option, --dereference, which will handle symlinks by "dereferencing" them.  A symlink will become a regular file in the archive with the contents set to the the contents of the target.  This can be applied either during archive creation, or during extraction (implemented for create, but not restore).
 * Usage text
 * Audit crypto
 * Have a service that actively tests the backups.  Download blocks and archives and check their HMAC.  Download an archive, decrypt, and try a block or two.  Do this every so often; often enough that everything is probabilistically checked at a reasonable frequency.
 * Option to backup to multiple backends
 * Clean up crypto-spec.md
 * Config file
 * Diehard randomness testing
 * ACD: Try adding Keep-Alive header?
 * Clean old entries out of mtime_cache
 * Restore file owner/group
 * At the top level of archive, store a table mapping uids/gids to names.  Then, during extraction, do a remap.  For every entry in the table, check the local system for the given user name or group name.  Use that to remap the archive's uid/gid to the local system's uid/gid.
 * Add the ability for keygen to deterministically generate a keystore from a password.  Use heavy password hashing (maybe time it to a minute or so?) by default.
 * Add --one-file-system flag
 * During archive creation, after reading all files, sleep for a second and then rescan the metadata on all files.  If there are any mismatches, reread those files.  This should catch any file modification that the existing file modification detection scheme misses (due to lag in mtime updates).
 * ACD backend: specify path
 * When warning that a symlink was backed up but its link was not, we should also print the link.
