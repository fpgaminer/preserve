Critical:

Major:
 * Handle symlinks
 * Handle hard links
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
 * Add a config option, --dereference, which will handle symlinks by "dereferencing" them.  A symlink will become a regular file in the archive with the contents set to the the contents of the target.  This can be applied either during archive creation, or during extraction.
 * Add a config option, --hard-dereference.  Same thing as above, but for hard links.
 * Throw warning when archiving a symlink, not dereferencing it, and the symlink points to another file which isn't being archived.
 * Throw warning when archiving a hard link, not dereferencing, and we haven't archived all hard links to the file.
 * Proper logging
 * At the top level of archive, store a table mapping uids/gids to names.  Then, during extraction, do a remap.  For every entry in the table, check the local system for the given user name or group name.  Use that to remap the archive's uid/gid to the local system's uid/gid.
 * Diehard randomness testing
 * Add an option --one-file-system, which should be on by default.  During backup, it identifies the stat.dev() of the directory it starts in (e.g. "/"), and then skips any directory/file which resides on a different stat.dev().  This will exclude /proc, /dev, /sys, etc. so that backing up "/" doesn't do terrible, terrible things.
 * Do we need to identify device files (files that are not "regular file" or "directory") and skip those?  Probably.  Or probably have a flag for it --skip-non-regular-files, on by default.  Use stat.mode() to identify.  The masks are (S_IFLNK==1010_0000_0000_0000==symbolic link;  S_IFREG==1000_0000_0000_0000==regular file; S_IFDIR==0100_0000_0000_0000==directory).
 * ACD: Try adding Keep-Alive header?
 * Clean old entries out of mtime_cache
 * Grab the inodes of our cache files, and then skip those during backup.
 * Maybe store the target directory canonical path in the Archive data structure during archive creation.  All file paths are relative to it, and the idea is that it's like tar which doesn't store the absolute path.  But maybe we should store it anyway, since it's useful information.  It wouldn't normally be used during extraction.
 * File backend should create blocks and archives with full read permission, no write permission, no execute permission.
