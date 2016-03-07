# Preserve [![Build Status](https://travis-ci.org/fpgaminer/preserve.svg?branch=master)](https://travis-ci.org/fpgaminer/preserve) [![Clippy Linting Result](http://clippy.bashy.io/github/fpgaminer/preserve/master/badge.svg)](http://clippy.bashy.io/github/fpgaminer/preserve/master/log) #
Preserve is an encrypted backup system written in Rust.  All backup data is encrypted, so backups can be stored on untrusted devices/services without exposing any of your data.  Backups are simple, operating very similar to creating an archive like Zip or Tar.  Deduplication makes this space efficient.

## Status
I am actively developing this project, so it is not stable or ready for general use.  The code is currently messy and missing many vital features.  Follow along if you're interested!

## Usage

1. Generate a keyfile

   ```
   preserve keygen --keyfile keyfile
   ```

    Make sure to store this keyfile in a safe place.  Anyone who has access to this keyfile can read your backups and/or corrupt them.

2. Create a backup

   ```
   preserve create --keyfile keyfile --backend file --backend-path /path/to/my/backups/ my-backup-`date +%Y-%m-%d_%H-%M-%S` /home/me/
   ```

   This will create a backup of everything inside `/home/me/`, the backup will be called something like `my-backup-2016-02-25_11-56-51`, the backup will be stored in the filesystem at `/path/to/my/backups`.  To take advantage of deduplication you should store all your backups in the same place.  If you backup multiple machines, you could use an external drive or NAS.  If you use the same keyfile for all machines then Preserve will dedup across all machines.

   Amazon Cloud Drive is also supported as a backend using `--backend acd`.  Setup instructions for ACD are forthcoming.

3. List backups

   ```
   preserve list --keyfile keyfile --backend file --backend-path /path/to/my/backups/
   ```

3. Restore a backup

   ```
   preserve restore --keyfile keyfile --backend file --backend-path /path/to/my/backups/ name-of-backup-to-restore /path/to/restore/it/to/
   ```

   This will restore the backup named `name-of-backup-to-restore`, extracting its contents to `/path/to/restore/it/to/`

## Build
```
cargo build
```

## Test
```
cargo test
```

## Details
It's easiest to understand Preserve by going through how it creates a backup.  When you tell Preserve to create a backup, it walks the specified path looking for all files and folders.  It collects information about all those files and folders (name, permissions, mtime, size) in a tree data structure.  Then it goes through all the files and reads their contents.  It reads file contents 1MB at a time.  For each 1MB chunk, it encrypts the chunk using convergent encryption.  Convergent encryption is determinsitic, so given the same 1MB chunk it will output the same 1MB encrypted block (plus id and mac).  Each block also has a small (32 bytes) unique identifier associated with it.  So after Preserve has finished reading all the chunks of a file, it stores the contents in the tree data structure as a list of these unique identifiers, and stores the actual blocks on the backend.  When it encounters the same block twice, it has to store the metadata twice, but the actual encrypted data only gets stored once on the backend.  This is how Preserve achieves its deduplication.  If you create one backup, and then create another of the same exact data, Preserve won't have to store any new blocks on the backend.  It would only need to store a new set of metadata.

When all files have been traversed, the tree data structure is serialized to JSON, compressed with XZ, encrypted using a public key, and then stored at the backend.

Various caches are used to speed this process up.  If a file hasn't changed since Preserve last backed it up, then it will pull its metadata and list of content identifiers from cache.  So it won't actually have to re-read the file.
